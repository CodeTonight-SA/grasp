#!/usr/bin/env python3
"""tools/bench_mcp_seal.py -- measure the added latency grasp-mcp-seal puts
in front of a local upstream MCP server.

Spins up a trivial stub Streamable HTTP MCP upstream (instant JSON reply, no
artificial delay) and issues N tools/call requests two ways: DIRECT (straight
to the stub) and PROXIED (through grasp.mcp_seal, pointed at the same stub).
Reports the p50/p95 latency of each series, and the delta the proxy adds on
top -- the measurement hypothesis H909 asks for. Stdlib only, loopback only.

Run::

    PYTHONPATH=. python3 tools/bench_mcp_seal.py [--n 200]
"""
from __future__ import annotations

import argparse
import http.client
import http.server
import json
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from grasp.mcp_seal import ProxyConfig, SealChain, make_server  # noqa: E402

HOST = "127.0.0.1"


class _InstantUpstream(http.server.BaseHTTPRequestHandler):
    """Replies to every tools/call immediately -- no artificial delay, so the
    series' latency is dominated by the thing under test, not by the stub."""

    def do_POST(self):  # noqa: N802 -- http.server's own method name
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        out = json.dumps({"jsonrpc": "2.0", "id": body.get("id"),
                          "result": {"content": [], "isError": False}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a) -> None:  # noqa: D102 -- keep bench output clean
        pass


def _serve(handler_cls) -> http.server.HTTPServer:
    server = http.server.HTTPServer((HOST, 0), handler_cls)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _call(port: int, call_id: int) -> float:
    payload = {"jsonrpc": "2.0", "id": call_id, "method": "tools/call",
               "params": {"name": "bench-tool", "arguments": {"i": call_id}}}
    body = json.dumps(payload).encode("utf-8")
    t0 = time.perf_counter()
    conn = http.client.HTTPConnection(HOST, port)
    conn.request("POST", "/mcp", body=body, headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    resp.read()
    conn.close()
    return time.perf_counter() - t0


def _series(port: int, n: int) -> list[float]:
    return [_call(port, i) for i in range(n)]


def _percentile(samples: list[float], p: float) -> float:
    """Nearest-rank percentile over a sorted copy -- no extra dependency."""
    ordered = sorted(samples)
    idx = min(len(ordered) - 1, max(0, round(p * (len(ordered) - 1))))
    return ordered[idx]


def _run_direct(n: int) -> tuple[list[float], http.server.HTTPServer]:
    upstream = _serve(_InstantUpstream)
    return _series(upstream.server_address[1], n), upstream


def _run_proxied(upstream_url: str, home: Path, n: int) -> list[float]:
    cfg = ProxyConfig(upstream=upstream_url, chain=SealChain(home))
    proxy = make_server(cfg, HOST, 0)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    try:
        return _series(proxy.server_address[1], n)
    finally:
        proxy.shutdown()
        proxy.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--n", type=int, default=200, help="requests per series (default 200)")
    args = parser.parse_args(argv)

    direct, upstream = _run_direct(args.n)
    upstream_url = f"http://{HOST}:{upstream.server_address[1]}"
    tmp_home = Path(tempfile.mkdtemp(prefix="grasp-mcp-seal-bench-"))
    try:
        proxied = _run_proxied(upstream_url, tmp_home, args.n)
    finally:
        upstream.shutdown()
        upstream.server_close()
        shutil.rmtree(tmp_home, ignore_errors=True)

    d_p50, d_p95 = _percentile(direct, 0.50), _percentile(direct, 0.95)
    p_p50, p_p95 = _percentile(proxied, 0.50), _percentile(proxied, 0.95)
    print(f"direct n={args.n} p50={d_p50 * 1000:.3f}ms p95={d_p95 * 1000:.3f}ms")
    print(f"proxy  n={args.n} p50={p_p50 * 1000:.3f}ms p95={p_p95 * 1000:.3f}ms")
    print(f"added  p50={(p_p50 - d_p50) * 1000:.3f}ms p95={(p_p95 - d_p95) * 1000:.3f}ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())
