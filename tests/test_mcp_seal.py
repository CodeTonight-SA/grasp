# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Tests for grasp.mcp_seal -- the tool-call seal reverse proxy.

Every test talks to two REAL throwaway HTTP servers on loopback only (a stub
upstream MCP server, and the seal proxy itself via ``grasp.mcp_seal.make_server``)
-- no stubbing of http.client/http.server internals, because the defect class
this module exists to prevent (silently buffering a stream, or silently
dropping a header) lives in the real wire behaviour, not in a mockable seam.

Mirrors the existing project convention (tests/test_byok_attest.py): a small,
single-purpose ``http.server.BaseHTTPRequestHandler`` subclass per scenario,
started via ``http.server.HTTPServer`` on a daemon thread, 127.0.0.1 only.
"""
from __future__ import annotations

import contextlib
import http.client
import http.server
import json
import socket
import threading
import time
from pathlib import Path

from grasp import mcp_seal as m

HOST = "127.0.0.1"


# ---------------------------------------------------------------------------
# Stub upstream MCP servers -- one small handler class per test scenario
# ---------------------------------------------------------------------------

class _JsonEchoUpstream(http.server.BaseHTTPRequestHandler):
    """Replies to every tools/call id with a plain JSON success result.
    Echoes any ``X-Test`` request header back as ``X-Echo`` (header-passthrough
    probe) and records the Authorization / Mcp-Session-Id it was sent."""

    seen_auth: list = []
    seen_session: list = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).seen_auth.append(self.headers.get("Authorization"))
        type(self).seen_session.append(self.headers.get("Mcp-Session-Id"))
        parsed = json.loads(body) if body else {}
        messages = parsed if isinstance(parsed, list) else [parsed]
        replies = [
            {"jsonrpc": "2.0", "id": msg["id"],
             "result": {"content": [], "isError": False}}
            for msg in messages if "id" in msg
        ]
        if not replies:
            self.send_response(202)
            self.end_headers()
            return
        out = json.dumps(replies if isinstance(parsed, list) else replies[0]).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        if self.headers.get("X-Test"):
            self.send_header("X-Echo", self.headers["X-Test"])
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # noqa: D102
        pass


class _ErrorResultUpstream(http.server.BaseHTTPRequestHandler):
    """Replies with a JSON-RPC protocol-level error for every call."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        out = json.dumps({
            "jsonrpc": "2.0", "id": body.get("id"),
            "error": {"code": -32000, "message": "boom"},
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # noqa: D102
        pass


class _SSEUpstream(http.server.BaseHTTPRequestHandler):
    """One tools/call -> one SSE event carrying the matching JSON-RPC reply."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        reply = json.dumps({"jsonrpc": "2.0", "id": body.get("id"),
                            "result": {"content": [], "isError": False}})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(f"data: {reply}\n\n".encode("utf-8"))

    def log_message(self, *a):  # noqa: D102
        pass


class _SSEDelayedSecondEventUpstream(http.server.BaseHTTPRequestHandler):
    """Sends the matching reply immediately, THEN sleeps, THEN sends a second
    harmless event before closing -- the timing probe for "never buffers the
    whole stream": a client must see event 1 well before event 2 arrives."""

    DELAY_S = 0.3

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        reply = json.dumps({"jsonrpc": "2.0", "id": body.get("id"),
                            "result": {"content": [], "isError": False}})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(f"data: {reply}\n\n".encode("utf-8"))
        self.wfile.flush()
        time.sleep(self.DELAY_S)
        self.wfile.write(b": keepalive\n\n")
        self.wfile.flush()

    def log_message(self, *a):  # noqa: D102
        pass


class _NeverRespondsUpstream(http.server.BaseHTTPRequestHandler):
    """Accepts the call but never sends a reply carrying the request id --
    the "unsettled intent" shape without needing a down upstream."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length) if length else b""
        out = json.dumps({"jsonrpc": "2.0", "id": "not-the-real-id",
                          "result": {"content": [], "isError": False}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # noqa: D102
        pass


class _CallCountingUpstream(http.server.BaseHTTPRequestHandler):
    """Counts every request it receives -- proves a refused call never reached it."""

    calls = 0

    def do_POST(self):  # noqa: N802
        type(self).calls += 1
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        out = json.dumps({"jsonrpc": "2.0", "id": body.get("id"),
                          "result": {"content": [], "isError": False}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # noqa: D102
        pass


# ---------------------------------------------------------------------------
# Harness: a real upstream + a real proxy, both on loopback, daemon threads
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def _running(upstream_handler, home: Path, on_seal_failure: str = "refuse"):
    upstream = http.server.HTTPServer((HOST, 0), upstream_handler)
    up_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    up_thread.start()
    upstream_url = f"http://{HOST}:{upstream.server_address[1]}"
    cfg = m.ProxyConfig(upstream=upstream_url, chain=m.SealChain(home),
                        on_seal_failure=on_seal_failure)
    proxy = m.make_server(cfg, HOST, 0)
    proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    proxy_thread.start()
    try:
        yield proxy.server_address[1]
    finally:
        proxy.shutdown()
        proxy.server_close()
        upstream.shutdown()
        upstream.server_close()


def _post(port: int, payload, headers: dict | None = None) -> tuple[int, dict, bytes]:
    conn = http.client.HTTPConnection(HOST, port)
    body = json.dumps(payload).encode("utf-8")
    hdrs = {"Content-Type": "application/json", **(headers or {})}
    conn.request("POST", "/mcp", body=body, headers=hdrs)
    resp = conn.getresponse()
    data = resp.read()
    out_headers = dict(resp.getheaders())
    conn.close()
    return resp.status, out_headers, data


def _tool_call(call_id, name="demo-tool", arguments=None) -> dict:
    return {"jsonrpc": "2.0", "id": call_id, "method": "tools/call",
            "params": {"name": name, "arguments": arguments or {}}}


# ---------------------------------------------------------------------------
# JSON and SSE single-call replies
# ---------------------------------------------------------------------------

def test_json_reply_seals_intent_and_outcome(tmp_path):
    home = tmp_path / "home"
    with _running(_JsonEchoUpstream, home) as port:
        status, _, data = _post(port, _tool_call(1, arguments={"x": 1}))
    assert status == 200
    assert json.loads(data)["result"]["isError"] is False
    out = m.verify_seal_chain(home)
    assert out["records"] == 2
    assert out["chain_verdict"] == "verified"
    assert out["unsettled"] == []


def test_sse_reply_seals_intent_and_outcome(tmp_path):
    home = tmp_path / "home"
    with _running(_SSEUpstream, home) as port:
        status, headers, data = _post(port, _tool_call(2))
    assert status == 200
    assert headers.get("Content-Type") == "text/event-stream"
    assert b'"id": 2' in data or b'"id":2' in data
    out = m.verify_seal_chain(home)
    assert out["records"] == 2
    assert out["chain_verdict"] == "verified"
    assert out["unsettled"] == []


# ---------------------------------------------------------------------------
# Batch requests
# ---------------------------------------------------------------------------

def test_batch_seals_every_call_and_pairs_each_outcome(tmp_path):
    home = tmp_path / "home"
    batch = [_tool_call(1, "toolA", {"a": 1}), _tool_call(2, "toolB", {"b": 2})]
    with _running(_JsonEchoUpstream, home) as port:
        status, _, data = _post(port, batch)
    assert status == 200
    replies = json.loads(data)
    assert {r["id"] for r in replies} == {1, 2}
    out = m.verify_seal_chain(home)
    assert out["records"] == 4  # 2 intents + 2 outcomes
    assert out["unsettled"] == []
    tools = sorted(idr["decision"]["tool"] for idr in _read_raw(home) if idr["kind"] == "mcp.tool.intent")
    assert tools == ["toolA", "toolB"]


# ---------------------------------------------------------------------------
# A notification-shaped tools/call (no id) alongside a real notification
# ---------------------------------------------------------------------------

def test_notification_with_no_id_does_not_crash_and_stays_unsettled(tmp_path):
    home = tmp_path / "home"
    batch = [
        {"jsonrpc": "2.0", "method": "tools/call",
         "params": {"name": "fire-and-forget", "arguments": {}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
    ]
    with _running(_JsonEchoUpstream, home) as port:
        status, _, data = _post(port, batch)
    assert status == 202  # upstream: no id anywhere, nothing to reply to
    assert data == b""
    out = m.verify_seal_chain(home)
    # The id-less tools/call still gets its intent sealed (completeness); the
    # bare notification is not a tools/call and seals nothing.
    assert out["records"] == 1
    assert len(out["unsettled"]) == 1


# ---------------------------------------------------------------------------
# Error result
# ---------------------------------------------------------------------------

def test_error_result_is_sealed_as_is_error(tmp_path):
    home = tmp_path / "home"
    with _running(_ErrorResultUpstream, home) as port:
        status, _, data = _post(port, _tool_call(7))
    assert status == 200
    assert json.loads(data)["error"]["message"] == "boom"
    out = m.verify_seal_chain(home)
    outcome = next(idr for idr in _read_raw(home) if idr["kind"] == "mcp.tool.outcome")
    assert outcome["decision"]["is_error"] is True
    opened = m._open_record(home, outcome["id"], out["_by_id"])
    assert opened["ok"] is True
    assert opened["plain"]["result"]["message"] == "boom"


# ---------------------------------------------------------------------------
# Upstream down
# ---------------------------------------------------------------------------

def test_upstream_down_refuses_cleanly_and_intent_stays_unsettled(tmp_path):
    home = tmp_path / "home"
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind((HOST, 0))
    dead_port = probe.getsockname()[1]
    probe.close()  # nobody is listening on this port now
    cfg = m.ProxyConfig(upstream=f"http://{HOST}:{dead_port}", chain=m.SealChain(home))
    proxy = m.make_server(cfg, HOST, 0)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, data = _post(proxy.server_address[1], _tool_call(1))
    finally:
        proxy.shutdown()
        proxy.server_close()
    assert status == 502
    assert json.loads(data)["error"]["code"] == -32000
    out = m.verify_seal_chain(home)
    assert out["records"] == 1  # the intent was sealed before the failed forward
    assert len(out["unsettled"]) == 1
    assert out["chain_verdict"] == "verified"


# ---------------------------------------------------------------------------
# Refuse and pass on seal failure
# ---------------------------------------------------------------------------

def test_refuse_on_seal_failure_never_reaches_upstream(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "seal.jsonl").mkdir()  # force append_idr to raise IsADirectoryError
    _CallCountingUpstream.calls = 0
    with _running(_CallCountingUpstream, home, on_seal_failure="refuse") as port:
        status, _, data = _post(port, _tool_call(9))
    assert status == 200
    body = json.loads(data)
    assert body["id"] == 9
    assert "refusing" in body["error"]["message"]
    assert _CallCountingUpstream.calls == 0


def test_pass_on_seal_failure_still_forwards_and_logs(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    (home / "seal.jsonl").mkdir()
    _CallCountingUpstream.calls = 0
    with _running(_CallCountingUpstream, home, on_seal_failure="pass") as port:
        status, _, data = _post(port, _tool_call(9))
    assert status == 200
    body = json.loads(data)
    assert body["result"]["isError"] is False
    assert _CallCountingUpstream.calls == 1
    failures = (home / "failures.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(failures) == 1
    assert json.loads(failures[0])["phase"] == "intent"


# ---------------------------------------------------------------------------
# Header passthrough (both directions)
# ---------------------------------------------------------------------------

def test_header_passthrough_both_directions(tmp_path):
    home = tmp_path / "home"
    _JsonEchoUpstream.seen_auth = []
    _JsonEchoUpstream.seen_session = []
    with _running(_JsonEchoUpstream, home) as port:
        status, headers, _ = _post(port, _tool_call(1), headers={
            "Authorization": "Bearer super-secret-token",
            "Mcp-Session-Id": "session-abc",
            "X-Test": "round-trip-value",
        })
    assert status == 200
    assert _JsonEchoUpstream.seen_auth == ["Bearer super-secret-token"]
    assert _JsonEchoUpstream.seen_session == ["session-abc"]
    assert headers.get("X-Echo") == "round-trip-value"


# ---------------------------------------------------------------------------
# No plaintext in the chain; openings carry it, mode 0600
# ---------------------------------------------------------------------------

SECRET_MARKER = "TOP-SECRET-ARG-VALUE-7f3a9c"


def test_no_plaintext_in_the_chain_but_openings_has_it(tmp_path):
    home = tmp_path / "home"
    with _running(_JsonEchoUpstream, home) as port:
        _post(port, _tool_call(1, arguments={"value": SECRET_MARKER}))
    chain_bytes = (home / "seal.jsonl").read_bytes()
    assert SECRET_MARKER.encode("utf-8") not in chain_bytes
    openings_path = home / "openings.jsonl"
    assert SECRET_MARKER.encode("utf-8") in openings_path.read_bytes()
    mode = openings_path.stat().st_mode & 0o777
    assert mode == 0o600


# ---------------------------------------------------------------------------
# Opening verifies (commitment recomputation)
# ---------------------------------------------------------------------------

def test_opening_verifies_and_a_wrong_salt_fails(tmp_path):
    home = tmp_path / "home"
    with _running(_JsonEchoUpstream, home) as port:
        _post(port, _tool_call(1, arguments={"value": "hello"}))
    out = m.verify_seal_chain(home)
    intent_id = next(i for i, idr in out["_by_id"].items() if idr.kind == "mcp.tool.intent")
    opened = m._open_record(home, intent_id, out["_by_id"])
    assert opened["ok"] is True
    assert opened["plain"]["arguments"] == {"value": "hello"}
    # Corrupt the stored salt -- the recomputed commitment must no longer match.
    openings_path = home / "openings.jsonl"
    lines = openings_path.read_text(encoding="utf-8").splitlines()
    corrupted = []
    for line in lines:
        entry = json.loads(line)
        if entry["record_id"] == intent_id:
            entry["salt"] = "00" * (len(entry["salt"]) // 2)
        corrupted.append(json.dumps(entry))
    openings_path.write_text("\n".join(corrupted) + "\n", encoding="utf-8")
    reopened = m._open_record(home, intent_id, out["_by_id"])
    assert reopened["ok"] is False


# ---------------------------------------------------------------------------
# Tampered leaf fails
# ---------------------------------------------------------------------------

def test_tampered_leaf_fails_verify(tmp_path):
    home = tmp_path / "home"
    with _running(_JsonEchoUpstream, home) as port:
        _post(port, _tool_call(1))
    ledger = home / "seal.jsonl"
    lines = ledger.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["decision"]["tool"] = "a-different-tool-entirely"
    lines[0] = json.dumps(tampered)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = m.verify_seal_chain(home)
    assert out["chain_verdict"] == "broken"
    assert out["ok"] is False


# ---------------------------------------------------------------------------
# Unsettled intent flagged
# ---------------------------------------------------------------------------

def test_unsettled_intent_is_flagged(tmp_path):
    home = tmp_path / "home"
    with _running(_NeverRespondsUpstream, home) as port:
        status, _, _ = _post(port, _tool_call(123))
    assert status == 200  # upstream answered -- just never with a matching id
    out = m.verify_seal_chain(home)
    assert out["records"] == 1  # only the intent; no outcome ever matched
    assert len(out["unsettled"]) == 1
    assert out["chain_verdict"] == "verified"


# ---------------------------------------------------------------------------
# SSE chunks arrive before the stream ends (never buffers the whole stream)
# ---------------------------------------------------------------------------

def test_sse_chunks_relayed_before_stream_ends(tmp_path):
    home = tmp_path / "home"
    with _running(_SSEDelayedSecondEventUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port)
        conn.request("POST", "/mcp", body=json.dumps(_tool_call(1)).encode("utf-8"),
                     headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        t0 = time.monotonic()
        first = resp.read1(65536)
        t1 = time.monotonic()
        second = resp.read1(65536)
        t2 = time.monotonic()
        conn.close()
    assert b"data:" in first
    assert b"keepalive" in second
    assert (t1 - t0) < 0.2, f"first chunk should arrive promptly, took {t1 - t0:.3f}s"
    assert (t2 - t1) > 0.2, (
        f"second chunk arrived after only {t2 - t1:.3f}s -- the proxy must not "
        "buffer the whole stream before relaying it"
    )
    out = m.verify_seal_chain(home)
    assert out["records"] == 2
    assert out["unsettled"] == []


# ---------------------------------------------------------------------------
# small shared helper
# ---------------------------------------------------------------------------

def _read_raw(home: Path) -> list[dict]:
    """Raw JSONL rows of the seal chain, as plain dicts (not PrecogIDR)."""
    path = home / "seal.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
