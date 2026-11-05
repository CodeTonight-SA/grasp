"""What the sidecar records when the upstream fails.

From the in-session council on this sidecar (seal 9b21b807cc92b40a). A garbage status line used to
kill the handler thread, and any failed forward left the intent with no record of the failure.

The third test pins a finding that did not hold. The same council said an unterminated final SSE
event should count as finished. The WHATWG server-sent events rule is the opposite: pending data at
end of stream is discarded, so a client never receives it. "Unsettled" is the truthful record.
"""
from __future__ import annotations

import http.server
import json
import socket
import socketserver
import threading

from grasp import mcp_seal as m
from test_mcp_seal import HOST, _post, _running, _tool_call


class _GarbageStatusHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(65536)
        self.request.sendall(b"this is not an http status line\r\n\r\n")


class _TruncatedReplyUpstream(http.server.BaseHTTPRequestHandler):
    """Declares more bytes than it sends, then closes."""

    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "1000")
        self.end_headers()
        self.wfile.write(b'{"jsonrpc"')
        self.close_connection = True

    def log_message(self, *args):
        pass


class _UnterminatedSSEUpstream(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(b'data: {"jsonrpc":"2.0","id":1,"result":{}}\n')
        self.close_connection = True

    def log_message(self, *args):
        pass


def _proxy_for(upstream_url: str, home):
    cfg = m.ProxyConfig(upstream=upstream_url, chain=m.SealChain(home))
    proxy = m.make_server(cfg, HOST, 0)
    threading.Thread(target=proxy.serve_forever, daemon=True).start()
    return proxy


def _dead_port() -> int:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind((HOST, 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


def test_upstream_down_records_the_failure_as_an_outcome(tmp_path):
    home = tmp_path / "home"
    proxy = _proxy_for(f"http://{HOST}:{_dead_port()}", home)
    try:
        status, _, data = _post(proxy.server_address[1], _tool_call(1))
    finally:
        proxy.shutdown()
        proxy.server_close()
    assert status == 502
    assert json.loads(data)["error"]["code"] == -32000
    out = m.verify_seal_chain(home)
    assert out["records"] == 2
    assert out["unsettled"] == []
    assert out["chain_verdict"] == "verified"


def test_garbage_status_line_is_refused_and_recorded(tmp_path):
    home = tmp_path / "home"
    upstream = socketserver.TCPServer((HOST, 0), _GarbageStatusHandler)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    proxy = _proxy_for(f"http://{HOST}:{upstream.server_address[1]}", home)
    try:
        status, _, data = _post(proxy.server_address[1], _tool_call(7))
    finally:
        proxy.shutdown()
        proxy.server_close()
        upstream.shutdown()
        upstream.server_close()
    assert status == 502
    assert json.loads(data)["id"] == 7
    assert m.verify_seal_chain(home)["unsettled"] == []


def test_truncated_reply_is_refused_and_stays_unsettled(tmp_path):
    """The upstream answered and then broke, so the call's outcome is unknown. A 502 is honest,
    and no outcome is invented."""
    home = tmp_path / "home"
    with _running(_TruncatedReplyUpstream, home) as port:
        status, _, data = _post(port, _tool_call(3))
    assert status == 502
    assert json.loads(data)["error"]["code"] == -32000
    assert len(m.verify_seal_chain(home)["unsettled"]) == 1


def test_unterminated_final_sse_event_stays_unsettled(tmp_path):
    home = tmp_path / "home"
    with _running(_UnterminatedSSEUpstream, home) as port:
        status, _, _ = _post(port, _tool_call(1))
    assert status == 200
    assert len(m.verify_seal_chain(home)["unsettled"]) == 1
