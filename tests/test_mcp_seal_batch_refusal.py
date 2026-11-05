"""A batch refused before forwarding must not leave a call looking as if it went out,
and a header named on a second Connection line must not cross the proxy in either direction.

Both come from the in-session council on this sidecar (seal 09bdac2c89f3b184). The first was a
real defect. The second was reported by a seat and tested false, and stays as an anchor so that
it cannot quietly become true.
"""
from __future__ import annotations

import http.server
import json

from grasp import mcp_seal as m
from test_mcp_seal import _CallCountingUpstream, _post, _running, _tool_call


def _fail_on_call(monkeypatch, failing_call: int) -> None:
    real = m.SealChain.seal_intent
    calls = {"n": 0}

    def flaky(self, **kwargs):
        calls["n"] += 1
        if calls["n"] == failing_call:
            raise OSError("simulated disk failure")
        return real(self, **kwargs)

    monkeypatch.setattr(m.SealChain, "seal_intent", flaky)


def test_idless_call_in_a_refused_batch_is_closed_out(tmp_path, monkeypatch):
    home = tmp_path / "home"
    idless = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "no-id", "arguments": {}}}
    _fail_on_call(monkeypatch, failing_call=2)
    _CallCountingUpstream.calls = 0
    with _running(_CallCountingUpstream, home, on_seal_failure="refuse") as port:
        status, _, data = _post(port, [idless, _tool_call(2, "second")])
    assert status == 200
    assert b"refusing" in data
    assert _CallCountingUpstream.calls == 0
    out = m.verify_seal_chain(home)
    assert out["unsettled"] == [], "a call that never left the proxy must not read as sent"


def test_idless_call_in_a_forwarded_batch_still_reads_as_unsettled(tmp_path):
    """The closing-out is for refused batches only. A forwarded id-less call can never get an
    outcome, and verify must keep saying so."""
    home = tmp_path / "home"
    idless = {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "no-id", "arguments": {}}}
    _CallCountingUpstream.calls = 0
    with _running(_CallCountingUpstream, home, on_seal_failure="refuse") as port:
        _post(port, [idless])
    assert _CallCountingUpstream.calls == 1
    assert len(m.verify_seal_chain(home)["unsettled"]) == 1


class _SecondConnectionLineUpstream(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Connection", "x-smuggle")
        self.send_header("X-Smuggle", "not-for-the-client")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def test_response_header_named_on_a_second_connection_line_is_stripped(tmp_path):
    with _running(_SecondConnectionLineUpstream, tmp_path / "home") as port:
        status, headers, _ = _post(port, _tool_call(1))
    assert status == 200
    assert not any(name.lower() == "x-smuggle" for name in headers), headers
