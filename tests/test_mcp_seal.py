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


class _LenientUpstream(http.server.BaseHTTPRequestHandler):
    """Executes every POST as a tool call regardless of whether the body is
    strictly valid JSON -- models an upstream whose own parser is more
    tolerant than this proxy's ``json.loads``. Records a call count so a
    test can prove whether a given body reached it at all."""

    calls = 0

    def do_POST(self):  # noqa: N802
        type(self).calls += 1
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length) if length else b""
        out = json.dumps({"jsonrpc": "2.0", "id": 1,
                          "result": {"content": [], "isError": False}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # noqa: D102
        pass


class _BigReplyUpstream(http.server.BaseHTTPRequestHandler):
    """A plain (non-SSE) JSON reply padded well past a small test cap -- the
    oversized-buffered-response probe (the response-side twin of the
    declared-Content-Length-cap test on the request side)."""

    PAD = "x" * 2048

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length)) if length else {}
        out = json.dumps({"jsonrpc": "2.0", "id": body.get("id"),
                          "result": {"content": [], "isError": False, "pad": self.PAD}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # noqa: D102
        pass


class _SSEBatchArrayUpstream(http.server.BaseHTTPRequestHandler):
    """A batch of tools/call replied to with ONE SSE event whose ``data:``
    is a JSON ARRAY of every response -- a legal JSON-RPC batch reply, just
    framed as a single SSE payload instead of one event per response."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        messages = json.loads(self.rfile.read(length)) if length else []
        replies = [
            {"jsonrpc": "2.0", "id": msg["id"], "result": {"content": [], "isError": False}}
            for msg in messages if "id" in msg
        ]
        payload = json.dumps(replies)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))

    def log_message(self, *a):  # noqa: D102
        pass


class _DuplicateHeaderUpstream(http.server.BaseHTTPRequestHandler):
    """Records every value of a repeated request header it actually received
    -- the probe for "no header value is silently dropped"."""

    seen_dup: list = []

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).seen_dup = self.headers.get_all("X-Dup") or []
        parsed = json.loads(body) if body else {}
        out = json.dumps({"jsonrpc": "2.0", "id": parsed.get("id"),
                          "result": {"content": [], "isError": False}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # noqa: D102
        pass


class _HeaderEchoUpstream(http.server.BaseHTTPRequestHandler):
    """Records every request header it actually received, exact name case --
    the probe for Connection-listed hop-by-hop stripping (RFC 7230 S6.1)."""

    seen_headers: dict = {}

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length) if length else b""
        type(self).seen_headers = dict(self.headers.items())
        out = json.dumps({"jsonrpc": "2.0", "id": None,
                          "result": {"content": [], "isError": False}}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):  # noqa: D102
        pass


class _NonUtf8ReplyUpstream(http.server.BaseHTTPRequestHandler):
    """Every POST gets a 200 whose body is bytes that are not valid UTF-8 --
    models an upstream MCP server whose reply is not well-formed text."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length) if length else b""
        out = b"\xff\xfe not valid utf-8 at all"
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
# A JSON-RPC id that is not a string/number/null -- not a dict key
# ---------------------------------------------------------------------------

def test_non_scalar_id_is_refused_not_a_crash(tmp_path):
    """JSON-RPC ids are string, number, or null -- never an array or object.
    ``_seal_intents`` tracks a pending call by ``pending[message["id"]]``,
    which raises ``TypeError: unhashable type`` for a list/dict id. That
    propagates out of the handler thread uncaught: the client sees the
    connection drop with no JSON-RPC error, and the call is never sealed
    either way. A refusal here is HTTP 200 carrying a JSON-RPC error object
    -- the same convention ``test_refuse_on_seal_failure_never_reaches_upstream``
    already exercises for a different refusal cause."""
    home = tmp_path / "home"
    _CallCountingUpstream.calls = 0
    body = json.dumps(_tool_call([], arguments={"x": 1})).encode("utf-8")
    with _running(_CallCountingUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.request("POST", "/mcp", body=body, headers={"Content-Type": "application/json"})
        try:
            resp = conn.getresponse()
            status = resp.status
            data = resp.read()
        except http.client.RemoteDisconnected:
            status, data = None, b""
        conn.close()
    assert status is not None, "a non-scalar id must be refused cleanly, not drop the connection"
    assert status == 200
    assert "error" in json.loads(data), f"expected a JSON-RPC error object, got {data!r}"
    assert _CallCountingUpstream.calls == 0, "an unrepresentable call must never reach upstream"
    out = m.verify_seal_chain(home)
    assert out["records"] == 0, "nothing can be honestly paired for an id that cannot be tracked"


def test_list_shaped_params_does_not_crash_the_handler(tmp_path):
    """``tools/call``'s ``params`` is specified as an object. ``_tool_call_args``
    used ``message.get("params") or {}``, which only normalises a FALSY
    non-dict (``None``, ``[]``) to ``{}`` -- a TRUTHY non-dict (a non-empty
    list) stays a list, and ``params.get("name", "")`` then raises
    ``AttributeError: 'list' object has no attribute 'get'`` uncaught in the
    handler thread: the client sees the connection drop with no JSON-RPC
    response, the same failure shape ``test_non_scalar_id_is_refused_not_a_crash``
    already covers for a different malformed shape."""
    home = tmp_path / "home"
    body = json.dumps({"jsonrpc": "2.0", "method": "tools/call",
                        "params": [1, 2, 3], "id": 1}).encode("utf-8")
    with _running(_JsonEchoUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.request("POST", "/mcp", body=body, headers={"Content-Type": "application/json"})
        try:
            resp = conn.getresponse()
            status = resp.status
            data = resp.read()
        except http.client.RemoteDisconnected:
            status, data = None, b""
        conn.close()
    assert status is not None, "a list-shaped params must not drop the connection"
    assert status == 200
    assert json.loads(data)["id"] == 1
    out = m.verify_seal_chain(home)
    assert out["records"] == 2, "a malformed-but-recoverable call is still sealed, not silently skipped"


def test_batch_earlier_valid_call_is_not_stranded_by_a_later_non_scalar_id(tmp_path):
    """A batch of two tools/call messages: the first has an ordinary id, the
    second's id is a list (unhashable). ``_seal_intents`` used to seal the
    first message's intent, THEN discover the second message's id cannot be
    tracked and refuse the whole batch -- leaving the first intent durably on
    the ledger for a call that was never forwarded and can never be paired
    with an outcome. The id-shape check must run as a pre-pass over the whole
    batch, before any intent in it is sealed."""
    home = tmp_path / "home"
    _CallCountingUpstream.calls = 0
    batch = [_tool_call(1, name="first"), _tool_call([1, 2], name="second")]
    with _running(_CallCountingUpstream, home) as port:
        status, _, data = _post(port, batch)
    assert status == 200
    assert _CallCountingUpstream.calls == 0, "a refused batch must never reach upstream"
    out = m.verify_seal_chain(home)
    assert out["records"] == 0, "the first message's intent must not be sealed when the " \
                                 "batch is refused for the second message's id"


def test_boolean_id_is_refused_like_a_non_scalar_id(tmp_path):
    """A JSON-RPC id is a string, number, or null -- the refusal message for a
    non-scalar id already says so. But ``bool`` is a Python ``int`` subclass,
    so ``True``/``False`` are hashable and used to slip past the check this
    message describes. A boolean id must be refused the same way a list or
    dict id is."""
    home = tmp_path / "home"
    _CallCountingUpstream.calls = 0
    with _running(_CallCountingUpstream, home) as port:
        status, _, data = _post(port, _tool_call(True))
    assert status == 200
    assert "error" in json.loads(data), f"expected a JSON-RPC error object, got {data!r}"
    assert _CallCountingUpstream.calls == 0, "a boolean id must never reach upstream"
    out = m.verify_seal_chain(home)
    assert out["records"] == 0, "a boolean id must not be sealed as if it were a real id"


# ---------------------------------------------------------------------------
# A batch response framed as a single SSE event carrying a JSON array
# ---------------------------------------------------------------------------

def test_sse_batch_response_as_one_array_event_seals_every_outcome(tmp_path):
    """The module docstring promises outcomes are matched 'in a JSON body
    or SSE data: frames', for batches included. One SSE event can legally
    carry the whole batch reply as a JSON array -- that must seal exactly
    like the buffered-JSON-array case does, not leave every call unsettled."""
    home = tmp_path / "home"
    batch = [_tool_call(1, "toolA"), _tool_call(2, "toolB")]
    with _running(_SSEBatchArrayUpstream, home) as port:
        status, headers, data = _post(port, batch)
    assert status == 200
    assert headers.get("Content-Type") == "text/event-stream"
    out = m.verify_seal_chain(home)
    assert out["records"] == 4  # 2 intents + 2 outcomes
    assert out["unsettled"] == [], "both outcomes must be sealed from the single array event"


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


def test_batch_earlier_sealed_intent_is_not_stranded_by_a_later_seal_failure(tmp_path, monkeypatch):
    """The sibling of ``test_batch_earlier_valid_call_is_not_stranded_by_a_
    later_non_scalar_id``, for a different refusal cause: a batch of two
    ``tools/call`` messages where the FIRST seals successfully (durably
    appended to the ledger) and the SECOND's ``seal_intent`` then raises
    ``OSError`` (e.g. disk full on the second write, not the first). With
    ``--on-seal-failure refuse`` the whole batch must be refused and never
    forwarded -- but the first message's intent is already durably on the
    ledger by the time the second message's failure is discovered, and
    nothing before this fix closed it out. Left alone it sits in
    ``verify``'s ``unsettled`` list forever, indistinguishable from a call
    that really reached the upstream but whose outcome merely went
    unobserved -- when in truth this one never left the proxy at all."""
    home = tmp_path / "home"
    _CallCountingUpstream.calls = 0
    real_append_idr = m.append_idr
    seen = {"n": 0}

    def _flaky_append(idr, *, path):
        seen["n"] += 1
        if seen["n"] == 2:
            raise OSError("disk full (simulated)")
        return real_append_idr(idr, path=path)

    monkeypatch.setattr(m, "append_idr", _flaky_append)
    batch = [_tool_call(1, name="first"), _tool_call(2, name="second")]
    with _running(_CallCountingUpstream, home, on_seal_failure="refuse") as port:
        status, _, data = _post(port, batch)
    assert status == 200
    assert _CallCountingUpstream.calls == 0, "a refused batch must never reach upstream"
    out = m.verify_seal_chain(home)
    assert out["unsettled"] == [], (
        "the first message's intent must not be left dangling when the batch "
        "is refused for the second message's seal failure"
    )


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


def test_duplicate_request_headers_are_not_collapsed(tmp_path):
    """A client is allowed to send the same header name twice (e.g. two
    ``Cookie`` lines). The proxy must forward every value -- a dict-based
    dedup would silently keep only the last one."""
    home = tmp_path / "home"
    _DuplicateHeaderUpstream.seen_dup = []
    body = json.dumps(_tool_call(1)).encode("utf-8")
    with _running(_DuplicateHeaderUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.putrequest("POST", "/mcp")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("X-Dup", "first")
        conn.putheader("X-Dup", "second")
        conn.endheaders(body)
        resp = conn.getresponse()
        resp.read()
        conn.close()
    assert resp.status == 200
    assert _DuplicateHeaderUpstream.seen_dup == ["first", "second"]


def test_connection_listed_header_is_stripped_from_forward(tmp_path):
    """RFC 7230 S6.1: a header NAMED inside the Connection field's value is
    hop-by-hop for THIS connection and must not be forwarded to the next hop
    -- even when its own name is not in the fixed HOP_BY_HOP set. Naming an
    arbitrary header in Connection must not be a way to smuggle it past the
    static list."""
    home = tmp_path / "home"
    _HeaderEchoUpstream.seen_headers = {}
    body = json.dumps(_tool_call(1)).encode("utf-8")
    with _running(_HeaderEchoUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.putrequest("POST", "/mcp")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("Connection", "x-smuggle")
        conn.putheader("X-Smuggle", "evil")
        conn.endheaders(body)
        resp = conn.getresponse()
        resp.read()
        conn.close()
    assert resp.status == 200
    assert "X-Smuggle" not in _HeaderEchoUpstream.seen_headers, (
        "a header named in Connection must be stripped, not forwarded to upstream"
    )


def test_hop_by_hop_headers_themselves_are_never_forwarded(tmp_path):
    """HOP_BY_HOP's own fixed members, not a header NAMED inside Connection's
    value (the test above covers that case already) -- a plain ``Connection``,
    ``Keep-Alive`` or ``TE`` header sent by the client must never reach
    upstream. Mutation-tested: emptying HOP_BY_HOP to frozenset() left the
    whole suite green with no test catching it before this one existed."""
    home = tmp_path / "home"
    _HeaderEchoUpstream.seen_headers = {}
    body = json.dumps(_tool_call(1)).encode("utf-8")
    with _running(_HeaderEchoUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.putrequest("POST", "/mcp")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("Connection", "keep-alive")
        conn.putheader("Keep-Alive", "timeout=5")
        conn.putheader("TE", "trailers")
        conn.endheaders(body)
        resp = conn.getresponse()
        resp.read()
        conn.close()
    assert resp.status == 200
    seen = {name.lower() for name in _HeaderEchoUpstream.seen_headers}
    for hop in ("connection", "keep-alive", "te"):
        assert hop not in seen, f"{hop!r} is hop-by-hop and must never reach upstream"


def test_second_connection_header_line_still_strips_its_named_header(tmp_path):
    """RFC 7230 S3.2.2: Connection is a comma-separated-list header, so a
    client MAY split it across two header lines instead of one comma-joined
    line -- both forms are the same field. ``headers.get("Connection")`` on
    an ``email.message.Message`` (``self.headers``) returns only the FIRST
    occurrence, not every value, so a client that sends ``Connection: close``
    THEN a separate ``Connection: x-smuggle`` line can smuggle ``X-Smuggle``
    past the strip -- the single-line case above never exercises this."""
    home = tmp_path / "home"
    _HeaderEchoUpstream.seen_headers = {}
    body = json.dumps(_tool_call(1)).encode("utf-8")
    with _running(_HeaderEchoUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.putrequest("POST", "/mcp")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", str(len(body)))
        conn.putheader("Connection", "close")
        conn.putheader("Connection", "x-smuggle")  # a SECOND Connection line
        conn.putheader("X-Smuggle", "evil")
        conn.endheaders(body)
        resp = conn.getresponse()
        resp.read()
        conn.close()
    assert resp.status == 200
    assert "X-Smuggle" not in _HeaderEchoUpstream.seen_headers, (
        "a header named in a SECOND Connection line must be stripped too, "
        "not forwarded to upstream just because it missed the first line"
    )


# ---------------------------------------------------------------------------
# Request body cap -- a declared Content-Length past the cap is refused
# BEFORE a single byte is read from the socket (resource-exhaustion probe)
# ---------------------------------------------------------------------------

def test_oversized_declared_body_is_refused_before_any_read(tmp_path, monkeypatch):
    monkeypatch.setenv("GRASP_MCP_SEAL_MAX_BODY_BYTES", "1024")
    home = tmp_path / "home"
    _CallCountingUpstream.calls = 0
    with _running(_CallCountingUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.putrequest("POST", "/mcp")
        conn.putheader("Content-Type", "application/json")
        # A caller claims a body far past the cap -- and never sends it. A
        # handler that trusts this header and calls rfile.read(n) blocks here
        # until the timeout fires; one that checks the cap first refuses
        # immediately without reading a byte.
        conn.putheader("Content-Length", "999999999")
        conn.endheaders()
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
    assert resp.status == 413
    assert "exceeds" in json.loads(data)["error"]["message"]
    assert _CallCountingUpstream.calls == 0


# ---------------------------------------------------------------------------
# Transfer-Encoding (chunked): refused cleanly, never silently dropped
# ---------------------------------------------------------------------------

def _send_chunked_post(port: int, body: bytes) -> bytes:
    """A raw socket, hand-framed ``Transfer-Encoding: chunked`` POST --
    ``http.client`` has no public one-shot way to declare this header on a
    single bytes body, and the whole point of the probe is the RAW bytes a
    real chunked-capable client would put on the wire."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    sock.connect((HOST, port))
    head = (
        f"POST /mcp HTTP/1.1\r\n"
        f"Host: {HOST}:{port}\r\n"
        f"Content-Type: application/json\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
    ).encode("utf-8")
    chunked = f"{len(body):x}\r\n".encode("ascii") + body + b"\r\n0\r\n\r\n"
    sock.sendall(head + chunked)
    reply = sock.recv(65536)
    sock.close()
    return reply


def test_chunked_request_body_is_refused_not_silently_dropped(tmp_path):
    """A client that sends a chunked request body (no Content-Length) must
    get a clean refusal -- not a 200 OK built from a silently-empty body
    that was never sealed and never reached the upstream."""
    home = tmp_path / "home"
    _CallCountingUpstream.calls = 0
    with _running(_CallCountingUpstream, home) as port:
        reply = _send_chunked_post(port, json.dumps(_tool_call(1)).encode("utf-8"))
    status_line = reply.split(b"\r\n", 1)[0]
    assert b"411" in status_line, f"expected 411 Length Required, got {status_line!r}"
    assert _CallCountingUpstream.calls == 0, "the undecoded chunked call must never reach upstream"
    out = m.verify_seal_chain(home)
    assert out["records"] == 0, "nothing can be honestly sealed for a body this proxy never read"


# ---------------------------------------------------------------------------
# Content-Length that is not a valid non-negative integer: refused cleanly,
# never silently treated as "no body" while the real bytes stay unread
# ---------------------------------------------------------------------------

def test_malformed_content_length_is_refused_not_silently_emptied(tmp_path):
    """A Content-Length header that fails int() (or parses negative) must
    not be treated like an absent header: the client likely DID send framed
    bytes right after it, and silently returning an empty body here leaves
    those real bytes unread on the socket -- the same request-smuggling /
    desync shape _ChunkedBodyNotSupported already guards, just reached via a
    different malformed header instead of Transfer-Encoding."""
    home = tmp_path / "home"
    _CallCountingUpstream.calls = 0
    body = json.dumps(_tool_call(1)).encode("utf-8")
    with _running(_CallCountingUpstream, home) as port:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, port))
        sock.sendall(
            f"POST /mcp HTTP/1.1\r\nHost: {HOST}:{port}\r\n"
            f"Content-Type: application/json\r\nContent-Length: notanumber\r\n\r\n"
            .encode("utf-8") + body
        )
        reply = sock.recv(65536)
        sock.close()
    status_line = reply.split(b"\r\n", 1)[0]
    assert b"400" in status_line, f"expected 400 Bad Request, got {status_line!r}"
    assert _CallCountingUpstream.calls == 0, (
        "a request this proxy cannot frame must never reach upstream"
    )
    out = m.verify_seal_chain(home)
    assert out["records"] == 0, "nothing can be honestly sealed for a body this proxy never read"


def test_negative_content_length_is_refused_not_silently_emptied(tmp_path):
    """A negative Content-Length parses fine as an int but hits the same
    ``n > 0 else b""`` branch as a genuinely absent body -- the real bytes
    sent after it are left unread exactly like the non-numeric case."""
    home = tmp_path / "home"
    _CallCountingUpstream.calls = 0
    body = json.dumps(_tool_call(1)).encode("utf-8")
    with _running(_CallCountingUpstream, home) as port:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, port))
        sock.sendall(
            f"POST /mcp HTTP/1.1\r\nHost: {HOST}:{port}\r\n"
            f"Content-Type: application/json\r\nContent-Length: -5\r\n\r\n"
            .encode("utf-8") + body
        )
        reply = sock.recv(65536)
        sock.close()
    status_line = reply.split(b"\r\n", 1)[0]
    assert b"400" in status_line, f"expected 400 Bad Request, got {status_line!r}"
    assert _CallCountingUpstream.calls == 0
    out = m.verify_seal_chain(home)
    assert out["records"] == 0


def test_conflicting_content_length_headers_are_refused_before_any_read(tmp_path):
    """RFC 7230 S3.3.2 / RFC 9112 S6.3: two Content-Length header lines with
    DIFFERENT values must be rejected, not resolved by trusting one of them --
    ``self.headers.get("Content-Length")`` (an ``email.message.Message``)
    silently returns only the FIRST occurrence, exactly the same shape this
    module already reads with ``get_all`` for ``Connection``
    (``test_second_connection_header_line_still_strips_its_named_header``)
    because a single ``.get`` there could smuggle a header past the strip.
    Content-Length was still read with plain ``.get``: a client sends a huge
    first value and a small second (true) value, then only the small body it
    promised. A handler that trusts the first value calls
    ``self.rfile.read(999999999)`` and blocks forever waiting for bytes that
    are never coming -- this test's 5s client timeout is what turns that hang
    into a failure, mirroring
    ``test_oversized_declared_body_is_refused_before_any_read``. A handler
    that detects the conflict first refuses immediately, before reading a
    single body byte."""
    home = tmp_path / "home"
    _CallCountingUpstream.calls = 0
    with _running(_CallCountingUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.putrequest("POST", "/mcp")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", "999999999")  # never sent -- would hang a naive reader
        conn.putheader("Content-Length", "2")  # the real, much smaller, length
        conn.endheaders(b"{}")
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
    assert resp.status == 400, f"expected 400 Bad Request, got {resp.status}"
    assert "Content-Length" in json.loads(data)["error"]["message"]
    assert _CallCountingUpstream.calls == 0, (
        "a request whose Content-Length conflicts with itself must never reach upstream"
    )
    out = m.verify_seal_chain(home)
    assert out["records"] == 0, "nothing can be honestly sealed for a body this proxy never read"


# ---------------------------------------------------------------------------
# A POST body that fails this proxy's own JSON parse: refused, never
# forwarded on good faith to a possibly more tolerant upstream
# ---------------------------------------------------------------------------

def test_unparseable_json_body_is_refused_not_silently_unsealed(tmp_path):
    """The module promises every forwarded tools/call is sealed. A body that
    fails this proxy's own json.loads must not be forwarded anyway -- a more
    tolerant upstream parser could still execute it as a real tool call with
    no intent or outcome ever recorded for it."""
    home = tmp_path / "home"
    _LenientUpstream.calls = 0
    malformed = b'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {},}'  # trailing comma
    with _running(_LenientUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.request("POST", "/mcp", body=malformed, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
    assert resp.status != 200, f"a body this proxy cannot parse must be refused, got {resp.status}"
    assert _LenientUpstream.calls == 0, "an unparseable body must never reach a possibly-lenient upstream"
    out = m.verify_seal_chain(home)
    assert out["records"] == 0


def test_invalid_utf8_body_is_refused_not_a_crash(tmp_path):
    """``json.loads`` on bytes that are not valid UTF-8 raises
    ``UnicodeDecodeError`` while trying to auto-detect the encoding -- a
    SIBLING of ``json.JSONDecodeError`` under ``ValueError``, not a subclass
    of it. ``_parse_body`` catches only ``json.JSONDecodeError``, so this
    shape propagates uncaught out of the handler thread: the client sees the
    connection drop with no response, not a clean refusal."""
    home = tmp_path / "home"
    _LenientUpstream.calls = 0
    malformed = b"\xff\xfe not valid utf-8 at all"
    with _running(_LenientUpstream, home) as port:
        conn = http.client.HTTPConnection(HOST, port, timeout=5)
        conn.request("POST", "/mcp", body=malformed, headers={"Content-Type": "application/json"})
        try:
            resp = conn.getresponse()
            status = resp.status
            resp.read()
        except http.client.RemoteDisconnected:
            status = None
        conn.close()
    assert status is not None, "invalid UTF-8 must be refused cleanly, not drop the connection"
    assert status != 200, f"a body this proxy cannot decode must be refused, got {status}"
    assert _LenientUpstream.calls == 0, "an undecodable body must never reach upstream"
    out = m.verify_seal_chain(home)
    assert out["records"] == 0


def test_invalid_utf8_upstream_reply_does_not_crash_the_outcome_seal(tmp_path, capsys):
    """``_seal_outcomes_from_bytes`` runs ``json.loads`` on the upstream's raw
    response bytes -- the exact same auto-detect-then-decode shape that
    ``_parse_body`` already learned can raise ``UnicodeDecodeError`` for bytes
    that are not valid UTF-8 (a ``ValueError`` SIBLING of
    ``json.JSONDecodeError``, not a subclass of it, so ``except
    json.JSONDecodeError`` does not catch it). That fix was never mirrored on
    the outcome side. The proxy has already written the reply to the client
    by the time this runs, so the crash is invisible to the caller -- it
    surfaces only as an uncaught exception in the server's own request-
    handling thread, which ``_running``'s ``proxy.shutdown()`` blocks until
    finished, so the exception has already been reported (or not) by the
    time this checks stderr."""
    home = tmp_path / "home"
    with _running(_NonUtf8ReplyUpstream, home) as port:
        status, _, _ = _post(port, _tool_call(1))
    assert status == 200, "the garbage reply is written to the client before any seal is attempted"
    err = capsys.readouterr().err
    assert "UnicodeDecodeError" not in err, (
        f"an upstream reply that is not valid UTF-8 crashed the handler thread "
        f"while sealing the outcome instead of being refused cleanly:\n{err}"
    )


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
# A status that MUST NOT carry Content-Length (RFC 9110 SS8.6)
# ---------------------------------------------------------------------------

class _NoContentUpstream(http.server.BaseHTTPRequestHandler):
    """204 No Content, with no body and no Content-Length of its own --
    the RFC-compliant shape this proxy must not add a header to."""

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(length) if length else b""
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):  # noqa: D102
        pass


def test_204_response_carries_no_content_length(tmp_path):
    home = tmp_path / "home"
    with _running(_NoContentUpstream, home) as port:
        status, headers, data = _post(port, _tool_call(1))
    assert status == 204
    assert data == b""
    assert "Content-Length" not in headers, (
        "RFC 9110 SS8.6: a 204 response MUST NOT carry Content-Length"
    )


# ---------------------------------------------------------------------------
# A buffered (non-SSE) upstream reply far past a configured cap: refused
# before anything is sent to the client, not buffered without bound
# ---------------------------------------------------------------------------

def test_oversized_buffered_response_is_refused_before_any_read(tmp_path, monkeypatch):
    """The request side refuses a declared-oversize body before reading a
    byte (GRASP_MCP_SEAL_MAX_BODY_BYTES). The response side had no such cap:
    a non-SSE reply is read whole via resp.read() with no limit at all --
    the asymmetric half of the same resource-exhaustion vector."""
    monkeypatch.setenv("GRASP_MCP_SEAL_MAX_RESPONSE_BYTES", "256")
    home = tmp_path / "home"
    with _running(_BigReplyUpstream, home) as port:
        status, _, data = _post(port, _tool_call(1))
    assert status == 502, f"expected a clean refusal, got {status}"
    assert "exceeds" in json.loads(data)["error"]["message"]
    out = m.verify_seal_chain(home)
    assert out["records"] == 1, "the intent was sealed before forwarding; the oversized reply is refused"
    assert len(out["unsettled"]) == 1


# ---------------------------------------------------------------------------
# The seal-breaking drill -- ships the attack beside the claim
# ---------------------------------------------------------------------------

def test_drill_shows_the_corrupted_copy_refuse_and_never_touches_the_real_chain(tmp_path):
    home = tmp_path / "home"
    with _running(_CallCountingUpstream, home) as port:
        _post(port, _tool_call(1))
    before = (home / "seal.jsonl").read_bytes()
    result = m.drill(home)
    after = (home / "seal.jsonl").read_bytes()
    assert after == before, "the real chain must never be touched by the drill"
    assert result["refused"] is True
    assert result["message"] == "this record no longer seals"
    assert result["verify"]["ok"] is False


def test_drill_with_no_chain_says_so_and_does_not_crash(tmp_path):
    result = m.drill(tmp_path / "never-served")
    assert result["refused"] is False
    assert "no chain at" in result["message"]
    assert result["verify"] is None


# ---------------------------------------------------------------------------
# GENESIS_ANCHOR: overridable per deployment, mirroring grasp.mcp_server's
# own GRASP_GENESIS_ANCHOR convention for exactly the same reason -- a
# long-lived shared sidecar is not a human, so the placeholder default must
# be nameable as whatever this deployment really roots at.
# ---------------------------------------------------------------------------

def test_genesis_anchor_defaults_to_the_placeholder(monkeypatch):
    monkeypatch.delenv("GRASP_MCP_SEAL_GENESIS_ANCHOR", raising=False)
    assert m._genesis_anchor() == "human:mcp-seal-sidecar"


def test_genesis_anchor_override_accepts_every_admissible_class(monkeypatch):
    for value in ("human:alice", "ci:nightly-42", "council:verdict-7", "hypo:H042"):
        monkeypatch.setenv("GRASP_MCP_SEAL_GENESIS_ANCHOR", value)
        assert m._genesis_anchor() == value


def test_genesis_anchor_override_rejects_an_inadmissible_value(monkeypatch):
    monkeypatch.setenv("GRASP_MCP_SEAL_GENESIS_ANCHOR", "operator-42")
    try:
        m._genesis_anchor()
        raised = False
    except ValueError as exc:
        raised = True
        assert "GRASP_MCP_SEAL_GENESIS_ANCHOR" in str(exc)
    assert raised, "an inadmissible override must be rejected, not silently accepted"


def test_invalid_byte_env_warning_accepts_a_valid_value():
    assert m._invalid_byte_env_warning("GRASP_MCP_SEAL_MAX_BODY_BYTES", "1048576", 10) is None


def test_invalid_byte_env_warning_flags_a_non_integer():
    warning = m._invalid_byte_env_warning("GRASP_MCP_SEAL_MAX_BODY_BYTES", "10MiB", 10)
    assert warning is not None
    assert "GRASP_MCP_SEAL_MAX_BODY_BYTES" in warning
    assert "10MiB" in warning


def test_invalid_byte_env_warning_flags_a_negative_value():
    warning = m._invalid_byte_env_warning("GRASP_MCP_SEAL_MAX_RESPONSE_BYTES", "-1", 10)
    assert warning is not None
    assert "GRASP_MCP_SEAL_MAX_RESPONSE_BYTES" in warning


def test_byte_env_startup_warnings_is_silent_when_both_are_unset_or_valid(monkeypatch):
    monkeypatch.delenv("GRASP_MCP_SEAL_MAX_BODY_BYTES", raising=False)
    monkeypatch.setenv("GRASP_MCP_SEAL_MAX_RESPONSE_BYTES", "2048")
    assert m._byte_env_startup_warnings() == []


def test_byte_env_startup_warnings_surfaces_a_typo_once_at_startup(monkeypatch):
    """Before this fix, a typo'd GRASP_MCP_SEAL_MAX_BODY_BYTES silently used
    the default forever -- indistinguishable, from the outside, from a
    correctly configured default. _max_body_bytes/_max_response_bytes are
    read on EVERY request (unlike GRASP_MCP_SEAL_GENESIS_ANCHOR, read once at
    construction), so making the reader itself raise would crash every
    request for the life of the process instead of just misconfiguring a
    limit -- this surfaces the typo loudly, once, at startup, without
    changing the per-request reader's safe-default behaviour at all."""
    monkeypatch.setenv("GRASP_MCP_SEAL_MAX_BODY_BYTES", "10MiB")
    monkeypatch.delenv("GRASP_MCP_SEAL_MAX_RESPONSE_BYTES", raising=False)
    warnings = m._byte_env_startup_warnings()
    assert len(warnings) == 1
    assert "GRASP_MCP_SEAL_MAX_BODY_BYTES" in warnings[0]
    # the per-request reader is UNCHANGED: still a safe fallback, never a raise
    assert m._max_body_bytes() == m._DEFAULT_MAX_BODY_BYTES


def test_seal_chain_construction_fails_fast_on_an_inadmissible_override(tmp_path, monkeypatch):
    """Validated at construction (startup), not lazily inside a per-request
    seal -- a typo'd override must refuse every call forever rather than
    fail loud once at serve time."""
    monkeypatch.setenv("GRASP_MCP_SEAL_GENESIS_ANCHOR", "not-a-prefix")
    try:
        m.SealChain(tmp_path / "home")
        raised = False
    except ValueError:
        raised = True
    assert raised, "SealChain must refuse to construct with an inadmissible genesis override"


def test_sealed_intent_uses_an_admissible_genesis_override(tmp_path, monkeypatch):
    """The override must actually reach the ledger, not just validate and do
    nothing -- a dead override is as wrong as no override at all."""
    monkeypatch.setenv("GRASP_MCP_SEAL_GENESIS_ANCHOR", "ci:nightly-seal-42")
    home = tmp_path / "home"
    with _running(_JsonEchoUpstream, home) as port:
        _post(port, _tool_call(1))
    rows = _read_raw(home)
    assert rows[0]["predecessor_idr"] == "ci:nightly-seal-42"


def test_verify_seal_chain_reports_broken_when_override_is_inadmissible(tmp_path, monkeypatch):
    """Must surface as a clean BROKEN verdict -- never an uncaught exception
    escaping grasp-mcp-seal verify (mirrors grasp.mcp_server's own
    _verify_decision_chain behaviour for the identical failure shape)."""
    home = tmp_path / "home"
    with _running(_JsonEchoUpstream, home) as port:
        _post(port, _tool_call(1))
    monkeypatch.setenv("GRASP_MCP_SEAL_GENESIS_ANCHOR", "not-a-prefix")
    out = m.verify_seal_chain(home)
    assert out["ok"] is False
    assert out["chain_verdict"] == "broken"
    assert "GRASP_MCP_SEAL_GENESIS_ANCHOR" in out["chain_error"]


# ---------------------------------------------------------------------------
# The doc's own examples must not refuse against this proxy's own defaults
# ---------------------------------------------------------------------------

def _bash_block_lines(doc_text: str) -> list[str]:
    """Every line inside a fenced ```bash block, flattened across all blocks."""
    blocks = doc_text.split("```bash")[1:]
    bodies = [block.split("```", 1)[0] for block in blocks]
    return [line for body in bodies for line in body.splitlines()]


def test_doc_non_loopback_serve_example_includes_allow_remote_bind():
    """``docs/install/mcp-seal.md``'s "behind mcp-proxy" example binds
    ``0.0.0.0``, which ``_cmd_serve`` refuses without ``--allow-remote-bind``
    -- a reader copying the example exactly as shown hits a refusal the doc
    never warns them about."""
    doc = Path(__file__).resolve().parent.parent / "docs" / "install" / "mcp-seal.md"
    lines = _bash_block_lines(doc.read_text(encoding="utf-8"))
    serve_lines = [ln for ln in lines if "grasp-mcp-seal serve" in ln and "--listen" in ln]
    for line in serve_lines:
        host = line.split("--listen", 1)[1].strip().split()[0].split(":")[0]
        if host not in ("127.0.0.1", "localhost", ""):
            assert "--allow-remote-bind" in line, \
                f"non-loopback --listen example is missing --allow-remote-bind: {line!r}"


# ---------------------------------------------------------------------------
# small shared helper
# ---------------------------------------------------------------------------

def _read_raw(home: Path) -> list[dict]:
    """Raw JSONL rows of the seal chain, as plain dicts (not PrecogIDR)."""
    path = home / "seal.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
