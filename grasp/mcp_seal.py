# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""grasp-mcp-seal -- a signed, tamper-evident tool-call seal for Streamable HTTP MCP.

A reverse proxy that sits between any Streamable HTTP MCP client (including
Anthropic's ``mcp-proxy``) and ONE fixed upstream MCP server. Every
``tools/call`` it forwards gets TWO signed GRASP records (reusing
:mod:`grasp.idr` + :mod:`grasp.idr_forest` -- the same signers and chain the
rest of the package uses, not a new implementation):

* ``mcp.tool.intent``  -- written BEFORE forwarding. If it cannot be written,
  the call is refused by default (``--on-seal-failure refuse``) and never
  reaches the upstream server.
* ``mcp.tool.outcome`` -- written AFTER the matching response is observed
  (by JSON-RPC ``id``, in a JSON body or in an SSE ``data:`` frame). If it
  cannot be written, the result still reaches the caller -- the failure is
  only logged. An intent with no outcome is visible to ``verify`` as
  "unsettled".

Commitments, not plaintext: the chain holds ``sha256(salt || canonical_json)``
for the tool arguments and the result, never the plaintext itself. Each
record's salt (+ the plaintext it commits to) lives in a separate
``openings.jsonl`` (mode 0600), so an operator can open ONE record to an
auditor without publishing anything else -- ``grasp-mcp-seal verify --open``.

HONEST LIMIT, stated here and in ``--help``: a record proves what THIS HOST
recorded. It does not prove that a call happened, or that the recorded set is
complete, against a host that lies about its own log. Anchor the head
externally (e.g. ``grasp anchor``) if that matters to your deployment.

Run::

    grasp-mcp-seal serve --upstream http://127.0.0.1:8080
    grasp-mcp-seal verify --home ~/.grasp/mcp-seal
    python -m grasp.mcp_seal serve --upstream ...   # equivalent

Standard library only, plus GRASP's own :mod:`grasp.idr` / :mod:`grasp.home`.
"""
from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import ipaddress
import json
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from grasp.idr import PrecogIDR, _canonical_json, append_idr, build_idr, read_idr_chain
from grasp.idr_forest import IdrForestError, build_chain_forest, verify_chain_integrity
from grasp.verdict import Verdict

SERVER_NAME = "grasp-mcp-seal"
SERVER_VERSION = "0.1.0"

#: Exogenous genesis for a fresh seal chain. Honest about what started it: the
#: sidecar process, not a specific human -- mirrors grasp.mcp_server's own
#: ``human:mcp-operator`` convention (the "human:" admissible-anchor class).
GENESIS_ANCHOR = "human:mcp-seal-sidecar"

#: Hop-by-hop headers (RFC 7230 6.1) plus Host/Content-Length -- the proxy
#: computes both of those itself for the fixed upstream, so neither the
#: client's nor the upstream's copy is ever carried through verbatim.
HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
})

SALT_BYTES = 16
READ_CHUNK = 65536
HONEST_LIMIT = (
    "a record proves what THIS HOST recorded. It does not prove that a call "
    "happened, or that the recorded set is complete, against a host that "
    "lies. Anchor the head externally (e.g. `grasp anchor`) if that matters."
)

#: Cap on a request body this proxy will read, overridable via
#: GRASP_MCP_SEAL_MAX_BODY_BYTES. A JSON-RPC tool-call payload is small; a
#: caller-declared Content-Length far past this is refused BEFORE a single
#: byte is read from the socket -- belt-and-braces against the uncapped
#: ``rfile.read(n)`` a hostile Content-Length would otherwise turn into
#: (an unauthenticated caller forcing a large synchronous read/allocation).
_DEFAULT_MAX_BODY_BYTES = 10 * 1024 * 1024  # 10 MiB


class _BodyTooLarge(Exception):
    """Declared Content-Length exceeds the configured cap -- raised before
    any byte of the body is read from the socket."""

    def __init__(self, declared: int, cap: int) -> None:
        super().__init__(f"declared {declared} bytes, cap {cap}")
        self.declared = declared
        self.cap = cap


class _MalformedContentLength(Exception):
    """The client declared a ``Content-Length`` that is not a valid
    non-negative integer. Treating this like an ABSENT header (as
    ``_read_body`` otherwise does for GET/DELETE with no body) would be
    wrong: the client most likely DID send framed bytes right after this
    header, and silently returning an empty body here leaves those real
    bytes unread on the socket -- the next request on the same persistent
    connection then misreads them as its own request line (the same
    request-smuggling / desync shape ``_ChunkedBodyNotSupported`` already
    guards, just reached via a different malformed header). Raised BEFORE
    any byte of the body is read."""

    def __init__(self, declared: str) -> None:
        super().__init__(f"not a valid non-negative integer: {declared!r}")
        self.declared = declared


class _ChunkedBodyNotSupported(Exception):
    """The client declared ``Transfer-Encoding`` -- this proxy does not
    decode a transfer-coded request body. Treating ``Content-Length`` as
    absent-means-empty (as ``_read_body`` otherwise does for GET/DELETE)
    would be wrong here: there IS a body, just not declared the way this
    proxy reads it, so a silent empty read forwards nothing, seals
    nothing, and leaves the real bytes unread on the socket -- which the
    next request on the same persistent connection then misreads as its
    own request line (an HTTP request-smuggling / desync shape). Raised
    BEFORE any byte is read, so the caller can refuse and force the
    connection closed instead."""


def _max_body_bytes() -> int:
    raw = os.environ.get("GRASP_MCP_SEAL_MAX_BODY_BYTES", "").strip()
    if not raw:
        return _DEFAULT_MAX_BODY_BYTES
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_MAX_BODY_BYTES
    return value if value >= 0 else _DEFAULT_MAX_BODY_BYTES


#: Cap on a BUFFERED (non-SSE) upstream response this proxy will hold in
#: memory before relaying it -- the response-side twin of
#: GRASP_MCP_SEAL_MAX_BODY_BYTES above. A buffered reply must be read whole
#: (to compute Content-Length for the client and to find the JSON-RPC ids to
#: seal), so with no cap a single oversized upstream reply is an unbounded
#: memory-allocation vector on this side too, asymmetric with the capped
#: request side. Overridable via GRASP_MCP_SEAL_MAX_RESPONSE_BYTES.
_DEFAULT_MAX_RESPONSE_BYTES = 64 * 1024 * 1024  # 64 MiB


def _max_response_bytes() -> int:
    raw = os.environ.get("GRASP_MCP_SEAL_MAX_RESPONSE_BYTES", "").strip()
    if not raw:
        return _DEFAULT_MAX_RESPONSE_BYTES
    try:
        value = int(raw)
    except ValueError:
        return _DEFAULT_MAX_RESPONSE_BYTES
    return value if value >= 0 else _DEFAULT_MAX_RESPONSE_BYTES


class _UpstreamResponseTooLarge(Exception):
    """A buffered (non-SSE) upstream response exceeded the configured cap
    before it finished -- raised before anything is sent to the client, so
    this becomes a clean refusal rather than a half-written reply."""

    def __init__(self, read: int, cap: int) -> None:
        super().__init__(f"read over {read} bytes, cap {cap}")
        self.read = read
        self.cap = cap


def _read_capped(resp: http.client.HTTPResponse, cap: int) -> bytes:
    """Read a response body incrementally (never one unbounded ``.read()``),
    raising once the running total exceeds ``cap`` -- before anything has
    been sent to the client, so the caller can still refuse cleanly."""
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = resp.read1(READ_CHUNK)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > cap:
            raise _UpstreamResponseTooLarge(total, cap)
        chunks.append(chunk)


# ---------------------------------------------------------------------------
# Paths, commitments, openings, failures
# ---------------------------------------------------------------------------

def default_home() -> Path:
    """``$GRASP_HOME/mcp-seal`` -- a subdirectory of the normal GRASP state
    dir, so the sidecar reuses the SAME signing key as the rest of GRASP
    (``grasp.keys.signing_key`` resolves through ``grasp_home()``) while its
    own ledger stays separate from the main decision chain (``idr.jsonl``)."""
    from grasp.home import grasp_home
    return grasp_home() / "mcp-seal"


def _ledger_path(home: Path) -> Path:
    return home / "seal.jsonl"


def _openings_path(home: Path) -> Path:
    return home / "openings.jsonl"


def _failures_path(home: Path) -> Path:
    return home / "failures.jsonl"


def _commit(salt: bytes, value: Any) -> str:
    """``sha256(salt || canonical_json(value))`` -- a commitment, not a hash
    of the value alone, so a small/guessable argument set cannot be
    dictionary-attacked from the chain file."""
    blob = salt + _canonical_json(value).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


def _fingerprint(decision: dict, inputs: dict) -> str:
    body = _canonical_json({"decision": decision, "inputs": inputs})
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _save_opening(home: Path, record_id: str, salt: bytes, plain: Any) -> None:
    """Append one (record_id, salt, plaintext) opening, mode 0600 always --
    even if the file pre-exists with looser permissions from another cause."""
    path = _openings_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = (_canonical_json({"record_id": record_id, "salt": salt.hex(), "plain": plain}) + "\n")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, line.encode("utf-8"))
    finally:
        os.close(fd)
    os.chmod(path, 0o600)


def _load_opening(home: Path, record_id: str) -> dict | None:
    path = _openings_path(home)
    if not path.exists():
        return None
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            if entry.get("record_id") == record_id:
                return entry
    return None


def _log_failure(home: Path, phase: str, detail: str) -> None:
    """An outcome (or, in --on-seal-failure=pass mode, an intent) that could
    not be sealed: logged, never silent, never fatal to the call itself."""
    path = _failures_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = _canonical_json({"ts": _now_iso(), "phase": phase, "detail": detail})
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(entry + "\n")
    print(f"grasp-mcp-seal: {phase} seal failed: {detail}", file=sys.stderr)


# ---------------------------------------------------------------------------
# The seal chain -- thin wrapper over grasp.idr's signer + append-only ledger
# ---------------------------------------------------------------------------

class SealChain:
    """One proxy instance's intent/outcome ledger.

    Thread-safe for concurrent requests WITHIN one process: an internal lock
    serialises the read-head-then-append sequence (``append_idr`` itself is
    already cross-process-safe via ``fcntl.flock``, but the read of "what is
    the current head" is a separate step that needs its own guard against two
    threads racing to extend the chain from the same stale head).
    """

    def __init__(self, home: Path) -> None:
        self.home = home
        self.home.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    @property
    def ledger_path(self) -> Path:
        return _ledger_path(self.home)

    def _head(self) -> tuple[str, int]:
        chain = read_idr_chain(path=self.ledger_path)
        if not chain:
            return GENESIS_ANCHOR, 0
        last = chain[-1]
        return last.id, last.depth + 1

    def seal_intent(self, *, tool: str, arguments: Any, session_digest: str | None,
                     jsonrpc_id: Any) -> PrecogIDR:
        salt = secrets.token_bytes(SALT_BYTES)
        decision = {
            "what": f"mcp tool call: {tool}",
            "tool": tool,
            "args_commitment": _commit(salt, arguments),
        }
        inputs = {"session_digest": session_digest, "jsonrpc_id": jsonrpc_id}
        with self._lock:
            predecessor, depth = self._head()
            idr = build_idr(
                prompt=f"mcp.tool.intent:{tool}",
                fingerprint=_fingerprint(decision, inputs),
                decision=decision, inputs=inputs,
                predecessor_idr=predecessor, depth=depth,
                kind="mcp.tool.intent",
            )
            append_idr(idr, path=self.ledger_path)
        _save_opening(self.home, idr.id, salt, {"arguments": arguments})
        return idr

    def seal_outcome(self, *, intent: PrecogIDR, tool: str, payload: Any, is_error: bool,
                      duration_s: float, session_digest: str | None, jsonrpc_id: Any) -> PrecogIDR:
        salt = secrets.token_bytes(SALT_BYTES)
        decision = {
            "what": f"mcp tool outcome: {tool}",
            "tool": tool,
            "result_commitment": _commit(salt, payload),
            "is_error": bool(is_error),
            "duration_ms": round(duration_s * 1000, 3),
        }
        inputs = {
            "intent_id": intent.id,
            "session_digest": session_digest,
            "jsonrpc_id": jsonrpc_id,
        }
        with self._lock:
            predecessor, depth = self._head()
            idr = build_idr(
                prompt=f"mcp.tool.outcome:{tool}",
                fingerprint=_fingerprint(decision, inputs),
                decision=decision, inputs=inputs,
                predecessor_idr=predecessor, depth=depth,
                kind="mcp.tool.outcome",
            )
            append_idr(idr, path=self.ledger_path)
        _save_opening(self.home, idr.id, salt, {"result": payload})
        return idr


# ---------------------------------------------------------------------------
# JSON-RPC helpers -- method/id/batch recognition, no re-serialisation
# ---------------------------------------------------------------------------

def _as_messages(parsed: Any) -> list[dict]:
    """A JSON-RPC body is one object or a batch (array) of objects/notifications."""
    if isinstance(parsed, list):
        return [m for m in parsed if isinstance(m, dict)]
    if isinstance(parsed, dict):
        return [parsed]
    return []


def _is_hashable(value: Any) -> bool:
    """True iff ``value`` can be a dict key -- a JSON-decoded list or dict
    (illegal as a JSON-RPC id, but syntactically valid JSON) is not."""
    try:
        hash(value)
    except TypeError:
        return False
    return True


def _tool_call_args(message: dict) -> tuple[str, Any]:
    params = message.get("params") or {}
    return str(params.get("name", "")), params.get("arguments", {})


def _session_digest(headers) -> str | None:
    """A plain (unsalted) hash of Mcp-Session-Id -- not a commitment: nothing
    is ever "opened" back to the raw id, so no salt/opening is kept for it."""
    sid = headers.get("Mcp-Session-Id")
    if not sid:
        return None
    return "sha256:" + hashlib.sha256(sid.encode("utf-8")).hexdigest()


class _UnparsableJSONRPCBody(Exception):
    """A non-empty POST body that fails this proxy's own ``json.loads``.
    Forwarding it on good faith (as a byte-identical passthrough) would let
    a more tolerant upstream parser still execute it as a real tool call --
    one this proxy never recognised as a message, so no intent or outcome
    is ever sealed for it. Refused instead of silently passed through."""


def _jsonrpc_error_obj(msg_id: Any, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32000, "message": message}}


def _refusal_body(messages: list[dict], was_batch: bool, reason: str) -> bytes:
    """Build the JSON-RPC error response for a refused request. Only
    messages carrying an ``id`` get an error object -- a notification never
    receives a response, refused or not."""
    errors = [_jsonrpc_error_obj(m["id"], reason) for m in messages if "id" in m]
    if not errors:
        payload: Any = _jsonrpc_error_obj(None, reason)
    else:
        payload = errors if was_batch else errors[0]
    return json.dumps(payload).encode("utf-8")


def _result_payload(message: dict) -> tuple[Any, bool]:
    """(payload, is_error) for a JSON-RPC response -- covers BOTH a
    protocol-level ``error`` member and a tool-level ``result.isError``
    (mirrors grasp.mcp_server's own ``isError`` convention)."""
    if "error" in message:
        return message.get("error"), True
    result = message.get("result")
    is_error = bool(isinstance(result, dict) and result.get("isError"))
    return result, is_error


# ---------------------------------------------------------------------------
# Incremental SSE line buffer -- bounded memory, never the whole stream
# ---------------------------------------------------------------------------

class _SSELineBuffer:
    """Feed it raw bytes as they arrive; it yields complete SSE ``data:``
    payloads as each event completes (a blank line terminates an event).
    Holds only the current partial line + the current event's accumulated
    data lines -- never the stream read so far."""

    def __init__(self) -> None:
        self._buf = b""
        self._data_lines: list[bytes] = []

    def feed(self, chunk: bytes) -> list[str]:
        self._buf += chunk
        payloads: list[str] = []
        while b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            line = line.rstrip(b"\r")
            payload = self._consume_line(line)
            if payload is not None:
                payloads.append(payload)
        return payloads

    def _consume_line(self, line: bytes) -> str | None:
        """One SSE line: accumulate a ``data:`` field, or -- on a blank line
        -- close out the current event and return its joined payload."""
        if not line:
            if not self._data_lines:
                return None
            payload = b"\n".join(self._data_lines).decode("utf-8", "replace")
            self._data_lines = []
            return payload
        if line.startswith(b"data:"):
            value = line[5:]
            if value.startswith(b" "):
                value = value[1:]
            self._data_lines.append(value)
        return None


# ---------------------------------------------------------------------------
# Upstream target + forwarding (the fixed-upstream, header-passthrough proxy)
# ---------------------------------------------------------------------------

@dataclass
class ProxyConfig:
    upstream: str
    chain: SealChain
    on_seal_failure: str = "refuse"
    upstream_https: bool = field(init=False)
    upstream_host: str = field(init=False)
    upstream_port: int = field(init=False)
    upstream_base_path: str = field(init=False)

    def __post_init__(self) -> None:
        parts = urlsplit(self.upstream)
        if parts.scheme not in ("http", "https"):
            raise ValueError(f"--upstream must be http:// or https://, got {self.upstream!r}")
        if not parts.hostname:
            raise ValueError(f"--upstream must include a host, got {self.upstream!r}")
        self.upstream_https = parts.scheme == "https"
        self.upstream_host = parts.hostname
        self.upstream_port = parts.port or (443 if self.upstream_https else 80)
        self.upstream_base_path = parts.path.rstrip("/")


def _connect(cfg: ProxyConfig) -> http.client.HTTPConnection:
    cls = http.client.HTTPSConnection if cfg.upstream_https else http.client.HTTPConnection
    return cls(cfg.upstream_host, cfg.upstream_port, timeout=30)


def _connection_listed_headers(value: str | None) -> frozenset[str]:
    """RFC 7230 S6.1: a header NAMED inside a ``Connection`` field's value is
    hop-by-hop for THAT connection specifically, on top of the fixed
    HOP_BY_HOP set -- it must not be forwarded to the next hop either, or a
    caller/upstream can smuggle an arbitrary header past the static list by
    naming it in ``Connection`` (e.g. ``Connection: x-smuggle`` plus an
    ``X-Smuggle`` header of its own)."""
    if not value:
        return frozenset()
    return frozenset(tok.strip().lower() for tok in value.split(",") if tok.strip())


def _connection_field_value(headers) -> str | None:
    """Every ``Connection`` value the client sent, RFC 7230 S3.2.2-joined.

    ``Connection`` is defined as a comma-separated-list header, so a client
    MAY legally split it across more than one header line instead of joining
    it with commas on one line -- both forms are the same field, and a
    recipient must treat them identically. ``headers.get("Connection")`` on
    an ``email.message.Message`` (what ``self.headers`` is) returns only the
    FIRST such line, silently dropping the rest -- which lets a client
    smuggle an arbitrary header past the hop-by-hop strip by naming it in a
    SECOND ``Connection`` line the single-value read never sees.
    ``get_all`` returns every occurrence; joining with ``", "`` reproduces
    the one-line form ``_connection_listed_headers`` already parses."""
    values = headers.get_all("Connection")
    return ", ".join(values) if values else None


def _forward_headers(headers) -> list[tuple[str, str]]:
    """Every header the client sent, minus HOP_BY_HOP and anything the
    client's own Connection header lists -- as a LIST of pairs, not a dict,
    so a repeated header name (two ``Cookie`` lines, say -- legal HTTP,
    however unusual) keeps every value. A dict would silently collapse to
    the last one, dropping the rest. No allowlist: a reverse proxy that only
    forwards headers it recognises breaks on the first header it does not --
    Authorization/Mcp-Session-Id/Accept all pass through simply because they
    are not hop-by-hop, same as anything else."""
    drop = HOP_BY_HOP | _connection_listed_headers(_connection_field_value(headers))
    return [(name, value) for name, value in headers.items() if name.lower() not in drop]


def _forward(cfg: ProxyConfig, method: str, path: str, headers: list[tuple[str, str]],
             body: bytes) -> tuple[http.client.HTTPConnection, http.client.HTTPResponse]:
    """Forward one request to the FIXED upstream. ``skip_accept_encoding``
    keeps this a pure passthrough -- we never want http.client silently
    asking upstream for a content-encoding the client never requested."""
    conn = _connect(cfg)
    target = cfg.upstream_base_path + path
    conn.putrequest(method, target, skip_host=True, skip_accept_encoding=True)
    conn.putheader("Host", f"{cfg.upstream_host}:{cfg.upstream_port}")
    for name, value in headers:
        conn.putheader(name, value)
    if body:
        conn.putheader("Content-Length", str(len(body)))
    conn.endheaders(body or None)
    return conn, conn.getresponse()


def _is_event_stream(resp: http.client.HTTPResponse) -> bool:
    ctype = (resp.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
    return ctype == "text/event-stream"


#: Status codes whose response MUST NOT carry Content-Length (RFC 9110
#: SS8.6): 1xx, 204 No Content, 304 Not Modified. ``resp.read()`` already
#: yields ``b""`` for these (http.client special-cases them), so the data
#: this proxy would report a length for is always 0 anyway -- the header
#: is pure surplus a strict client is entitled to reject.
_NO_CONTENT_LENGTH_STATUSES = frozenset({204, 304})


def _forbids_content_length(status: int) -> bool:
    return status in _NO_CONTENT_LENGTH_STATUSES or 100 <= status < 200


# ---------------------------------------------------------------------------
# The proxy handler
# ---------------------------------------------------------------------------

@dataclass
class _PendingCall:
    intent: PrecogIDR
    tool: str
    session_digest: str | None
    jsonrpc_id: Any
    started: float


class _SealHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"{SERVER_NAME}/{SERVER_VERSION}"

    def log_message(self, fmt: str, *args) -> None:  # noqa: D102 -- quiet by default
        pass

    def do_GET(self) -> None:  # noqa: N802 -- http.server's own method name
        self._handle("GET")

    def do_DELETE(self) -> None:  # noqa: N802
        self._handle("DELETE")

    def do_POST(self) -> None:  # noqa: N802
        self._handle("POST")

    # -- request intake ------------------------------------------------

    def _read_body(self) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            raise _ChunkedBodyNotSupported()
        length = self.headers.get("Content-Length")
        if not length:
            return b""
        try:
            n = int(length)
        except ValueError:
            raise _MalformedContentLength(length) from None
        if n < 0:
            raise _MalformedContentLength(length)
        cap = _max_body_bytes()
        if n > cap:
            raise _BodyTooLarge(n, cap)
        return self.rfile.read(n) if n > 0 else b""

    def _parse_body(self, method: str, body: bytes) -> tuple[bool, list[dict]]:
        if method != "POST" or not body:
            return False, []
        try:
            parsed = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            # json.loads on bytes auto-detects the text encoding before
            # parsing; bytes that are not valid UTF-8 (or UTF-16/32) raise
            # UnicodeDecodeError there -- a SIBLING of JSONDecodeError under
            # ValueError, not a subclass of it, so catching only the latter
            # let this shape escape uncaught and crash the handler thread.
            raise _UnparsableJSONRPCBody(str(exc)) from None
        return isinstance(parsed, list), _as_messages(parsed)

    # -- the main dispatch -----------------------------------------------

    def _handle(self, method: str) -> None:
        cfg: ProxyConfig = self.server.seal_config  # type: ignore[attr-defined]
        body = self._read_body_or_refuse()
        if body is None:
            return  # already refused -- framing could not be trusted
        was_batch, messages = self._parse_body_or_refuse(method, body)
        if messages is None:
            return  # already refused -- body was not valid JSON
        pending: dict[Any, _PendingCall] = {}
        if method == "POST" and messages:
            pending, refusal = self._seal_intents(cfg, messages)
            if refusal is not None:
                self._write_json(200, _refusal_body(messages, was_batch, refusal))
                return
        try:
            conn, resp = _forward(cfg, method, self.path, _forward_headers(self.headers), body)
        except OSError as exc:
            self._write_json(502, _refusal_body(messages, was_batch, f"upstream unreachable: {exc}"))
            return
        try:
            self._relay(resp, pending, cfg)
        finally:
            conn.close()

    def _refuse_framing(self, status: int, message: str) -> None:
        """A request whose framing cannot be trusted: nothing (or not
        enough) was read from the socket to know where it ends, so the
        connection is forced closed rather than leave the client's bytes
        sitting unread for the next request on it to misparse."""
        self.close_connection = True
        self._write_json(status, json.dumps(_jsonrpc_error_obj(None, message)).encode("utf-8"))

    def _read_body_or_refuse(self) -> bytes | None:
        """The request body, or ``None`` once a refusal has already been
        written -- the three framing defects this proxy cannot safely
        guess past (an oversize declared length, one that is not a valid
        non-negative integer, or a transfer-coded body it does not
        decode)."""
        try:
            return self._read_body()
        except _BodyTooLarge as exc:
            self._refuse_framing(413, f"request body of {exc.declared} bytes exceeds the "
                                       f"{exc.cap}-byte cap (GRASP_MCP_SEAL_MAX_BODY_BYTES)")
        except _MalformedContentLength as exc:
            self._refuse_framing(
                400, f"Content-Length is not a valid non-negative integer: {exc.declared!r}")
        except _ChunkedBodyNotSupported:
            self._refuse_framing(411, "this proxy requires Content-Length and does not decode "
                                       "Transfer-Encoding; send the request with Content-Length set")
        return None

    def _parse_body_or_refuse(self, method: str, body: bytes) -> tuple[bool, list[dict] | None]:
        """(was_batch, messages), or (False, None) once a refusal has
        already been written. The body was already fully read by this
        point, so a refusal here does not desync the connection -- it is
        refused because forwarding it unseen would mean trusting a
        possibly more lenient upstream not to execute it unsealed."""
        try:
            return self._parse_body(method, body)
        except _UnparsableJSONRPCBody as exc:
            message = f"request body is not valid JSON: {exc}"
            self._write_json(400, json.dumps(_jsonrpc_error_obj(None, message)).encode("utf-8"))
            return False, None

    def _write_json(self, status: int, body: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- sealing intents before forwarding --------------------------------

    def _seal_intents(self, cfg: ProxyConfig,
                       messages: list[dict]) -> tuple[dict[Any, _PendingCall], str | None]:
        pending: dict[Any, _PendingCall] = {}
        session_digest = _session_digest(self.headers)
        for message in messages:
            if "id" in message and not _is_hashable(message["id"]):
                # JSON-RPC ids are a string, number, or null -- never an
                # array or object. An unhashable id can never be tracked as
                # a pending call (``pending[message["id"]]`` below would
                # raise TypeError and crash the handler thread), so refuse
                # BEFORE sealing an intent for it -- sealing first and
                # discovering this after would leave a real ledger record
                # that can never be paired with an outcome, unconditional
                # on ``on_seal_failure`` since there is no "pass" shape for
                # a call this proxy cannot track at all.
                return {}, "refusing -- a JSON-RPC id must be a string, number, or null"
            sealed = self._seal_one_intent(cfg, message, session_digest)
            if sealed is None and cfg.on_seal_failure == "refuse" and \
                    message.get("method") == "tools/call":
                return {}, "refusing -- intent could not be sealed"
            if sealed is not None and "id" in message:
                pending[message["id"]] = sealed
        return pending, None

    def _seal_one_intent(self, cfg: ProxyConfig, message: dict,
                          session_digest: str | None) -> _PendingCall | None:
        if message.get("method") != "tools/call":
            return None
        tool, arguments = _tool_call_args(message)
        started = time.monotonic()
        try:
            intent = cfg.chain.seal_intent(
                tool=tool, arguments=arguments, session_digest=session_digest,
                jsonrpc_id=message.get("id"),
            )
        except OSError as exc:
            # Logging and refuse/pass are orthogonal: log always, let the
            # caller decide whether this failure aborts the whole request.
            _log_failure(cfg.chain.home, "intent", f"{tool}: {exc}")
            return None
        return _PendingCall(intent=intent, tool=tool, session_digest=session_digest,
                             jsonrpc_id=message.get("id"), started=started)

    # -- relaying the response, sealing outcomes as they are observed ----

    def _relay(self, resp: http.client.HTTPResponse, pending: dict, cfg: ProxyConfig) -> None:
        if _is_event_stream(resp):
            self._relay_streamed(resp, pending, cfg)
        else:
            self._relay_buffered(resp, pending, cfg)

    def _copy_response_headers(self, resp: http.client.HTTPResponse) -> None:
        drop = HOP_BY_HOP | _connection_listed_headers(resp.getheader("Connection"))
        for name, value in resp.getheaders():
            if name.lower() not in drop:
                self.send_header(name, value)

    def _relay_buffered(self, resp: http.client.HTTPResponse, pending: dict, cfg: ProxyConfig) -> None:
        try:
            data = _read_capped(resp, _max_response_bytes())
        except _UpstreamResponseTooLarge as exc:
            # Nothing has been sent to the client yet -- refuse cleanly
            # instead of buffering an unbounded upstream reply.
            message = (f"upstream response of over {exc.read} bytes exceeds the "
                       f"{exc.cap}-byte cap (GRASP_MCP_SEAL_MAX_RESPONSE_BYTES)")
            self._write_json(502, json.dumps(_jsonrpc_error_obj(None, message)).encode("utf-8"))
            return
        self.send_response(resp.status)
        self._copy_response_headers(resp)
        if not _forbids_content_length(resp.status):
            self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        if pending:
            self._seal_outcomes_from_bytes(data, pending, cfg)

    def _relay_streamed(self, resp: http.client.HTTPResponse, pending: dict, cfg: ProxyConfig) -> None:
        self.send_response(resp.status)
        self._copy_response_headers(resp)
        # No Content-Length is known up front; never buffer to compute one.
        # Connection: close delimits the body instead (read-until-EOF).
        self.send_header("Connection", "close")
        self.end_headers()
        self.close_connection = True
        buf = _SSELineBuffer()
        self._pump_stream(resp, buf, pending, cfg)

    def _pump_stream(self, resp: http.client.HTTPResponse, buf: "_SSELineBuffer",
                      pending: dict, cfg: ProxyConfig) -> None:
        """Read upstream one chunk at a time (``read1`` -- at most one
        network read, never waiting to fill a bigger buffer) and forward
        each chunk to the client immediately, before parsing it."""
        while True:
            chunk = resp.read1(READ_CHUNK)
            if not chunk:
                return
            self.wfile.write(chunk)
            self.wfile.flush()
            if pending:
                self._seal_outcomes_from_sse(buf.feed(chunk), pending, cfg)

    def _seal_outcomes_from_sse(self, payloads: list[str], pending: dict, cfg: ProxyConfig) -> None:
        for payload in payloads:
            self._maybe_seal_outcome(payload, pending, cfg)

    def _seal_outcomes_from_bytes(self, data: bytes, pending: dict, cfg: ProxyConfig) -> None:
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            return
        for message in _as_messages(parsed):
            self._seal_one_outcome(message, pending, cfg)

    def _maybe_seal_outcome(self, payload: str, pending: dict, cfg: ProxyConfig) -> None:
        """One SSE event's ``data:`` payload -- a single JSON-RPC response
        object, OR (a legal batch reply) a JSON array of several. Reuses
        ``_as_messages`` so both shapes seal exactly like the buffered-JSON
        path does; a dict-only check here would silently leave every
        outcome in an array-framed SSE batch reply unsettled."""
        try:
            message = json.loads(payload)
        except json.JSONDecodeError:
            return
        for one in _as_messages(message):
            self._seal_one_outcome(one, pending, cfg)

    def _seal_one_outcome(self, message: dict, pending: dict, cfg: ProxyConfig) -> None:
        call = pending.pop(message.get("id"), None)
        if call is None:
            return
        payload, is_error = _result_payload(message)
        duration = time.monotonic() - call.started
        try:
            cfg.chain.seal_outcome(
                intent=call.intent, tool=call.tool, payload=payload, is_error=is_error,
                duration_s=duration, session_digest=call.session_digest,
                jsonrpc_id=call.jsonrpc_id,
            )
        except OSError as exc:
            _log_failure(cfg.chain.home, "outcome", f"{call.tool}: {exc}")


def make_server(cfg: ProxyConfig, host: str = "127.0.0.1",
                 port: int = 0) -> http.server.ThreadingHTTPServer:
    server = http.server.ThreadingHTTPServer((host, port), _SealHandler)
    server.daemon_threads = True
    server.seal_config = cfg  # type: ignore[attr-defined]
    return server


def _is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Offline verification -- chain integrity + intent/outcome pairing + openings
# ---------------------------------------------------------------------------

def verify_seal_chain(home: Path) -> dict:
    """Re-verify ``<home>/seal.jsonl`` offline: every signature (tamper
    detection via grasp.idr_forest -- the SAME chain primitive the rest of
    GRASP uses), then which intents have no matching outcome yet.

    Returns a dict with an internal ``_by_id`` index (popped by the CLI
    before printing) so ``--open`` need not re-read the ledger."""
    path = _ledger_path(home)
    malformed: list[int] = []
    chain = read_idr_chain(path=path, malformed=malformed)
    out: dict[str, Any] = {
        "home": str(home), "records": len(chain), "malformed_lines": len(malformed),
        "_by_id": {idr.id: idr for idr in chain},
    }
    if not chain:
        out.update(chain_verdict="empty", unsettled=[], ok=True)
        return out
    try:
        forest = build_chain_forest(chain, genesis_anchor=GENESIS_ANCHOR)
    except IdrForestError as exc:
        out.update(chain_verdict=Verdict.BROKEN.value, chain_error=str(exc), unsettled=[], ok=False)
        return out
    verdict = verify_chain_integrity(forest)
    out["chain_verdict"] = verdict.value
    out["unsettled"] = _unsettled_intents(chain)
    out["ok"] = verdict is Verdict.VERIFIED and not out["malformed_lines"]
    return out


def _unsettled_intents(chain: list[PrecogIDR]) -> list[str]:
    settled = {idr.inputs.get("intent_id") for idr in chain if idr.kind == "mcp.tool.outcome"}
    return [idr.id for idr in chain if idr.kind == "mcp.tool.intent" and idr.id not in settled]


def _open_record(home: Path, record_id: str, by_id: dict[str, PrecogIDR]) -> dict:
    """Recompute one record's commitment from its opening -- proves the
    salt+plaintext on file really produces the hash the chain committed to,
    without requiring anything but this one record's opening."""
    idr = by_id.get(record_id)
    if idr is None:
        return {"ok": False, "error": f"no such record in the chain: {record_id!r}"}
    opening = _load_opening(home, record_id)
    if opening is None:
        return {"ok": False, "error": f"no opening on file for {record_id!r}"}
    salt = bytes.fromhex(opening["salt"])
    plain = opening.get("plain") or {}
    if idr.kind == "mcp.tool.intent":
        committed = idr.decision.get("args_commitment")
        recomputed = _commit(salt, plain.get("arguments"))
    else:
        committed = idr.decision.get("result_commitment")
        recomputed = _commit(salt, plain.get("result"))
    return {
        "ok": recomputed == committed, "record_id": record_id, "kind": idr.kind,
        "tool": idr.decision.get("tool"), "committed": committed,
        "recomputed": recomputed, "plain": plain,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _cmd_serve(args: argparse.Namespace) -> int:
    home = Path(args.home) if args.home else default_home()
    host, _, port_s = args.listen.rpartition(":")
    if not host:
        print("grasp-mcp-seal: --listen must be HOST:PORT", file=sys.stderr)
        return 2
    try:
        port = int(port_s)
    except ValueError:
        print(f"grasp-mcp-seal: --listen port is not an integer: {port_s!r}", file=sys.stderr)
        return 2
    if not _is_loopback(host) and not args.allow_remote_bind:
        print(f"grasp-mcp-seal: refusing to bind {host!r} (not loopback) without "
              "--allow-remote-bind", file=sys.stderr)
        return 2
    try:
        cfg = ProxyConfig(upstream=args.upstream, chain=SealChain(home),
                          on_seal_failure=args.on_seal_failure)
    except ValueError as exc:
        print(f"grasp-mcp-seal: {exc}", file=sys.stderr)
        return 2
    server = make_server(cfg, host, port)
    bound_host, bound_port = server.server_address[:2]
    print(f"grasp-mcp-seal: {bound_host}:{bound_port} -> {args.upstream} "
          f"(home={home}, on-seal-failure={args.on_seal_failure}). {HONEST_LIMIT}",
          file=sys.stderr)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    home = Path(args.home) if args.home else default_home()
    out = verify_seal_chain(home)
    by_id = out.pop("_by_id")
    if args.open_id:
        out["opening"] = _open_record(home, args.open_id, by_id)
    print(json.dumps(out) if args.json else json.dumps(out, indent=2, sort_keys=True))
    if not out.get("ok"):
        return 1
    if args.open_id and not out["opening"].get("ok"):
        return 1
    return 0


def _add_serve_command(sub) -> None:
    serve = sub.add_parser(
        "serve",
        help="run the reverse-proxy seal sidecar in front of one fixed upstream",
    )
    serve.add_argument("--upstream", required=True,
                        help="the ONE fixed upstream Streamable HTTP MCP server URL")
    serve.add_argument("--listen", default="127.0.0.1:8091",
                        help="HOST:PORT to bind (default 127.0.0.1:8091)")
    serve.add_argument("--home", help="state dir (default: $GRASP_HOME/mcp-seal)")
    serve.add_argument(
        "--on-seal-failure", choices=["refuse", "pass"], default="refuse",
        help="refuse (default): do not forward a call whose intent cannot be "
             "sealed. pass: forward anyway -- the explicit brake release",
    )
    serve.add_argument("--allow-remote-bind", action="store_true",
                        help="allow binding a non-loopback address")
    serve.set_defaults(func=_cmd_serve)


def _add_verify_command(sub) -> None:
    verify = sub.add_parser("verify", help="re-verify the seal chain offline, no account needed")
    verify.add_argument("--home", help="state dir (default: $GRASP_HOME/mcp-seal)")
    verify.add_argument("--open", dest="open_id", metavar="RECORD_ID",
                         help="recompute one record's commitment from its opening")
    verify.add_argument("--json", action="store_true", help="single-line JSON (default: pretty)")
    verify.set_defaults(func=_cmd_verify)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="grasp-mcp-seal",
        description=f"{SERVER_NAME} {SERVER_VERSION} -- signed tool-call seal for Streamable "
                    f"HTTP MCP. Honest limit: {HONEST_LIMIT}",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    _add_serve_command(sub)
    _add_verify_command(sub)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
