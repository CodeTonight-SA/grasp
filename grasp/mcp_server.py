# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""GRASP MCP server — cryptographic causation for any MCP-speaking agent harness.

A standard-library-only Model Context Protocol server (stdio transport,
newline-delimited JSON-RPC 2.0) that lets an agent CLI — Gemini CLI, Claude
Code, or any other MCP host — record what it decided, what it believed, and
whether its claims are grounded, as signed, tamper-evident, replayable GRASP
records. The server is a thin adapter: every guarantee is provided by the
grasp package itself, and every record it writes re-verifies offline with the
same package (``grasp_verify``) — the host's own report is never the
criterion.

Run directly::

    grasp-mcp                      # console script
    python -m grasp.mcp_server     # equivalent

State lives under ``$GRASP_HOME`` (default ``~/.grasp``): ``idr.jsonl`` (the
decision ledger), ``context.jsonl`` (the belief chain). The first decision of
a ledger roots at the ``human:`` exogenous anchor class — the operator who
launched the session is the genesis anchor, so no chain traces its authority
to the agent's own say-so.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import asdict
from typing import Any

from grasp.context_chain import checkpoint, verify_context_chain
from grasp.home import grasp_home
from grasp.idr import build_idr, append_idr, content_addr, read_idr_chain
from grasp.idr_forest import (
    IdrForestError,
    build_chain_forest,
    find_unanchored,
    forest_merkle_root,
    is_admissible_anchor,
    verify_chain_integrity,
)
from grasp.provenance import record_proveit_provenance
from grasp.prove_it import verify_quote
from grasp.verdict import Verdict

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "grasp"
SERVER_VERSION = "0.2.0"

#: Exogenous genesis for a fresh decision ledger: the human operator who
#: started the session (the ``human:`` admissible-anchor class).
GENESIS_ANCHOR = "human:mcp-operator"


# ---------------------------------------------------------------------------
# The five tools
# ---------------------------------------------------------------------------

def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _decision_head() -> tuple[str, int]:
    """(predecessor_id, depth) for the next decision record."""
    chain = read_idr_chain()
    if not chain:
        return GENESIS_ANCHOR, 0
    head = chain[-1]
    return head.id, head.depth + 1


def tool_record_decision(args: dict) -> dict:
    what = str(args.get("what", "")).strip()
    why = str(args.get("why", "")).strip()
    if not what:
        return {"ok": False, "error": "'what' is required — the decision taken"}
    kind = str(args.get("kind", "agent-decision")).strip() or "agent-decision"
    inputs = args.get("inputs") if isinstance(args.get("inputs"), dict) else {}
    decision = {"what": what, "why": why}
    predecessor, depth = _decision_head()
    fingerprint = hashlib.sha256(
        _canonical({"decision": decision, "inputs": inputs}).encode("utf-8")
    ).hexdigest()
    idr = build_idr(
        prompt=why,
        fingerprint=fingerprint,
        decision=decision,
        predecessor_idr=predecessor,
        depth=depth,
        kind=kind,
        inputs=inputs,
    )
    append_idr(idr)
    return {
        "ok": True,
        "id": idr.id,
        "content_addr": content_addr(asdict(idr)),
        "predecessor_idr": predecessor,
        "depth": depth,
        "ts": idr.ts,
        "scheme": idr.audit.get("scheme"),
    }


def tool_record_belief(args: dict) -> dict:
    belief = str(args.get("belief", "")).strip()
    if not belief:
        return {"ok": False, "error": "'belief' is required — the reasoning-state summary"}
    next_step = args.get("next_step")
    records_idr = args.get("records_idr") or None
    node = checkpoint(
        next_step={"step": str(next_step)} if next_step else None,
        summary=belief,
        title="mcp belief checkpoint",
        records_idr=str(records_idr) if records_idr else None,
    )
    return {"ok": True, "id": node.id, "ts": node.ts,
            "records_idr": records_idr, "depth": node.depth}


def tool_prove_claim(args: dict) -> dict:
    title = str(args.get("title", "claim")).strip() or "claim"
    quote = str(args.get("quote", ""))
    source_path = str(args.get("source_path", "")).strip()
    source_text = args.get("source_text")
    if not quote.strip():
        return {"ok": False, "error": "'quote' is required — the verbatim span to verify"}
    if source_text is None:
        if not source_path:
            return {"ok": False, "error": "one of 'source_path' or 'source_text' is required"}
        try:
            with open(source_path, encoding="utf-8", errors="replace") as fh:
                source_text = fh.read()
        except OSError as exc:
            return {"ok": False, "error": f"source unreadable: {exc}"}
    status, start, end = verify_quote(quote, str(source_text))
    verified = status == "verified"
    fuzzy = status == "fuzzy"
    prov = {
        "grounding_rate": 1.0 if verified else 0.0,
        "tally": {
            "verified": 1 if verified else 0,
            "fuzzy": 1 if fuzzy else 0,
            "not_found": 0 if (verified or fuzzy) else 1,
        },
    }
    spec = {"title": title, "citations": [{"id": "c1"}]}
    chain = record_proveit_provenance(spec, prov)
    return {
        "ok": True,
        "status": status,
        "start": start,
        "end": end,
        "filed_safe": verified,
        "source_sha256": hashlib.sha256(str(source_text).encode("utf-8")).hexdigest(),
        "chain": chain,
    }


def tool_verify(_args: dict) -> dict:
    out: dict[str, Any] = {"ok": True, "home": str(grasp_home())}
    chain = read_idr_chain()
    out["decisions"] = len(chain)
    if chain:
        # The ledger's genesis record may have ``predecessor_idr: null`` (e.g. a
        # ledger first seeded by a prove-it artifact) — that is NOT an admissible
        # exogenous anchor, so use the ``human:`` fallback as the forest's
        # declared root. Every node still verifies purely by its own HMAC, so the
        # fallback never changes the tamper verdict; it only lets the forest build
        # instead of crashing ``AttributeError: 'NoneType' … 'startswith'``.
        root = chain[0].predecessor_idr
        genesis = root if is_admissible_anchor(root) else GENESIS_ANCHOR
        try:
            forest = build_chain_forest(chain, genesis_anchor=genesis)
            verdict = verify_chain_integrity(forest)
            out["decision_chain"] = verdict.value
            out["merkle_root"] = forest_merkle_root(forest)
            unanchored = find_unanchored(forest)
            if unanchored:
                # Informational: nodes not reaching an exogenous root. Does NOT
                # change ``decision_chain`` (the tamper verdict) — signatures are
                # a separate axis from anchoring.
                out["unanchored"] = len(unanchored)
        except IdrForestError as exc:
            out["decision_chain"] = Verdict.BROKEN.value
            out["decision_chain_error"] = str(exc)
    else:
        out["decision_chain"] = "empty"
    belief = verify_context_chain()
    out["belief_chain"] = belief.value if belief is not None else "empty"
    out["ok"] = out.get("decision_chain") in ("empty", Verdict.VERIFIED.value) and \
        out.get("belief_chain") in ("empty", Verdict.VERIFIED.value)
    return out


def tool_status(_args: dict) -> dict:
    home = grasp_home()
    chain = read_idr_chain()
    return {
        "ok": True,
        "home": str(home),
        "decisions": len(chain),
        "decision_head": chain[-1].id if chain else None,
        "last_ts": chain[-1].ts if chain else None,
        "ledger": str(home / "idr.jsonl"),
        "belief_chain": str(home / "context.jsonl"),
        "server": f"{SERVER_NAME} {SERVER_VERSION}",
    }


TOOLS: dict[str, tuple[Any, dict]] = {
    "grasp_record_decision": (tool_record_decision, {
        "description": (
            "Record a consequential decision as a signed, hash-chained GRASP "
            "Intent Decision Record (IDR). Call this whenever you take an action "
            "that matters: editing a file, running a state-changing command, "
            "choosing between approaches. Returns the record id and content "
            "address. The record is tamper-evident and third-party verifiable."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["what", "why"],
            "properties": {
                "what": {"type": "string", "description": "The decision taken, plainly stated"},
                "why": {"type": "string", "description": "The reasoning behind it"},
                "kind": {"type": "string", "description": "Decision class (default agent-decision)"},
                "inputs": {"type": "object", "description": "Key inputs the decision depended on"},
            },
        },
    }),
    "grasp_record_belief": (tool_record_belief, {
        "description": (
            "Snapshot your current reasoning state (what you believe and plan) "
            "into the signed GRASP belief chain. Optionally cross-link the "
            "decision record it produced via records_idr (its content address)."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["belief"],
            "properties": {
                "belief": {"type": "string", "description": "Summary of current beliefs/mental state"},
                "next_step": {"type": "string", "description": "The planned next step"},
                "records_idr": {"type": "string", "description": "content_addr of the decision this belief produced"},
            },
        },
    }),
    "grasp_prove_claim": (tool_prove_claim, {
        "description": (
            "Verify that a quotation exists verbatim in its source before you "
            "assert it, and record the result as signed provenance. A fabricated "
            "quote returns not_found and filed_safe=false — it cannot pass."
        ),
        "inputSchema": {
            "type": "object",
            "required": ["quote"],
            "properties": {
                "title": {"type": "string", "description": "Short label for the claim"},
                "quote": {"type": "string", "description": "The verbatim span being cited"},
                "source_path": {"type": "string", "description": "Path to the source file"},
                "source_text": {"type": "string", "description": "Source text (alternative to source_path)"},
            },
        },
    }),
    "grasp_verify": (tool_verify, {
        "description": (
            "Re-verify the entire recorded history offline: every decision "
            "signature, the chain linkage, the Merkle root, and the belief "
            "chain. Returns VERIFIED / DEGRADED / BROKEN per chain — the "
            "arithmetic, not the agent, is the judge."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    }),
    "grasp_status": (tool_status, {
        "description": "Show the GRASP ledger location, record counts, and chain head.",
        "inputSchema": {"type": "object", "properties": {}},
    }),
}


# ---------------------------------------------------------------------------
# MCP stdio plumbing (newline-delimited JSON-RPC 2.0)
# ---------------------------------------------------------------------------

def _response(req_id: Any, result: dict) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _error(req_id: Any, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


def handle_message(msg: dict) -> dict | None:
    """Handle one JSON-RPC message; return the response dict or None (notification)."""
    method = msg.get("method", "")
    req_id = msg.get("id")
    params = msg.get("params") or {}

    if method == "initialize":
        client_proto = params.get("protocolVersion") or PROTOCOL_VERSION
        return _response(req_id, {
            "protocolVersion": client_proto,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })
    if method in ("notifications/initialized", "notifications/cancelled"):
        return None
    if method == "ping":
        return _response(req_id, {})
    if method == "tools/list":
        return _response(req_id, {"tools": [
            {"name": name, "description": meta["description"], "inputSchema": meta["inputSchema"]}
            for name, (_fn, meta) in TOOLS.items()
        ]})
    if method == "tools/call":
        name = params.get("name", "")
        entry = TOOLS.get(name)
        if entry is None:
            return _error(req_id, -32602, f"unknown tool: {name}")
        fn = entry[0]
        try:
            result = fn(params.get("arguments") or {})
        except Exception as exc:  # noqa: BLE001 — surface as tool error, never crash the server
            result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        return _response(req_id, {
            "content": [{"type": "text", "text": _canonical(result)}],
            "isError": not result.get("ok", False),
        })
    if req_id is None:
        return None  # unknown notification — ignore
    return _error(req_id, -32601, f"method not found: {method}")


def main() -> None:
    """Serve MCP over stdio until EOF. Diagnostics go to stderr only."""
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            print(_canonical(_error(None, -32700, "parse error")), flush=True)
            continue
        try:
            resp = handle_message(msg)
        except Exception as exc:  # noqa: BLE001 — protocol-level guard
            resp = _error(msg.get("id"), -32603, f"internal error: {type(exc).__name__}")
            print(f"grasp-mcp: {exc}", file=sys.stderr)
        if resp is not None:
            print(_canonical(resp), flush=True)


if __name__ == "__main__":
    main()
