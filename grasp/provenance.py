# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""provenance — attach signed, replayable provenance to a prove-it artifact.

Composes three substrate primitives without reimplementing any of them:

  1. **prove-it provenance** — the spec's grounding_rate + tally (from
     :func:`grasp.prove_it.render`).
  2. **IDR leaf** (:mod:`grasp.idr`) — HMAC-SHA256-signed decision record
     capturing the prove-it decision (title, grounding_rate, citation counts).
     Tamper-evident.
  3. **memory-chain node** (:mod:`grasp.context_chain`) — signed context-delta
     cross-referencing the IDR leaf by content_addr (the 'backed by Y' link).

One provenance run therefore writes into BOTH chains — the decision chain
(what was decided) and the memory chain (what was believed when it was
decided) — which is the composition this package exists to demonstrate.

CONTRACT — ADDITIVE + FAIL-OPEN (load-bearing safety property)
--------------------------------------------------------------
This module NEVER blocks the render path. ``record_proveit_provenance`` NEVER
raises — any failure degrades to ``{"ok": False, ...}`` + a stderr line.
``path`` / ``idr_path`` / ``head_pointer`` are injectable for hermetic tests.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from typing import Any

__all__ = ["record_proveit_provenance", "IDR_KIND"]

# The IDR ``kind`` for a prove-it artifact decision leaf — a distinct kind so
# verifiers can enumerate prove-it surfaces by kind.
IDR_KIND = "prove-it-artifact"


def _fingerprint(spec: dict) -> str:
    """Stable content key: sha256 of title + sorted citation ids (first 16 hex chars)."""
    title = spec.get("title", "")
    cids = sorted(str(c.get("id", "")) for c in spec.get("citations", []))
    basis = f"{title}|{cids}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _idr_decision(spec: dict, prov: dict) -> dict:
    """The signed decision body for the prove-it IDR leaf."""
    tally = prov.get("tally", {})
    return {
        "action": "prove-it-artifact",
        "title": spec.get("title", ""),
        "grounding_rate": prov.get("grounding_rate", 0.0),
        "tally_verified": tally.get("verified", 0),
        "tally_fuzzy": tally.get("fuzzy", 0),
        "tally_not_found": tally.get("not_found", 0),
    }


def record_proveit_provenance(
    spec: dict,
    prov: dict,
    *,
    path: Path | None = None,
    idr_path: Path | None = None,
    head_pointer: Path | None = None,
) -> dict:
    """Attach signed, replayable provenance to a prove-it artifact. ADDITIVE + FAIL-OPEN.

    ``spec``  — the prove-it citations spec dict (title, sources, citations).
    ``prov``  — the provenance dict returned by render() (grounding_rate, tally, …).

    Returns ``{ok, grounding_rate, idr_addr, memory_head, reason}``. NEVER raises.
    ``path`` / ``idr_path`` / ``head_pointer`` are injectable for hermetic tests.
    """
    try:
        return _record(spec, prov, path=path, idr_path=idr_path, head_pointer=head_pointer)
    except Exception as exc:  # noqa: BLE001 — fail-open is the contract
        _warn(f"prove-it provenance recording degraded (artifact unaffected): {exc}")
        return {"ok": False, "grounding_rate": 0.0, "idr_addr": "",
                "memory_head": "", "reason": f"error: {type(exc).__name__}"}


def _record(spec: dict, prov: dict, *, path: Any, idr_path: Any, head_pointer: Any) -> dict:
    """Inner record path (wrapped by record_proveit_provenance's fail-open guard)."""
    from dataclasses import asdict
    import grasp.idr as _idr
    import grasp.context_chain as _cc

    fp = _fingerprint(spec)
    decision = _idr_decision(spec, prov)

    leaf = _idr.build_idr(
        prompt="", fingerprint=fp, decision=decision,
        predecessor_idr=None, depth=0, kind=IDR_KIND,
        inputs={"grounding_rate": prov.get("grounding_rate", 0.0)},
    )
    _idr.append_idr(leaf, path=idr_path)
    idr_addr = _idr.content_addr(asdict(leaf))

    title = spec.get("title", "")
    rate_pct = int(prov.get("grounding_rate", 0.0) * 100)
    node = _cc.checkpoint(
        next_step=None,
        summary=f"prove-it: {title} @ {rate_pct}%"[:600],
        title="prove-it provenance",
        tier="feedback",
        records_idr=idr_addr,
        path=path,
        head_pointer=head_pointer,
    )
    return {
        "ok": True,
        "grounding_rate": prov.get("grounding_rate", 0.0),
        "idr_addr": idr_addr,
        "memory_head": node.id,
        "reason": "recorded",
    }


def _warn(msg: str) -> None:
    print(f"[prove-it-provenance] {msg}", file=sys.stderr)
