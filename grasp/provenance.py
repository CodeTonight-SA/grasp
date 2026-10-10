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

When citations carry support attestations (a caller's machine readings, see
:class:`grasp.prove_it.SupportAttestation`), the signed decision body also
commits to them, as ``support_attestations_sha256``. A run without any seals
exactly the body it sealed before, so older records keep their addresses.
:func:`verify_proveit_provenance` is the read side: it re-checks a run against
its signed record, offline, and reports problems instead of raising.

CONTRACT — ADDITIVE + FAIL-OPEN (load-bearing safety property)
--------------------------------------------------------------
This module NEVER blocks the render path. ``record_proveit_provenance`` NEVER
raises — any failure degrades to ``{"ok": False, ...}`` + a stderr line.
``path`` / ``idr_path`` / ``head_pointer`` are injectable for hermetic tests.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

__all__ = ["record_proveit_provenance", "verify_proveit_provenance", "IDR_KIND"]

# The IDR ``kind`` for a prove-it artifact decision leaf — a distinct kind so
# verifiers can enumerate prove-it surfaces by kind.
IDR_KIND = "prove-it-artifact"


def _fingerprint(spec: dict) -> str:
    """Stable content key: sha256 of title + sorted citation ids (first 16 hex chars)."""
    title = spec.get("title", "")
    cids = sorted(str(c.get("id", "")) for c in spec.get("citations", []))
    basis = f"{title}|{cids}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]


def _attestations_digest(citations: list) -> str:
    """SHA-256 over every citation's support attestation, in citation order, or
    "" when there are none. Each reading is hashed beside its citation id, so
    editing, adding, removing or moving any reading changes the digest."""
    pairs = [[c.get("id"), c["support_attestation"]]
             for c in citations if "support_attestation" in c]
    if not pairs:
        return ""
    canonical = json.dumps(pairs, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _idr_decision(spec: dict, prov: dict) -> dict:
    """The signed decision body for the prove-it IDR leaf. Sealing and verifying
    both build it here, so the two can never disagree about what is signed."""
    tally = prov.get("tally", {})
    decision = {
        "action": "prove-it-artifact",
        "title": spec.get("title", ""),
        "grounding_rate": prov.get("grounding_rate", 0.0),
        "tally_verified": tally.get("verified", 0),
        "tally_fuzzy": tally.get("fuzzy", 0),
        "tally_not_found": tally.get("not_found", 0),
    }
    digest = _attestations_digest(prov.get("citations", []))
    if digest:  # only when present: a run without readings seals what it always did
        decision["support_attestations_sha256"] = digest
    return decision


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


# ---------------------------------------------------------------------------
# Read side: re-check a run against the signed record it was sealed into
# ---------------------------------------------------------------------------

def verify_proveit_provenance(spec: dict, prov: dict, idr_addr: str, *,
                              idr_path: Path | None = None) -> list[str]:
    """Re-check a prove-it run against the signed decision record it was sealed into.

    Checks that every support attestation is well formed, that the local
    decision ledger holds a record at ``idr_addr``, that the record commits to
    exactly this run (the title, grounding rate, tally and support attestations
    that :func:`record_proveit_provenance` seals), and that its signature holds.
    Returns plain-language problems; an empty list means it verified. It reads
    the ledger and the signing key and nothing else: no network and no model.
    """
    problems = _attestation_problems(prov.get("citations", []))
    leaves = _sealed_leaves(idr_addr, idr_path)
    if not leaves:
        return problems + [f"no signed decision record at {idr_addr} in the local decision ledger"]
    differ = _differing_keys(_idr_decision(spec, prov), leaves[0].decision)
    if differ:
        problems.append("this record does not match its signed decision record; these "
                        "differ: " + ", ".join(differ))
    return problems + _signature_problems(leaves)


def _attestation_problems(citations: list) -> list[str]:
    """A problem for each support attestation that is not well formed."""
    from grasp.prove_it import SupportAttestation
    problems = []
    for c in citations:
        if "support_attestation" not in c:
            continue
        try:
            SupportAttestation.from_dict(c["support_attestation"])
        except ValueError as exc:
            problems.append(f"citation {c.get('id')}: {exc}")
    return problems


def _sealed_leaves(idr_addr: str, idr_path: Path | None) -> list:
    """Every ledger record at ``idr_addr``. Two records can share one address,
    differing only in their id, time and signature."""
    from dataclasses import asdict
    import grasp.idr as _idr
    return [leaf for leaf in _idr.read_idr_chain(path=idr_path)
            if _idr.content_addr(asdict(leaf)) == idr_addr]


def _differing_keys(expected: dict, sealed: dict) -> list[str]:
    return sorted(k for k in set(expected) | set(sealed) if expected.get(k) != sealed.get(k))


def _signature_problems(leaves: list) -> list[str]:
    """One record whose signature holds is enough. A signature that cannot be
    checked is never treated as one that holds."""
    from grasp.idr_forest import _verify_node
    from grasp.verdict import Verdict
    verdicts = {_verify_node(leaf) for leaf in leaves}
    if Verdict.VERIFIED in verdicts:
        return []
    if Verdict.BROKEN in verdicts:
        return ["the signed decision record's signature does not match its body: it was "
                "changed after sealing, or this machine holds a different signing key"]
    return ["the signed decision record's signature could not be checked on this machine "
            "(no verifying key for its scheme), so it is unverified"]


def _warn(msg: str) -> None:
    print(f"[prove-it-provenance] {msg}", file=sys.stderr)
