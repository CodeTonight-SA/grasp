# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""witness — one gesture: see it, prove it, seal it.

Thin composition over the substrate this package already ships — no new
crypto, no new spec, no new storage:

1. **SEE + PROVE** — :func:`grasp.footer.render_footer` renders the
   per-response prove-it artifact and runs the L1 deterministic floor over
   the response's ``[[cite:ID]]``-bound claims (a fabricated quote renders
   ✗; it cannot pass).
2. **SEAL** — :func:`grasp.provenance.record_proveit_provenance` appends
   the signed IDR leaf + the cross-referencing memory-chain node
   (additive + fail-open: a recording failure degrades the card, never
   blocks the render, and the card says so).
3. **ANCHOR HONESTY** — the card references an anchored Merkle root ONLY
   when the newest continuity receipt actually covers the sealed leaf;
   otherwise it prints ``sealed · not yet covered by an anchored root``.
   Coverage is arithmetic (the leaf's content address in the receipt's
   own committed leaf set), and the referent shown is the root digest a
   verifier can re-check — never a bare date.

Language lock (design council seal ``1ba40ebcbfb44b60``): a witness says
sealed / tamper-evident / complement-to-watermarks. It never says signed,
non-repudiable, compliant, or true. The claims tally speaks for BOUND
claims only and prints its denominator — assertions the author did not
bind to a source are not measured, and the card must not imply otherwise.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from grasp.card import render_card
from grasp.footer import FooterResult, provider_glyph, render_footer
from grasp.home import grasp_home
from grasp.prove_it import STATUS_FUZZY, STATUS_NOT_FOUND, STATUS_VERIFIED
from grasp.provenance import record_proveit_provenance

__all__ = ["witness", "WitnessResult", "anchor_coverage", "with_anchor"]

NOT_COVERED = "sealed · not yet covered by an anchored root"


@dataclass(frozen=True)
class WitnessResult:
    """One witnessed response: state + card + the composed parts.

    ``state``: ``sealed`` (all bound claims located, seal recorded) ·
    ``degraded`` (seal attempted, recording failed — the card says so) ·
    ``proven`` (``seal=False``; floor ran, no ledger writes) ·
    ``unproven`` (a bound claim is NOT in its source; exit non-zero) ·
    ``unwitnessed`` (nothing bound this turn — no card, no ledger).
    """

    state: str
    footer: FooterResult
    seal: dict | None = None
    anchor: str = ""
    card: str = ""
    model: str = ""

    @property
    def text(self) -> str:
        """Card + fineprint link rows, terminal-ready. Empty when unwitnessed."""
        if not self.footer.emitted:
            return ""
        body = self.card or self.footer.card
        return "\n".join((body, *self.footer.fineprint))

    @property
    def exit_code(self) -> int:
        """Non-zero exactly when a bound claim failed the floor — the
        ``grasp attest`` honesty stance applied to one response."""
        return 1 if self.state == "unproven" else 0


def anchor_coverage(idr_addr: str, *, home: Path | None = None) -> str:
    """The newest continuity receipt's verdict on ONE sealed leaf.

    A leaf sealed after the newest anchor is honestly NOT covered until
    the next ``grasp anchor`` run — the between-anchors window is a stated
    limit, not a hidden one (see :mod:`grasp.continuity`).
    """
    from grasp.continuity import load_receipts

    if not idr_addr:
        return NOT_COVERED
    receipts, _unreadable = load_receipts((home or grasp_home()) / "storage")
    for receipt in reversed(receipts):  # newest first
        leaves = receipt.get("leaves")
        if not isinstance(leaves, list):  # malformed receipt: skip, never crash
            continue
        if idr_addr in leaves:
            root12 = str(receipt.get("merkle_root", ""))[:12]
            when = str(receipt.get("created_utc", ""))
            return f"root {root12} · {when}" if when else f"root {root12}"
    return NOT_COVERED


def with_anchor(result: WitnessResult, anchor_line: str) -> WitnessResult:
    """A copy of RESULT whose card carries ANCHOR_LINE — for callers that
    anchor AFTER sealing (the CLI's ``--anchor``) and must not print a card
    whose anchor row went stale the moment the root was stamped. A receipt
    that reads ``not yet covered`` after a successful anchor is the exact
    stale-face the coverage row exists to prevent."""
    from dataclasses import replace

    if result.seal is None or not result.seal.get("ok") or not result.footer.provenance:
        return result
    card = render_card("grasp_witness", _card_fields(
        result.model, result.footer.provenance, result.seal, anchor_line,
        result.state == "unproven"))
    return replace(result, anchor=anchor_line, card=card)


def _bound_tally(tally: dict) -> str:
    """Denominator-honest claims row: the tally speaks for bound claims only."""
    total = sum(tally.values())
    return (f"{total} bound — ✓{tally.get(STATUS_VERIFIED, 0)} "
            f"≈{tally.get(STATUS_FUZZY, 0)} ✗{tally.get(STATUS_NOT_FOUND, 0)}")


def _card_fields(model: str, prov: dict, seal: dict | None,
                 anchor: str, unproven: bool) -> dict:
    fields: dict[str, Any] = {
        "ok": not unproven,
        "verified": not unproven,
        "model": f"{provider_glyph(model)} {model}",
        "claims": _bound_tally(prov["tally"]),
        "grounding": prov["grounding_rate"],
    }
    if seal is not None:
        if seal.get("ok"):
            # Slice the HEX, not the "sha256:" prefix, or the row shows
            # five useful characters instead of twelve.
            addr12 = str(seal.get("idr_addr", "")).removeprefix("sha256:")[:12]
            head = str(seal.get("memory_head", ""))
            fields["decision"] = f"idr {addr12} · memory {head}"
            fields["anchor"] = anchor or NOT_COVERED
        else:
            fields["decision"] = "unrecorded (degraded)"
    return fields


def witness(spec: dict, *, model: str, seal: bool = True,
            mode: str | None = None, home: Path | None = None,
            chain_path: Path | None = None, idr_path: Path | None = None,
            head_pointer: Path | None = None) -> WitnessResult:
    """Witness one response: render + prove, then (by default) seal.

    ``spec`` is the standard prove-it spec. ``chain_path`` / ``idr_path`` /
    ``head_pointer`` pass through to the provenance recorder for hermetic
    tests. Auto-callers that only want the floor pass ``seal=False`` —
    sealing is an explicit gesture, never a side effect of looking.

    An UNPROVEN answer still seals when asked to (deliberate): the IDR is
    an event log, and the honest record of a claim that FAILED the floor —
    ✗ tally, grounding below 1.00 — is exactly the record a skeptic wants
    kept. The card's glyph and exit code carry the failure either way.
    """
    footer = render_footer(spec, model=model, mode=mode, home=home)
    if not footer.emitted or footer.provenance is None:
        return WitnessResult(state="unwitnessed", footer=footer, model=model)

    prov = footer.provenance
    unproven = prov["tally"].get(STATUS_NOT_FOUND, 0) > 0

    seal_result: dict | None = None
    anchor_line = ""
    if seal:
        seal_result = record_proveit_provenance(
            spec, prov, path=chain_path, idr_path=idr_path,
            head_pointer=head_pointer)
        if seal_result.get("ok"):
            anchor_line = anchor_coverage(
                str(seal_result.get("idr_addr", "")), home=home)

    if unproven:
        state = "unproven"
    elif seal_result is None:
        state = "proven"
    else:
        state = "sealed" if seal_result.get("ok") else "degraded"

    card = render_card("grasp_witness",
                       _card_fields(model, prov, seal_result, anchor_line,
                                    unproven))
    return WitnessResult(state=state, footer=footer, seal=seal_result,
                         anchor=anchor_line, card=card, model=model)
