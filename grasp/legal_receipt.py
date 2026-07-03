# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""legal_receipt — GRASP receipt for a legal deliverable.

GRASP = Governed Reasoning And Signable Provenance. A legal deliverable (memo,
opinion, contract analysis) is SAFE TO FILE only when every quote it relies on
is provably present, verbatim, in its cited source — and the check itself is
recorded tamper-evidently. This module composes three primitives (compose,
never reimplement):

  1. :func:`grasp.prove_it.render` — the deterministic L1 citation floor
     (verified / fuzzy / not_found + per-source SHA-256 + offsets).
  2. :func:`grasp.provenance.record_proveit_provenance` — signed IDR leaf +
     memory-chain node (fail-open, additive — never blocks the receipt).
  3. A SHA-256 fingerprint over the deliverable file itself.

The receipt is ONE self-contained JSON a skeptic can check without this
package: re-hash the sources, re-read each quote at its recorded offsets,
re-verify the signed chains. "Never file a red" is mechanical here:
``filed_safe`` is False — and the CLI exits 1 — whenever any citation is
not_found, or when there are no citations at all (an unchecked deliverable is
not a checked one).

CLI:
    grasp-legal-receipt spec.json \
        [--deliverable FILE] [--matter REF] [--jurisdiction J] \
        [--out receipt.json] [--html artifact.html] [--no-record]
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

from grasp.prove_it import STATUS_FUZZY, STATUS_NOT_FOUND, STATUS_VERIFIED, render
from grasp.provenance import record_proveit_provenance

__all__ = ["RECEIPT_KIND", "RECEIPT_VERSION", "build_legal_receipt", "receipt_summary", "main"]

RECEIPT_VERSION = 1
RECEIPT_KIND = "grasp-legal-receipt"

_VERIFY_HOWTO = [
    "Re-hash each source text (SHA-256) and compare with sources[*].sha256 — a changed source cannot match.",
    "For each citation, read the source at [start, end) — the quoted words must be there verbatim (fuzzy tolerates whitespace/typography only, never words).",
    "Any citation with status not_found is a quote its cited source does not contain — the deliverable must not be filed on it.",
    "chain.idr_addr / chain.memory_head are the signed decision + belief records; verify them against the IDR forest and memory chain.",
]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _filed_safety(prov: dict) -> tuple[bool, str]:
    """Mechanical never-file-a-red gate. Returns (safe, plain-language reason)."""
    n_cites = len(prov.get("citations", []))
    if n_cites == 0:
        return False, "no citations were checked — an unchecked deliverable is not a checked one"
    reds = prov.get("tally", {}).get(STATUS_NOT_FOUND, 0)
    if reds:
        return False, f"{reds} citation(s) NOT FOUND in their cited sources — never file a red"
    return True, f"all {n_cites} citation(s) verbatim-present in their cited sources"


def build_legal_receipt(
    spec: dict,
    *,
    deliverable_path: Path | str | None = None,
    matter: str = "",
    jurisdiction: str = "",
    record: bool = True,
    path: Path | None = None,
    idr_path: Path | None = None,
    head_pointer: Path | None = None,
) -> tuple[dict, str]:
    """Build the GRASP receipt for a legal deliverable. Returns (receipt, html).

    ``spec`` is a prove-it citations spec (title, response, sources, citations).
    ``record=False`` skips the signed-chain write (previews); the receipt then
    carries chain.recorded=False with reason "recording disabled".
    ``path`` / ``idr_path`` / ``head_pointer`` inject hermetic ledgers for tests.
    """
    html, prov = render(spec)

    deliverable = None
    if deliverable_path is not None:
        p = Path(deliverable_path)
        deliverable = {"path": str(p), "sha256": _sha256_file(p), "bytes": p.stat().st_size}

    if record:
        chain = record_proveit_provenance(
            spec, prov, path=path, idr_path=idr_path, head_pointer=head_pointer)
    else:
        chain = {"ok": False, "idr_addr": "", "memory_head": "", "reason": "recording disabled"}

    filed_safe, reason = _filed_safety(prov)
    receipt = {
        "receipt_version": RECEIPT_VERSION,
        "kind": RECEIPT_KIND,
        "title": spec.get("title", ""),
        "matter": matter,
        "jurisdiction": jurisdiction,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "deliverable": deliverable,
        "grounding_rate": prov.get("grounding_rate", 0.0),
        "tally": prov.get("tally", {}),
        "sources": prov.get("sources", {}),
        "citations": prov.get("citations", []),
        "chain": {
            "recorded": bool(chain.get("ok")),
            "idr_addr": chain.get("idr_addr", ""),
            "memory_head": chain.get("memory_head", ""),
            "reason": chain.get("reason", ""),
        },
        "filed_safe": filed_safe,
        "filed_safe_reason": reason,
        "verify_howto": _VERIFY_HOWTO,
    }
    return receipt, html


def receipt_summary(receipt: dict) -> str:
    """Plain-language summary — readable by a first-time reader."""
    tally = receipt.get("tally", {})
    reds = tally.get(STATUS_NOT_FOUND, 0)
    verdict = "SAFE TO FILE" if receipt.get("filed_safe") else "DO NOT FILE"
    lines = [f"GRASP legal receipt — {receipt.get('title') or '(untitled)'}"]
    ctx_parts = []
    if receipt.get("matter"):
        ctx_parts.append(f"Matter: {receipt['matter']}")
    if receipt.get("jurisdiction"):
        ctx_parts.append(f"Jurisdiction: {receipt['jurisdiction']}")
    if ctx_parts:
        lines.append(" · ".join(ctx_parts))
    lines.append(
        f"Citations: {tally.get(STATUS_VERIFIED, 0)} verified · "
        f"{tally.get(STATUS_FUZZY, 0)} fuzzy · {reds} NOT FOUND")
    lines.append(f"Grounding: {int(round(receipt.get('grounding_rate', 0.0) * 100))}%")
    chain = receipt.get("chain", {})
    if chain.get("recorded"):
        lines.append(
            f"Signed chain: IDR {chain.get('idr_addr', '')[:16]} · "
            f"memory head {chain.get('memory_head', '')[:16]}")
    else:
        lines.append(f"Signed chain: not recorded ({chain.get('reason', 'unknown')})")
    lines.append(f"Verdict: {verdict} — {receipt.get('filed_safe_reason', '')}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build a GRASP receipt for a legal deliverable.")
    ap.add_argument("spec", help="path to a prove-it citations spec JSON")
    ap.add_argument("--deliverable", help="deliverable file to fingerprint (memo, opinion, contract analysis)")
    ap.add_argument("--matter", default="", help="matter reference")
    ap.add_argument("--jurisdiction", default="", help="governing jurisdiction")
    ap.add_argument("--out", help="receipt JSON output path (default: <spec>.receipt.json)")
    ap.add_argument("--html", help="also write the clickable prove-it artifact here")
    ap.add_argument("--no-record", action="store_true",
                    help="skip the signed IDR/memory-chain write (preview only)")
    args = ap.parse_args(argv)

    spec_path = Path(args.spec)
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    receipt, html = build_legal_receipt(
        spec,
        deliverable_path=args.deliverable,
        matter=args.matter,
        jurisdiction=args.jurisdiction,
        record=not args.no_record,
    )
    out = Path(args.out) if args.out else spec_path.with_suffix(".receipt.json")
    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    if args.html:
        Path(args.html).write_text(html, encoding="utf-8")
    print(receipt_summary(receipt))
    print(f"Receipt: {out}")
    return 0 if receipt["filed_safe"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
