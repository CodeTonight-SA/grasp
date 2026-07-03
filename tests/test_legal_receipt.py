# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Goodhart-resistant tests for grasp/legal_receipt.py (the GRASP legal receipt).

Contract properties proven:
  - CLEAN deliverable: filed_safe=True, receipt hashes independently recomputable
    (the test re-derives SHA-256 itself), signed chain LANDS in hermetic tmp
    ledgers (+1 IDR line, memory head set) — verified against the ledgers, not a flag.
  - FABRICATED citation (the phantom-authority class): filed_safe=False and the
    CLI exits 1 — mutate verify_quote to always-pass and these assertions fail.
  - ZERO citations: filed_safe=False (an unchecked deliverable is not checked).
  - TAMPER EVIDENCE: editing the deliverable after receipt issue changes its
    recomputed SHA-256 away from the recorded one.
  - FAIL-OPEN: a chain-write failure degrades to chain.recorded=False, never
    raises, and never flips the filed_safe verdict.

All writes go to tmp paths — no real state chain is touched.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import grasp.legal_receipt as lr
import grasp.idr as idr_mod

SOURCE = ("The claim must be brought within six years of the date on which "
          "the cause of action accrued.")


def _spec(quote: str = "within six years") -> dict:
    return {
        "title": "Limitation memo — test matter",
        "response": "Time bar applies [[cite:c1]].",
        "sources": [{"id": "s1", "label": "Limitation Act (test)", "text": SOURCE}],
        "citations": [{"id": "c1", "claim": "Six-year bar.",
                       "source_id": "s1", "quote": quote}],
    }


def _paths(tmp_path: Path) -> dict:
    return {
        "path": tmp_path / "context.jsonl",
        "idr_path": tmp_path / "idr.jsonl",
        "head_pointer": tmp_path / "HEAD",
    }


def test_clean_receipt_files_safe_and_chain_lands(tmp_path):
    receipt, html = lr.build_legal_receipt(_spec(), **_paths(tmp_path))
    assert receipt["filed_safe"] is True
    assert receipt["tally"]["not_found"] == 0
    assert receipt["kind"] == "grasp-legal-receipt"
    # chain LANDED: idr ledger has exactly one line, head is a real id
    assert receipt["chain"]["recorded"] is True
    assert len(receipt["chain"]["idr_addr"]) > 8
    idr_lines = (tmp_path / "idr.jsonl").read_text(encoding="utf-8").strip().splitlines()
    assert len(idr_lines) == 1
    assert receipt["chain"]["memory_head"]
    # source hash is independently recomputable (the skeptic's step 1)
    recorded = receipt["sources"]["s1"]["sha256"]
    assert recorded == hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()
    assert "<" in html and "cite" in html.lower()


def test_fabricated_citation_blocks_filing(tmp_path):
    fabricated = "the burden lies on the claimant to prove deliberate concealment"
    receipt, _ = lr.build_legal_receipt(_spec(quote=fabricated), **_paths(tmp_path))
    assert receipt["filed_safe"] is False
    assert receipt["tally"]["not_found"] == 1
    assert "never file a red" in receipt["filed_safe_reason"]


def test_zero_citations_not_safe(tmp_path):
    spec = _spec()
    spec["citations"] = []
    spec["response"] = "No citations here."
    receipt, _ = lr.build_legal_receipt(spec, **_paths(tmp_path))
    assert receipt["filed_safe"] is False
    assert "unchecked" in receipt["filed_safe_reason"]


def test_deliverable_tamper_evidence(tmp_path):
    doc = tmp_path / "memo.md"
    doc.write_text("original filed text", encoding="utf-8")
    receipt, _ = lr.build_legal_receipt(_spec(), deliverable_path=doc, **_paths(tmp_path))
    recorded = receipt["deliverable"]["sha256"]
    assert recorded == hashlib.sha256(b"original filed text").hexdigest()
    doc.write_text("tampered after issue", encoding="utf-8")
    assert lr._sha256_file(doc) != recorded


def test_chain_failure_fail_open(tmp_path, monkeypatch):
    def boom(*_a, **_k):
        raise RuntimeError("ledger offline")

    monkeypatch.setattr(idr_mod, "append_idr", boom)
    receipt, _ = lr.build_legal_receipt(_spec(), **_paths(tmp_path))
    assert receipt["chain"]["recorded"] is False
    # verdict is a property of the citations, never of chain availability
    assert receipt["filed_safe"] is True


def test_cli_writes_and_exit_codes(tmp_path, capsys):
    spec_p = tmp_path / "spec.json"
    spec_p.write_text(json.dumps(_spec()), encoding="utf-8")
    rc = lr.main([str(spec_p), "--no-record",
                  "--html", str(tmp_path / "artifact.html"),
                  "--out", str(tmp_path / "receipt.json")])
    assert rc == 0
    assert (tmp_path / "receipt.json").exists()
    assert (tmp_path / "artifact.html").exists()
    out = capsys.readouterr().out
    assert "SAFE TO FILE" in out

    spec_p.write_text(json.dumps(_spec(quote="phantom holding that exists nowhere")),
                      encoding="utf-8")
    rc = lr.main([str(spec_p), "--no-record"])
    assert rc == 1
    assert "DO NOT FILE" in capsys.readouterr().out
