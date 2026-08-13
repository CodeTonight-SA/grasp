# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""witness — one gesture: composition, honesty states, and exit codes.

Every test here was proven able to fail: the plain-path fineprint test
fails against the pre-fix ``artifact.as_uri()`` footer; the fabricated
quote flips state AND exit code (inherited liveness from the prove-it
floor's own falsifier); the degraded test forces a real recording failure.
"""
from __future__ import annotations

import json

import pytest

from grasp.witness import NOT_COVERED, anchor_coverage, with_anchor, witness

MODEL = "claude-fable-5"

SOURCE = "facta, non verba — deeds not words; the record is checkable."


def _spec(quote: str = "facta, non verba") -> dict:
    return {
        "title": "witness-test",
        "response": "The motto holds [[cite:c1]].",
        "sources": [{"id": "s", "label": "src", "text": SOURCE}],
        "citations": [{"id": "c1", "claim": "The motto holds",
                       "source_id": "s", "quote": quote}],
    }


@pytest.fixture
def home(tmp_path):
    return tmp_path / "grasp-home"


@pytest.fixture
def ledgers(tmp_path):
    return {
        "chain_path": tmp_path / "chain.jsonl",
        "idr_path": tmp_path / "idr.jsonl",
        "head_pointer": tmp_path / "head.json",
    }


# ------------------------------------------------------------------ sealed

def test_witness_seals_and_addresses_idempotently(home, ledgers):
    first = witness(_spec(), model=MODEL, home=home, **ledgers)
    second = witness(_spec(), model=MODEL, home=home, **ledgers)
    assert first.state == "sealed"
    assert first.seal and first.seal["ok"]
    # The artifact ADDRESS is idempotent (same spec -> same path); the
    # ledger APPEND is an event log, so both witnessings recorded.
    assert first.footer.artifact_path == second.footer.artifact_path
    assert second.seal and second.seal["ok"]
    lines = ledgers["idr_path"].read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert "WITNESS" in first.card
    assert "3 bound" not in first.card  # one citation -> "1 bound"
    assert "1 bound — ✓1 ≈0 ✗0" in first.card
    assert "decision" in first.card and "idr" in first.card


def test_unanchored_seal_says_so(home, ledgers):
    result = witness(_spec(), model=MODEL, home=home, **ledgers)
    # A fresh home has no continuity receipts: the card must say the leaf
    # is not yet covered — sealed and anchored never blur.
    assert result.anchor == NOT_COVERED
    assert NOT_COVERED in result.card


# ---------------------------------------------------------------- unproven

def test_fabricated_quote_flips_state_and_exit_code(home, ledgers):
    result = witness(_spec("words that are not in the source"),
                     model=MODEL, home=home, **ledgers)
    assert result.state == "unproven"
    assert result.exit_code == 1
    assert "✗1" in result.card
    assert "╭─ GRASP ✗" in result.card  # the glyph flips with the floor


# ---------------------------------------------------------------- degraded

def test_seal_failure_degrades_honestly(home, tmp_path):
    # An idr_path that IS a directory cannot be appended to: recording
    # fails, the fail-open contract catches it, and the card says so
    # instead of showing a clean face.
    bad = tmp_path / "idr-as-dir"
    bad.mkdir()
    result = witness(_spec(), model=MODEL, home=home,
                     chain_path=tmp_path / "chain.jsonl", idr_path=bad,
                     head_pointer=tmp_path / "head.json")
    assert result.state == "degraded"
    assert result.exit_code == 0  # degraded is honest, not unproven
    assert "unrecorded (degraded)" in result.card


# ----------------------------------------------------------------- proven

def test_no_seal_stops_at_proven(home, ledgers):
    result = witness(_spec(), model=MODEL, seal=False, home=home, **ledgers)
    assert result.state == "proven"
    assert result.seal is None
    assert not ledgers["idr_path"].exists()  # no ledger writes at rung 2
    assert "decision" not in result.card


# ------------------------------------------------------------- unwitnessed

def test_nothing_bound_is_unwitnessed(home, ledgers):
    spec = _spec()
    spec["response"] = "No citations at all this turn."
    result = witness(spec, model=MODEL, home=home, **ledgers)
    assert result.state == "unwitnessed"
    assert result.text == ""
    assert not ledgers["idr_path"].exists()


def test_with_anchor_rerenders_the_card_not_a_footnote(home, ledgers):
    """The CLI's --anchor path must print ONE card with the fresh coverage
    row — a card still reading 'not yet covered' after a successful anchor
    is a stale receipt (in-session council finding)."""
    sealed = witness(_spec(), model=MODEL, home=home, **ledgers)
    assert NOT_COVERED in sealed.card
    fresh = with_anchor(sealed, "root cafecafecafe · 2026-08-13T21:00:00Z")
    assert "root cafecafecafe" in fresh.card
    assert NOT_COVERED not in fresh.card
    assert fresh.state == sealed.state and fresh.seal == sealed.seal
    # The original is untouched (frozen dataclass, replace-not-mutate).
    assert NOT_COVERED in sealed.card


def test_with_anchor_is_a_noop_without_a_good_seal(home, ledgers):
    unsealed = witness(_spec(), model=MODEL, seal=False, home=home, **ledgers)
    assert with_anchor(unsealed, "root cafecafecafe") is unsealed


def test_unproven_but_sealed_still_takes_an_anchor(home, ledgers):
    """Council round 2 (seal dd78d89e09229907): an UNPROVEN answer that
    sealed is a recorded leaf, and --anchor must cover it — gating on
    state == 'sealed' made the operator's explicit anchor a silent no-op
    on exactly the failure record most worth covering."""
    result = witness(_spec("words that are not in the source"),
                     model=MODEL, home=home, **ledgers)
    assert result.state == "unproven"
    assert result.seal and result.seal["ok"]  # sealed despite the ✗
    fresh = with_anchor(result, "root cafecafecafe · 2026-08-13T21:30:00Z")
    assert "root cafecafecafe" in fresh.card
    assert fresh.state == "unproven"          # the anchor never launders the ✗
    assert fresh.exit_code == 1


def test_anchor_coverage_skips_malformed_receipts(tmp_path):
    home = tmp_path / "grasp-home"
    ots = home / "storage" / "ots"
    ots.mkdir(parents=True)
    addr = "sha256:" + "ab" * 32
    (ots / "root-000000000000.receipt.json").write_text(
        json.dumps({"merkle_root": "00" * 32, "leaves": "not-a-list"}),
        encoding="utf-8")
    # Malformed receipt: skipped, never a crash, honestly uncovered.
    assert anchor_coverage(addr, home=home) == NOT_COVERED


# ------------------------------------------------------------- link surface

def test_fineprint_is_plain_path_never_file_uri(home, ledgers):
    """Fails against the pre-fix footer (artifact.as_uri()) — the probed
    ground truth is that file:// is the one guaranteed-dead click surface."""
    result = witness(_spec(), model=MODEL, home=home, **ledgers)
    assert "file://" not in result.text
    assert result.footer.artifact_path in result.text


# ------------------------------------------------------------------ anchor

def test_anchor_coverage_reads_the_receipt_leaf_set(tmp_path):
    home = tmp_path / "grasp-home"
    ots = home / "storage" / "ots"
    ots.mkdir(parents=True)
    addr = "sha256:" + "ab" * 32
    receipt = {
        "kind": "grasp-continuity-receipt",
        "created_utc": "2026-08-13T00:01:21Z",
        "merkle_root": "cd" * 32,
        "leaf_count": 1,
        "leaves": [addr],
        "tip_id": "t1",
        "tip_ts": "2026-08-13T00:01:00Z",
    }
    (ots / "root-cafecafecafe.receipt.json").write_text(
        json.dumps(receipt), encoding="utf-8")
    line = anchor_coverage(addr, home=home)
    assert line.startswith("root " + ("cd" * 32)[:12])
    assert "2026-08-13T00:01:21Z" in line
    # A leaf NOT in the receipt is honestly uncovered.
    assert anchor_coverage("sha256:" + "ee" * 32, home=home) == NOT_COVERED
