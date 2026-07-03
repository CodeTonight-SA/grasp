# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Goodhart-resistant tests for grasp/provenance.py.

Proves the three contract properties:
  - the record LANDS: IDR count goes +1 AND memory HEAD advances to a new id
    AND the chain verifies (verified against the ledgers, not a flag).
  - FAIL-OPEN: when the IDR primitive raises, record_proveit_provenance returns
    ok=False and does NOT raise — and prove_it.render() is unaffected.
  - uniform shape: the degraded record carries all documented keys.

All writes go to a tmp ledger (hermetic — no real state chain touched).
"""
from __future__ import annotations

from pathlib import Path

import grasp.provenance as pvp
import grasp.context_chain as context_chain
import grasp.idr as idr_mod
import grasp.prove_it as prove_it_mod
from grasp.verdict import Verdict


# ---------------------------------------------------------------------------
# Minimal fixtures — no git/network
# ---------------------------------------------------------------------------

def _spec(title: str = "Test claim") -> dict:
    """Minimal prove-it citations spec with one verified claim."""
    source_text = "The quick brown fox jumps over the lazy dog."
    return {
        "title": title,
        "response": "The fox [[cite:c1]] is quick.",
        "sources": [{"id": "s1", "label": "test source", "text": source_text}],
        "citations": [
            {"id": "c1", "claim": "The fox is quick.",
             "source_id": "s1", "quote": "The quick brown fox"}
        ],
    }


def _prov_from_spec(spec: dict) -> dict:
    """Derive a real provenance dict via prove_it.render (pure, no I/O)."""
    _html, prov = prove_it_mod.render(spec)
    return prov


def _paths(tmp_path: Path) -> dict:
    return {
        "path": tmp_path / "context.jsonl",
        "idr_path": tmp_path / "idr.jsonl",
        "head_pointer": tmp_path / "HEAD",
    }


def _idr_count(p: Path) -> int:
    return sum(1 for ln in p.read_text().splitlines() if ln.strip()) if p.is_file() else 0


# ---------------------------------------------------------------------------
# The record LANDS — verified against the ledgers (not a flag)
# ---------------------------------------------------------------------------

def test_record_lands_idr_and_advances_memory_head(tmp_path):
    """record_proveit_provenance appends an IDR line AND advances the memory HEAD."""
    p = _paths(tmp_path)
    spec = _spec()
    prov = _prov_from_spec(spec)

    assert _idr_count(p["idr_path"]) == 0
    assert not p["head_pointer"].exists()

    rec = pvp.record_proveit_provenance(spec, prov, **p)

    assert rec["ok"] is True
    assert _idr_count(p["idr_path"]) == 1                        # IDR leaf landed
    assert p["head_pointer"].read_text().strip() == rec["memory_head"]  # HEAD advanced
    assert rec["idr_addr"].startswith("sha256:")
    assert 0.0 <= rec["grounding_rate"] <= 1.0


def test_recorded_chain_verifies(tmp_path):
    """The memory-chain node written by the recorder passes verify_context_chain."""
    p = _paths(tmp_path)
    spec = _spec()
    prov = _prov_from_spec(spec)
    pvp.record_proveit_provenance(spec, prov, **p)
    assert context_chain.verify_context_chain(path=p["path"]) == Verdict.VERIFIED


def test_records_idr_cross_reference_is_resolvable(tmp_path):
    """The memory node's decision carries records_idr matching the IDR addr."""
    p = _paths(tmp_path)
    spec = _spec()
    prov = _prov_from_spec(spec)
    rec = pvp.record_proveit_provenance(spec, prov, **p)
    chain = context_chain.read_context_chain(path=p["path"], head_pointer=p["head_pointer"])
    assert chain
    assert chain[-1].decision.get("records_idr") == rec["idr_addr"]


def test_two_distinct_artifacts_write_two_nodes(tmp_path):
    """A second, different artifact advances the chain again (HEAD moves to a new id)."""
    p = _paths(tmp_path)
    spec1 = _spec("First claim")
    spec2 = _spec("Second claim")
    first = pvp.record_proveit_provenance(spec1, _prov_from_spec(spec1), **p)
    second = pvp.record_proveit_provenance(spec2, _prov_from_spec(spec2), **p)
    assert first["memory_head"] != second["memory_head"]
    assert _idr_count(p["idr_path"]) == 2


# ---------------------------------------------------------------------------
# FAIL-OPEN — never crash the (already-written) artifact path
# ---------------------------------------------------------------------------

def test_fail_open_when_idr_unavailable(monkeypatch, tmp_path):
    """If the IDR primitive raises, recorder returns ok=False and does NOT raise."""

    def _boom(*a, **k):
        raise RuntimeError("signing key vault offline")

    monkeypatch.setattr(idr_mod, "append_idr", _boom, raising=True)
    spec = _spec()
    prov = _prov_from_spec(spec)
    rec = pvp.record_proveit_provenance(spec, prov, **_paths(tmp_path))
    assert rec["ok"] is False
    assert "error" in rec["reason"]


def test_fail_open_returns_uniform_shape(monkeypatch, tmp_path):
    """Degraded record keeps all documented keys (callers read them safely)."""
    monkeypatch.setattr(idr_mod, "append_idr",
                        lambda *a, **k: (_ for _ in ()).throw(ValueError("boom")),
                        raising=True)
    spec = _spec()
    prov = _prov_from_spec(spec)
    rec = pvp.record_proveit_provenance(spec, prov, **_paths(tmp_path))
    assert set(rec) >= {"ok", "grounding_rate", "idr_addr", "memory_head", "reason"}


def test_render_unaffected_when_recorder_raises(monkeypatch, tmp_path):
    """Even if the entire recorder raises, prove_it.render() still produces HTML."""
    monkeypatch.setattr(pvp, "_record",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("provenance down")),
                        raising=True)
    spec = _spec()
    # render() must return (html, prov) without raising regardless
    html_out, prov = prove_it_mod.render(spec)
    assert "<html" in html_out.lower()
    assert "grounding_rate" in prov
