# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Tests for the GRASP MCP server's ``GRASP_GENESIS_ANCHOR`` override.

A fresh decision ledger roots at a genesis anchor -- by default the
placeholder ``human:mcp-operator``, which is wrong for a shared,
bridge-fronted daemon (see docs/install/claude-for-work.md). These tests
cover the override itself (``_genesis_anchor``), its use when recording the
first decision of a ledger (``tool_record_decision``), and its use as the
fallback root when verifying a ledger whose own genesis record carries no
admissible predecessor (``_verify_decision_chain``).
"""
from __future__ import annotations

import pytest

from grasp import mcp_server
from grasp.idr import PrecogIDR


# ---------------------------------------------------------------------------
# _genesis_anchor() itself
# ---------------------------------------------------------------------------


def test_genesis_anchor_defaults_to_the_placeholder(monkeypatch):
    monkeypatch.delenv("GRASP_GENESIS_ANCHOR", raising=False)
    assert mcp_server._genesis_anchor() == "human:mcp-operator"


def test_genesis_anchor_override_accepts_every_admissible_class(monkeypatch):
    for value in ("human:alice", "ci:nightly-42", "council:verdict-7", "hypo:H042"):
        monkeypatch.setenv("GRASP_GENESIS_ANCHOR", value)
        assert mcp_server._genesis_anchor() == value


def test_genesis_anchor_override_rejects_an_inadmissible_value(monkeypatch):
    monkeypatch.setenv("GRASP_GENESIS_ANCHOR", "operator-42")
    with pytest.raises(ValueError, match="GRASP_GENESIS_ANCHOR"):
        mcp_server._genesis_anchor()


# ---------------------------------------------------------------------------
# tool_record_decision: the override actually reaches the ledger
# ---------------------------------------------------------------------------


def test_record_decision_uses_an_admissible_genesis_override(tmp_path, monkeypatch):
    monkeypatch.setenv("GRASP_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("GRASP_GENESIS_ANCHOR", "ci:nightly-42")
    result = mcp_server.tool_record_decision({"what": "x", "why": "y"})
    assert result["ok"] is True
    assert result["predecessor_idr"] == "ci:nightly-42"


def test_record_decision_rejects_an_inadmissible_genesis_override(tmp_path, monkeypatch):
    monkeypatch.setenv("GRASP_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("GRASP_GENESIS_ANCHOR", "not-a-prefix")
    result = mcp_server.tool_record_decision({"what": "x", "why": "y"})
    assert result["ok"] is False
    assert "GRASP_GENESIS_ANCHOR" in result["error"]
    assert "not-a-prefix" in result["error"]
    # No decision was appended -- the ledger must stay empty on refusal.
    assert not (tmp_path / "home" / "idr.jsonl").exists()


def test_record_decision_default_genesis_is_unaffected(tmp_path, monkeypatch):
    monkeypatch.setenv("GRASP_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("GRASP_GENESIS_ANCHOR", raising=False)
    result = mcp_server.tool_record_decision({"what": "x", "why": "y"})
    assert result["ok"] is True
    assert result["predecessor_idr"] == "human:mcp-operator"


# ---------------------------------------------------------------------------
# _verify_decision_chain: the override as a legacy-ledger fallback root
# ---------------------------------------------------------------------------


def _fake_idr(predecessor_idr: str | None) -> PrecogIDR:
    """A minimal, unsigned PrecogIDR -- enough to exercise the genesis-anchor
    fallback in _verify_decision_chain without touching real signing/I/O."""
    return PrecogIDR(
        happi="1.6", kind="agent-decision", id="legacy-1",
        predecessor_idr=predecessor_idr, depth=0, fingerprint="deadbeef",
        ts="2026-01-01T00:00:00Z", decision={"what": "x", "why": "y"},
        inputs={}, audit={"scheme": "hmac-sha256", "signature": "irrelevant",
                           "key_fingerprint": "irrelevant"},
    )


def test_verify_uses_the_default_genesis_for_a_legacy_root(monkeypatch):
    """A ledger's genesis record may carry predecessor_idr: null (e.g. a
    ledger first seeded by a prove-it artifact) -- not an admissible anchor.
    With no override, the forest must still build against the placeholder
    default rather than crash (the fake record's made-up signature still
    reads BROKEN on its own tamper check -- that is a separate concern from
    whether the genesis fallback itself succeeded)."""
    monkeypatch.delenv("GRASP_GENESIS_ANCHOR", raising=False)
    out: dict = {}
    anchored, forest = mcp_server._verify_decision_chain([_fake_idr(None)], out)
    assert forest is not None
    assert "decision_chain_error" not in out
    # "a forest" is not enough -- it must be rooted at the REAL default
    # placeholder, not just at whatever _genesis_anchor() happened to return.
    assert forest.roots == ("human:mcp-operator",)


def test_verify_reports_broken_when_override_is_inadmissible_for_a_legacy_root(monkeypatch):
    """If GRASP_GENESIS_ANCHOR is ALSO invalid when a legacy root needs the
    fallback, that must surface as a clean BROKEN verdict -- never an
    uncaught exception escaping grasp_verify."""
    monkeypatch.setenv("GRASP_GENESIS_ANCHOR", "not-a-prefix")
    out: dict = {}
    anchored, forest = mcp_server._verify_decision_chain([_fake_idr(None)], out)
    assert anchored is False
    assert forest is None
    assert out["decision_chain"] == "broken"
    assert "GRASP_GENESIS_ANCHOR" in out["decision_chain_error"]
