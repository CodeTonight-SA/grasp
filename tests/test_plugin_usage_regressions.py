# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Regression tests for the four GRASP-as-plugin usage bugs surfaced by a real
Gemini CLI session (2026-07-11).

Each test reproduces the EXACT call that crashed and asserts the fix. The
Goodhart anchors are explicit: the CLI must exit NON-ZERO on a tampered ledger
(an "always exit 0" CLI fails), and a raw-dict-built forest must verify
IDENTICALLY to the PrecogIDR-built one (a coercion that dropped a field would
diverge on the Merkle root).
"""
from __future__ import annotations

from dataclasses import asdict

import pytest

from grasp.cli import main as cli_main
from grasp.context_chain import verify_context_chain
from grasp.idr import build_idr, read_idr_chain
from grasp.idr_forest import (
    IdrForestError,
    add_idr,
    build_chain_forest,
    empty_forest,
    forest_merkle_root,
    is_admissible_anchor,
    verify_chain_integrity,
)
from grasp.mcp_server import tool_prove_claim, tool_record_decision, tool_verify
from grasp.verdict import Verdict


@pytest.fixture
def home(tmp_path, monkeypatch):
    """Per-test throwaway ``GRASP_HOME``. The session conftest home is shared;
    these tests each seed their own ledger, so they need isolation."""
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("GRASP_HOME", str(h))
    return h


# ---------------------------------------------------------------------------
# Bug A — grasp_verify crashed 'NoneType' object has no attribute 'startswith'
# ---------------------------------------------------------------------------


def test_bug_a_grasp_verify_survives_prove_it_seeded_ledger(home):
    """A ledger whose genesis is a prove-it artifact has ``predecessor_idr:
    null``. ``grasp_verify`` must VERIFY it, not crash on ``None.startswith``."""
    tool_prove_claim({"title": "claim", "quote": "hello", "source_text": "hello world"})
    out = tool_verify({})
    assert out["ok"] is True
    assert out["decision_chain"] == "verified"
    assert out["merkle_root"]
    # Honest: the prove-it genesis is not exogenously rooted — surfaced, not hidden.
    assert out.get("unanchored", 0) >= 1


def test_bug_a_is_admissible_anchor_rejects_non_str_cleanly():
    """Root cause: ``_is_admissible_anchor(None)`` did ``None.startswith(...)``.
    A non-str is a clean ``False`` → ``empty_forest`` raises ``IdrForestError``,
    never a raw ``AttributeError``."""
    assert is_admissible_anchor("human:x") is True
    assert is_admissible_anchor(None) is False
    assert is_admissible_anchor(42) is False
    with pytest.raises(IdrForestError):
        empty_forest((None,))  # MUST be IdrForestError, not AttributeError


# ---------------------------------------------------------------------------
# Bug B — verify_context_chain(ctx, idrs) crashed 'list' has no attribute 'exists'
# ---------------------------------------------------------------------------


def test_bug_b_verify_context_chain_wrong_type_is_clear_typeerror(home):
    """The positional mis-call ``verify_context_chain(ctx, idrs)`` bound a list
    to ``path`` and crashed opaquely deep in the reader. A wrong-type path must
    now raise a CLEAR ``TypeError`` naming the expected types."""
    with pytest.raises(TypeError) as exc:
        verify_context_chain(["ctx-entry"], ["idr-entry"])
    assert "path must be a str" in str(exc.value)
    # The read-side guard too — a list where a path was expected.
    with pytest.raises(TypeError):
        read_idr_chain(path=["not-a-path"])
    # The CORRECT call still works: an empty chain is vacuously VERIFIED.
    assert verify_context_chain() is Verdict.VERIFIED


# ---------------------------------------------------------------------------
# Bug C — build_chain_forest(list-of-dicts) crashed 'dict' has no attribute 'id'
# ---------------------------------------------------------------------------


def test_bug_c_build_chain_forest_accepts_raw_dicts(home):
    """A skeptic reads the JSONL ledger (``json.loads`` → dicts) and builds a
    forest. Raw dicts must coerce to ``PrecogIDR`` and verify IDENTICALLY to the
    typed path — same Merkle root (coercion is lossless)."""
    first = build_idr(prompt="a", fingerprint="fa", decision={"x": 1},
                      predecessor_idr="council:genesis", depth=0)
    second = build_idr(prompt="b", fingerprint="fb", decision={"y": 2},
                       predecessor_idr=first.id, depth=1)
    typed = build_chain_forest([first, second], genesis_anchor="council:genesis")
    raw = build_chain_forest([asdict(first), asdict(second)],
                             genesis_anchor="council:genesis")
    assert verify_chain_integrity(raw) is Verdict.VERIFIED
    # Goodhart: a coercion that dropped or reordered a field would diverge here.
    assert forest_merkle_root(raw) == forest_merkle_root(typed)


def test_bug_c_add_idr_rejects_unsupported_type():
    """Neither a ``PrecogIDR`` nor a mapping → a clear ``TypeError``, not the
    opaque ``'int' object has no attribute 'id'``."""
    forest = empty_forest(("council:genesis",))
    with pytest.raises(TypeError) as exc:
        add_idr(forest, 42)
    assert "PrecogIDR or mapping" in str(exc.value)


# ---------------------------------------------------------------------------
# Bug D — no shell verify entrypoint (grasp-status: command not found)
# ---------------------------------------------------------------------------


def test_bug_d_grasp_cli_verify_exit_codes(home, capsys):
    """``grasp verify`` must exit 0 on a clean ledger and NON-ZERO on a tampered
    one. Goodhart anchor: an 'always exit 0' CLI fails the tamper case."""
    tool_record_decision({"what": "step one", "why": "because"})
    assert cli_main(["verify"]) == 0
    capsys.readouterr()  # drain
    ledger = home / "idr.jsonl"
    text = ledger.read_text()
    assert "step one" in text
    ledger.write_text(text.replace("step one", "step 0ne"))  # flip a signed byte
    assert cli_main(["verify"]) == 1  # BROKEN → non-zero exit


def test_bug_d_grasp_cli_status_ok(home, capsys):
    """``grasp status`` returns 0 and reports the ledger + server."""
    tool_record_decision({"what": "x", "why": "y"})
    assert cli_main(["status"]) == 0
    out = capsys.readouterr().out
    assert "server" in out and "idr.jsonl" in out
