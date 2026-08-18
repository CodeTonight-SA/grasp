"""Continuity receipts — VERIFIED must mean complete-or-fail.

The defect these tests anchor (internal red-team, 2026-08-13): ``tool_verify``
recomputes the Merkle root over whatever the ledger currently contains, so
deleting the newest records — or corrupting a line, which the parser skips —
yielded a smaller, internally consistent chain that still read VERIFIED.

Mutation sensitivity: reverting the continuity term out of ``tool_verify``'s
``ok`` aggregation makes ``test_truncation_after_anchor_breaks_verify`` and
``test_corrupt_line_is_counted_and_breaks_continuity`` fail — the exact
green-over-truncation defect. Verified by hand before first commit (the
prove-it-can-fail step); do not weaken these assertions.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from grasp.continuity import (
    build_receipt,
    check_continuity,
    load_receipts,
    receipt_path,
    write_receipt,
)
from grasp.home import grasp_home
from grasp.idr import append_idr, build_idr, read_idr_chain
from grasp.idr_forest import build_chain_forest
from grasp.mcp_server import tool_anchor, tool_verify
from grasp.cli import _verify_failure_reason

GENESIS = "council:test-genesis"


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("GRASP_HOME", str(tmp_path))
    monkeypatch.setenv("GRASP_SIGNING_KEY", "continuity-test-key-0123456789abcdef")
    return tmp_path


def _ledger(home: Path) -> Path:
    return home / "idr.jsonl"


def _grow_chain(n: int, *, start_pred: str | None = None,
                start_depth: int = 0) -> None:
    """Append ``n`` signed records, each chaining to its predecessor."""
    pred = start_pred
    depth = start_depth
    if pred is None:
        chain = read_idr_chain()
        pred = chain[-1].id if chain else GENESIS
        depth = (chain[-1].depth + 1) if chain else 0
    for i in range(n):
        idr = build_idr(
            prompt=f"test decision {depth}",
            fingerprint=f"fp-{depth:04d}",
            decision={"action": "test", "step": depth},
            predecessor_idr=pred,
            depth=depth,
        )
        append_idr(idr)
        pred = idr.id
        depth += 1


def _write_receipt_for_current_chain() -> Path:
    chain = read_idr_chain()
    forest = build_chain_forest(chain, genesis_anchor=chain[0].predecessor_idr)
    receipt = build_receipt(forest, chain)
    return write_receipt(receipt, grasp_home() / "storage")


def _drop_last_line(path: Path) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:-1]) + ("\n" if len(lines) > 1 else ""),
                    encoding="utf-8")


# --------------------------------------------------------------------------
# Back-compat honesty: absence of receipts is reported, never failed.
# --------------------------------------------------------------------------

def test_no_receipts_reports_but_does_not_fail(home):
    _grow_chain(3)
    out = tool_verify({})
    assert out["ok"] is True
    assert out["continuity"]["status"] == "no-receipts"
    assert out["malformed_lines"] == 0


# --------------------------------------------------------------------------
# The defect: truncation after an anchor must now FAIL, loudly.
# --------------------------------------------------------------------------

def test_truncation_after_anchor_breaks_verify(home):
    _grow_chain(4)
    _write_receipt_for_current_chain()
    _drop_last_line(_ledger(home))

    out = tool_verify({})
    assert out["ok"] is False, (
        "a truncated ledger must not verify once a continuity receipt exists")
    cont = out["continuity"]
    assert cont["status"] == "broken"
    assert cont["missing"] == 1
    assert cont["anchored_leaf_count"] == 4
    assert cont["current_leaf_count"] == 3
    # The chains themselves are internally consistent — the OLD defect relied
    # on exactly that. Tamper and continuity stay separate axes.
    assert out["decision_chain"] == "verified"
    reason = _verify_failure_reason(out)
    assert "CONTINUITY" in reason


def test_corrupt_line_is_counted_and_breaks_continuity(home):
    _grow_chain(4)
    _write_receipt_for_current_chain()
    ledger = _ledger(home)
    lines = ledger.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1][:-10] + "corrupted!"  # no longer valid JSON
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out = tool_verify({})
    assert out["malformed_lines"] == 1, "a skipped line must never be silent"
    assert out["ok"] is False
    assert out["continuity"]["status"] == "broken"


def test_append_after_anchor_still_ok(home):
    _grow_chain(3)
    _write_receipt_for_current_chain()
    _grow_chain(2)

    out = tool_verify({})
    assert out["ok"] is True
    cont = out["continuity"]
    assert cont["status"] == "ok"
    assert cont["anchored_leaf_count"] == 3
    assert cont["current_leaf_count"] == 5


def test_corrupt_receipt_is_detected(home):
    _grow_chain(3)
    path = _write_receipt_for_current_chain()
    data = json.loads(path.read_text(encoding="utf-8"))
    data["leaves"][0] = "sha256:" + "0" * 64  # doctor one anchored leaf
    path.write_text(json.dumps(data), encoding="utf-8")

    out = tool_verify({})
    assert out["ok"] is False
    assert out["continuity"]["status"] == "receipt-corrupt"
    assert "CONTINUITY" in _verify_failure_reason(out)


# --------------------------------------------------------------------------
# check_continuity unit semantics: a rewritten record is a missing leaf.
# --------------------------------------------------------------------------

def test_check_continuity_detects_rewritten_leaf(home):
    _grow_chain(3)
    path = _write_receipt_for_current_chain()
    anchored = set(json.loads(path.read_text(encoding="utf-8"))["leaves"])
    # A key-holder rewrite-and-reseal keeps the chain HMAC-valid but moves the
    # record's content address: one anchored leaf vanishes, one new appears.
    rewritten = set(anchored)
    victim = sorted(rewritten)[0]
    rewritten.discard(victim)
    rewritten.add("sha256:" + "f" * 64)

    verdict = check_continuity(rewritten, grasp_home() / "storage")
    assert verdict["status"] == "broken"
    assert verdict["missing"] == 1
    assert victim in verdict["missing_sample"]


def test_receipt_path_shares_the_proof_digest_rule(home):
    # One root, one file family: root-<d12>.txt / .txt.ots / .receipt.json —
    # a doctored merkle_root no longer names its own proof.
    import hashlib
    root = "ab" * 32
    d12 = hashlib.sha256(root.encode("utf-8")).hexdigest()[:12]
    p = receipt_path(root, Path("/tmp/x"))
    assert p.name == f"root-{d12}.receipt.json"
    assert p.parent.name == "ots"


def test_load_receipts_surfaces_unreadable_files(home):
    _grow_chain(2)
    _write_receipt_for_current_chain()
    junk = grasp_home() / "storage" / "ots" / "root-deadbeef0000.receipt.json"
    junk.write_text("{not json", encoding="utf-8")
    receipts, unreadable = load_receipts(grasp_home() / "storage")
    assert len(receipts) == 1
    assert unreadable == ["root-deadbeef0000.receipt.json"]


# --------------------------------------------------------------------------
# tool_anchor: refuses to notarise a chain that does not verify.
# --------------------------------------------------------------------------

def test_tool_anchor_refuses_tampered_chain(home):
    _grow_chain(3)
    ledger = _ledger(home)
    lines = ledger.read_text(encoding="utf-8").splitlines()
    doctored = json.loads(lines[1])
    doctored["decision"]["action"] = "tampered"  # signed field, not re-signed
    lines[1] = json.dumps(doctored, sort_keys=True)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    out = tool_anchor({})
    assert out["ok"] is False
    assert "refusing to anchor" in out["detail"]


def test_tool_anchor_empty_ledger(home):
    out = tool_anchor({})
    assert out["ok"] is False
    assert "empty ledger" in out["detail"]


# --------------------------------------------------------------------------
# Roadmap items 3-4: expected-root pinning + refuse-on-gap mode.
# --------------------------------------------------------------------------


def _receipt_root(home):
    receipts, _ = load_receipts(home / "storage")
    assert receipts, "expected at least one receipt"
    return receipts[-1]["merkle_root"]


def test_refuse_on_gap_fails_without_receipts(home):
    _grow_chain(3)
    out = tool_verify({"refuse_on_gap": True})
    assert out["ok"] is False
    assert out["continuity"]["status"] == "refuse-on-gap"


def test_expected_root_missing_fails(home):
    _grow_chain(3)
    out = tool_verify({"expected_root": "ab" * 32})
    assert out["ok"] is False
    assert out["continuity"]["status"] == "expected-root-missing"


def test_expected_root_match_passes(home):
    _grow_chain(3)
    _write_receipt_for_current_chain()
    root = _receipt_root(home)
    out = tool_verify({"expected_root": root})
    assert out["ok"] is True
    assert out["continuity"]["status"] == "ok"


def test_expected_root_mismatch_fails(home):
    _grow_chain(3)
    _write_receipt_for_current_chain()
    out = tool_verify({"expected_root": "ab" * 32})
    assert out["ok"] is False
    assert out["continuity"]["status"] == "expected-root-mismatch"


def test_deleted_receipts_fail_against_pinned_root(home, monkeypatch):
    _grow_chain(3)
    _write_receipt_for_current_chain()
    root = _receipt_root(home)
    # delete every receipt — the exact attack the out-of-band pin exists to catch
    for p in (home / "storage" / "ots").glob("*.receipt.json"):
        p.unlink()
    monkeypatch.setenv("GRASP_EXPECTED_ROOT", root)
    out = tool_verify({})
    assert out["ok"] is False
    assert out["continuity"]["status"] == "expected-root-missing"


# --------------------------------------------------------------------------
# Roadmap item 2: the anchored leaf commits to record timestamps.
# --------------------------------------------------------------------------


def test_receipt_is_leaf_version_2(home):
    _grow_chain(2)
    p = _write_receipt_for_current_chain()
    receipt = json.loads(p.read_text(encoding="utf-8"))
    assert receipt.get("leaf_version") == 2
    chain = read_idr_chain()
    forest = build_chain_forest(chain, genesis_anchor=chain[0].predecessor_idr)
    from grasp.idr_forest import _forest_leaves_ts
    assert receipt["leaves"] == _forest_leaves_ts(forest)


def test_ts_rewrite_moves_anchored_leaf(home):
    """The key-holder backdating attack: rewrite a record's timestamp and
    re-seal with the local key. The content address is unchanged (ts is not in
    it) — only the timestamp-aware leaf catches it. Mutation-sensitive: this
    fails if leaf_version 2 is reverted to bare content-address leaves."""
    from grasp.idr import _sign_real
    _grow_chain(3)
    _write_receipt_for_current_chain()
    ledger = _ledger(home)
    lines = ledger.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[-1])
    row["ts"] = "2020-01-01T00:00:00Z"  # backdate the newest record
    row["audit"] = _sign_real({k: v for k, v in row.items() if k != "audit"})
    lines[-1] = json.dumps(row, sort_keys=True)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = tool_verify({})
    assert out["ok"] is False
    assert out["continuity"]["status"] == "broken"
