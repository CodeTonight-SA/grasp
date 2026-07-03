# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Mutation-sensitive tests for grasp/idr.py — the signed decision record.

Load-bearing properties: the content address excludes volatile metadata
(id/ts/audit) and is stable across re-issues of the same semantic decision;
signing is real HMAC-SHA256 over the canonical body digest; the JSONL chain
round-trips, tolerates legacy records missing optional fields, and traverses
predecessor links cycle-safely."""
from __future__ import annotations

import json
from dataclasses import asdict

import pytest

from grasp.idr import (
    PrecogIDR,
    _canonical_json,
    append_idr,
    build_idr,
    compute_entry_hash,
    content_addr,
    read_idr_chain,
)


def _idr(decision=None, predecessor=None, depth=0, anatomy=None):
    return build_idr(
        prompt="",
        fingerprint="f" * 16,
        decision=decision or {"action": "test"},
        predecessor_idr=predecessor,
        depth=depth,
        decision_anatomy=anatomy,
    )


def test_content_addr_excludes_volatile_fields():
    a, b = _idr({"action": "same"}), _idr({"action": "same"})
    assert a.id != b.id                # random suffix + wall clock differ
    assert a.audit != b.audit or a.ts != b.ts
    assert content_addr(asdict(a)) == content_addr(asdict(b))
    assert content_addr(asdict(a)).startswith("sha256:")


def test_content_addr_moves_with_semantic_content():
    a, b = _idr({"action": "one"}), _idr({"action": "two"})
    assert content_addr(asdict(a)) != content_addr(asdict(b))


def test_anatomy_none_addresses_like_legacy_record():
    plain = _idr({"action": "same"})
    with_none = asdict(_idr({"action": "same"}))
    legacy = {k: v for k, v in with_none.items() if k != "decision_anatomy"}
    assert content_addr(legacy) == content_addr(asdict(plain))


def test_present_anatomy_is_addressed():
    bare = _idr({"action": "same"})
    with_anatomy = _idr({"action": "same"}, anatomy={"why": "because"})
    assert content_addr(asdict(bare)) != content_addr(asdict(with_anatomy))


def test_anatomy_rejects_non_mapping():
    with pytest.raises(TypeError):
        _idr(anatomy="not a mapping")


def test_signing_is_hmac_over_entry_hash():
    idr = _idr()
    assert idr.audit["scheme"] == "hmac-sha256"
    assert idr.audit["signature"].startswith("hmac-sha256:")
    assert len(idr.audit["key_fingerprint"]) == 8


def test_compute_entry_hash_excludes_signature_metadata():
    body = {"decision": {"a": 1}, "depth": 0}
    with_meta = {**body, "signature": "x", "key_fingerprint": "y", "scheme": "z",
                 "entry_hash": "e", "chain_hash": "c", "sequence": 9}
    assert compute_entry_hash(body) == compute_entry_hash(with_meta)
    assert compute_entry_hash(body) != compute_entry_hash({**body, "depth": 1})


def test_canonical_json_is_sorted_and_compact():
    blob = _canonical_json({"b": 1, "a": 2})
    assert blob == '{"a":2,"b":1}'


def test_append_and_read_round_trip(tmp_path):
    ledger = tmp_path / "idr.jsonl"
    first = _idr({"n": 1})
    second = _idr({"n": 2}, predecessor=first.id, depth=1)
    append_idr(first, path=ledger)
    append_idr(second, path=ledger)

    all_rows = read_idr_chain(path=ledger)
    assert [r.id for r in all_rows] == [first.id, second.id]

    chain = read_idr_chain(predecessor_id=second.id, path=ledger)
    assert [r.id for r in chain] == [first.id, second.id]  # root→leaf
    assert chain[1].predecessor_idr == first.id


def test_read_tolerates_legacy_record_missing_optional_fields(tmp_path):
    """A legacy line written before optional fields existed must still load
    (falling back to dataclass defaults), never be silently dropped."""
    ledger = tmp_path / "idr.jsonl"
    row = asdict(_idr({"n": 1}))
    del row["decision_anatomy"]
    ledger.write_text(json.dumps(row) + "\n", encoding="utf-8")
    loaded = read_idr_chain(path=ledger)
    assert len(loaded) == 1
    assert loaded[0].decision_anatomy is None


def test_read_skips_malformed_lines(tmp_path):
    ledger = tmp_path / "idr.jsonl"
    good = _idr({"n": 1})
    ledger.write_text("not-json\n" + _canonical_json(asdict(good)) + "\n", encoding="utf-8")
    loaded = read_idr_chain(path=ledger)
    assert [r.id for r in loaded] == [good.id]


def test_chain_traversal_is_cycle_safe(tmp_path):
    ledger = tmp_path / "idr.jsonl"
    a = _idr({"n": 1})
    # Manufacture a cycle: b -> a and a -> b (write raw rows).
    b = _idr({"n": 2}, predecessor=a.id, depth=1)
    rows = [asdict(a), asdict(b)]
    rows[0]["predecessor_idr"] = b.id  # a now claims b as predecessor: cycle
    ledger.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    chain = read_idr_chain(predecessor_id=b.id, path=ledger)
    assert len(chain) == 2  # terminated, not infinite


def test_dataclass_field_set_is_the_wire_contract():
    expected = {"happi", "kind", "id", "predecessor_idr", "depth", "fingerprint",
                "ts", "decision", "inputs", "audit", "decision_anatomy"}
    assert set(PrecogIDR.__dataclass_fields__) == expected
