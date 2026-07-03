# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Mutation-sensitive tests for grasp/merkle.py (RFC 6962).

The load-bearing properties: any leaf change (or reorder) moves the root; an
inclusion proof verifies ONLY the committed leaf against the true root — a
tampered leaf, a foreign proof, or a wrong root all fail."""
from __future__ import annotations

import hashlib

import pytest

from grasp.merkle import (
    MerkleError,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    verify_inclusion,
)

LEAVES = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]


def test_root_is_deterministic():
    assert merkle_root(LEAVES) == merkle_root(list(LEAVES))


def test_empty_tree_root_is_sha256_of_empty_string():
    # RFC 6962: MTH({}) = SHA-256 of the empty string.
    assert merkle_root([]) == hashlib.sha256(b"").hexdigest()


def test_single_leaf_root_is_domain_separated_leaf_hash():
    # 0x00 domain prefix: the root of one leaf is NOT sha256(leaf).
    assert merkle_root([b"only"]) == leaf_hash(b"only").hex()
    assert merkle_root([b"only"]) != hashlib.sha256(b"only").hexdigest()


def test_any_leaf_change_moves_the_root():
    before = merkle_root(LEAVES)
    tampered = list(LEAVES)
    tampered[2] = b"GAMMA-TAMPERED"
    assert merkle_root(tampered) != before


def test_leaf_order_is_committed():
    reordered = list(reversed(LEAVES))
    assert merkle_root(reordered) != merkle_root(LEAVES)


def test_inclusion_proof_verifies_every_leaf():
    root = merkle_root(LEAVES)
    for i, leaf in enumerate(LEAVES):
        proof = inclusion_proof(LEAVES, i)
        assert verify_inclusion(leaf, proof, root) is True
        assert len(proof) <= 3  # ~ceil(log2(5))


def test_tampered_leaf_fails_verification():
    root = merkle_root(LEAVES)
    proof = inclusion_proof(LEAVES, 1)
    assert verify_inclusion(b"beta-TAMPERED", proof, root) is False


def test_foreign_proof_fails_verification():
    root = merkle_root(LEAVES)
    proof_for_other = inclusion_proof(LEAVES, 3)
    assert verify_inclusion(LEAVES[1], proof_for_other, root) is False


def test_wrong_root_fails_verification():
    proof = inclusion_proof(LEAVES, 0)
    assert verify_inclusion(LEAVES[0], proof, "00" * 32) is False


def test_malformed_proof_side_fails_closed():
    root = merkle_root(LEAVES)
    proof = [(sib, "X") for sib, _ in inclusion_proof(LEAVES, 0)]
    assert verify_inclusion(LEAVES[0], proof, root) is False


def test_empty_tree_inclusion_raises():
    with pytest.raises(MerkleError):
        inclusion_proof([], 0)


def test_out_of_range_index_raises():
    with pytest.raises(MerkleError):
        inclusion_proof(LEAVES, len(LEAVES))
