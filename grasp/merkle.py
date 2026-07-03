# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Merkle tree with inclusion proofs — the cryptographic-commitment primitive.

What it buys: an ``O(log N)`` **inclusion proof** — prove that ONE decision
record is committed by a single root hash WITHOUT revealing the others. That is
selective disclosure to a skeptic: "here is proof this exact decision is in the
committed set", handing over ~log2(N) hashes, not the whole chain.

Construction: RFC 6962 (Certificate Transparency) Merkle Tree Hash — chosen over
a hand-rolled append-incremental Merkle Mountain Range because cryptographic
code must be provably correct, and RFC 6962 is a fully-specified, widely-audited
standard. (MMR's append-incrementality is a noted follow-up for very large
chains; for typical decision-record volumes the full-set root recompute is
cheap.)

Security:
- **Domain separation** — leaves are hashed with a 0x00 prefix, internal nodes
  with 0x01. This makes a leaf hash and an internal hash live in disjoint
  spaces, so an attacker cannot present an internal node as a leaf
  (second-preimage / "leaf-as-node" forgery). Standard RFC 6962.
- **No duplication** — the tree splits at the largest power of two below n
  (RFC 6962), never duplicating the last leaf, so the classic CVE-2012-2459
  duplicate-leaf ambiguity cannot arise.

Pure stdlib (``hashlib``).
"""

from __future__ import annotations

import hashlib
from typing import List, Sequence, Tuple

__all__ = [
    "leaf_hash",
    "node_hash",
    "merkle_root",
    "inclusion_proof",
    "verify_inclusion",
    "MerkleError",
]

# Proof step: (sibling_hash_hex, side) where side is "L" if the sibling sits to the
# LEFT of the running hash, "R" if to the right. Ordered leaf -> root.
ProofStep = Tuple[str, str]


class MerkleError(ValueError):
    """Raised on malformed inputs (empty tree root, out-of-range index)."""


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256(0x00 || data). The 0x00 prefix domain-separates
    leaves from internal nodes."""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 internal node hash: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_pow2_below(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2). RFC 6962's split point k."""
    k = 1
    while k < n:
        k <<= 1          # smallest power of two >= n
    return k >> 1         # largest power of two < n


def _mth(leaves: Sequence[bytes]) -> bytes:
    """Merkle Tree Hash over raw leaf data (RFC 6962 section 2.1)."""
    n = len(leaves)
    if n == 0:
        # RFC 6962: MTH({}) = SHA-256() of the empty string.
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hash(leaves[0])
    k = _largest_pow2_below(n)
    return node_hash(_mth(leaves[:k]), _mth(leaves[k:]))


def merkle_root(leaves: Sequence[bytes]) -> str:
    """Hex SHA-256 Merkle root committing to ALL leaves, in order. Any change to any
    leaf (or the order) changes the root (tamper-evidence)."""
    return _mth(leaves).hex()


def _path(m: int, leaves: Sequence[bytes]) -> List[ProofStep]:
    """Audit path (sibling hashes, leaf -> root) for leaf index m. RFC 6962 PATH."""
    n = len(leaves)
    if n == 1:
        return []
    k = _largest_pow2_below(n)
    if m < k:
        # leaf is in the LEFT subtree; its sibling (the right subtree) is on the RIGHT
        return _path(m, leaves[:k]) + [(_mth(leaves[k:]).hex(), "R")]
    # leaf is in the RIGHT subtree; its sibling (the left subtree) is on the LEFT
    return _path(m - k, leaves[k:]) + [(_mth(leaves[:k]).hex(), "L")]


def inclusion_proof(leaves: Sequence[bytes], index: int) -> List[ProofStep]:
    """Return the inclusion (audit) proof for ``leaves[index]`` — ~ceil(log2(n))
    sibling hashes, ordered leaf -> root. Raises ``MerkleError`` on a bad index."""
    n = len(leaves)
    if n == 0:
        raise MerkleError("inclusion_proof on an empty tree")
    if not 0 <= index < n:
        raise MerkleError(f"index {index} out of range for {n} leaves")
    return _path(index, leaves)


def verify_inclusion(leaf: bytes, proof: Sequence[ProofStep], root_hex: str) -> bool:
    """True iff ``leaf`` combined with ``proof`` reproduces ``root_hex``. The verifier
    needs ONLY the leaf, the ~log2(n) proof hashes, and the root — never the other
    leaves. A tampered leaf, a wrong/reordered proof, or a wrong root all fail."""
    h = leaf_hash(leaf)
    for sib_hex, side in proof:
        try:
            sib = bytes.fromhex(sib_hex)
        except (ValueError, TypeError):
            return False
        if side == "R":
            h = node_hash(h, sib)
        elif side == "L":
            h = node_hash(sib, h)
        else:
            return False
    return h.hex() == root_hex
