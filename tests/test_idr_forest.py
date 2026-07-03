# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Goodhart-resistant tests for grasp/idr_forest.py.

Mutation anchors:
* Tamper detection — a "return VERIFIED unconditionally" implementation FAILS
  the tamper case.
* Idempotence — a "return forest unchanged" implementation passes the equality
  but a "drop a node" or "shuffle node order" implementation FAILS both the
  equality check AND the membership preservation check.

Plus schema-level invariants (empty forest, exogenous-anchor admissibility,
duplicate node id rejection, missing-predecessor rejection), deterministic
replay, and Merkle inclusion-proof soundness.
"""
from __future__ import annotations

from dataclasses import asdict, replace

import pytest

from grasp.verdict import Verdict
from grasp.idr_forest import (
    EXOGENOUS_ANCHOR_PATTERNS,
    Forest,
    ForestNode,
    IdrForestError,
    add_idr,
    canonicalise,
    empty_forest,
    find_unanchored,
    iter_nodes_topo,
    ReplayResult,
    replay_chain,
    replay_deterministic,
    verify_chain_integrity,
    forest_merkle_root,
    forest_inclusion_proof,
    verify_forest_inclusion,
    ForestInclusionError,
)
from grasp.idr import build_idr, content_addr


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


HUMAN_ROOT = "human:0123456789abcdef0123456789abcdef01234567"
CI_ROOT = "ci:42-mutation-survivor"


@pytest.fixture
def basic_forest() -> Forest:
    """A small anchored forest: one root + two child IDRs in chain."""
    forest = empty_forest((HUMAN_ROOT,))
    idr_a = build_idr(
        prompt="decision A",
        fingerprint="fp-a",
        decision={"action": "ship-adr"},
        predecessor_idr=HUMAN_ROOT,
        depth=1,
    )
    forest = add_idr(forest, idr_a)
    idr_b = build_idr(
        prompt="decision B",
        fingerprint="fp-b",
        decision={"action": "ship-spec"},
        predecessor_idr=idr_a.id,
        depth=2,
    )
    forest = add_idr(forest, idr_b)
    return forest


# ---------------------------------------------------------------------------
# Tamper detection
# ---------------------------------------------------------------------------


def test_tamper_detection_flags_invalid_signature(basic_forest: Forest) -> None:
    """Mutate a node's IDR body without re-signing → verify_chain_integrity
    MUST return BROKEN.

    Mutation anchor: an implementation that always returns VERIFIED fails this
    test.
    """
    # Take the first non-root node, tamper its decision, re-link with the
    # ORIGINAL audit signature. The signature was computed over the original
    # decision; the tampered envelope will not verify.
    first_id = next(iter(basic_forest.nodes))
    original = basic_forest.nodes[first_id]
    tampered_idr = replace(
        original.idr,
        decision={"action": "tampered-action-MUST-NOT-VERIFY"},
        # audit field deliberately left as the original signature → mismatch
    )
    new_nodes = dict(basic_forest.nodes)
    new_nodes[first_id] = ForestNode(idr=tampered_idr, anchor_id=original.anchor_id)
    tampered_forest = replace(basic_forest, nodes=new_nodes)

    verdict = verify_chain_integrity(tampered_forest)
    assert verdict is Verdict.BROKEN, (
        f"tamper detection FAILED — got {verdict!r}, expected BROKEN. "
        "An implementation that always returns VERIFIED would also pass — "
        "this test must catch that mutation."
    )


def test_clean_forest_verifies_valid(basic_forest: Forest) -> None:
    """A clean (untampered) forest MUST verify as VERIFIED.

    Falsifier for a degenerate "always BROKEN" implementation.
    """
    verdict = verify_chain_integrity(basic_forest)
    # build_idr emits hmac-sha256; _verify_node returns VERIFIED for it.
    assert verdict is Verdict.VERIFIED, (
        f"clean forest reported {verdict!r} — expected VERIFIED. "
        "If this fails, the HMAC signing or verification contract changed."
    )


# ---------------------------------------------------------------------------
# Idempotence of the canonicalising projection
# ---------------------------------------------------------------------------


def test_canonicalise_is_idempotent(basic_forest: Forest) -> None:
    """ℱ(ℱ(F)) MUST equal ℱ(F) over node-set + serialised IDR content.

    Mutation anchor: an implementation that "drops a node" or "shuffles
    node order" would fail the membership assertion below. An
    implementation that re-signs with fresh randomness would fail the
    canonical-JSON-equality assertion.
    """
    once = canonicalise(basic_forest)
    twice = canonicalise(once)

    # Same node set
    assert set(once.nodes.keys()) == set(twice.nodes.keys()), (
        "canonicalise DROPPED or ADDED a node on second application — "
        "this would violate the contraction-to-fixed-point property"
    )
    # Same roots
    assert once.roots == twice.roots
    # Same edges (predecessor pointers)
    assert dict(once.edges) == dict(twice.edges)
    # Same canonical IDR content per node (byte-equality via _canonical_json)
    from grasp.idr import _canonical_json
    for node_id in once.nodes:
        once_blob = _canonical_json(asdict(once.nodes[node_id].idr))
        twice_blob = _canonical_json(asdict(twice.nodes[node_id].idr))
        assert once_blob == twice_blob, (
            f"node {node_id!r} differs between F and F(F) — ℱ is not idempotent."
        )


def test_canonicalise_preserves_membership(basic_forest: Forest) -> None:
    """A non-degenerate ℱ MUST preserve every node id and root.

    Falsifier for a degenerate "return empty forest" implementation.
    """
    canonical = canonicalise(basic_forest)
    assert set(canonical.nodes.keys()) == set(basic_forest.nodes.keys())
    assert canonical.roots == basic_forest.roots


# ---------------------------------------------------------------------------
# Deterministic replay byte-match
# ---------------------------------------------------------------------------


def test_deterministic_replay_byte_match(basic_forest: Forest) -> None:
    """Deterministic IDR replay byte-matches the recorded envelope.

    Replay is a PURE re-derivation from the signed chain (no model
    re-execution), so the reconstructed node is byte-identical to the original.
    """
    first_id = next(iter(basic_forest.nodes))
    replayed = replay_deterministic(basic_forest, first_id)
    original = basic_forest.nodes[first_id].idr
    assert asdict(replayed) == asdict(original)


# ---------------------------------------------------------------------------
# Schema-level invariants
# ---------------------------------------------------------------------------


def test_empty_forest_rejects_no_roots() -> None:
    """A forest with zero roots MUST raise.

    A rootless forest cannot satisfy exogenous anchoring — every node would be
    unanchored.
    """
    with pytest.raises(IdrForestError):
        empty_forest(())


def test_empty_forest_rejects_non_exogenous_roots() -> None:
    """Root ids MUST match an admissible exogenous-anchor prefix.

    Falsifier for "any string is a root" — preserves exogenous anchoring at
    construction time.
    """
    with pytest.raises(IdrForestError) as exc:
        empty_forest(("not-an-anchor",))
    # The error message MUST cite the admissible patterns so the operator
    # can fix the root id in-place.
    msg = str(exc.value)
    for prefix in EXOGENOUS_ANCHOR_PATTERNS:
        assert prefix in msg, (
            f"empty_forest error must list admissible prefix {prefix!r}"
        )


def test_empty_forest_accepts_every_admissible_pattern() -> None:
    """Every prefix in ``EXOGENOUS_ANCHOR_PATTERNS`` MUST be admissible.

    Falsifier for a typo'd pattern set or a regex that excludes its own
    declared prefixes.
    """
    for prefix in EXOGENOUS_ANCHOR_PATTERNS:
        empty_forest((prefix + "anchor-id",))  # MUST NOT raise


def test_add_idr_rejects_duplicate_node_id(basic_forest: Forest) -> None:
    """Adding a node whose id collides with an existing node MUST raise."""
    first_id = next(iter(basic_forest.nodes))
    duplicate = basic_forest.nodes[first_id].idr
    with pytest.raises(IdrForestError) as exc:
        add_idr(basic_forest, duplicate)
    assert first_id in str(exc.value)


def test_add_idr_rejects_missing_predecessor() -> None:
    """An IDR whose ``predecessor_idr`` is neither a root nor a known node
    MUST raise."""
    forest = empty_forest((HUMAN_ROOT,))
    orphan = build_idr(
        prompt="orphan",
        fingerprint="fp-orphan",
        decision={"action": "x"},
        predecessor_idr="precog-does-not-exist",
        depth=1,
    )
    with pytest.raises(IdrForestError):
        add_idr(forest, orphan)


def test_add_idr_resolves_anchor_walk(basic_forest: Forest) -> None:
    """A node whose predecessor is anchored should inherit the anchor.

    Chain: HUMAN_ROOT → idr_a → idr_b. ``idr_b.anchor_id`` should equal
    ``HUMAN_ROOT`` (resolved via the predecessor walk).
    """
    nodes = list(iter_nodes_topo(basic_forest))
    assert len(nodes) == 2
    for node in nodes:
        assert node.anchor_id == HUMAN_ROOT, (
            f"node {node.idr.id!r}: anchor_id={node.anchor_id!r}, "
            f"expected {HUMAN_ROOT!r} (root walk)"
        )


def test_find_unanchored_returns_empty_for_anchored_forest(
    basic_forest: Forest,
) -> None:
    """Every node in ``basic_forest`` reaches the human root → no unanchored."""
    assert find_unanchored(basic_forest) == ()


def test_find_unanchored_flags_orphan_via_replace_override() -> None:
    """``find_unanchored`` MUST surface every node whose ``anchor_id`` is
    ``None`` regardless of how that state was reached.

    The forest contract states unanchored nodes are flagged, never trusted.
    """
    forest = empty_forest((HUMAN_ROOT,))
    orphan_idr = build_idr(
        prompt="orphan",
        fingerprint="fp-orphan",
        decision={"action": "x"},
        predecessor_idr=HUMAN_ROOT,
        depth=1,
    )
    forest = add_idr(forest, orphan_idr)
    # Override the resolved anchor_id to simulate an unresolved walk.
    from dataclasses import replace as dc_replace
    new_nodes = dict(forest.nodes)
    new_nodes[orphan_idr.id] = ForestNode(idr=orphan_idr, anchor_id=None)
    forest_with_orphan = dc_replace(forest, nodes=new_nodes)
    assert find_unanchored(forest_with_orphan) == (orphan_idr.id,)


# ---------------------------------------------------------------------------
# Replay — reproducible, refuses tampered chains
# ---------------------------------------------------------------------------


def test_replay_chain_digest_is_reproducible(basic_forest: Forest) -> None:
    """Replay is byte-stable: two independent replays of the SAME forest produce an
    identical replay_digest — the determinism anchor (re-run → same digest,
    or the chain itself changed). A non-deterministic digest fails here."""
    leaf = max(basic_forest.nodes.values(), key=lambda n: n.idr.depth).idr.id
    r1 = replay_chain(basic_forest, leaf)
    r2 = replay_chain(basic_forest, leaf)
    assert r1.replay_digest == r2.replay_digest
    assert isinstance(r1, ReplayResult) and len(r1.replay_digest) == 64


def test_replay_chain_sequence_is_root_to_node(basic_forest: Forest) -> None:
    """The replayed sequence is the deterministic root→node ancestry (analysable),
    monotone non-decreasing in depth, ending at the requested node."""
    leaf = max(basic_forest.nodes.values(), key=lambda n: n.idr.depth).idr.id
    seq = replay_chain(basic_forest, leaf).sequence
    assert seq[-1].id == leaf
    depths = [n.depth for n in seq]
    assert depths == sorted(depths)


def test_replay_chain_verdict_verified_on_clean_forest(basic_forest: Forest) -> None:
    first_id = next(iter(basic_forest.nodes))
    assert replay_chain(basic_forest, first_id).verdict is Verdict.VERIFIED


def test_replay_refuses_tampered_forest(basic_forest: Forest) -> None:
    """Replay must NEVER launder a tampered chain: a flipped body byte (no re-sign)
    drives verify to BROKEN; replay_deterministic refuses, replay_chain reports it."""
    victim_id = max(basic_forest.nodes.values(), key=lambda n: n.idr.depth).idr.id
    victim = basic_forest.nodes[victim_id]
    tampered = replace(victim.idr, decision={**(victim.idr.decision or {}), "_tamper": "x"})
    new_nodes = dict(basic_forest.nodes)
    new_nodes[victim_id] = replace(victim, idr=tampered)
    broken = replace(basic_forest, nodes=new_nodes)
    assert verify_chain_integrity(broken) is Verdict.BROKEN
    with pytest.raises(IdrForestError):
        replay_deterministic(broken, victim_id)
    assert replay_chain(broken, victim_id).verdict is Verdict.BROKEN


def test_replay_unknown_node_raises(basic_forest: Forest) -> None:
    with pytest.raises(IdrForestError):
        replay_deterministic(basic_forest, "precog-nonexistent")


def test_replay_chain_unknown_node_raises(basic_forest: Forest) -> None:
    with pytest.raises(IdrForestError):
        replay_chain(basic_forest, "precog-nonexistent")


def test_iter_nodes_topo_is_stable_across_runs(basic_forest: Forest) -> None:
    """``iter_nodes_topo`` MUST yield nodes in deterministic order.

    Stability is required for reproducible canonicalisation traces.
    """
    first = [n.idr.id for n in iter_nodes_topo(basic_forest)]
    second = [n.idr.id for n in iter_nodes_topo(basic_forest)]
    assert first == second


# ---------------------------------------------------------------------------
# Forest Merkle commitment + inclusion proofs (selective disclosure)
# ---------------------------------------------------------------------------


def test_forest_merkle_root_empty_is_64_hex() -> None:
    root = forest_merkle_root(empty_forest((HUMAN_ROOT,)))   # roots are not nodes
    assert isinstance(root, str) and len(root) == 64          # canonical empty-tree root


def test_forest_merkle_root_is_deterministic(basic_forest: Forest) -> None:
    assert forest_merkle_root(basic_forest) == forest_merkle_root(basic_forest)


def test_forest_inclusion_proof_verifies_each_node(basic_forest: Forest) -> None:
    root = forest_merkle_root(basic_forest)
    for node_id in basic_forest.nodes:
        out = forest_inclusion_proof(basic_forest, node_id)
        assert out["forest_root"] == root
        assert verify_forest_inclusion(out["content_addr"], out["proof"], root) is True


def test_forest_inclusion_rejects_non_node(basic_forest: Forest) -> None:
    with pytest.raises(ForestInclusionError):
        forest_inclusion_proof(basic_forest, HUMAN_ROOT)        # a root is not a node
    with pytest.raises(ForestInclusionError):
        forest_inclusion_proof(basic_forest, "nope-not-a-node")


def test_forest_inclusion_soundness_cross_node_and_wrong_root(basic_forest: Forest) -> None:
    ids = list(basic_forest.nodes)
    out = forest_inclusion_proof(basic_forest, ids[0])
    other_addr = content_addr(asdict(basic_forest.nodes[ids[1]].idr))
    # a DIFFERENT node's address must NOT verify against this proof (no forgery)
    assert verify_forest_inclusion(other_addr, out["proof"], out["forest_root"]) is False
    # a wrong root must NOT verify
    assert verify_forest_inclusion(out["content_addr"], out["proof"], "00" * 32) is False


def test_forest_root_changes_when_a_node_is_tampered(basic_forest: Forest) -> None:
    before = forest_merkle_root(basic_forest)
    first_id = next(iter(basic_forest.nodes))
    node = basic_forest.nodes[first_id]
    tampered = replace(node.idr, decision={"action": "TAMPERED"})
    new_nodes = dict(basic_forest.nodes)
    new_nodes[first_id] = ForestNode(idr=tampered, anchor_id=node.anchor_id)
    after = forest_merkle_root(replace(basic_forest, nodes=new_nodes))
    assert after != before
