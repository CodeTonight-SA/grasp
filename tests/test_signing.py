# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Mutation-sensitive tests for grasp/signing.py + the asymmetric verify path.

Exercise Ed25519 and ML-DSA-65 (FIPS 204) end-to-end: sign, verify,
tamper→BROKEN, monotone DEGRADED when key material is missing, and the published
verification-key resolution. Requires the optional cryptography package; skipped
cleanly on a hermetic core install (the no-crypto path is pinned separately in
test_signing_no_crypto.py).
"""
from __future__ import annotations

import json
import secrets

import pytest

pytest.importorskip("cryptography")

from grasp import signing
from grasp.idr import build_idr
from grasp.idr_forest import build_chain_forest, verify_chain_integrity
from grasp.verdict import Verdict

EH = "sha256:" + "ab" * 32


def _seed() -> bytes:
    return secrets.token_bytes(32)


def test_ed25519_round_trip_and_tamper():
    seed, pub = signing.generate_keypair("ed25519")
    audit = signing.sign(EH, "ed25519", ed25519_seed=seed)
    assert audit["scheme"] == "ed25519"
    assert len(bytes.fromhex(audit["signature"])) == 64
    assert signing.verify(EH, audit, ed25519_pub=pub) is Verdict.VERIFIED
    # a signature from a different seed must NOT verify under this public key
    other = signing.sign(EH, "ed25519", ed25519_seed=_seed())
    assert signing.verify(EH, other, ed25519_pub=pub) is Verdict.BROKEN


def test_ml_dsa_65_round_trip_and_tamper():
    seed, pub = signing.generate_keypair("ml-dsa-65")
    audit = signing.sign(EH, "ml-dsa-65", ml_dsa_seed=seed)
    assert audit["scheme"] == "ml-dsa-65"
    assert len(bytes.fromhex(audit["signature"])) == 3309  # ML-DSA-65 wire size
    assert signing.verify(EH, audit, ml_dsa_pub=pub) is Verdict.VERIFIED
    other = signing.sign(EH, "ml-dsa-65", ml_dsa_seed=_seed())
    assert signing.verify(EH, other, ml_dsa_pub=pub) is Verdict.BROKEN


def test_dual_sign_verify_monotone():
    es, ep = signing.generate_keypair("ed25519")
    ms, mp = signing.generate_keypair("ml-dsa-65")
    audit = signing.sign(EH, "ed25519+ml-dsa-65", ed25519_seed=es, ml_dsa_seed=ms)
    assert set(audit["signature"]) == {"ed25519", "ml-dsa-65"}
    assert signing.verify(EH, audit, ed25519_pub=ep, ml_dsa_pub=mp) is Verdict.VERIFIED
    # one half uncheckable → DEGRADED, never VERIFIED
    assert signing.verify(EH, audit, ed25519_pub=ep) is Verdict.DEGRADED
    # tamper the ed25519 half → BROKEN even though the ml-dsa half is intact
    bad = dict(audit)
    bad["signature"] = dict(audit["signature"])
    bad["signature"]["ed25519"] = "00" * 64
    assert signing.verify(EH, bad, ed25519_pub=ep, ml_dsa_pub=mp) is Verdict.BROKEN


def test_verify_missing_key_is_degraded_not_broken():
    seed, _ = signing.generate_keypair("ed25519")
    audit = signing.sign(EH, "ed25519", ed25519_seed=seed)
    assert signing.verify(EH, audit, ed25519_pub=None) is Verdict.DEGRADED


def test_full_idr_path_ed25519(monkeypatch):
    seed, pub = signing.generate_keypair("ed25519")
    monkeypatch.setenv("GRASP_SIGNING_SCHEME", "ed25519")
    monkeypatch.setenv("GRASP_ED25519_SEED", seed.hex())
    monkeypatch.setenv("GRASP_ED25519_PUB", pub.hex())
    idr = build_idr(prompt="x", fingerprint="f" * 16, decision={"a": 1},
                    predecessor_idr=None, depth=0)
    assert idr.audit["scheme"] == "ed25519"
    forest = build_chain_forest([idr], genesis_anchor="ci:test")
    assert verify_chain_integrity(forest) is Verdict.VERIFIED


def test_full_idr_path_tamper_is_broken(monkeypatch):
    seed, pub = signing.generate_keypair("ed25519")
    monkeypatch.setenv("GRASP_SIGNING_SCHEME", "ed25519")
    monkeypatch.setenv("GRASP_ED25519_SEED", seed.hex())
    monkeypatch.setenv("GRASP_ED25519_PUB", pub.hex())
    idr = build_idr(prompt="x", fingerprint="f" * 16, decision={"a": 1},
                    predecessor_idr=None, depth=0)
    idr.decision = {"a": 2}  # mutate the signed body without re-signing
    forest = build_chain_forest([idr], genesis_anchor="ci:test")
    assert verify_chain_integrity(forest) is Verdict.BROKEN


def test_published_key_resolution_via_verify_keys_map(monkeypatch):
    seed, pub = signing.generate_keypair("ml-dsa-65")
    fp = signing.pubkey_fingerprint(pub)
    monkeypatch.setenv("GRASP_SIGNING_SCHEME", "ml-dsa-65")
    monkeypatch.setenv("GRASP_ML_DSA_65_SEED", seed.hex())
    monkeypatch.setenv("GRASP_VERIFY_KEYS", json.dumps({fp: pub.hex()}))
    idr = build_idr(prompt="x", fingerprint="f" * 16, decision={"a": 1},
                    predecessor_idr=None, depth=0)
    assert idr.audit["scheme"] == "ml-dsa-65"
    forest = build_chain_forest([idr], genesis_anchor="ci:test")
    assert verify_chain_integrity(forest) is Verdict.VERIFIED
