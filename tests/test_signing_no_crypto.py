# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""The no-cryptography degradation path, pinned WITHOUT the optional package.

Simulate cryptography being absent (monkeypatch signing._crypto → None) and
assert monotone-safe behaviour: asymmetric signing raises a clear error,
asymmetric verification reads DEGRADED (never VERIFIED, never a crash), and the
default scheme falls back to HMAC-SHA256. Runs on every install, so the safe
fallback is always pinned even when the optional dependency is absent.
"""
from __future__ import annotations

import pytest

from grasp import signing
from grasp.keys import signing_scheme
from grasp.verdict import Verdict

EH = "sha256:" + "ab" * 32


@pytest.fixture
def no_crypto(monkeypatch):
    monkeypatch.setattr(signing, "_crypto", lambda: None)


def test_crypto_available_false(no_crypto):
    assert signing.crypto_available() is False


def test_sign_asymmetric_raises_clearly(no_crypto):
    with pytest.raises(signing.SigningUnavailable):
        signing.sign(EH, "ed25519", ed25519_seed=b"\x00" * 32)


def test_verify_asymmetric_degrades_not_broken(no_crypto):
    audit = {"scheme": "ed25519", "key_fingerprint": "x" * 16, "signature": "00" * 64}
    assert signing.verify(EH, audit, ed25519_pub=b"\x00" * 32) is Verdict.DEGRADED


def test_signing_scheme_falls_back_to_hmac(no_crypto, monkeypatch):
    monkeypatch.delenv("GRASP_SIGNING_SCHEME", raising=False)
    monkeypatch.delenv("GRASP_SIGNING_KEY", raising=False)
    assert signing_scheme() == "hmac-sha256"
