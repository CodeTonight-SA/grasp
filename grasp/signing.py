# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Asymmetric signing backends -- Ed25519 and ML-DSA-65 (FIPS 204, "Dilithium-3").

GRASP's original scheme is HMAC-SHA256 (symmetric -- see grasp.keys). This module
adds first-class asymmetric signing so a record can be attributed to a *public*
verification key: the custody split the threat model names as roadmap item 1
("Ed25519 default + published verification key").

cryptography (>= 44) is an OPTIONAL dependency. Without it the hermetic stdlib
core still signs HMAC-SHA256, and any asymmetric scheme verifies as DEGRADED --
monotone toward safe, never silently upgraded to VERIFIED.

Signatures cover the canonical entry hash ("sha256:<hex>" from
grasp.idr.compute_entry_hash) -- the SAME message the HMAC path signs -- so a
mixed-scheme ledger verifies per record with one hash domain.

Schemes (wire identifiers):

* hmac-sha256 -- symmetric MAC over the entry hash.
* ed25519 -- Ed25519 signature (classical, 64-byte signature).
* ml-dsa-65 -- ML-DSA-65 signature (post-quantum, 3309-byte signature).
* ed25519+ml-dsa-65 -- dual/hybrid: both signatures over the same hash. The
  strongest posture: classical Ed25519 plus post-quantum ML-DSA-65, verified
  monotone (BROKEN if any present half fails; DEGRADED if a half cannot be
  checked).
* sha256-placeholder -- legacy, not tamper-evident; read-only (see idr.py).
"""

from __future__ import annotations

import hashlib

from grasp.verdict import Verdict

HMAC_SCHEME = "hmac-sha256"
ED25519_SCHEME = "ed25519"
ML_DSA_65_SCHEME = "ml-dsa-65"
DUAL_SCHEME = "ed25519+ml-dsa-65"
PLACEHOLDER_SCHEME = "sha256-placeholder"

ASYMMETRIC_SCHEMES = (ED25519_SCHEME, ML_DSA_65_SCHEME, DUAL_SCHEME)
ALL_SCHEMES = (HMAC_SCHEME, ED25519_SCHEME, ML_DSA_65_SCHEME, DUAL_SCHEME, PLACEHOLDER_SCHEME)


class SigningUnavailable(RuntimeError):
    """A scheme requiring cryptography was requested but it is not installed,
    or the required key material was not provided."""


def _crypto():
    """Lazily import the two asymmetric backends; None when absent.

    The import is guarded and lazy so the hermetic stdlib core (HMAC signing +
    offline verification) stays importable with no third-party dependency.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa  # noqa: PLC0415
        return ed25519, mldsa
    except ImportError:  # pragma: no cover - exercised via the no-crypto test path
        return None


def crypto_available() -> bool:
    """True when Ed25519 / ML-DSA-65 signing is available in this environment."""
    return _crypto() is not None


def pubkey_fingerprint(pubkey: bytes) -> str:
    """Short public-key fingerprint (sha256, first 16 hex chars).

    Identifies WHICH key signed without revealing it -- the asymmetric analogue of
    the HMAC key fingerprint, but over PUBLIC material so it is safe to publish.
    """
    return hashlib.sha256(pubkey).hexdigest()[:16]


def generate_keypair(scheme: str) -> tuple[bytes, bytes]:
    """Generate a fresh keypair for an asymmetric scheme.

    Returns (seed_bytes, public_bytes). The seed is the private material (32
    bytes for both Ed25519 and ML-DSA-65); the public bytes are raw (32 bytes
    Ed25519, 1952 bytes ML-DSA-65). Raises SigningUnavailable when cryptography
    is not installed.
    """
    c = _crypto()
    if c is None:
        raise SigningUnavailable(
            "{scheme} requires the 'cryptography' package (pip install cryptography)".format(scheme=scheme)
        )
    ed25519, mldsa = c
    if scheme == ED25519_SCHEME:
        priv = ed25519.Ed25519PrivateKey.generate()
        return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()
    if scheme == ML_DSA_65_SCHEME:
        priv = mldsa.MLDSA65PrivateKey.generate()
        return priv.private_bytes_raw(), priv.public_key().public_bytes_raw()
    raise ValueError("generate_keypair: not a single asymmetric scheme: {!r}".format(scheme))


def _ed25519_public(seed: bytes):
    c = _crypto()
    assert c is not None  # guarded by caller
    return c[0].Ed25519PrivateKey.from_private_bytes(seed).public_key()


def _ml_dsa_public(seed: bytes):
    c = _crypto()
    assert c is not None  # guarded by caller
    return c[1].MLDSA65PrivateKey.from_seed_bytes(seed).public_key()


def public_from_seed(scheme: str, seed: bytes) -> bytes:
    """Derive the raw public key for a scheme from a 32-byte private seed."""
    c = _crypto()
    if c is None:
        raise SigningUnavailable(
            "{scheme} requires the 'cryptography' package (pip install cryptography)".format(scheme=scheme)
        )
    if scheme == ED25519_SCHEME:
        return _ed25519_public(seed).public_bytes_raw()
    if scheme == ML_DSA_65_SCHEME:
        return _ml_dsa_public(seed).public_bytes_raw()
    raise ValueError("public_from_seed: not a single asymmetric scheme: {!r}".format(scheme))


def sign(
    entry_hash: str,
    scheme: str,
    *,
    hmac_key: bytes | None = None,
    ed25519_seed: bytes | None = None,
    ml_dsa_seed: bytes | None = None,
) -> dict:
    """Return the audit block for entry_hash under scheme.

    The audit block is written onto the record AFTER the entry hash is computed;
    it carries only scheme, key_fingerprint and signature -- never key material.
    """
    message = entry_hash.encode("utf-8")

    if scheme == HMAC_SCHEME:
        import hmac as _hmac
        if hmac_key is None:
            raise SigningUnavailable("hmac-sha256 signing requires a signing key")
        sig = _hmac.new(hmac_key, message, hashlib.sha256).hexdigest()
        return {
            "scheme": HMAC_SCHEME,
            "key_fingerprint": hashlib.sha256(hmac_key).hexdigest()[:8],
            "signature": HMAC_SCHEME + ":" + sig,
        }

    c = _crypto()
    if c is None:
        raise SigningUnavailable(
            "{scheme} requires the 'cryptography' package (pip install cryptography)".format(scheme=scheme)
        )
    ed25519, mldsa = c

    if scheme == ED25519_SCHEME:
        if ed25519_seed is None:
            raise SigningUnavailable(
                "ed25519 signing requires an Ed25519 seed (run grasp keygen --scheme ed25519)"
            )
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_seed)
        pub = priv.public_key().public_bytes_raw()
        return {
            "scheme": ED25519_SCHEME,
            "key_fingerprint": pubkey_fingerprint(pub),
            "signature": priv.sign(message).hex(),
        }

    if scheme == ML_DSA_65_SCHEME:
        if ml_dsa_seed is None:
            raise SigningUnavailable(
                "ml-dsa-65 signing requires an ML-DSA-65 seed (run grasp keygen --scheme ml-dsa-65)"
            )
        priv = mldsa.MLDSA65PrivateKey.from_seed_bytes(ml_dsa_seed)
        pub = priv.public_key().public_bytes_raw()
        return {
            "scheme": ML_DSA_65_SCHEME,
            "key_fingerprint": pubkey_fingerprint(pub),
            "signature": priv.sign(message).hex(),
        }

    if scheme == DUAL_SCHEME:
        if ed25519_seed is None or ml_dsa_seed is None:
            raise SigningUnavailable(
                "ed25519+ml-dsa-65 dual signing requires BOTH an Ed25519 and an "
                "ML-DSA-65 seed (run grasp keygen --scheme ed25519+ml-dsa-65)"
            )
        e_priv = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_seed)
        m_priv = mldsa.MLDSA65PrivateKey.from_seed_bytes(ml_dsa_seed)
        e_pub = e_priv.public_key().public_bytes_raw()
        m_pub = m_priv.public_key().public_bytes_raw()
        return {
            "scheme": DUAL_SCHEME,
            "key_fingerprint": {
                "ed25519": pubkey_fingerprint(e_pub),
                "ml-dsa-65": pubkey_fingerprint(m_pub),
            },
            "signature": {
                "ed25519": e_priv.sign(message).hex(),
                "ml-dsa-65": m_priv.sign(message).hex(),
            },
        }

    raise ValueError("unknown signing scheme: {!r}".format(scheme))


def _ed25519_verify(pub: bytes, message: bytes, signature: str) -> bool:
    c = _crypto()
    if c is None:
        return False
    from cryptography.exceptions import InvalidSignature
    try:
        c[0].Ed25519PublicKey.from_public_bytes(pub).verify(bytes.fromhex(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def _ml_dsa_verify(pub: bytes, message: bytes, signature: str) -> bool:
    c = _crypto()
    if c is None:
        return False
    from cryptography.exceptions import InvalidSignature
    try:
        c[1].MLDSA65PublicKey.from_public_bytes(pub).verify(bytes.fromhex(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify(
    entry_hash: str,
    audit: dict,
    *,
    hmac_key: bytes | None = None,
    ed25519_pub: bytes | None = None,
    ml_dsa_pub: bytes | None = None,
) -> Verdict:
    """Verify one audit block against entry_hash. Monotone toward safe:

    * VERIFIED -- every present signature checked under available key material.
    * BROKEN -- a checked signature does not match (tamper / corruption).
    * DEGRADED -- a scheme or key material this build cannot check. Never
      upgraded to VERIFIED, never raises on a real on-disk record.
    """
    scheme = audit.get("scheme") if isinstance(audit, dict) else None
    message = entry_hash.encode("utf-8")
    signature = audit.get("signature")

    if scheme == HMAC_SCHEME:
        if hmac_key is None:
            return Verdict.DEGRADED
        import hmac as _hmac
        expected = HMAC_SCHEME + ":" + _hmac.new(hmac_key, message, hashlib.sha256).hexdigest()
        return (
            Verdict.VERIFIED
            if _hmac.compare_digest(str(signature), expected)
            else Verdict.BROKEN
        )

    if scheme in ASYMMETRIC_SCHEMES and _crypto() is None:
        # No asymmetric backend installed: cannot check -- DEGRADED, never a
        # false BROKEN (which would accuse tampering we could not evaluate).
        return Verdict.DEGRADED

    if scheme == ED25519_SCHEME:
        if ed25519_pub is None:
            return Verdict.DEGRADED
        return Verdict.VERIFIED if _ed25519_verify(ed25519_pub, message, str(signature)) else Verdict.BROKEN

    if scheme == ML_DSA_65_SCHEME:
        if ml_dsa_pub is None:
            return Verdict.DEGRADED
        return Verdict.VERIFIED if _ml_dsa_verify(ml_dsa_pub, message, str(signature)) else Verdict.BROKEN

    if scheme == DUAL_SCHEME:
        sigs = signature if isinstance(signature, dict) else {}
        e_sig, m_sig = sigs.get("ed25519"), sigs.get("ml-dsa-65")
        e_ok = _ed25519_verify(ed25519_pub, message, str(e_sig)) if (ed25519_pub is not None and e_sig) else None
        m_ok = _ml_dsa_verify(ml_dsa_pub, message, str(m_sig)) if (ml_dsa_pub is not None and m_sig) else None
        # Any checked half that fails => tamper (BROKEN), regardless of the other.
        if e_ok is False or m_ok is False:
            return Verdict.BROKEN
        # Both halves checked and passed => fully verified.
        if e_ok is True and m_ok is True:
            return Verdict.VERIFIED
        # At least one half uncheckable, none failed => monotone DEGRADED.
        return Verdict.DEGRADED

    return Verdict.DEGRADED
