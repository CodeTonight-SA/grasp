# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Signing-key resolution for GRASP.

The default signing scheme is HMAC-SHA256 over a locally held key. The key
never ships with the package and never enters a record; only signatures do.

Resolution order:

1. ``$GRASP_SIGNING_KEY`` — UTF-8 secret in the environment (tests use this).
2. ``<grasp_home>/keys/signing.key`` — persisted key file (created on first
   use with 0600 permissions and a fresh 32-byte random secret).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path

from grasp.home import grasp_home


def signed_record(body: dict, home: Path | None = None) -> dict:
    """Sign a record body with the deployment key: HMAC-SHA256 over the
    canonical JSON, plus a short key fingerprint. The shared shape for
    license acceptances, visibility ACLs, and honesty-ledger events."""
    key = signing_key(home)
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return {**body,
            "fingerprint": hashlib.sha256(key).hexdigest()[:16],
            "sig": hmac.new(key, payload.encode("utf-8"),
                            hashlib.sha256).hexdigest()}


def verify_record(record: dict, home: Path | None = None) -> bool:
    """True iff the record's signature matches its body under this
    deployment's key — the read-side half of :func:`signed_record`."""
    body = {k: v for k, v in record.items() if k not in ("fingerprint", "sig")}
    expected = signed_record(body, home)
    return hmac.compare_digest(record.get("sig", ""), expected["sig"])


def signing_key(home: Path | None = None) -> bytes:
    """Return the signing key as bytes, generating and persisting on first use."""
    env = os.environ.get("GRASP_SIGNING_KEY", "")
    if env:
        return env.encode("utf-8")
    base = home if home is not None else grasp_home()
    key_path = base / "keys" / "signing.key"
    if key_path.exists():
        return key_path.read_bytes()
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_hex(32).encode("ascii")
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, key)

    finally:
        os.close(fd)
    return key


# ---------------------------------------------------------------------------
# Asymmetric signing (Ed25519 / ML-DSA-65) — key generation, seeds, and the
# published-verification-key resolution that closes the symmetric custody gap.
# ---------------------------------------------------------------------------

_SINGLE_ASYMMETRIC = {
    "ed25519": ("GRASP_ED25519_SEED", "GRASP_ED25519_PUB"),
    "ml-dsa-65": ("GRASP_ML_DSA_65_SEED", "GRASP_ML_DSA_65_PUB"),
}


def signing_scheme() -> str:
    """Resolve the active signing scheme.

    Precedence (least-surprise):
    1. GRASP_SIGNING_SCHEME env — explicit selection.
    2. GRASP_SIGNING_KEY set → hmac-sha256 (preserve symmetric intent).
    3. ed25519 when cryptography is installed, else hmac-sha256
       (the hermetic stdlib core keeps working with zero dependencies).
    """
    env = os.environ.get("GRASP_SIGNING_SCHEME", "").strip()
    if env:
        return env
    if os.environ.get("GRASP_SIGNING_KEY"):
        return "hmac-sha256"
    from grasp import signing as _signing
    return "ed25519" if _signing.crypto_available() else "hmac-sha256"


def _seed_env(scheme: str) -> bytes | None:
    raw = os.environ.get(_SINGLE_ASYMMETRIC[scheme][0], "")
    if not raw:
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return None


def _pub_env(scheme: str) -> bytes | None:
    raw = os.environ.get(_SINGLE_ASYMMETRIC[scheme][1], "")
    if not raw:
        return None
    try:
        return bytes.fromhex(raw)
    except ValueError:
        return None


def _verify_keys_map() -> dict[str, str]:
    raw = os.environ.get("GRASP_VERIFY_KEYS", "")
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return dict(parsed) if isinstance(parsed, dict) else {}
    except (ValueError, TypeError):
        return {}


def persist_asymmetric_keypair(scheme: str, home: Path | None = None) -> tuple[bytes, bytes]:
    """Generate and persist an asymmetric keypair; return (seed, pubkey).

    The private seed is written with 0600 permissions (exclusive create) and
    never enters a record; the public key is written readably so it can be
    published for verification.
    """
    from grasp import signing as _signing
    seed, pub = _signing.generate_keypair(scheme)
    base = home if home is not None else grasp_home()
    keydir = base / "keys"
    keydir.mkdir(parents=True, exist_ok=True)
    priv_path = keydir / (scheme + ".key")
    if not priv_path.exists():
        fd = os.open(priv_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, seed)
        finally:
            os.close(fd)
    pub_path = keydir / (scheme + ".pub")
    if not pub_path.exists():
        pub_path.write_bytes(pub)
    return seed, pub


def _load_or_create_seed(scheme: str, home: Path | None) -> bytes:
    env = _seed_env(scheme)
    if env is not None:
        return env
    base = home if home is not None else grasp_home()
    priv_path = base / "keys" / (scheme + ".key")
    if priv_path.exists():
        return priv_path.read_bytes()
    seed, _ = persist_asymmetric_keypair(scheme, home)
    return seed


def load_signing_seeds(scheme: str, home: Path | None = None) -> tuple[bytes | None, bytes | None]:
    """Return (ed25519_seed, ml_dsa_seed) for the scheme, generating and
    persisting keys on first use. HMAC returns (None, None)."""
    if scheme == "hmac-sha256":
        return None, None
    if scheme == "ed25519":
        return _load_or_create_seed("ed25519", home), None
    if scheme == "ml-dsa-65":
        return None, _load_or_create_seed("ml-dsa-65", home)
    if scheme == "ed25519+ml-dsa-65":
        return _load_or_create_seed("ed25519", home), _load_or_create_seed("ml-dsa-65", home)
    raise ValueError("unknown signing scheme: {!r}".format(scheme))


def resolve_public_key(scheme: str, fingerprint: str | None, home: Path | None = None) -> bytes | None:
    """Resolve the PUBLIC key matching fingerprint for scheme.

    Trusted sources, in order: a direct GRASP_*_PUB env key, the
    GRASP_VERIFY_KEYS JSON map (fingerprint → hex pubkey — the published-key
    path), then the locally persisted <scheme>.pub. Returns None when no
    matching key is found, which the verifier maps to DEGRADED (never VERIFIED).
    """
    if fingerprint is None:
        return None
    from grasp import signing as _signing
    direct = _pub_env(scheme)
    if direct is not None and _signing.pubkey_fingerprint(direct) == fingerprint:
        return direct
    for fp, hexpub in _verify_keys_map().items():
        if fp == fingerprint:
            try:
                return bytes.fromhex(hexpub)
            except ValueError:
                continue
    base = home if home is not None else grasp_home()
    pub_path = base / "keys" / (scheme + ".pub")
    if pub_path.exists():
        pub = pub_path.read_bytes()
        if _signing.pubkey_fingerprint(pub) == fingerprint:
            return pub
    return None

