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
