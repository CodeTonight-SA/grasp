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

import os
import secrets
from pathlib import Path

from grasp.home import grasp_home


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
