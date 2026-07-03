# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Tri-state verification verdict shared by the chain verifiers.

``VERIFIED`` — every checked signature/link held. ``DEGRADED`` — the chain is
structurally intact but some records could not be fully verified (for example
legacy placeholder-signed records). ``BROKEN`` — at least one record fails
verification: tampering or corruption.
"""

from __future__ import annotations

from enum import Enum


class Verdict(str, Enum):
    """Tri-state verification verdict."""

    VERIFIED = "verified"
    DEGRADED = "degraded"
    BROKEN = "broken"
