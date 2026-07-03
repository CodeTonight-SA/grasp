# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""State directory resolution for GRASP.

Every module that persists state (decision chains, memory chains, receipts)
resolves its base directory through :func:`grasp_home`, so the whole package
is relocatable: set ``GRASP_HOME`` (tests point it at a temp dir) or accept
the default ``~/.grasp``.
"""

from __future__ import annotations

import os
from pathlib import Path


def grasp_home() -> Path:
    """Return the GRASP state directory, creating it if needed.

    Resolution order: ``$GRASP_HOME`` (non-empty) -> ``~/.grasp``.
    """
    raw = os.environ.get("GRASP_HOME", "").strip()
    home = Path(raw).expanduser() if raw else Path.home() / ".grasp"
    home.mkdir(parents=True, exist_ok=True)
    return home
