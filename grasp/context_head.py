# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Context memory-chain HEAD pointer — the thin chain-position shim.

``<grasp_home>/context-HEAD.txt`` holds the id of the latest context node.
Reads/writes are atomic (write-temp + ``os.replace``) so a concurrent reader
never observes a half-written pointer. ``read_latest()`` is the single shim
every reader routes through.

This module is the READ side of the chain: it performs NO signing/crypto and
imports no model/LLM machinery (the import-isolation test in
``tests/test_context_chain.py`` makes that a compile-time fact, not a
convention).
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from grasp.home import grasp_home


def _default_head_path() -> Path:
    return grasp_home() / "context-HEAD.txt"


def _session_prefix(sid: str) -> str:
    """4-hex-char prefix derived from the session id (sha256) — distinct for
    distinct ids, filename-safe by construction (a raw session id containing
    path separators can never reach a filename)."""
    return hashlib.sha256(sid.encode("utf-8")).hexdigest()[:4]


def _session_path(base: Path) -> Path:
    """Per-session namespacing — when ``GRASP_SESSION_ID`` is set, insert a
    4-char hash prefix of it into ``base``'s filename stem so two concurrent
    sessions keep INDEPENDENT, non-interleaving chains/HEADs
    (``context-HEAD.txt`` -> ``context-HEAD-a7b2.txt``).

    When ``GRASP_SESSION_ID`` is empty/unset, ``base`` is returned UNCHANGED —
    single-session behaviour needs no namespace.
    """
    sid = os.environ.get("GRASP_SESSION_ID", "").strip()
    if not sid:
        return base
    return base.with_name(f"{base.stem}-{_session_prefix(sid)}{base.suffix}")


def head_path(path: Path | None = None) -> Path:
    return path or _session_path(_default_head_path())


def read_head(path: Path | None = None) -> str | None:
    """Return the latest context node id, or ``None`` if the chain has no head."""
    p = head_path(path)
    if not p.exists():
        return None
    head = p.read_text(encoding="utf-8").strip()
    return head or None


def write_head(node_id: str, path: Path | None = None) -> None:
    """Atomically point HEAD at ``node_id``: write a temp sibling then
    ``os.replace`` (atomic rename on POSIX) so readers see all-or-nothing."""
    p = head_path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(node_id.strip() + "\n", encoding="utf-8")
    os.replace(tmp, p)


def read_latest(chain_path: Path | None = None, head_pointer: Path | None = None) -> Any:
    """Canonical reader shim — resolve HEAD and return the latest context node
    or ``None``. Local import of ``context_chain`` keeps this module load
    import-clean (no chain/forest deps at import time)."""
    from grasp.context_chain import read_context_chain  # noqa: E402 (deferred; avoids cycle)

    head = read_head(head_pointer)
    if head is None:
        return None
    chain = read_context_chain(head=head, path=chain_path)
    return chain[-1] if chain else None
