# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Confinement tests for the GRASP MCP server's ``source_path`` argument.

Every test here calls ``tool_prove_claim`` directly (``from grasp import
mcp_server``) rather than spawning a subprocess -- these are unit tests of the
confinement policy itself, not of the stdio/JSON-RPC transport (which
tests/test_mcp_server.py already covers end to end).

The Goodhart anchor for this file: a refusal must look EXACTLY the same
whether the requested path escapes the configured roots, does not exist, is
the wrong type, or is too large -- if any of those becomes distinguishable
from the others, the file-content oracle this confinement closes reopens.
"""
from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from grasp import mcp_server

# ---------------------------------------------------------------------------
# source_path: off by default
# ---------------------------------------------------------------------------


def test_source_path_disabled_without_grasp_source_roots(tmp_path, monkeypatch):
    monkeypatch.delenv("GRASP_SOURCE_ROOTS", raising=False)
    real = tmp_path / "real.txt"
    real.write_text("the quote is right here")
    result = mcp_server.tool_prove_claim({"quote": "x", "source_path": str(real)})
    assert result == {"ok": False, "error": mcp_server._SOURCE_PATH_DISABLED}
    assert "source_text" in result["error"]
    assert "GRASP_SOURCE_ROOTS" in result["error"]


def test_source_path_empty_env_means_disabled_too(tmp_path, monkeypatch):
    """Unset and the empty string must be indistinguishable: the same refusal."""
    monkeypatch.delenv("GRASP_SOURCE_ROOTS", raising=False)
    target = str(tmp_path / "f.txt")
    unset = mcp_server.tool_prove_claim({"quote": "x", "source_path": target})
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", "")
    empty = mcp_server.tool_prove_claim({"quote": "x", "source_path": target})
    assert unset == empty
    assert unset["error"] == mcp_server._SOURCE_PATH_DISABLED


# ---------------------------------------------------------------------------
# source_path: confined reads succeed
# ---------------------------------------------------------------------------


def test_source_path_within_configured_root_is_read(tmp_path, monkeypatch):
    monkeypatch.setenv("GRASP_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", str(tmp_path))
    src = tmp_path / "source.txt"
    src.write_text("the anchor is confirmed in block 1")
    result = mcp_server.tool_prove_claim({
        "quote": "confirmed in block 1", "source_path": str(src),
    })
    assert result["ok"] is True
    assert result["status"] == "verified"


def test_source_path_several_roots_each_checked(tmp_path, monkeypatch):
    dir_a = tmp_path / "a"
    dir_b = tmp_path / "b"
    dir_a.mkdir()
    dir_b.mkdir()
    src = dir_b / "doc.txt"
    src.write_text("the second root holds this file")
    monkeypatch.setenv("GRASP_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", os.pathsep.join([str(dir_a), str(dir_b)]))
    result = mcp_server.tool_prove_claim({
        "quote": "the second root holds this file", "source_path": str(src),
    })
    assert result["ok"] is True
    assert result["status"] == "verified"


def test_source_text_is_not_gated_by_source_roots(tmp_path, monkeypatch):
    """source_text bypasses the roots policy entirely -- it was never the
    oracle, so it stays unaffected by whether source_path is enabled."""
    monkeypatch.setenv("GRASP_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("GRASP_SOURCE_ROOTS", raising=False)
    result = mcp_server.tool_prove_claim({"quote": "hello", "source_text": "hello world"})
    assert result["ok"] is True
    assert result["status"] == "verified"


# ---------------------------------------------------------------------------
# source_path: escapes are refused
# ---------------------------------------------------------------------------


def test_source_path_traversal_outside_roots_is_refused(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    secret = tmp_path / "secret.txt"
    secret.write_text("top secret")
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", str(allowed))
    traversal = str(allowed / ".." / "secret.txt")
    result = mcp_server.tool_prove_claim({"quote": "x", "source_path": traversal})
    assert result == {"ok": False, "error": mcp_server._SOURCE_PATH_REFUSED}


def test_source_path_symlink_escape_is_refused(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    secret_dir = tmp_path / "secret"
    secret_dir.mkdir()
    secret = secret_dir / "secret.txt"
    secret.write_text("top secret")
    link = allowed / "link.txt"
    os.symlink(secret, link)
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", str(allowed))
    result = mcp_server.tool_prove_claim({"quote": "x", "source_path": str(link)})
    assert result == {"ok": False, "error": mcp_server._SOURCE_PATH_REFUSED}


def test_source_path_prefix_sibling_is_not_contained(tmp_path, monkeypatch):
    """``/root-evil`` must never be treated as inside ``/root``."""
    root = tmp_path / "root"
    root.mkdir()
    sibling = tmp_path / "root-evil"
    sibling.mkdir()
    decoy = sibling / "file.txt"
    decoy.write_text("not actually inside root")
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", str(root))
    result = mcp_server.tool_prove_claim({"quote": "x", "source_path": str(decoy)})
    assert result == {"ok": False, "error": mcp_server._SOURCE_PATH_REFUSED}


# ---------------------------------------------------------------------------
# source_path: only regular files are ever opened
# ---------------------------------------------------------------------------


def test_source_path_fifo_is_refused_without_hanging(tmp_path, monkeypatch):
    if not hasattr(os, "mkfifo"):
        pytest.skip("FIFOs are POSIX-only")
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fifo = allowed / "pipe"
    os.mkfifo(fifo)
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", str(allowed))
    outcome: dict = {}

    def _call() -> None:
        outcome.update(mcp_server.tool_prove_claim({
            "quote": "x", "source_path": str(fifo),
        }))

    t = threading.Thread(target=_call, daemon=True)
    t.start()
    t.join(timeout=5)
    assert not t.is_alive(), "tool_prove_claim blocked trying to open a FIFO"
    assert outcome == {"ok": False, "error": mcp_server._SOURCE_PATH_REFUSED}


def test_source_path_dev_zero_is_refused(monkeypatch):
    if not Path("/dev/zero").exists():
        pytest.skip("/dev/zero not present on this platform")
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", "/dev")
    result = mcp_server.tool_prove_claim({"quote": "x", "source_path": "/dev/zero"})
    assert result == {"ok": False, "error": mcp_server._SOURCE_PATH_REFUSED}


# ---------------------------------------------------------------------------
# source_path: the size cap
# ---------------------------------------------------------------------------


def test_source_path_oversize_is_refused(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    big = allowed / "big.txt"
    big.write_text("0123456789X")  # 11 bytes
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", str(allowed))
    monkeypatch.setenv("GRASP_SOURCE_MAX_BYTES", "10")
    result = mcp_server.tool_prove_claim({"quote": "x", "source_path": str(big)})
    assert result == {"ok": False, "error": mcp_server._SOURCE_PATH_REFUSED}


def test_source_path_at_the_cap_is_read(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    exact = allowed / "exact.txt"
    exact.write_text("0123456789")  # exactly 10 bytes
    monkeypatch.setenv("GRASP_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", str(allowed))
    monkeypatch.setenv("GRASP_SOURCE_MAX_BYTES", "10")
    result = mcp_server.tool_prove_claim({"quote": "0123456789", "source_path": str(exact)})
    assert result["ok"] is True
    assert result["status"] == "verified"


# ---------------------------------------------------------------------------
# source_path: a refusal reveals nothing about the file
# ---------------------------------------------------------------------------


def test_source_path_refusal_identical_whether_or_not_file_exists(tmp_path, monkeypatch):
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    big = allowed / "big.txt"
    big.write_text("this file is deliberately over the cap for this test")
    missing = allowed / "does-not-exist.txt"
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", str(allowed))
    monkeypatch.setenv("GRASP_SOURCE_MAX_BYTES", "4")
    r_exists = mcp_server.tool_prove_claim({"quote": "x", "source_path": str(big)})
    r_missing = mcp_server.tool_prove_claim({"quote": "x", "source_path": str(missing)})
    assert r_exists == r_missing == {"ok": False, "error": mcp_server._SOURCE_PATH_REFUSED}


def test_source_path_refusal_carries_no_hash_or_offsets(tmp_path, monkeypatch):
    """The no-leak property must hold for BOTH refusal shapes -- source_path
    disabled outright (GRASP_SOURCE_ROOTS unset) and roots SET but this
    particular path refused (outside every root, here). ``_read_source_path``
    answers the same ``(None, error)`` shape for both, so a leak introduced
    in only one branch must still be caught."""
    monkeypatch.delenv("GRASP_SOURCE_ROOTS", raising=False)
    unset_result = mcp_server.tool_prove_claim({
        "quote": "x", "source_path": str(tmp_path / "anything.txt"),
    })
    assert unset_result["ok"] is False

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("GRASP_SOURCE_ROOTS", str(allowed))
    refused_result = mcp_server.tool_prove_claim({
        "quote": "x", "source_path": str(tmp_path / "outside-the-root.txt"),
    })
    assert refused_result["ok"] is False
    assert refused_result["error"] == mcp_server._SOURCE_PATH_REFUSED

    leaking_keys = {"source_sha256", "start", "end", "filed_safe", "status"}
    assert not (leaking_keys & set(unset_result))
    assert not (leaking_keys & set(refused_result))
