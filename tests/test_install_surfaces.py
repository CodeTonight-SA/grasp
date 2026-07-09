# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Schema sanity for the universal-install surfaces.

Every host manifest shipped in this repo must parse and point at the same
``grasp-mcp`` entrypoint that ``pyproject.toml`` actually installs. A
manifest naming a command the package does not provide would be a stub
install surface — it looks wired and is not — so the manifests, the
entrypoint, and the install docs are pinned to each other here.
"""
from __future__ import annotations

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

INSTALL_HOSTS = (
    "claude-code", "claude-desktop", "claude-for-work",
    "chatgpt", "codex", "gemini-cli", "antigravity",
)


def _load(rel: str) -> dict:
    path = REPO_ROOT / rel
    assert path.is_file(), f"missing manifest: {rel}"
    return json.loads(path.read_text())


def test_claude_plugin_manifest_parses_and_launches_grasp_mcp():
    manifest = _load(".claude-plugin/plugin.json")
    assert manifest["name"] == "grasp"
    assert manifest["version"] == "0.2.0"
    assert manifest["description"]
    assert manifest["author"]["name"] == "CodeTonight SA"
    assert manifest["mcpServers"]["grasp"]["command"] == "grasp-mcp"


def test_root_mcp_json_matches_plugin_server():
    config = _load(".mcp.json")
    assert config["mcpServers"]["grasp"]["command"] == "grasp-mcp"


def test_marketplace_catalog_lists_this_repo_as_the_plugin():
    catalog = _load(".claude-plugin/marketplace.json")
    assert catalog["name"] == "grasp"
    assert catalog["owner"]["name"] == "CodeTonight SA"
    entries = {p["name"]: p for p in catalog["plugins"]}
    assert entries["grasp"]["source"] == "./"
    assert entries["grasp"]["description"]


def test_gemini_extension_agrees_with_claude_plugin():
    gemini = _load("gemini-extension.json")
    plugin = _load(".claude-plugin/plugin.json")
    assert gemini["name"] == plugin["name"] == "grasp"
    assert gemini["version"] == plugin["version"]
    assert (gemini["mcpServers"]["grasp"]["command"]
            == plugin["mcpServers"]["grasp"]["command"] == "grasp-mcp")


def test_grasp_mcp_entrypoint_is_actually_installed():
    pyproject = (REPO_ROOT / "pyproject.toml").read_text()
    assert 'grasp-mcp = "grasp.mcp_server:main"' in pyproject


def test_install_matrix_docs_exist_and_are_linked_from_readme():
    readme = (REPO_ROOT / "README.md").read_text()
    for host in INSTALL_HOSTS:
        rel = f"docs/install/{host}.md"
        doc = REPO_ROOT / rel
        assert doc.is_file(), f"missing install doc: {rel}"
        assert "grasp" in doc.read_text().lower()
        assert rel in readme, f"README does not link {rel}"


def test_plugin_skill_carries_the_behaviour_contract():
    skill = REPO_ROOT / "skills" / "grasp-provenance" / "SKILL.md"
    assert skill.is_file()
    text = skill.read_text()
    assert text.startswith("---")
    assert "name: grasp-provenance" in text
    for tool in ("grasp_record_decision", "grasp_record_belief",
                 "grasp_prove_claim", "grasp_verify"):
        assert tool in text, f"behaviour contract missing {tool}"
