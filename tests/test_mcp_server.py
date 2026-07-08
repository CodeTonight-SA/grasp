# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""End-to-end tests for the GRASP MCP server (stdio transport).

Every test drives the REAL server as a subprocess over stdio — the same path
an MCP host (Gemini CLI, Claude Code) uses — with ``GRASP_HOME`` pointed at a
temp dir so no real ledger is touched. The Goodhart anchors: a tampered
ledger byte MUST flip ``grasp_verify`` to BROKEN, and a fabricated quote MUST
come back ``not_found`` — if either can pass, the suite fails.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]


class McpClient:
    """Minimal newline-delimited JSON-RPC client over a server subprocess."""

    def __init__(self, home: Path):
        env = dict(os.environ, GRASP_HOME=str(home), PYTHONPATH=str(REPO_ROOT))
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "grasp.mcp_server"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=env, cwd=str(REPO_ROOT),
        )
        self._id = 0

    def request(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method}
        if params is not None:
            msg["params"] = params
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        assert line, f"server produced no response to {method}"
        return json.loads(line)

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        resp = self.request("tools/call", {"name": name, "arguments": arguments or {}})
        assert "result" in resp, f"tool call failed at RPC layer: {resp}"
        content = resp["result"]["content"][0]["text"]
        return json.loads(content)

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        self.proc.wait(timeout=10)


@pytest.fixture()
def client(tmp_path):
    c = McpClient(tmp_path / "grasp-home")
    resp = c.request("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    })
    assert resp["result"]["serverInfo"]["name"] == "grasp"
    yield c
    c.close()


def test_tools_list_exposes_all_five(client):
    resp = client.request("tools/list")
    names = {t["name"] for t in resp["result"]["tools"]}
    assert names == {
        "grasp_record_decision", "grasp_record_belief",
        "grasp_prove_claim", "grasp_verify", "grasp_status",
    }
    for tool in resp["result"]["tools"]:
        assert tool["description"]
        assert tool["inputSchema"]["type"] == "object"


def test_decision_chain_records_and_verifies(client, tmp_path):
    r1 = client.call_tool("grasp_record_decision", {
        "what": "edited config.yaml to raise the timeout",
        "why": "requests were timing out at 5s under load",
    })
    assert r1["ok"] and r1["depth"] == 0
    assert r1["predecessor_idr"].startswith("human:")
    assert r1["scheme"] == "hmac-sha256"

    r2 = client.call_tool("grasp_record_decision", {
        "what": "restarted the service",
        "why": "config change requires a reload",
        "inputs": {"service": "api"},
    })
    assert r2["ok"] and r2["depth"] == 1
    assert r2["predecessor_idr"] == r1["id"]

    v = client.call_tool("grasp_verify")
    assert v["decisions"] == 2
    assert v["decision_chain"] == "verified"
    assert v["merkle_root"]
    assert v["ok"] is True

    ledger = tmp_path / "grasp-home" / "idr.jsonl"
    assert ledger.exists() and len(ledger.read_text().strip().splitlines()) == 2


def test_belief_checkpoint_cross_links(client):
    d = client.call_tool("grasp_record_decision", {
        "what": "chose approach A over B", "why": "A is reversible",
    })
    b = client.call_tool("grasp_record_belief", {
        "belief": "the system is in state X; approach A is underway",
        "next_step": "run the smoke test",
        "records_idr": d["content_addr"],
    })
    assert b["ok"] and b["records_idr"] == d["content_addr"]
    v = client.call_tool("grasp_verify")
    assert v["belief_chain"] == "verified"


def test_tampered_ledger_reads_broken(client, tmp_path):
    """Goodhart anchor: one flipped byte in a signed field MUST flip the verdict."""
    client.call_tool("grasp_record_decision", {"what": "step one", "why": "because"})
    client.call_tool("grasp_record_decision", {"what": "step two", "why": "because"})
    ledger = tmp_path / "grasp-home" / "idr.jsonl"
    text = ledger.read_text()
    assert "step one" in text
    ledger.write_text(text.replace("step one", "step 0ne"))
    v = client.call_tool("grasp_verify")
    assert v["decision_chain"] == "broken"
    assert v["ok"] is False


def test_prove_claim_verbatim_and_fabricated(client, tmp_path):
    src = tmp_path / "source.txt"
    src.write_text("The anchor is confirmed in Bitcoin block 956992 today.")
    good = client.call_tool("grasp_prove_claim", {
        "title": "anchor claim",
        "quote": "confirmed in Bitcoin block 956992",
        "source_path": str(src),
    })
    assert good["ok"] and good["status"] == "verified" and good["filed_safe"] is True
    assert good["end"] > good["start"] >= 0

    fake = client.call_tool("grasp_prove_claim", {
        "title": "fabricated claim",
        "quote": "refuted in Bitcoin block 111111",
        "source_path": str(src),
    })
    assert fake["status"] == "not_found" and fake["filed_safe"] is False


def test_status_reports_ledger(client):
    client.call_tool("grasp_record_decision", {"what": "x", "why": "y"})
    s = client.call_tool("grasp_status")
    assert s["ok"] and s["decisions"] == 1 and s["decision_head"]
    assert s["ledger"].endswith("idr.jsonl")


def test_unknown_tool_and_method_are_clean_errors(client):
    resp = client.request("tools/call", {"name": "nope", "arguments": {}})
    assert resp["error"]["code"] == -32602
    resp2 = client.request("bogus/method")
    assert resp2["error"]["code"] == -32601
