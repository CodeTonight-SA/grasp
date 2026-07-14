"""Provenance-card contract: portable, deterministic, honest.

Falsifiers each test enforces: a card with ANSI escapes breaks TUI
portability; a line wider than WIDTH wraps in narrow panes; a card that
renders keys absent from the result invents data; raw-JSON text in the
MCP response reintroduces the wall-of-noise UX these cards replace.
"""
from __future__ import annotations

from grasp.card import WIDTH, render_card
from grasp.mcp_server import handle_message

VERIFIED_RESULT = {
    "ok": True,
    "verified": True,
    "grounding_rate": 1.0,
    "quote": "wired agy -> GRIP infrastructure",
    "source_path": "settings.json",
    "sha256": "8b3abe4de82d5e709cca2e95ed9374a1061eeb6e96c3dc18158b903b",
    "id": "idr-0001",
}


def test_verified_card_shape_and_portability():
    card = render_card("grasp_prove_claim", VERIFIED_RESULT)
    lines = card.splitlines()
    assert lines[0].startswith("╭─ GRASP ✓ prove claim")
    assert lines[-1].startswith("╰")
    assert "██████████ 1.00" in card
    assert "sha256" not in lines[0]
    assert all(len(line) <= WIDTH for line in lines)
    assert "\x1b" not in card  # no ANSI — portability contract


def test_hashes_are_shortened_not_dumped():
    card = render_card("grasp_prove_claim", VERIFIED_RESULT)
    assert "8b3abe4de82d…" in card
    assert "8b3abe4de82d5e709cca" not in card  # full hash never rendered


def test_failed_result_renders_error_glyph_and_row():
    card = render_card("grasp_prove_claim",
                       {"ok": False, "error": "source unreadable"})
    assert card.splitlines()[0].startswith("╭─ GRASP ✗")
    assert "source unreadable" in card


def test_unverified_claim_gets_cross_glyph_even_when_ok():
    card = render_card("grasp_prove_claim",
                       {"ok": True, "verified": False,
                        "grounding_rate": 0.0, "filed_safe": False})
    assert card.splitlines()[0].startswith("╭─ GRASP ✗")
    assert "░░░░░░░░░░ 0.00" in card


def test_card_is_deterministic_and_honest():
    result = {"ok": True, "zeta": "z", "alpha": "a", "id": "n-1"}
    a = render_card("grasp_status", result)
    b = render_card("grasp_status", result)
    assert a == b
    assert "alpha" in a and "zeta" in a
    assert "grounding" not in a  # absent keys are never invented


def test_unknown_tool_falls_back_to_tool_name():
    card = render_card("grasp_future_tool", {"ok": True, "id": "x"})
    assert "grasp_future_tool" in card.splitlines()[0]


def test_mcp_response_carries_card_text_and_structured_json():
    resp = handle_message({
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {"name": "grasp_status", "arguments": {}},
    })
    result = resp["result"]
    text = result["content"][0]["text"]
    assert text.startswith("╭─ GRASP")
    assert not text.lstrip().startswith("{")  # never raw JSON to humans
    assert isinstance(result["structuredContent"], dict)
    assert result["structuredContent"].get("ok") is True
    assert result["isError"] is False
