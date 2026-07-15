# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Per-response footer contract: salient|always|off, provable by floor.

Falsifiers: a footer emitted in off mode voids the knob; a salient-mode
footer on a claim-free turn is noise (the design's >15% noise falsifier);
a fabricated quote rendering ✓ voids the L1 floor; a fineprint naming
``grasp open`` without the command existing is a stub; two renders of the
same spec landing at different paths voids idempotent addressing.
"""
from __future__ import annotations

import pytest

from grasp import cli
from grasp.footer import (
    FOOTER_MODES,
    footer_mode,
    provider_glyph,
    render_footer,
    salient_citations,
)


def _spec(response: str, quote: str = "the moat proves the claim") -> dict:
    return {
        "title": "test response",
        "response": response,
        "sources": [{"id": "s1", "label": "design doc",
                     "text": f"Context: {quote} — end."}],
        "citations": [{"id": "c1", "claim": "the salient claim",
                       "source_id": "s1", "quote": quote}],
    }


CITED = "The claim holds [[cite:c1]] and that is salient."
UNCITED = "A chatty turn with nothing bound to a source."


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("GRASP_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


# --------------------------------------------------------------- mode knob

def test_mode_resolution_order(monkeypatch):
    monkeypatch.setenv("GRASP_FOOTER_MODE", "always")
    assert footer_mode() == "always"          # env honoured
    assert footer_mode("off") == "off"        # explicit beats env
    monkeypatch.setenv("GRASP_FOOTER_MODE", "loud")  # operator typo
    assert footer_mode() == "salient"         # fail-open to default
    monkeypatch.delenv("GRASP_FOOTER_MODE")
    assert footer_mode() == "salient"


def test_invalid_explicit_mode_raises():
    with pytest.raises(ValueError, match="unknown footer mode"):
        footer_mode("loud")
    assert FOOTER_MODES == ("salient", "always", "off")


def test_off_mode_emits_nothing(home):
    result = render_footer(_spec(CITED), model="claude-fable-5", mode="off",
                           home=home)
    assert not result.emitted and result.text == ""


# --------------------------------------------------------------- salience

def test_salient_citations_are_ordered_and_deduped():
    text = "a [[cite:x]] b [[cite:y]] c [[cite:x]]"
    assert salient_citations(text) == ["x", "y"]
    assert salient_citations(UNCITED) == []


def test_salient_mode_skips_claim_free_turns(home):
    result = render_footer(_spec(UNCITED), model="claude-fable-5",
                           mode="salient", home=home)
    assert not result.emitted
    assert "no salient claims" in result.reason


def test_always_mode_renders_badge_card_without_claims(home):
    result = render_footer(_spec(UNCITED), model="grok-4", mode="always",
                           home=home)
    assert result.emitted and result.artifact_path == ""
    assert "✦ grok-4" in result.card            # provider glyph accent
    assert "nothing salient this turn" in result.card
    assert "╭─ GRASP ● prove-it — this response" in result.card
    assert result.fineprint == ()


# --------------------------------------------------------------- proven path

def test_salient_footer_proves_and_links(home):
    result = render_footer(_spec(CITED), model="claude-fable-5",
                           mode="salient", home=home)
    assert result.emitted
    assert "╭─ GRASP ✓ prove-it — this response" in result.card
    assert "◆ claude-fable-5" in result.card
    assert "✓1 ≈0 ✗0" in result.card
    assert "█" in result.card                   # grounding bar rendered
    assert result.card.splitlines()[-1].startswith("╰─ facta, non verba")
    # fineprint: plain-URL inspect row + the real fallback command
    assert result.fineprint[0].startswith("┆ inspect  file://")
    assert result.fineprint[1].startswith("┆ or run   grasp open ")
    assert result.artifact_path.endswith(".html")
    html = open(result.artifact_path, encoding="utf-8").read()
    assert "prove-it deterministic provenance" in html
    assert result.provenance["grounding_rate"] == 1.0


def test_fabricated_quote_flips_the_glyph(home):
    spec = _spec(CITED)
    spec["citations"][0]["quote"] = "words that are not in the source"
    result = render_footer(spec, model="claude-fable-5", mode="salient",
                           home=home)
    assert result.emitted
    assert "╭─ GRASP ✗ prove-it — this response" in result.card
    assert "✗1" in result.card                  # the not-found tally shows
    assert result.provenance["tally"]["not_found"] == 1


def test_same_spec_addresses_the_same_artifact(home):
    first = render_footer(_spec(CITED), model="m", mode="salient", home=home)
    second = render_footer(_spec(CITED), model="m", mode="salient", home=home)
    # spec-addressed id: idempotent path (embedded timestamp may differ)
    assert first.artifact_path == second.artifact_path


# --------------------------------------------------------------- theming

def test_provider_glyphs_are_deterministic():
    assert provider_glyph("claude-fable-5") == "◆"
    assert provider_glyph("gpt-5.5") == "○"
    assert provider_glyph("grok-4") == "✦"
    assert provider_glyph("gemini-3.1-pro") == "✧"
    assert provider_glyph("deepseek-chat") == "◈"
    assert provider_glyph("llama-3.3-70b") == "▲"
    assert provider_glyph("qwen-max") == "❖"
    unknown = provider_glyph("frontier-x-9000")
    assert unknown == provider_glyph("frontier-x-9000")  # stable
    assert unknown in ("◇", "◆", "○", "●", "✦", "✧", "◈", "❖")


# --------------------------------------------------------------- grasp open

def test_grasp_open_prints_artifact_path(home, capsys):
    result = render_footer(_spec(CITED), model="m", mode="salient", home=home)
    artifact_id = result.fineprint[1].rsplit(" ", 1)[-1]
    code = cli.main(["open", artifact_id, "--no-browser"])
    assert code == 0
    assert capsys.readouterr().out.strip() == result.artifact_path


def test_grasp_open_unknown_id_fails_loud(home, capsys):
    code = cli.main(["open", "deadbeef0000", "--no-browser"])
    assert code == 1
    assert "no prove-it artifact matching" in capsys.readouterr().err
