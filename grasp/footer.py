# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Per-response prove-it footer — provable AI as the default surface.

Every response that makes salient (source-bound) claims can close on a
compact provenance card: model badge, claim tally, grounding bar, and a
fineprint inspect-link row pointing at the full HTML prove-it artifact.
``facta, non verba`` — the moat proves the model's own claims each turn.

Three modes, one knob (explicit argument > ``$GRASP_FOOTER_MODE`` > default):

- ``salient`` (default) — footer only when the response carries at least
  one ``[[cite:ID]]``-bound claim (the SAME scope the L1 floor governs:
  a claim the author bound to a verbatim source quote);
- ``always`` — a model-badge card even on turns with no salient claims;
- ``off`` — never.

Portability contract (same as the cards): unicode box-drawing, NO ANSI.
The inspect link is a plain-URL fineprint row BELOW the sealed box —
modern terminals auto-link plain text, long paths never break the box,
and ``grasp open <id>`` is the honest fallback when they don't.
"""
from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from grasp.card import render_card
from grasp.home import grasp_home
from grasp.prove_it import (
    CITE_RE,
    STATUS_FUZZY,
    STATUS_NOT_FOUND,
    STATUS_VERIFIED,
    render,
)

FOOTER_MODES = ("salient", "always", "off")
_DEFAULT_MODE = "salient"

# Per-provider glyph accents — deterministic delight, no ANSI. Matched on
# the model string's leading family token; unknown families hash into the
# fallback set so the SAME model always carries the SAME glyph.
_PROVIDER_GLYPHS = (
    ("claude", "◆"), ("anthropic", "◆"),
    ("gpt", "○"), ("openai", "○"), ("o1", "○"), ("o3", "○"),
    ("grok", "✦"), ("xai", "✦"),
    ("gemini", "✧"), ("google", "✧"),
    ("deepseek", "◈"),
    ("llama", "▲"), ("groq", "▲"),
    ("qwen", "❖"),
    ("mistral", "▞"),
    ("local", "⌂"), ("ollama", "⌂"),
)
_FALLBACK_GLYPHS = ("◇", "◆", "○", "●", "✦", "✧", "◈", "❖")


def footer_mode(explicit: str | None = None) -> str:
    """Resolve the footer mode. An invalid EXPLICIT mode is a programmer
    error and raises; an invalid environment value falls back to the
    default (an operator typo must never break a response pipeline)."""
    if explicit is not None:
        if explicit not in FOOTER_MODES:
            raise ValueError(
                f"unknown footer mode {explicit!r} — one of: {', '.join(FOOTER_MODES)}")
        return explicit
    env = os.environ.get("GRASP_FOOTER_MODE", "").strip().lower()
    return env if env in FOOTER_MODES else _DEFAULT_MODE


def provider_glyph(model: str) -> str:
    """The model family's glyph accent — deterministic, never colourful."""
    low = (model or "").strip().lower()
    for prefix, glyph in _PROVIDER_GLYPHS:
        if low.startswith(prefix):
            return glyph
    digest = hashlib.sha256(low.encode("utf-8")).digest()[0]
    return _FALLBACK_GLYPHS[digest % len(_FALLBACK_GLYPHS)]


def salient_citations(response_md: str) -> list[str]:
    """The response's ``[[cite:ID]]`` ids, order-preserved, deduplicated.
    This IS the salience floor: a salient claim is one the author bound
    to a source — no NLP guesswork, deterministic by construction."""
    seen: dict[str, None] = {}
    for match in CITE_RE.finditer(response_md or ""):
        seen.setdefault(match.group(1))
    return list(seen)


def artifact_dir(home: Path | None = None) -> Path:
    """Where per-response prove-it artifacts live (``<home>/prove-it``)."""
    directory = (home or grasp_home()) / "prove-it"
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def _artifact_id(spec: dict) -> str:
    """Spec-addressed id: the same response+citations always map to the
    same artifact path (idempotent re-render; the embedded generation
    timestamp may differ, the address never does)."""
    canonical = json.dumps(spec, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


@dataclass(frozen=True)
class FooterResult:
    """What the footer decided and rendered for one response."""

    emitted: bool
    reason: str
    card: str = ""
    fineprint: tuple[str, ...] = field(default=())
    artifact_path: str = ""
    provenance: dict | None = None

    @property
    def text(self) -> str:
        """The full terminal footer: sealed card + fineprint rows."""
        if not self.emitted:
            return ""
        return "\n".join((self.card, *self.fineprint)) if self.fineprint else self.card


def _tally_summary(tally: dict) -> str:
    return (f"{sum(tally.values())} — ✓{tally.get(STATUS_VERIFIED, 0)} "
            f"≈{tally.get(STATUS_FUZZY, 0)} ✗{tally.get(STATUS_NOT_FOUND, 0)}")


def render_footer(spec: dict, *, model: str, mode: str | None = None,
                  home: Path | None = None) -> FooterResult:
    """Render the per-response footer for a prove-it spec.

    ``spec`` is the standard prove-it spec (``response`` markdown with
    ``[[cite:ID]]`` tokens, ``sources``, ``citations``). Verification is
    the L1 deterministic floor — a fabricated quote renders ✗ and flips
    the card glyph; it cannot pass.
    """
    resolved = footer_mode(mode)
    if resolved == "off":
        return FooterResult(emitted=False, reason="footer mode is off")

    cite_ids = salient_citations(spec.get("response", ""))
    badge = f"{provider_glyph(model)} {model}"

    if not cite_ids:
        if resolved == "salient":
            return FooterResult(
                emitted=False,
                reason="no salient claims — nothing bound to a source this turn")
        card = render_card("grasp_footer", {
            "ok": True, "model": badge,
            "claims": "0 — nothing salient this turn",
        })
        return FooterResult(emitted=True, reason="always mode, no claims",
                            card=card)

    html, prov = render(spec)
    artifact = artifact_dir(home) / f"{_artifact_id(spec)}.html"
    artifact.write_text(html, encoding="utf-8")

    tally = prov["tally"]
    card = render_card("grasp_footer", {
        "ok": True,
        "verified": tally.get(STATUS_NOT_FOUND, 0) == 0,
        "model": badge,
        "claims": _tally_summary(tally),
        "grounding": prov["grounding_rate"],
    })
    fineprint = (
        f"┆ inspect  {artifact.as_uri()}",
        f"┆ or run   grasp open {artifact.stem}",
    )
    return FooterResult(emitted=True, reason="salient claims proven",
                        card=card, fineprint=fineprint,
                        artifact_path=str(artifact), provenance=prov)
