"""Portable provenance cards for GRASP MCP tool results.

Harness TUIs (Grok Build, Gemini CLI, Codex, Antigravity, Claude Code,
Claude Desktop) render MCP tool output as plain text. Raw canonical JSON
reads as a wall of noise; these cards give every GRASP result one
glanceable, consistent shape in ANY harness:

- unicode box-drawing + a few glyphs, NO ANSI colour (many TUIs mangle
  or strip escape codes — portability beats colour);
- width-capped so narrow panes never wrap mid-box;
- deterministic (same result dict -> byte-identical card);
- honest: rows render only keys PRESENT in the result — the card never
  invents fields;
- every card closes on the ethos it enforces: facta, non verba.

The full result dict still travels as MCP ``structuredContent`` — the
card is for humans, the JSON for programs.
"""
from __future__ import annotations

import json
import re
from typing import Any

WIDTH = 62  # total card width incl. borders; safe in narrow TUI panes

_ETHOS = "facta, non verba"  # deeds, not words — closes every card

_TITLES = {
    "grasp_record_decision": "decision recorded",
    "grasp_record_belief": "belief recorded",
    "grasp_prove_claim": "prove claim",
    "grasp_verify": "chain verify",
    "grasp_status": "status",
    "grasp_activate": "activated — chain born",
    "grasp_footer": "prove-it — this response",
    "grasp_honesty": "provider honesty — floor-hold scoreboard",
    "grasp_attest": "self-attestation — grasp proves grasp",
}

# Curated display order; anything else follows alphabetically. ``model``
# and ``honesty`` render only when a result carries them (honest by
# construction) — the provider-honesty ledger populates them downstream.
_PREFERRED = (
    "status", "model", "verified", "claims", "honesty", "grounding_rate",
    "grounding", "quote", "claim", "source_path", "source_sha256", "sha256",
    "id", "idr_id", "context_id", "head", "depth", "ts", "entries", "count",
    "filed_safe",
)
_SKIP = {"ok", "error"}
_MAX_ROWS = 10
_HEXISH = re.compile(r"^(sha256:)?[0-9a-f]{16,}$")

# Provider-honesty states (populated by the deterministic-floor
# intervention): a glanceable glyph + word, never ANSI colour.
_HONESTY = {
    "honest": "● honest",
    "floor_held": "◆ floor-held",
    "failed_over": "✗ failed-over",
}


def _short(value: str) -> str:
    if _HEXISH.match(value):
        prefix = "sha256:" if value.startswith("sha256:") else ""
        body = value[len(prefix):]
        return f"{prefix}{body[:12]}…"
    return value


def _bar(rate: float, slots: int = 10) -> str:
    filled = max(0, min(slots, round(rate * slots)))
    return "█" * filled + "░" * (slots - filled) + f" {rate:.2f}"


def _fmt(key: str, value: Any) -> str:
    if key in ("grounding_rate", "grounding") and isinstance(value, (int, float)):
        return _bar(float(value))  # "grounding" fits the 11-col label field
    if key == "honesty" and isinstance(value, str):
        return _HONESTY.get(value, value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return _short(value)
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return str(value)


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _row(label: str, value: str) -> str:
    inner = WIDTH - 4  # "│ " + " │"
    body = f"{label:<11}{value}"
    return f"│ {_clip(body, inner):<{inner}} │"


def _title_line(glyph: str, title: str) -> str:
    head = f"╭─ GRASP {glyph} {title} "
    return head + "─" * (WIDTH - len(head) - 1) + "╮"


def _footer_line() -> str:
    # Mirrors _title_line: the ethos rides the closing border, so it adds
    # no row, stays within WIDTH, and every card ends on facta, non verba.
    head = f"╰─ {_ETHOS} "
    return head + "─" * (WIDTH - len(head) - 1) + "╯"


def _glyph(tool: str, result: dict) -> str:
    if not result.get("ok", False):
        return "✗"
    if tool in ("grasp_prove_claim", "grasp_footer") and "verified" in result:
        return "✓" if result.get("verified") else "✗"
    return "●"


def compose_card(title: str, rows: list[tuple[str, str]], *,
                 glyph: str = "●") -> str:
    """Assemble a card from PRE-ORDERED (label, value) rows — for surfaces
    whose display order is data-driven (a ranked scoreboard) where dict-key
    ordering cannot express rank. The caller owns row capping."""
    lines = [_title_line(glyph, title)]
    lines.extend(_row(label, value) for label, value in rows)
    lines.append(_footer_line())
    return "\n".join(lines)


def bar(rate: float) -> str:
    """The grounding/hold-rate bar, public — one bar shape everywhere."""
    return _bar(rate)


def render_card(tool: str, result: dict) -> str:
    """One portable card for one tool result. Pure + deterministic."""
    keys = [k for k in _PREFERRED if k in result]
    keys += sorted(k for k in result
                   if k not in _PREFERRED and k not in _SKIP)
    rows = [(key, _fmt(key, result[key])) for key in keys[:_MAX_ROWS]]
    if not result.get("ok", False):
        rows.append(("error", str(result.get("error", "unknown"))))
    return compose_card(_TITLES.get(tool, tool), rows,
                        glyph=_glyph(tool, result))
