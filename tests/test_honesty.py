# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Honesty-ledger contract: block the lie, fail over honest, mark private.

Falsifiers: a fabricated claim leaving intervene() voids the floor; a
checker error on salient claims that still emits voids fail-closed; an
unsigned or tampered ledger line counting toward a scoreboard voids
tamper-evidence; the shame surface rendering without BOTH gates voids the
L3 default; an attestation passing while terms are stale voids provable
compliance.
"""
from __future__ import annotations

import json

import pytest

from grasp.activate import accept_licenses, license_files
from grasp.honesty import (
    floor_gate,
    intervene,
    ledger_path,
    public_shame_card,
    read_ledger,
    record_event,
    scoreboard,
    scoreboard_card,
    self_attestation,
    shame_surface_enabled,
)

GOOD_QUOTE = "the suite is green"
SOURCE = {"id": "s1", "label": "log", "text": f"note: {GOOD_QUOTE}. end."}


def _spec(quote: str = GOOD_QUOTE) -> dict:
    return {
        "response": "claim [[cite:c1]]",
        "sources": [dict(SOURCE)],
        "citations": [{"id": "c1", "claim": "claim", "source_id": "s1",
                       "quote": quote}],
    }


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("GRASP_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


# ------------------------------------------------------------- floor gate

def test_floor_gate_passes_grounded_claims():
    verdict = floor_gate(_spec())
    assert verdict.verdict == "pass" and verdict.send_allowed


def test_floor_gate_blocks_fabrication():
    verdict = floor_gate(_spec("words never in the source"))
    assert verdict.verdict == "fail" and not verdict.send_allowed
    assert verdict.not_found == 1


def test_floor_gate_is_trivially_open_without_claims():
    verdict = floor_gate({"response": "chatty", "citations": []})
    assert verdict.verdict == "pass" and not verdict.salient
    assert verdict.send_allowed


def test_floor_gate_fails_closed_on_checker_error():
    # a malformed spec crashes the checker mid-verify -> error verdict,
    # and for salient claims send_allowed is False (fail-CLOSED)
    broken = {"response": "x [[cite:c1]]",
              "citations": [{"id": "c1", "claim": "c", "source_id": "s1",
                             "quote": "q"}]}  # sources key missing entirely
    verdict = floor_gate(broken)
    assert verdict.verdict == "error" and verdict.salient
    assert not verdict.send_allowed


# ------------------------------------------------------------- intervene

def test_first_provider_honest(home):
    result = intervene(lambda model: _spec(), ("model-a",), home=home)
    assert result["ok"] and result["honesty"] == "honest"
    assert result["model"] == "model-a"
    events, tampered = read_ledger(home)
    assert tampered == 0
    assert [e["event"] for e in events] == ["floor_pass"]


def test_fabricator_blocked_then_failover_marks_both(home):
    def build(model: str) -> dict:
        return _spec() if model == "honest-b" else _spec("fabricated words")

    result = intervene(build, ("liar-a", "honest-b"), home=home)
    assert result["ok"] and result["honesty"] == "failed_over"
    assert result["model"] == "honest-b"
    assert result["blocked"] == "liar-a"
    events, _ = read_ledger(home)
    assert [e["event"] for e in events] == ["floor_fail", "failed_over"]
    assert events[1]["rescued_from"] == "liar-a"


def test_all_providers_fail_holds_the_floor_and_sends_nothing(home):
    result = intervene(lambda m: _spec("fabricated"), ("a", "b"), home=home)
    assert not result["ok"] and result["honesty"] == "floor_held"
    assert "send refused" in result["error"]
    assert "spec" not in result  # nothing to emit — the refusal IS the outcome
    events, _ = read_ledger(home)
    assert [e["event"] for e in events] == ["floor_fail", "floor_fail",
                                            "floor_held"]


def test_checker_error_fails_closed_with_alert(home):
    broken = {"response": "x [[cite:c1]]",
              "citations": [{"id": "c1", "claim": "c", "source_id": "s1",
                             "quote": "q"}]}
    result = intervene(lambda m: broken, ("model-a", "model-b"), home=home)
    assert not result["ok"] and result["alert"] is True
    assert result["honesty"] == "floor_held"
    events, _ = read_ledger(home)
    assert events[-1]["event"] == "checker_error"  # blamed on the checker


def test_generator_crash_moves_down_the_ladder(home):
    def build(model: str) -> dict:
        if model == "dead-a":
            raise RuntimeError("provider unreachable")
        return _spec()

    result = intervene(build, ("dead-a", "live-b"), home=home)
    assert result["ok"] and result["honesty"] == "failed_over"
    events, _ = read_ledger(home)
    assert events[0]["event"] == "generator_error"


def test_empty_ladder_is_a_programmer_error(home):
    with pytest.raises(ValueError, match="at least one provider"):
        intervene(lambda m: _spec(), (), home=home)


# ------------------------------------------------------------- the ledger

def test_ledger_events_are_signed_and_tamper_evident(home):
    intervene(lambda m: _spec(), ("model-a",), home=home)
    path = ledger_path(home)
    line = json.loads(path.read_text().splitlines()[0])
    assert line["sig"] and line["fingerprint"]
    # tamper one byte of the body -> the line is excluded AND counted
    line["model"] = "someone-else"
    path.write_text(json.dumps(line) + "\n")
    events, tampered = read_ledger(home)
    assert events == [] and tampered == 1
    board = scoreboard(home)
    assert board["providers"] == [] and board["tampered"] == 1


# ------------------------------------------------------------- scoreboard

def _seed_ledger(home) -> None:
    intervene(lambda m: _spec(), ("clean-a",), home=home)

    def build(model: str) -> dict:
        return _spec() if model == "rescuer-c" else _spec("fabricated")

    intervene(build, ("liar-b", "rescuer-c"), home=home)


def test_scoreboard_ranks_by_hold_rate(home):
    _seed_ledger(home)
    board = scoreboard(home)
    models = [p["model"] for p in board["providers"]]
    assert models == ["clean-a", "rescuer-c", "liar-b"]  # 1.0, 1.0, 0.0
    assert board["providers"][-1]["hold_rate"] == 0.0


def test_scoreboard_card_shows_glyphs_bars_and_ethos(home):
    _seed_ledger(home)
    card = scoreboard_card(home)
    lines = card.splitlines()
    clean = next(line for line in lines if "clean-a" in line)
    liar = next(line for line in lines if "liar-b" in line)
    assert clean.startswith("│ ●") and "█" in clean
    assert liar.startswith("│ ✗") and "░" in liar
    assert lines[-1].startswith("╰─ facta, non verba")


def test_empty_scoreboard_is_honest(home):
    card = scoreboard_card(home)
    assert "no floor events recorded yet" in card


# ------------------------------------------- shame surface (dual-gated)

def test_shame_surface_is_off_by_default_and_single_gated(home):
    _seed_ledger(home)
    assert not shame_surface_enabled(home)
    assert public_shame_card(home) == ""
    # one gate alone is NOT enough (Goodhart anchor on the L3 default)
    home.mkdir(parents=True, exist_ok=True)
    (home / "enterprise-switch.json").write_text('{"public_shame": true}')
    assert not shame_surface_enabled(home)
    assert public_shame_card(home) == ""


def test_shame_surface_renders_only_behind_both_gates(home):
    _seed_ledger(home)
    home.mkdir(parents=True, exist_ok=True)
    (home / "enterprise-switch.json").write_text('{"public_shame": true}')
    (home / "legal-ack-shame.txt").write_text(
        "legal review LR-2026-001 acknowledges the public honesty surface")
    assert shame_surface_enabled(home)
    card = public_shame_card(home)
    assert "⚑" in card and "liar-b" in card
    assert "failed floor 1×" in card
    assert "failed-over to rescuer-c" in card


def test_shame_switch_false_keeps_surface_off(home):
    _seed_ledger(home)
    home.mkdir(parents=True, exist_ok=True)
    (home / "enterprise-switch.json").write_text('{"public_shame": false}')
    (home / "legal-ack-shame.txt").write_text("ack")
    assert not shame_surface_enabled(home)


# ------------------------------------------------------------- attestation

@pytest.fixture()
def terms_root(tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    (root / "LICENSE").write_text("AGPL-3.0-only\n")
    return root


def test_attestation_fails_before_acceptance(home, terms_root):
    result = self_attestation(terms_root, home)
    assert not result["attested"]
    assert result["terms"].startswith("✗")


def test_attestation_holds_after_activation(home, terms_root):
    from grasp.activate import ActivationConfig, activate
    accept_licenses(license_files(terms_root), home)
    activate(ActivationConfig(mode="private", backends=("local",),
                              admins=("fp-1",)), terms_root, home)
    result = self_attestation(terms_root, home)
    assert result["attested"], result.get("error")
    assert result["mode"] == "private"
    assert result["terms"].startswith("✓")
    assert result["acl"].startswith("✓")
    assert result["egress"].startswith("✓")
    assert "off (L3 default)" in result["shame-gate"]
    # the attestation itself is a signed ledger event — provable history
    events, _ = read_ledger(home)
    assert events[-1]["event"] == "self_attestation"
    assert events[-1]["attested"] is True


def test_attestation_catches_changed_terms(home, terms_root):
    from grasp.activate import ActivationConfig, activate
    accept_licenses(license_files(terms_root), home)
    activate(ActivationConfig(mode="public", backends=("local",)),
             terms_root, home)
    (terms_root / "LICENSE").write_text("AGPL-3.0-only WITH new clause\n")
    result = self_attestation(terms_root, home)
    assert not result["attested"]
    assert "not accepted" in result["terms"]


def test_attestation_catches_tampered_acl(home, terms_root):
    from grasp.activate import ActivationConfig, activate
    accept_licenses(license_files(terms_root), home)
    activate(ActivationConfig(mode="combination",
                              backends=("local", "website"),
                              admins=("fp-1",)), terms_root, home)
    acl = home / "visibility-acl.json"
    record = json.loads(acl.read_text())
    record["admins"] = ["intruder"]
    acl.write_text(json.dumps(record))
    result = self_attestation(terms_root, home)
    assert not result["attested"]
    assert "INVALID" in result["acl"]
