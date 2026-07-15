# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Provider honesty-ledger + deterministic-floor intervention.

When a provider cannot hold the L1 truth-floor (a salient claim's quote is
NOT in its cited source — the fabrication class), GRASP refuses to speak
the lie: the send is BLOCKED, generation fails over to the next provider
on the caller's ladder (monotone toward honest — a failover can only make
output MORE proven, never less), and the failure is recorded as a signed
event in the PRIVATE honesty ledger, surfaced to the operator/admin only.

Fail direction (the deliberate inversion of the usual fail-open default):
when the floor-CHECKER itself errors on a response with salient claims we
fail CLOSED — emitting an unverified claim is itself the harm. A response
with no salient claims sails through open (there is nothing to prove).

Public name-and-shame is built COMPLETE but DEFAULT-OFF by construction:
the ⚑ flagged public-chain view activates only when BOTH the enterprise
switch AND a legal acknowledgement file are present. Naming a vendor
"dishonest" publicly on one-sided evidence is a defamation surface — the
flip, not the code, is the legally-reviewed step.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from grasp.activate import egress_guard, license_files, licenses_accepted
from grasp.card import bar, compose_card, render_card
from grasp.home import grasp_home
from grasp.keys import signed_record, verify_record
from grasp.prove_it import (
    STATUS_NOT_FOUND,
    Citation,
    Source,
    verify_all,
)

# Scoreboard glyph ladder — deterministic thresholds on the floor-hold rate.
_HOLD_GLYPHS = ((0.95, "●"), (0.50, "◆"), (0.0, "✗"))

_LEDGER_NAME = "honesty.jsonl"
_SHAME_SWITCH = "enterprise-switch.json"
_SHAME_ACK = "legal-ack-shame.txt"


# ------------------------------------------------------------- floor gate

@dataclass(frozen=True)
class FloorVerdict:
    """One provider's response judged against the deterministic floor."""

    verdict: str          # "pass" | "fail" | "error"
    salient: bool         # did the response bind any claim to a source?
    claims: int = 0
    not_found: int = 0
    detail: str = ""

    @property
    def send_allowed(self) -> bool:
        """Fail-CLOSED for salient claims: only a passed floor (or a turn
        with nothing to prove) may leave."""
        if self.verdict == "pass":
            return True
        return not self.salient  # error/fail on non-salient: nothing to prove


def floor_gate(spec: dict) -> FloorVerdict:
    """Run one response spec through the L1 floor. Deterministic; a
    checker crash on a salient response returns an ``error`` verdict
    whose ``send_allowed`` is False (fail-closed, never a silent pass)."""
    citations = spec.get("citations") or []
    if not citations:
        return FloorVerdict(verdict="pass", salient=False,
                            detail="no source-bound claims — nothing to prove")
    try:
        sources = [Source(id=s["id"], label=s.get("label", s["id"]),
                          text=s["text"]) for s in spec["sources"]]
        cites = [Citation(id=str(c["id"]), claim=c["claim"],
                          source_id=c["source_id"], quote=c["quote"])
                 for c in citations]
        verify_all(cites, sources)
    except Exception as exc:  # noqa: BLE001 — the checker itself broke
        return FloorVerdict(verdict="error", salient=True,
                            claims=len(citations),
                            detail=f"floor checker error: {exc}")
    not_found = sum(1 for c in cites if c.status == STATUS_NOT_FOUND)
    if not_found:
        return FloorVerdict(verdict="fail", salient=True, claims=len(cites),
                            not_found=not_found,
                            detail=f"{not_found} claim(s) not in their source")
    return FloorVerdict(verdict="pass", salient=True, claims=len(cites))


# ------------------------------------------------------------- the ledger

def ledger_path(home: Path | None = None) -> Path:
    return (home or grasp_home()) / _LEDGER_NAME


def record_event(event: str, model: str, verdict: FloorVerdict,
                 home: Path | None = None, **extra) -> dict:
    """Append one signed event to the private honesty ledger."""
    body = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "event": event,
        "model": model,
        "claims": verdict.claims,
        "not_found": verdict.not_found,
        **extra,
    }
    record = signed_record(body, home)
    path = ledger_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def read_ledger(home: Path | None = None) -> tuple[list[dict], int]:
    """All signature-valid events plus the count of TAMPERED lines
    (excluded from every aggregate, surfaced loudly — tamper-evidence)."""
    path = ledger_path(home)
    if not path.exists():
        return [], 0
    valid: list[dict] = []
    tampered = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            tampered += 1
            continue
        if verify_record(record, home):
            valid.append(record)
        else:
            tampered += 1
    return valid, tampered


# ------------------------------------------------------------- intervention

def _checker_error_result(model: str, verdict: FloorVerdict,
                          blocked: list[str], home: Path | None) -> dict:
    """Fail-CLOSED on salient claims: alert, do not emit, and do not blame
    the provider — the CHECKER broke, not the model."""
    record_event("checker_error", model, verdict, home)
    return {"ok": False, "honesty": "floor_held", "model": model,
            "alert": True, "error": verdict.detail,
            "blocked": ", ".join(blocked) or None}


def _passed_result(model: str, position: int, verdict: FloorVerdict,
                   spec: dict, blocked: list[str], home: Path | None) -> dict:
    honesty = "honest" if position == 0 else "failed_over"
    record_event("floor_pass" if position == 0 else "failed_over",
                 model, verdict, home,
                 rescued_from=blocked[-1] if blocked else None)
    result = {"ok": True, "honesty": honesty, "model": model,
              "claims": verdict.claims, "spec": spec}
    if blocked:
        result["blocked"] = ", ".join(blocked)
    return result


def _floor_held_result(ladder: tuple[str, ...], blocked: list[str],
                       home: Path | None) -> dict:
    """Every provider fabricated: the floor held — GRASP refuses to speak."""
    record_event("floor_held", ladder[-1], FloorVerdict("fail", True), home,
                 exhausted=", ".join(ladder))
    return {"ok": False, "honesty": "floor_held", "model": ladder[-1],
            "blocked": ", ".join(blocked),
            "error": "no provider could ground the claims — send refused"}


def intervene(build_spec: Callable[[str], dict], ladder: tuple[str, ...],
              *, home: Path | None = None) -> dict:
    """Walk the provider ladder until one holds the floor.

    ``build_spec(model)`` generates (or re-generates) the response spec on
    the named provider — the caller owns generation (GRIP wires its HAL
    ladder in here; grasp never imports a provider SDK). Monotone toward
    honest: a later provider's output is accepted only if IT passes the
    floor; nothing unproven is ever emitted. ``honesty`` in the result is
    ``honest`` | ``failed_over`` | ``floor_held`` (nothing sent).
    """
    if not ladder:
        raise ValueError("intervene needs at least one provider on the ladder")
    blocked: list[str] = []
    for position, model in enumerate(ladder):
        try:
            spec = build_spec(model)
        except Exception as exc:  # noqa: BLE001 — generator died ≠ dishonest
            record_event("generator_error", model,
                         FloorVerdict("error", True, detail=str(exc)), home)
            blocked.append(model)
            continue
        verdict = floor_gate(spec)
        if verdict.verdict == "error":
            return _checker_error_result(model, verdict, blocked, home)
        if verdict.send_allowed:
            return _passed_result(model, position, verdict, spec, blocked, home)
        record_event("floor_fail", model, verdict, home)
        blocked.append(model)
    return _floor_held_result(ladder, blocked, home)


# ------------------------------------------------------------- scoreboard

def _hold_rate(passes: int, fails: int) -> float:
    total = passes + fails
    return passes / total if total else 1.0


def scoreboard(home: Path | None = None) -> dict:
    """Per-provider floor-hold standings — deterministic from the ledger,
    never invented. Checker errors are excluded (the checker broke, not
    the provider); tampered lines are excluded AND counted."""
    events, tampered = read_ledger(home)
    passes: dict[str, int] = {}
    fails: dict[str, int] = {}
    for e in events:
        model = e.get("model", "?")
        if e["event"] in ("floor_pass", "failed_over"):
            passes[model] = passes.get(model, 0) + 1
        elif e["event"] == "floor_fail":
            fails[model] = fails.get(model, 0) + 1
    providers = sorted(
        set(passes) | set(fails),
        key=lambda m: (-_hold_rate(passes.get(m, 0), fails.get(m, 0)), m))
    return {
        "providers": [
            {"model": m,
             "passes": passes.get(m, 0),
             "fails": fails.get(m, 0),
             "hold_rate": round(_hold_rate(passes.get(m, 0),
                                           fails.get(m, 0)), 3)}
            for m in providers
        ],
        "events": len(events),
        "tampered": tampered,
    }


def _hold_glyph(rate: float) -> str:
    for floor_value, glyph in _HOLD_GLYPHS:
        if rate >= floor_value:
            return glyph
    return "✗"


def scoreboard_card(home: Path | None = None) -> str:
    """The ranked honesty scoreboard as a portable card."""
    board = scoreboard(home)
    if not board["providers"]:
        return render_card("grasp_honesty", {
            "ok": True, "entries": 0,
            "detail": "no floor events recorded yet"})
    # glyph in the label column; bar + full model name in the value so a
    # long model id is clipped by the card, never by the 11-col label
    rows = [(_hold_glyph(p["hold_rate"]),
             f"{bar(p['hold_rate'])}  {p['model']}  ✓{p['passes']} ✗{p['fails']}")
            for p in board["providers"][:8]]
    if board["tampered"]:
        rows.append(("tampered",
                     f"{board['tampered']} line(s) EXCLUDED — signature invalid"))
    return compose_card("provider honesty — floor-hold scoreboard", rows)


# ------------------------------------------- public shame surface (gated)

def shame_surface_enabled(home: Path | None = None) -> bool:
    """True ONLY when both gates are present: the enterprise switch
    (``enterprise-switch.json`` with ``public_shame: true``) AND the
    legal acknowledgement file. Anything less: OFF by construction."""
    base = home or grasp_home()
    switch = base / _SHAME_SWITCH
    ack = base / _SHAME_ACK
    if not (switch.exists() and ack.exists() and ack.read_text().strip()):
        return False
    try:
        return json.loads(switch.read_text(encoding="utf-8")).get(
            "public_shame") is True
    except (json.JSONDecodeError, OSError):
        return False


def public_shame_card(home: Path | None = None) -> str:
    """The ⚑ flagged public-chain view of floor-failing providers.
    Renders ONLY when the dual gate is open; otherwise the empty string —
    a Goodhart test pins that default."""
    if not shame_surface_enabled(home):
        return ""
    board = scoreboard(home)
    flagged = [p for p in board["providers"] if p["fails"]]
    if not flagged:
        return ""
    events, _ = read_ledger(home)
    rescued_by = {
        e.get("rescued_from"): e.get("model")
        for e in events if e["event"] == "failed_over" and e.get("rescued_from")
    }
    rows = []
    for p in sorted(flagged, key=lambda x: (x["hold_rate"], x["model"]))[:4]:
        rows.append(("⚑", f"{p['model']}: failed floor {p['fails']}×"))
        rescue = rescued_by.get(p["model"])
        if rescue:
            # its own row — a clipped rescuer name is a dead fact
            rows.append(("", f"  → failed-over to {rescue}"))
    return compose_card("providers that failed the deterministic floor",
                        rows, glyph="⚑")


# ------------------------------------------------------------- attestation

def _check_terms(licenses_root: Path, home: Path | None) -> tuple[str, bool, str]:
    ok = licenses_accepted(license_files(licenses_root), home)
    return ("terms", ok,
            "acceptance matches current file hashes" if ok
            else "terms not accepted for the current files")


def _activation_mode(base: Path) -> str:
    """The deployment mode from the LAST activation record, or ''."""
    idr_file = base / "idr.jsonl"
    if not idr_file.exists():
        return ""
    mode = ""
    for line in idr_file.read_text(encoding="utf-8").splitlines():
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        if rec.get("kind") == "grasp-activation":
            mode = rec.get("decision", {}).get("mode", "")
    return mode


def _check_acl(base: Path, home: Path | None) -> tuple[str, bool, str]:
    acl_file = base / "visibility-acl.json"
    if not acl_file.exists():
        return ("acl", False, "visibility ACL missing")
    try:
        record = json.loads(acl_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return ("acl", False, "ACL unreadable")
    ok = verify_record(record, home)
    return ("acl", ok, "ACL signature verifies" if ok
            else "ACL signature INVALID — tampered?")


def _check_zero_egress(base: Path) -> tuple[str, bool, str]:
    """Re-run the private-mode socket-free round-trip, right now."""
    try:
        with egress_guard():
            probe_dir = base / "storage"
            probe_dir.mkdir(parents=True, exist_ok=True)
            (probe_dir / "attest-selfcheck").write_bytes(b"zero-egress")
            ok = (probe_dir / "attest-selfcheck").read_bytes() == b"zero-egress"
        # key "egress" (6 chars) — "zero-egress" fills the 11-col label
        # field exactly, gluing the glyph to the label on the card
        return ("egress", ok,
                "private ops re-ran socket-free" if ok
                else "round-trip mismatch")
    except Exception as exc:  # noqa: BLE001 — a failed replay is a finding
        return ("egress", False, f"replay failed: {exc}")


def _run_attestation_checks(licenses_root: Path, base: Path,
                            home: Path | None) -> tuple[str, list]:
    mode = _activation_mode(base)
    checks = [
        _check_terms(licenses_root, home),
        ("activation", bool(mode),
         f"mode {mode}" if mode else "no activation record found"),
    ]
    if mode in ("private", "combination"):
        checks.append(_check_acl(base, home))
    if mode == "private":
        checks.append(_check_zero_egress(base))
    shame_on = shame_surface_enabled(home)
    checks.append(("shame-gate", True,
                   "public surface ON (dual-gated)" if shame_on
                   else "public surface off (L3 default)"))
    return mode, checks


def self_attestation(licenses_root: Path, home: Path | None = None) -> dict:
    """GRASP proves GRASP: re-verify, right now, that this deployment
    abides by its own configuration. Every check is a REAL re-execution —
    provable compliance, never asserted compliance."""
    base = home or grasp_home()
    mode, checks = _run_attestation_checks(licenses_root, base, home)
    attested = all(ok for _, ok, _ in checks)
    result: dict = {"ok": attested, "attested": attested,
                    "checks": f"{sum(1 for _, ok, _ in checks if ok)}"
                              f"/{len(checks)} hold"}
    if mode:
        result["mode"] = mode
    for name, ok, detail in checks:
        result[name] = f"{'✓' if ok else '✗'} {detail}"
    if not attested:
        result["error"] = "; ".join(
            f"{name}: {detail}" for name, ok, detail in checks if not ok)
    record_event("self_attestation", "grasp",
                 FloorVerdict("pass" if attested else "fail",
                              salient=True, claims=len(checks)),
                 home, attested=attested)
    return result


def attestation_card(licenses_root: Path, home: Path | None = None) -> str:
    return render_card("grasp_attest", self_attestation(licenses_root, home))
