# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Wizard-shell contract: the whole interactive flow runs hermetically
through the injected WizardIO seam — no terminal, no builtins patching.

Falsifiers: a private picker offering an egress backend voids the air-gap
rule at the UI layer; a declined-terms path that still activates voids the
license gate; a silent fallback on invalid input hides operator error; a
wizard that skips the closing card ships no birth certificate.
"""
from __future__ import annotations

import json

import pytest

from grasp.activate import accept_licenses, license_files
from grasp.storage import ProbeResult, adapter_names
from grasp.wizard import WizardCancelled, WizardIO, run_wizard


class ScriptedIO:
    """A WizardIO backend driven by a canned answer list, capturing output."""

    def __init__(self, answers: list[str]) -> None:
        self.answers = list(answers)
        self.lines: list[str] = []

    def read(self, prompt: str) -> str:
        self.lines.append(prompt)
        if not self.answers:
            raise AssertionError(f"wizard asked more than scripted: {prompt!r}")
        return self.answers.pop(0)

    def write(self, line: str) -> None:
        self.lines.append(str(line))

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


def _io(answers: list[str]) -> tuple[WizardIO, ScriptedIO]:
    scripted = ScriptedIO(answers)
    return WizardIO(read=scripted.read, write=scripted.write), scripted


CANNED_PROBES = [
    ProbeResult("local", True, "records under this deployment's state dir"),
    ProbeResult("bitcoin-ots", False, "ots CLI not found",
                remedy="pipx install opentimestamps-client"),
    ProbeResult("s3", False, "no credentials in the environment"),
    ProbeResult("sepolia", False, "no signer command configured"),
    ProbeResult("ipfs", False, "kubo API not reachable on :5001"),
    ProbeResult("website", True, "renders a static chain-site locally"),
]


@pytest.fixture()
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("GRASP_HOME", str(tmp_path / "home"))
    return tmp_path / "home"


@pytest.fixture()
def terms_root(tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    (root / "LICENSE").write_text("AGPL-3.0-only\n")
    (root / "TERMS-OF-SERVICE.md").write_text("terms v1\n")
    return root


@pytest.fixture(autouse=True)
def _canned_probes(monkeypatch):
    monkeypatch.setattr("grasp.wizard.probe_all", lambda: list(CANNED_PROBES))


# ------------------------------------------------------------- happy paths

def test_public_flow_on_defaults_ends_on_birth_card(home, terms_root):
    io, scripted = _io(["", "", "y"])  # mode default, backends default, accept
    result = run_wizard(io, licenses_root=terms_root, home=home)
    assert result["ok"] and result["mode"] == "public"
    assert result["backends"] == "local"
    assert "╭─ Act I · Tier" in scripted.text
    assert "╭─ Act II · Storage" in scripted.text
    assert "╭─ Act III · Terms" in scripted.text
    assert "╭─ GRASP ● activated — chain born" in scripted.text
    assert "╰─ facta, non verba" in scripted.text
    assert (home / "idr.jsonl").exists()  # the signed birth record landed


def test_private_flow_excludes_egress_backends_and_writes_acl(home, terms_root):
    io, scripted = _io(["private", "local", "y", "fp-1, fp-2"])
    result = run_wizard(io, licenses_root=terms_root, home=home)
    assert result["mode"] == "private" and result["acl"] is True
    # every egress-capable backend is marked excluded in the picker
    for name in ("bitcoin-ots", "s3", "sepolia", "ipfs", "website"):
        assert f"{name}" in scripted.text
    assert scripted.text.count("private mode: excluded") == 5
    acl = json.loads((home / "visibility-acl.json").read_text())
    assert acl["admins"] == ["fp-1", "fp-2"]


def test_already_accepted_terms_skip_the_confirm(home, terms_root):
    accept_licenses(license_files(terms_root), home)
    io, scripted = _io(["", ""])  # no acceptance answer needed
    result = run_wizard(io, licenses_root=terms_root, home=home)
    assert result["ok"]
    assert "I have read and accept" not in scripted.text


# ------------------------------------------------------------- refusal paths

def test_declined_terms_cancel_without_activating(home, terms_root):
    io, scripted = _io(["", "", "n"])
    with pytest.raises(WizardCancelled):
        run_wizard(io, licenses_root=terms_root, home=home)
    assert "Activation cancelled — terms not accepted." in scripted.text
    assert not (home / "idr.jsonl").exists()  # no birth record


def test_invalid_mode_warns_and_uses_default(home, terms_root):
    io, scripted = _io(["stealthy", "", "y"])
    result = run_wizard(io, licenses_root=terms_root, home=home)
    assert result["mode"] == "public"
    assert "'stealthy' is not an option — using public" in scripted.text


def test_invalid_backend_falls_back_to_local_with_warning(home, terms_root):
    io, scripted = _io(["", "carrier-pigeon", "y"])
    result = run_wizard(io, licenses_root=terms_root, home=home)
    assert result["backends"] == "local"
    assert "no valid backend chosen — falling back to local" in scripted.text


def test_private_mode_cannot_pick_an_egress_backend(home, terms_root):
    # s3 is typed, but private offers only the zero-egress set -> local
    io, scripted = _io(["private", "s3", "y", "fp-admin"])
    result = run_wizard(io, licenses_root=terms_root, home=home)
    assert result["mode"] == "private" and result["backends"] == "local"
    assert "no valid backend chosen — falling back to local" in scripted.text


# ------------------------------------------------------------- redaction seam

def test_private_reports_unconfigured_redaction_seam(home, terms_root, monkeypatch):
    monkeypatch.delenv("GRASP_REDACTION_CMD", raising=False)
    io, scripted = _io(["private", "local", "y", "fp-1"])
    run_wizard(io, licenses_root=terms_root, home=home)
    assert "PII redaction seam: ✗ not configured" in scripted.text


def test_private_detects_resolvable_redaction_seam(home, terms_root, monkeypatch):
    import sys
    monkeypatch.setenv("GRASP_REDACTION_CMD", f"{sys.executable} -m redact")
    io, scripted = _io(["private", "local", "y", "fp-1"])
    run_wizard(io, licenses_root=terms_root, home=home)
    assert "PII redaction seam: ✓" in scripted.text


def test_public_mode_never_mentions_the_seam_or_admins(home, terms_root):
    io, scripted = _io(["", "", "y"])
    run_wizard(io, licenses_root=terms_root, home=home)
    assert "PII redaction seam" not in scripted.text
    assert "admins >" not in scripted.text


# ------------------------------------------------------------- live picker

def test_real_probe_all_renders_every_registered_backend(home, terms_root,
                                                         monkeypatch):
    # the one non-canned test: the picker lists the REAL six-name registry
    from grasp.storage import probe_all as real_probe_all
    monkeypatch.setattr("grasp.wizard.probe_all", real_probe_all)
    io, scripted = _io(["", "", "y"])
    run_wizard(io, licenses_root=terms_root, home=home)
    for name in adapter_names():
        assert name in scripted.text
    assert len(adapter_names()) == 6  # the full promised domain, no subset


def test_picker_shows_remedy_for_unready_offered_backend(home, terms_root):
    io, scripted = _io(["", "", "y"])
    run_wizard(io, licenses_root=terms_root, home=home)
    assert "↳ pipx install opentimestamps-client" in scripted.text
