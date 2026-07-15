"""The ``grasp activate`` wizard — a thin TUI shell over the tested core.

All activation RULES live in ``grasp.activate`` (mode legality, the
zero-egress air-gap constraint, the signed license gate, the birth IDR).
This module only gathers inputs and renders — three acts, box-drawing
banners consistent with the provenance cards, a LIVE storage-backend
picker (real ✓/✗ probes), and the activation card as the closing frame.

Testable by construction: every read/write goes through an injected
``WizardIO`` (default: stdin/stdout), so the whole interactive flow runs
hermetically under a scripted IO — no terminal, no monkeypatching of
builtins. (The activate-grip lesson: build the seam AND use it.)
"""
from __future__ import annotations

import os
import shlex
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from grasp.activate import (
    MODES,
    PRIVATE_ALLOWED,
    ActivationConfig,
    accept_licenses,
    activate,
    activation_card,
    license_files,
    licenses_accepted,
)
from grasp.card import WIDTH
from grasp.storage import ProbeResult, probe_all


@dataclass
class WizardIO:
    """The single seam every prompt and line of output passes through."""

    read: Callable[[str], str] = input
    write: Callable[[str], None] = print


def _banner(act: str, title: str) -> str:
    head = f"╭─ {act} · {title} "
    return head + "─" * max(0, WIDTH - len(head) - 1) + "╮"


class WizardCancelled(RuntimeError):
    """The operator declined the terms — a clean cancel, not an error."""


def _choose(io: WizardIO, label: str, options: tuple[str, ...], default: str) -> str:
    io.write(f"{label}: {' / '.join(options)}")
    raw = io.read(f"  [{default}] > ").strip().lower()
    if not raw:
        return default
    if raw not in options:
        io.write(f"  {raw!r} is not an option — using {default}")
        return default
    return raw


def _render_picker(io: WizardIO, probes: list[ProbeResult], offered: set[str]) -> None:
    io.write("Storage backends (live probe — choose from the ready ones):")
    for probe in probes:
        gated = "" if probe.name in offered else "  (private mode: excluded — reaches outside)"
        glyph = "✓" if probe.ready else "✗"
        io.write(f"  {glyph} {probe.name:<12} {probe.detail}{gated}")
        if not probe.ready and probe.remedy and probe.name in offered:
            io.write(f"      ↳ {probe.remedy}")


def _select_backends(io: WizardIO, mode: str, probes: list[ProbeResult]) -> tuple[str, ...]:
    offered = {p.name for p in probes if mode != "private" or p.name in PRIVATE_ALLOWED}
    _render_picker(io, probes, offered)
    raw = io.read("  backends (comma-separated) [local] > ").strip().lower()
    picked = [name.strip() for name in raw.split(",") if name.strip()] or ["local"]
    valid = tuple(name for name in picked if name in offered)
    if not valid:
        io.write("  no valid backend chosen — falling back to local")
        return ("local",)
    return valid


def _redaction_seam() -> tuple[bool, str]:
    """Detect the operator-wired PII-redaction seam. Detection only —
    honesty: we report whether a shield is configured and resolvable,
    never that redaction is enforced by us.

    A deployment wires redaction by setting ``GRASP_REDACTION_CMD`` to the
    command records pass through before storage (e.g. GRIP's redaction
    shield, or any stdin->stdout filter).
    """
    raw = os.environ.get("GRASP_REDACTION_CMD", "").strip()
    if not raw:
        return False, ("not configured — records store unredacted; set "
                       "GRASP_REDACTION_CMD to wire a PII shield")
    head = shlex.split(raw)[0]
    if shutil.which(head) or Path(head).exists():
        return True, raw
    return False, f"configured but {head!r} is not executable on this machine"


def _collect_admins(io: WizardIO) -> tuple[str, ...]:
    io.write("Verified admin/individual fingerprints (comma-separated) — "
             "only these may read records:")
    raw = io.read("  admins > ").strip()
    return tuple(fp.strip() for fp in raw.split(",") if fp.strip())


def _confirm(io: WizardIO, question: str) -> bool:
    return io.read(f"{question} [y/N] > ").strip().lower() in ("y", "yes")


def run_wizard(io: WizardIO, *, licenses_root: Path, home: Path | None = None) -> dict:
    """Drive the three-act activation. Returns the activation result dict.

    Raises ActivationError (from the core) on an illegal choice or refused
    terms — the shell surfaces it, never swallows it.
    """
    io.write(_banner("Act I", "Tier — how open is this deployment"))
    mode = _choose(io, "Mode", MODES, default="public")

    io.write(_banner("Act II", "Storage — where records + anchors live"))
    probes = probe_all()
    backends = _select_backends(io, mode, probes)

    io.write(_banner("Act III", "Terms + access"))
    files = license_files(licenses_root)
    io.write("License / terms to accept: "
             + (", ".join(f.name for f in files) or "NONE FOUND"))
    if not licenses_accepted(files, home):
        if not _confirm(io, "I have read and accept these terms"):
            io.write("Activation cancelled — terms not accepted.")
            raise WizardCancelled()
        accept_licenses(files, home)
        io.write("  terms accepted (signed, bound to their content hash)")

    admins: tuple[str, ...] = ()
    if mode in ("private", "combination"):
        wired, detail = _redaction_seam()
        io.write(f"  PII redaction seam: {'✓' if wired else '✗'} {detail}")
        admins = _collect_admins(io)

    config = ActivationConfig(mode=mode, backends=backends, admins=admins)
    result = activate(config, licenses_root, home)
    io.write("")
    io.write(activation_card(result))
    return result
