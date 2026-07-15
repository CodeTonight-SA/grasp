"""Activation core — the engine under the ``grasp activate`` wizard.

Non-interactive by design (the TUI wizard is a thin shell over these
functions), so every activation rule is testable without a terminal:

- **three modes** — ``public`` | ``private`` | ``combination``;
- **the air-gap rule (council-confirmed)** — ``private`` means ZERO
  egress, so private deployments may select only egress-free backends;
  deployments wanting a public witness over private records choose
  ``combination``;
- **the license gate** — activation refuses until the deployment's
  license/terms files are accepted; acceptance is a SIGNED record binding
  each file's sha256, so changed terms require re-acceptance;
- **the egress self-test** — private activation runs its storage
  self-check under ``egress_guard()``, which blocks socket creation
  in-process. Honesty: this proves OUR code paths open no sockets during
  private operations — it is the shipped falsifier for the zero-telemetry
  claim, not an OS firewall (air-gapping the host remains a deployment
  concern);
- **the birth certificate** — activation emits a signed IDR (the new
  deployment's first decision record) and renders it as a provenance card.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import socket
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from grasp.card import render_card
from grasp.home import grasp_home
from grasp.idr import append_idr, build_idr
from grasp.keys import signing_key
from grasp.storage import ProbeResult, adapter_names, get_adapter

MODES = ("public", "private", "combination")

# private = zero egress: only backends that never open a socket qualify.
# (Even Bitcoin-OTS submits to public calendar servers.) Public witnessing
# over private records is exactly what "combination" is for.
PRIVATE_ALLOWED = frozenset({"local"})


class ActivationError(RuntimeError):
    """A refusal with a plain-language remedy — never a silent skip."""


@dataclass(frozen=True)
class ActivationConfig:
    mode: str
    backends: tuple[str, ...]
    admins: tuple[str, ...] = field(default=())

    def __post_init__(self) -> None:
        if self.mode not in MODES:
            raise ActivationError(
                f"unknown mode {self.mode!r} — choose one of: {', '.join(MODES)}")
        unknown = [b for b in self.backends if b not in adapter_names()]
        if unknown:
            raise ActivationError(
                f"unknown storage backend(s) {', '.join(unknown)} — "
                f"available: {', '.join(adapter_names())}")
        if not self.backends:
            raise ActivationError("select at least one storage backend")
        if self.mode == "private":
            egress = [b for b in self.backends if b not in PRIVATE_ALLOWED]
            if egress:
                raise ActivationError(
                    f"private mode is zero-egress: {', '.join(egress)} "
                    "reach outside this machine. Keep private storage "
                    "local-only, or choose combination mode for a public "
                    "witness over private records")
        if self.mode in ("private", "combination") and not self.admins:
            raise ActivationError(
                f"{self.mode} mode needs at least one verified admin "
                "fingerprint for the visibility allowlist")


# ---------------------------------------------------------------- licenses

def license_files(root: Path) -> list[Path]:
    """The license/terms files an install carries (AGPL today; the adopted
    terms suite once signed off). Sorted for deterministic acceptance."""
    found = {p for pattern in ("LICENSE*", "TERMS*", "legal/*.md")
             for p in root.glob(pattern) if p.is_file()}
    return sorted(found)


def _acceptance_path(home: Path | None = None) -> Path:
    return (home or grasp_home()) / "license-acceptance.json"


def _signed(body: dict, home: Path | None = None) -> dict:
    key = signing_key(home)
    payload = json.dumps(body, sort_keys=True, separators=(",", ":"))
    return {**body,
            "fingerprint": hashlib.sha256(key).hexdigest()[:16],
            "sig": hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()}


def accept_licenses(files: list[Path], home: Path | None = None) -> dict:
    """Record signed acceptance of exactly these terms (by content hash)."""
    if not files:
        raise ActivationError(
            "no license/terms files found — a distribution without terms "
            "is mis-packaged; refusing to record an empty acceptance")
    body = {
        "accepted_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": [{"name": f.name,
                   "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
                  for f in files],
    }
    record = _signed(body, home)
    path = _acceptance_path(home)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return record


def licenses_accepted(files: list[Path], home: Path | None = None) -> bool:
    """True only when every CURRENT file hash is in the signed acceptance —
    changed terms honestly demand re-acceptance."""
    path = _acceptance_path(home)
    if not files or not path.exists():
        return False
    accepted = {entry["sha256"]
                for entry in json.loads(path.read_text(encoding="utf-8"))["files"]}
    current = {hashlib.sha256(f.read_bytes()).hexdigest() for f in files}
    return current <= accepted


def require_acceptance(files: list[Path], home: Path | None = None) -> None:
    if not licenses_accepted(files, home):
        names = ", ".join(f.name for f in files) or "none found"
        raise ActivationError(
            f"license terms not yet accepted (files: {names}) — run the "
            "activation wizard's license step, or call "
            "grasp.activate.accept_licenses(...) after reading them")


# ---------------------------------------------------------------- egress guard

class EgressBlocked(RuntimeError):
    """A private-mode operation attempted to open a network socket."""


@contextmanager
def egress_guard():
    """Block in-process socket creation — the zero-telemetry falsifier.

    Proves the guarded code path opens no sockets; not an OS firewall.
    """
    real_socket, real_connect = socket.socket, socket.create_connection

    def _blocked(*_args, **_kwargs):
        raise EgressBlocked(
            "private mode is zero-egress: a network socket was requested")

    socket.socket, socket.create_connection = _blocked, _blocked  # type: ignore[misc]
    try:
        yield
    finally:
        socket.socket, socket.create_connection = real_socket, real_connect  # type: ignore[misc]


# ---------------------------------------------------------------- visibility ACL

def write_visibility_acl(admins: tuple[str, ...], home: Path | None = None) -> Path:
    """Signed allowlist of verified individuals/admins who may read records."""
    record = _signed({"admins": sorted(admins),
                      "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, home)
    path = (home or grasp_home()) / "visibility-acl.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True), encoding="utf-8")
    return path


# ---------------------------------------------------------------- activation

def activate(config: ActivationConfig, licenses_root: Path,
             home: Path | None = None) -> dict:
    """Run the full activation: gate, harden, probe, and sign the birth IDR."""
    base = home or grasp_home()
    require_acceptance(license_files(licenses_root), home)

    if config.mode == "private":
        with egress_guard():  # the self-test: private ops open no sockets
            local = get_adapter("local", root=base / "storage")
            local.put("activation-selfcheck", b"zero-egress")
            if local.get("activation-selfcheck") != b"zero-egress":
                raise ActivationError("private self-check failed: local "
                                      "storage round-trip mismatch")

    acl_path: str | None = None
    if config.mode in ("private", "combination"):
        acl_path = str(write_visibility_acl(config.admins, home))

    probes: list[ProbeResult] = [get_adapter(name).probe() for name in config.backends]

    idr = build_idr(
        prompt="grasp activate",
        fingerprint=hashlib.sha256(signing_key(home)).hexdigest()[:16],
        decision={
            "what": "deployment activation",
            "why": "operator completed the GRASP activation wizard",
            "how": "grasp.activate.activate",
            "mode": config.mode,
            "backends": list(config.backends),
            "probes": {p.name: p.ready for p in probes},
            "visibility_acl": bool(acl_path),
        },
        predecessor_idr=None,
        depth=0,
        kind="grasp-activation",
    )
    append_idr(idr, path=(base / "idr.jsonl") if home is not None else None)

    return {
        "ok": True,
        "id": idr.id,
        "mode": config.mode,
        "backends": ", ".join(config.backends),
        "probes_ready": sum(1 for p in probes if p.ready),
        "count": len(probes),
        "acl": bool(acl_path),
    }


def activation_card(result: dict) -> str:
    """The deployment's birth certificate, as a provenance card."""
    return render_card("grasp_activate", result)
