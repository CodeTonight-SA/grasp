"""Activation-core contract: gated, air-gapped, signed, honest.

Falsifiers: a private mode accepting an egress-capable backend voids the
zero-telemetry claim; an activation without accepted terms voids the
license gate; acceptance surviving CHANGED terms binds users to text they
never read; an egress guard that lets a socket through is theatre; an
activation that emits no signed IDR has no birth certificate.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import json
import socket
import urllib.request

import pytest

from grasp.activate import (
    ActivationConfig,
    ActivationError,
    EgressBlocked,
    accept_licenses,
    activate,
    activation_card,
    egress_guard,
    license_files,
    licenses_accepted,
    require_acceptance,
    write_visibility_acl,
)
from grasp.keys import signing_key


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


# ------------------------------------------------------------ config rules

def test_unknown_mode_and_backend_refused():
    with pytest.raises(ActivationError, match="unknown mode"):
        ActivationConfig(mode="stealthy", backends=("local",))
    with pytest.raises(ActivationError, match="carrier-pigeon"):
        ActivationConfig(mode="public", backends=("carrier-pigeon",))


def test_private_mode_is_zero_egress_by_construction():
    with pytest.raises(ActivationError, match="combination"):
        ActivationConfig(mode="private", backends=("local", "s3"), admins=("fp1",))
    # even the Bitcoin witness reaches calendar servers — private refuses it
    with pytest.raises(ActivationError, match="zero-egress"):
        ActivationConfig(mode="private", backends=("bitcoin-ots",), admins=("fp1",))


def test_private_and_combination_require_admins():
    with pytest.raises(ActivationError, match="admin"):
        ActivationConfig(mode="private", backends=("local",))
    with pytest.raises(ActivationError, match="admin"):
        ActivationConfig(mode="combination", backends=("local", "website"))


# ------------------------------------------------------------ license gate

def test_acceptance_binds_current_hashes(home, terms_root):
    files = license_files(terms_root)
    assert [f.name for f in files] == ["LICENSE", "TERMS-OF-SERVICE.md"]
    assert not licenses_accepted(files, home)
    record = accept_licenses(files, home)
    assert licenses_accepted(files, home)
    # signature verifies against the home signing key over the canonical body
    body = {k: record[k] for k in ("accepted_at", "files")}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac_mod.new(signing_key(home), payload, hashlib.sha256).hexdigest()
    assert record["sig"] == expected


def test_changed_terms_demand_reacceptance(home, terms_root):
    files = license_files(terms_root)
    accept_licenses(files, home)
    (terms_root / "TERMS-OF-SERVICE.md").write_text("terms v2 — changed\n")
    assert not licenses_accepted(license_files(terms_root), home)
    with pytest.raises(ActivationError, match="not yet accepted"):
        require_acceptance(license_files(terms_root), home)


def test_empty_terms_set_refused(home, tmp_path):
    with pytest.raises(ActivationError, match="mis-packaged"):
        accept_licenses([], home)


# ------------------------------------------------------------ egress guard

def test_egress_guard_blocks_sockets_and_restores():
    with egress_guard():
        with pytest.raises(EgressBlocked):
            socket.socket()
        with pytest.raises(EgressBlocked):  # urllib bottoms out in sockets too
            urllib.request.urlopen("http://127.0.0.1:1/")
    socket.socket().close()  # restored afterwards


# ------------------------------------------------------------ activation e2e

def test_activate_refuses_before_acceptance(home, terms_root):
    config = ActivationConfig(mode="public", backends=("local",))
    with pytest.raises(ActivationError, match="not yet accepted"):
        activate(config, terms_root, home)


def test_public_activation_emits_signed_birth_idr(home, terms_root):
    accept_licenses(license_files(terms_root), home)
    result = activate(ActivationConfig(mode="public", backends=("local",)),
                      terms_root, home)
    assert result["ok"] and result["id"].startswith("precog-")
    lines = (home / "idr.jsonl").read_text().strip().splitlines()
    born = json.loads(lines[-1])
    assert born["kind"] == "grasp-activation"
    assert born["decision"]["mode"] == "public"
    # real HMAC signing, never the legacy non-tamper-evident placeholder
    assert born["audit"]["scheme"] == "hmac-sha256"
    assert born["audit"]["signature"].startswith("hmac-sha256:")


def test_private_activation_selfchecks_under_guard_and_writes_acl(home, terms_root):
    accept_licenses(license_files(terms_root), home)
    result = activate(
        ActivationConfig(mode="private", backends=("local",), admins=("fp-admin-1",)),
        terms_root, home)
    assert result["ok"] and result["acl"]
    acl = json.loads((home / "visibility-acl.json").read_text())
    assert acl["admins"] == ["fp-admin-1"] and acl["sig"]


def test_visibility_acl_is_signed(home):
    path = write_visibility_acl(("b", "a"), home)
    record = json.loads(path.read_text())
    assert record["admins"] == ["a", "b"]  # deterministic order
    body = {k: record[k] for k in ("admins", "ts")}
    payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    assert record["sig"] == hmac_mod.new(
        signing_key(home), payload, hashlib.sha256).hexdigest()


def test_activation_card_is_the_birth_certificate(home, terms_root):
    accept_licenses(license_files(terms_root), home)
    result = activate(ActivationConfig(mode="public", backends=("local",)),
                      terms_root, home)
    card = activation_card(result)
    assert card.splitlines()[0].startswith("╭─ GRASP ● activated — chain born")
    assert "public" in card
    assert card.splitlines()[-1].startswith("╰─ facta, non verba")
