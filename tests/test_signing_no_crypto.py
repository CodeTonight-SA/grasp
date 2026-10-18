# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""The no-cryptography degradation path, pinned WITHOUT the optional package.

Simulate cryptography being absent (monkeypatch signing._crypto → None) and
assert monotone-safe behaviour: asymmetric signing raises a clear error,
asymmetric verification reads DEGRADED (never VERIFIED, never a crash), and the
default scheme REFUSES rather than falling back to HMAC-SHA256 unless the
operator opts in, in which case the fallback announces itself once (GRASP#20,
2026-10-18). Runs on every install, so the behaviour without the optional
dependency is always pinned.
"""
from __future__ import annotations

import pytest

from grasp import signing
from grasp import keys
from grasp.keys import signing_scheme
from grasp.verdict import Verdict

EH = "sha256:" + "ab" * 32


@pytest.fixture
def no_crypto(monkeypatch):
    monkeypatch.setattr(signing, "_crypto", lambda: None)


def test_crypto_available_false(no_crypto):
    assert signing.crypto_available() is False


def test_sign_asymmetric_raises_clearly(no_crypto):
    with pytest.raises(signing.SigningUnavailable):
        signing.sign(EH, "ed25519", ed25519_seed=b"\x00" * 32)


def test_verify_asymmetric_degrades_not_broken(no_crypto):
    audit = {"scheme": "ed25519", "key_fingerprint": "x" * 16, "signature": "00" * 64}
    assert signing.verify(EH, audit, ed25519_pub=b"\x00" * 32) is Verdict.DEGRADED


def _implicit(monkeypatch):
    """No explicit scheme, no symmetric key: the resolver's third step decides."""
    monkeypatch.delenv("GRASP_SIGNING_SCHEME", raising=False)
    monkeypatch.delenv("GRASP_SIGNING_KEY", raising=False)
    monkeypatch.setattr(keys, "_fallback_announced", False)


def test_signing_scheme_refuses_without_the_backend_by_default(no_crypto, monkeypatch):
    """INVERTED on 2026-10-18 (GRASP#20). This test used to pin the silent fall
    back to HMAC-SHA256 as the default. A record a stranger cannot verify,
    produced where a verifiable one was one install away, is the defect; the
    operator chose refusal as the default and the loud fallback behind an
    explicit opt-in. The refusal names the remedy and the opt-in."""
    _implicit(monkeypatch)
    monkeypatch.delenv(keys.ALLOW_HMAC_FALLBACK_ENV, raising=False)
    with pytest.raises(keys.SigningBackendUnavailable) as excinfo:
        signing_scheme()
    text = str(excinfo.value)
    assert "cryptography" in text and keys.ALLOW_HMAC_FALLBACK_ENV in text


def test_the_opt_in_falls_back_to_hmac_and_says_so_once(no_crypto, monkeypatch, capsys):
    _implicit(monkeypatch)
    monkeypatch.setenv(keys.ALLOW_HMAC_FALLBACK_ENV, "1")
    assert signing_scheme() == "hmac-sha256"
    assert signing_scheme() == "hmac-sha256"
    err = capsys.readouterr().err
    assert err.count("NOT stranger-verifiable") == 1, err
    assert "cryptography" in err


def test_an_explicit_hmac_request_is_honoured_silently(no_crypto, monkeypatch, capsys):
    """Asking for the symmetric scheme is not a fallback: no refusal, no notice."""
    _implicit(monkeypatch)
    monkeypatch.delenv(keys.ALLOW_HMAC_FALLBACK_ENV, raising=False)
    monkeypatch.setenv("GRASP_SIGNING_SCHEME", "hmac-sha256")
    assert signing_scheme() == "hmac-sha256"
    monkeypatch.delenv("GRASP_SIGNING_SCHEME")
    monkeypatch.setenv("GRASP_SIGNING_KEY", "test-secret")
    assert signing_scheme() == "hmac-sha256"
    assert capsys.readouterr().err == ""


def test_the_opt_in_is_exact(no_crypto, monkeypatch):
    _implicit(monkeypatch)
    for value in ("", "0", "true", "yes"):
        monkeypatch.setenv(keys.ALLOW_HMAC_FALLBACK_ENV, value)
        with pytest.raises(keys.SigningBackendUnavailable):
            signing_scheme()


def test_the_cli_turns_the_refusal_into_one_line_and_exit_2(monkeypatch, capsys):
    """A stranger running `grasp` on a machine without the backend sees the
    refusal, the remedy and the opt-in on one stderr line, never a traceback."""
    import argparse
    from grasp import cli

    def raising(_args):
        raise keys.SigningBackendUnavailable("the backend is missing; remedy X; opt-in Y")

    class Parser:
        def parse_args(self, argv):
            return argparse.Namespace(func=raising)

    monkeypatch.setattr(cli, "_build_parser", lambda: Parser())
    assert cli.main(["seal"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("grasp: ") and "remedy X" in err and "Traceback" not in err
