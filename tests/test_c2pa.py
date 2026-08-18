# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Mutation-sensitive tests for grasp/c2pa.py (roadmap item 6: the C2PA bridge).

Signing uses the PUBLIC C2PA test credentials vendored from the c2pa-rs
repository (contentauth/c2pa-rs, sdk/tests/fixtures/certs/), which the c2pa
SDK's default trust accepts — so a signed asset reports is_valid True in the
test environment. The bridge itself never needs the credential to VERIFY a
binding; the deterministic gate is the assertion comparison.

Skipped cleanly on a hermetic install without the optional c2pa-python dep;
the no-dep degradation path is pinned separately in test_c2pa_unavailable.py.
"""
from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path

import pytest

pytest.importorskip("c2pa")

from grasp import c2pa

FIXTURES = Path(__file__).parent / "fixtures" / "c2pa"
CERTS_PEM = (FIXTURES / "es256_certs.pem").read_bytes()
KEY_PEM = (FIXTURES / "es256_private.pem").read_bytes()

ADDR = "sha256:" + "ab" * 32
ROOT = "sha256:" + "cd" * 32
TS = "2026-08-18T02:00:00Z"


def _png_1x1() -> bytes:
    sig = b"\x89PNG\r\n\x1a\n"

    def chunk(typ, data):
        c = typ + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c) & 0xFFFFFFFF)

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    idat = zlib.compress(b"\x00\xff\x00\x00")
    return sig + chunk(b"IHDR", ihdr) + chunk(b"IDAT", idat) + chunk(b"IEND", b"")


def _sign() -> bytes:
    manifest = c2pa.build_manifest(ADDR, ROOT, TS)
    return c2pa.sign_asset(manifest, _png_1x1(), "png",
                           cert_pem=CERTS_PEM, key_pem=KEY_PEM)


def test_manifest_carries_the_binding_assertion():
    manifest = json.loads(c2pa.build_manifest(ADDR, ROOT, TS))
    assert manifest["claim_generator"] == "grasp/0.3.0"
    a = manifest["assertions"][0]
    assert a["label"] == "grasp.idr.addr"
    assert a["data"] == {"content_addr": ADDR, "anchor_root": ROOT, "ts": TS}


def test_sign_and_extract_round_trip():
    signed = _sign()
    assert len(signed) > len(_png_1x1())  # the manifest was embedded
    data = c2pa.extract_assertion(signed)
    assert data == {"content_addr": ADDR, "anchor_root": ROOT, "ts": TS}


def test_binding_verifies_for_the_right_address():
    assert c2pa.verify_binding(_sign(), content_addr=ADDR, anchor_root=ROOT, ts=TS) is True


def test_binding_fails_on_mismatch():
    signed = _sign()
    wrong = "sha256:" + "ef" * 32
    assert c2pa.verify_binding(signed, content_addr=wrong, anchor_root=ROOT) is False
    assert c2pa.verify_binding(signed, content_addr=ADDR, anchor_root=wrong) is False
    assert c2pa.verify_binding(signed, content_addr=ADDR, anchor_root=ROOT,
                               ts="2020-01-01T00:00:00Z") is False


def test_binding_fails_on_unsigned_asset():
    assert c2pa.verify_binding(_png_1x1(), content_addr=ADDR, anchor_root=ROOT) is False


def test_manifest_validation_reports_valid():
    verdict = c2pa.manifest_validation(_sign())
    assert verdict is not None
    assert verdict["is_valid"] is True
