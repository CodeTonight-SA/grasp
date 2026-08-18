# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Mutation-sensitive tests for grasp/rfc3161.py (RFC 3161 TSP client).

Hermetic by construction: every fixture below is a frozen DER literal. The
granted response is a REAL CMS token — TSTInfo and signedAttrs hand-assembled,
RSA-signed with OpenSSL against a freshly generated key, then the bytes were
frozen here. The test suite never runs OpenSSL and never touches a network.

Mutation sensitivity (verified by hand before first commit; do not weaken):

* Flipping any byte of the request literal, or changing the DER encoder,
  breaks the exact-byte request tests.
* Flipping a byte of the CMS signature breaks test_signature_tamper_fails.
* Flipping a byte of the imprint inside the token breaks both the digest and
  the signature check (test_imprint_tamper_fails).
* Weakening message_imprint_matches, verify_message_imprint, the nonce echo,
  the status gate, or the signature check each breaks its dedicated test.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from unittest import mock

import pytest

from grasp import rfc3161
from grasp.rfc3161 import (
    DerError,
    OID_SHA1,
    OID_SHA256,
    OID_TST_INFO,
    TimeStampRejectedError,
    TsaRequestError,
    build_timestamp_request,
    compute_message_imprint,
    extract_tst_info,
    message_imprint_matches,
    parse_timestamp_request,
    parse_timestamp_response,
    parse_tst_info,
    send_timestamp_request,
    time_window,
    timestamp_age,
    verify_message_imprint,
    verify_time_stamp_response,
    verify_time_stamp_token,
)
from grasp.rfc3161 import _parse_content_info, _parse_signed_data, _parse_signer_info

# ---------------------------------------------------------------------------
# Frozen fixtures (see module docstring of this file for provenance)
# ---------------------------------------------------------------------------
FIXTURE_DATA = bytes.fromhex(
    "4752415350205246432033313631206865726d657469632066697874757265207061796c6f6164")
FIXTURE_IMPRINT = bytes.fromhex(
    "d4985f133c273cb9c439992c882acb0ac1fb5ed4c60a9964ede2385eaee11e7c")
POLICY = "1.3.6.1.4.1.13762.3"
NONCE = 0x5A5A5A5A5A5A5A5A
SERIAL = 0x010203040506
GEN_TIME = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)

#: TimeStampReq for sha256("abc"), no options — hand-computed DER, so the
#: encoder is tested against arithmetic rather than against itself.
REQUEST_SHA256_ABC_HEX = (
    "3034020101302f300b06096086480165030402010420"
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

#: TimeStampReq for FIXTURE_DATA with policy + nonce + certReq=True.
REQUEST_FULL_HEX = (
    "304b020101302f300b06096086480165030402010420"
    "d4985f133c273cb9c439992c882acb0ac1fb5ed4c60a9964ede2385eaee11e7c"
    "06082b06010401eb420302085a5a5a5a5a5a5a5a0101ff")

#: Full granted TimeStampResp: PKIStatusInfo(0) + CMS token whose signedAttrs
#: carry a genuine OpenSSL RSA-2048/SHA-256 signature over a hand-built
#: TSTInfo (genTime 2025-06-01T12:00:00Z, accuracy 1s/500ms/250us, nonce echo).
GRANTED_RESPONSE_HEX = (
    "308205e13003020100308205d806092a864886f70d010702a08205c9308205c5020103"
    "310f300d06096086480165030402010500308181060b2a864886f70d0109100104a072"
    "0470306e02010106082b06010401eb4203302f300b06096086480165030402010420d4"
    "985f133c273cb9c439992c882acb0ac1fb5ed4c60a9964ede2385eaee11e7c02060102"
    "03040506180f32303235303630313132303030305a300b020101800201f4810200fa02"
    "085a5a5a5a5a5a5a5aa0820359308203553082023da003020102021474863dd1df5208"
    "a955c487a560992e58e4feb303300d06092a864886f70d01010b0500303a311f301d06"
    "035504030c164752415350205246433331363120546573742054534131173015060355"
    "040a0c0e436f6465546f6e69676874205341301e170d3236303831383030313535385a"
    "170d3336303831353030313535385a303a311f301d06035504030c1647524153502052"
    "46433331363120546573742054534131173015060355040a0c0e436f6465546f6e6967"
    "687420534130820122300d06092a864886f70d01010105000382010f003082010a0282"
    "01010093becdbd870ac032a33839d228946acb3a0f8d4a28157196100e4b12367f8454"
    "a290b4048b5642de7da296c5fd6e3db6a7dba9568b8e412072880c4ae11273f7cf5114"
    "06556d2d5f2d491633b45f02264e53057ab2d8ce3b23d4c120b81d68110764a661d62a"
    "fdcf9d9c25ff065589053773dc3ae782e10c0e04b8d3f16a0d939dbda1d59238dd74fd"
    "7cacacc941ee6a92fef64293b83590a4e1b1956337cbeb030eabac4aeb3661c487df83"
    "f52727c6af3ca7bb5e50cf12bb7b206026b545dfa41669f26ba4bde2b644c316a931fe"
    "250dbffad80eb93c92060531d06e248149085df7231b6cc98fc05ad17da4389e3613ca"
    "00780e5bf607d322421b5c7ad6ef0203010001a3533051301d0603551d0e04160414d1"
    "0ac7ee74ebe2c05ce7bacf2ae0f464a1e9c512301f0603551d23041830168014d10ac7"
    "ee74ebe2c05ce7bacf2ae0f464a1e9c512300f0603551d130101ff040530030101ff30"
    "0d06092a864886f70d01010b05000382010100369a6ffa8eaaf0029b318056c988d1b2"
    "2a778f8c6e5b8310395cff302a2ecddd046d90f6f2a92cac35579421d27efaab5085b5"
    "0577314d721b90dbd6e38e01f20c576b4c879a942e60c395650840e2285de5733f1ec4"
    "8459f2760e10468ee2cf02e40d57e1f0cdc4e701e80f34e7b8b147769380fde1abeec5"
    "8d657fd925e6c0e6623eb21821deb33f463df993de5cea74faff946d0ed9b053d1504e"
    "71e2b30b964660c5851ed811eb4aaaa109ded343ee3aef9a53790464ea874748cd2c77"
    "07896d1471358c2d4ee53c3567d958568eaa46517afba0b6ecf5c599d39fb956f18823"
    "396491234b6f01e57ee915772259e5864f7df1d6d063d28bca6e04b10f8d318201cc30"
    "8201c80201013052303a311f301d06035504030c164752415350205246433331363120"
    "546573742054534131173015060355040a0c0e436f6465546f6e696768742053410214"
    "74863dd1df5208a955c487a560992e58e4feb303300d06096086480165030402010500"
    "a04d301a06092a864886f70d010903310d060b2a864886f70d0109100104302f06092a"
    "864886f70d01090431220420698f187792a826bbeb06adaed8933e199092fde00339b6"
    "7fa7a96d592f456319300d06092a864886f70d01010b05000482010044b8398f28fb92"
    "f0250edd9819db39c92c8cfce2a9732810c54661fad6a5fb13879faca5ef299d42eb1b"
    "3b7c1b05fc638abbb0f13577de37476cccc147e42246571b21e7abc58011ac0d81fb77"
    "92b0d2639fce7b457889920cbeb94105a9389eef80a49d2a2c1aef84fc423114320129"
    "ffc0e6c0bb5728a33a7dec9c38095cadc26b34da96239d0cd6dca50559c9bfdf32bdda"
    "23ac2a8205e4fa7cf9ad0fd36ba784c550755987b8d302a0654843992e8b39e4d19b9c"
    "e22f298e2aae9dd0217befda4c19f5c414f8194bcebcb09dad9e17cdb0f458442ae6c4"
    "02b9ed863e2b6503cdb14697bd1222f9ad271cd22168aeb660a7f2bb143a9efbd8c972"
    "b7e3bcaa")

#: Same token with the signatureAlgorithm swapped to ecdsa-with-SHA256: the
#: deterministic checks still pass, the signature reports unsupported_algorithm.
ECDSA_CLAIM_TOKEN_HEX = (
    "308205d506092a864886f70d010702a08205c6308205c2020103310f300d0609608648"
    "0165030402010500308181060b2a864886f70d0109100104a0720470306e0201010608"
    "2b06010401eb4203302f300b06096086480165030402010420d4985f133c273cb9c439"
    "992c882acb0ac1fb5ed4c60a9964ede2385eaee11e7c0206010203040506180f323032"
    "35303630313132303030305a300b020101800201f4810200fa02085a5a5a5a5a5a5a5a"
    "a0820359308203553082023da003020102021474863dd1df5208a955c487a560992e58"
    "e4feb303300d06092a864886f70d01010b0500303a311f301d06035504030c16475241"
    "5350205246433331363120546573742054534131173015060355040a0c0e436f646554"
    "6f6e69676874205341301e170d3236303831383030313535385a170d33363038313530"
    "30313535385a303a311f301d06035504030c1647524153502052464333313631205465"
    "73742054534131173015060355040a0c0e436f6465546f6e6967687420534130820122"
    "300d06092a864886f70d01010105000382010f003082010a028201010093becdbd870a"
    "c032a33839d228946acb3a0f8d4a28157196100e4b12367f8454a290b4048b5642de7d"
    "a296c5fd6e3db6a7dba9568b8e412072880c4ae11273f7cf511406556d2d5f2d49163"
    "3b45f02264e53057ab2d8ce3b23d4c120b81d68110764a661d62afdcf9d9c25ff0655"
    "89053773dc3ae782e10c0e04b8d3f16a0d939dbda1d59238dd74fd7cacacc941ee6a9"
    "2fef64293b83590a4e1b1956337cbeb030eabac4aeb3661c487df83f52727c6af3ca7"
    "bb5e50cf12bb7b206026b545dfa41669f26ba4bde2b644c316a931fe250dbffad80eb9"
    "3c92060531d06e248149085df7231b6cc98fc05ad17da4389e3613ca00780e5bf607d3"
    "22421b5c7ad6ef0203010001a3533051301d0603551d0e04160414d10ac7ee74ebe2c0"
    "5ce7bacf2ae0f464a1e9c512301f0603551d23041830168014d10ac7ee74ebe2c05ce7"
    "bacf2ae0f464a1e9c512300f0603551d130101ff040530030101ff300d06092a864886"
    "f70d01010b05000382010100369a6ffa8eaaf0029b318056c988d1b22a778f8c6e5b83"
    "10395cff302a2ecddd046d90f6f2a92cac35579421d27efaab5085b50577314d721b90"
    "dbd6e38e01f20c576b4c879a942e60c395650840e2285de5733f1ec48459f2760e104"
    "68ee2cf02e40d57e1f0cdc4e701e80f34e7b8b147769380fde1abeec58d657fd925e6c"
    "0e6623eb21821deb33f463df993de5cea74faff946d0ed9b053d1504e71e2b30b9646"
    "60c5851ed811eb4aaaa109ded343ee3aef9a53790464ea874748cd2c7707896d147135"
    "8c2d4ee53c3567d958568eaa46517afba0b6ecf5c599d39fb956f18823396491234b6f"
    "01e57ee915772259e5864f7df1d6d063d28bca6e04b10f8d318201c9308201c5020101"
    "3052303a311f301d06035504030c164752415350205246433331363120546573742054"
    "534131173015060355040a0c0e436f6465546f6e69676874205341021474863dd1df52"
    "08a955c487a560992e58e4feb303300d06096086480165030402010500a04d301a0609"
    "2a864886f70d010903310d060b2a864886f70d0109100104302f06092a864886f70d01"
    "090431220420698f187792a826bbeb06adaed8933e199092fde00339b67fa7a96d592f"
    "456319300a06082a8648ce3d0403020482010044b8398f28fb92f0250edd9819db39c9"
    "2c8cfce2a9732810c54661fad6a5fb13879faca5ef299d42eb1b3b7c1b05fc638abbb"
    "0f13577de37476cccc147e42246571b21e7abc58011ac0d81fb7792b0d2639fce7b45"
    "7889920cbeb94105a9389eef80a49d2a2c1aef84fc423114320129ffc0e6c0bb5728a3"
    "3a7dec9c38095cadc26b34da96239d0cd6dca50559c9bfdf32bdda23ac2a8205e4fa7c"
    "f9ad0fd36ba784c550755987b8d302a0654843992e8b39e4d19b9ce22f298e2aae9dd"
    "0217befda4c19f5c414f8194bcebcb09dad9e17cdb0f458442ae6c402b9ed863e2b650"
    "3cdb14697bd1222f9ad271cd22168aeb660a7f2bb143a9efbd8c972b7e3bcaa")

#: ContentInfo(id-signedData) whose eContentType is id-data — a token that is
#: NOT a TSTInfo envelope; extraction must refuse it.
WRONG_CONTENT_TYPE_TOKEN_HEX = (
    "303b06092a864886f70d010702a02e302c020103310f300d0609608648016503040201"
    "0500301406092a864886f70d010701a007040568656c6c6f3100")

#: PKIStatusInfo: status 2 (rejection), statusString "bad algorithm",
#: failInfo bit 0 (bad_alg).
REJECTION_RESPONSE_HEX = "301a3018020102300f0c0d62616420616c676f726974686d03020080"

#: granted status with NO token — a TSA bug the verifier must refuse.
GRANTED_NO_TOKEN_HEX = "30053003020100"

#: Minimal TSTInfo with fractional-seconds Zulu genTime.
TSTINFO_FRACTION_HEX = (
    "305602010106082b06010401eb4203302f300b060960864801650304020104208950ab"
    "fda7b727630760dd35bcf5c3daa7631aff223a90f7728c0d2521dde10c020107181332"
    "303235303630313132303030302e3530305a")

#: Minimal TSTInfo with a +02:30 offset genTime.
TSTINFO_OFFSET_HEX = (
    "305602010106082b06010401eb4203302f300b060960864801650304020104208950ab"
    "fda7b727630760dd35bcf5c3daa7631aff223a90f7728c0d2521dde10c020107181332"
    "303235303630313132303030302b30323330")

CERT_HEX = (
    "308203553082023da003020102021474863dd1df5208a955c487a560992e58e4feb303"
    "300d06092a864886f70d01010b0500303a311f301d06035504030c1647524153502052"
    "46433331363120546573742054534131173015060355040a0c0e436f6465546f6e6967"
    "6874205341301e170d3236303831383030313535385a170d3336303831353030313535"
    "385a303a311f301d06035504030c164752415350205246433331363120546573742054"
    "534131173015060355040a0c0e436f6465546f6e6967687420534130820122300d0609"
    "2a864886f70d01010105000382010f003082010a028201010093becdbd870ac032a338"
    "39d228946acb3a0f8d4a28157196100e4b12367f8454a290b4048b5642de7da296c5f"
    "d6e3db6a7dba9568b8e412072880c4ae11273f7cf511406556d2d5f2d491633b45f02"
    "264e53057ab2d8ce3b23d4c120b81d68110764a661d62afdcf9d9c25ff06558905377"
    "3dc3ae782e10c0e04b8d3f16a0d939dbda1d59238dd74fd7cacacc941ee6a92fef642"
    "93b83590a4e1b1956337cbeb030eabac4aeb3661c487df83f52727c6af3ca7bb5e50c"
    "f12bb7b206026b545dfa41669f26ba4bde2b644c316a931fe250dbffad80eb93c92060"
    "531d06e248149085df7231b6cc98fc05ad17da4389e3613ca00780e5bf607d322421b5"
    "c7ad6ef0203010001a3533051301d0603551d0e04160414d10ac7ee74ebe2c05ce7bac"
    "f2ae0f464a1e9c512301f0603551d23041830168014d10ac7ee74ebe2c05ce7bacf2ae"
    "0f464a1e9c512300f0603551d130101ff040530030101ff300d06092a864886f70d010"
    "10b05000382010100369a6ffa8eaaf0029b318056c988d1b22a778f8c6e5b8310395cf"
    "f302a2ecddd046d90f6f2a92cac35579421d27efaab5085b50577314d721b90dbd6e38"
    "e01f20c576b4c879a942e60c395650840e2285de5733f1ec48459f2760e10468ee2cf0"
    "2e40d57e1f0cdc4e701e80f34e7b8b147769380fde1abeec58d657fd925e6c0e6623eb"
    "21821deb33f463df993de5cea74faff946d0ed9b053d1504e71e2b30b964660c5851e"
    "d811eb4aaaa109ded343ee3aef9a53790464ea874748cd2c7707896d1471358c2d4ee5"
    "3c3567d958568eaa46517afba0b6ecf5c599d39fb956f18823396491234b6f01e57ee9"
    "15772259e5864f7df1d6d063d28bca6e04b10f8d")

GRANTED = bytes.fromhex(GRANTED_RESPONSE_HEX)
ECDSA_CLAIM = bytes.fromhex(ECDSA_CLAIM_TOKEN_HEX)
WRONG_CT = bytes.fromhex(WRONG_CONTENT_TYPE_TOKEN_HEX)
REJECTED = bytes.fromhex(REJECTION_RESPONSE_HEX)
GRANTED_NO_TOKEN = bytes.fromhex(GRANTED_NO_TOKEN_HEX)
CERT = bytes.fromhex(CERT_HEX)
SHA256_ABC = bytes.fromhex(
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


def _token(der: bytes) -> bytes:
    return parse_timestamp_response(der).token_der


def _granted_tst():
    return extract_tst_info(_token(GRANTED))


def _header(req, name):
    """Case-insensitive header lookup: urllib normalises keys to
    'Content-type' / 'User-agent', so exact-case get_header is a trap."""
    for table in (req.headers, req.unredirected_hdrs):
        for key, value in table.items():
            if key.lower() == name.lower():
                return value
    return None


# ---------------------------------------------------------------------------
# TimeStampReq building
# ---------------------------------------------------------------------------
def test_compute_message_imprint_sha256_exact():
    mi = compute_message_imprint(b"abc")
    assert mi.hash_algorithm.algorithm == OID_SHA256
    assert mi.hash_algorithm.parameters is None  # RFC 5754: no params for SHA-2
    assert mi.hashed_message == SHA256_ABC
    assert mi.hashed_message == hashlib.sha256(b"abc").digest()


def test_compute_message_imprint_sha1_carries_null_params():
    mi = compute_message_imprint(b"abc", "sha1")
    assert mi.hash_algorithm.algorithm == OID_SHA1
    assert mi.hash_algorithm.parameters == b"\x05\x00"
    assert mi.hashed_message == hashlib.sha1(b"abc").digest()


def test_compute_message_imprint_unknown_algorithm_raises():
    with pytest.raises(ValueError):
        compute_message_imprint(b"abc", "sha999")


def test_build_request_exact_bytes_no_options():
    # Hand-computed literal: version 1 + sha256("abc") imprint, no defaults
    # emitted (DER omits BOOLEAN DEFAULT FALSE).
    assert build_timestamp_request(b"abc") == bytes.fromhex(REQUEST_SHA256_ABC_HEX)


def test_build_request_exact_bytes_with_options():
    assert build_timestamp_request(
        FIXTURE_DATA, req_policy=POLICY, nonce=NONCE, cert_req=True
    ) == bytes.fromhex(REQUEST_FULL_HEX)


def test_build_request_nonce_and_certreq_bytes():
    der = build_timestamp_request(b"n", nonce=0x0102030405060708, cert_req=True)
    assert b"\x02\x08\x01\x02\x03\x04\x05\x06\x07\x08" in der
    assert der.endswith(b"\x01\x01\xff")
    der_no_cert = build_timestamp_request(b"n", nonce=7)
    assert b"\x01\x01\xff" not in der_no_cert


def test_build_request_requires_data_or_imprint():
    with pytest.raises(ValueError):
        build_timestamp_request()


def test_build_request_negative_nonce_raises():
    with pytest.raises(ValueError):
        build_timestamp_request(b"x", nonce=-1)


def test_build_request_hash_alias_sha_256():
    assert (compute_message_imprint(b"abc", "SHA-256").hash_algorithm.algorithm
            == OID_SHA256)


# ---------------------------------------------------------------------------
# TimeStampReq parsing
# ---------------------------------------------------------------------------
def test_parse_request_roundtrip():
    req = parse_timestamp_request(build_timestamp_request(
        FIXTURE_DATA, req_policy=POLICY, nonce=NONCE, cert_req=True))
    assert req.version == 1
    assert req.message_imprint.hashed_message == FIXTURE_IMPRINT
    assert req.req_policy == POLICY
    assert req.nonce == NONCE
    assert req.cert_req is True


def test_parse_request_literal():
    req = parse_timestamp_request(bytes.fromhex(REQUEST_SHA256_ABC_HEX))
    assert req.version == 1
    assert req.message_imprint.hash_algorithm.algorithm == OID_SHA256
    assert req.message_imprint.hashed_message == SHA256_ABC
    assert req.nonce is None
    assert req.cert_req is False
    assert req.req_policy is None


def test_parse_request_rejects_truncated():
    with pytest.raises(DerError):
        parse_timestamp_request(b"\x30\x05\x02\x01\x01")


# ---------------------------------------------------------------------------
# TimeStampResp / status parsing
# ---------------------------------------------------------------------------
def test_parse_granted_response_status():
    resp = parse_timestamp_response(GRANTED)
    assert resp.status.status == 0
    assert resp.status.status_name == "granted"
    assert resp.status.status_string == ()
    assert resp.status.fail_info == frozenset()
    assert resp.token_der is not None


def test_parse_rejection_response_named_bits():
    resp = parse_timestamp_response(REJECTED)
    assert resp.status.status == 2
    assert resp.status.status_name == "rejection"
    assert resp.status.status_string == ("bad algorithm",)
    assert resp.status.fail_info == frozenset({"bad_alg"})
    assert resp.token_der is None


def test_parse_granted_without_token():
    resp = parse_timestamp_response(GRANTED_NO_TOKEN)
    assert resp.status.status == 0
    assert resp.token_der is None


def test_parse_response_truncated_raises():
    with pytest.raises(DerError):
        parse_timestamp_response(b"\x30\x05")


def test_parse_response_trailing_junk_raises():
    with pytest.raises(DerError):
        parse_timestamp_response(GRANTED + b"\x00")


# ---------------------------------------------------------------------------
# TSTInfo extraction
# ---------------------------------------------------------------------------
def test_extract_tst_info_all_fields():
    tst = _granted_tst()
    assert tst.version == 1
    assert tst.policy == POLICY
    assert tst.serial_number == SERIAL
    assert tst.gen_time == GEN_TIME
    assert tst.gen_time.tzinfo is not None
    assert tst.accuracy == rfc3161.Accuracy(seconds=1, millis=500, micros=250)
    assert tst.ordering is False
    assert tst.nonce == NONCE
    assert tst.tsa is None
    assert tst.message_imprint.hash_algorithm.algorithm == OID_SHA256
    assert tst.message_imprint.hashed_message == FIXTURE_IMPRINT


def test_extract_tst_info_rejects_wrong_econtent_type():
    with pytest.raises(DerError):
        extract_tst_info(WRONG_CT)


def test_parse_tst_info_fractional_zulu():
    tst = parse_tst_info(bytes.fromhex(TSTINFO_FRACTION_HEX))
    assert tst.gen_time == datetime(2025, 6, 1, 12, 0, 0, 500000,
                                    tzinfo=timezone.utc)


def test_parse_tst_info_offset():
    tst = parse_tst_info(bytes.fromhex(TSTINFO_OFFSET_HEX))
    assert tst.gen_time == datetime(2025, 6, 1, 12, 0, 0,
                                    tzinfo=timezone(timedelta(hours=2,
                                                              minutes=30)))


def test_accuracy_total_seconds():
    assert rfc3161.Accuracy(1, 500, 250).total_seconds == 1.50025


# ---------------------------------------------------------------------------
# Imprint / digest / nonce checks
# ---------------------------------------------------------------------------
def test_verify_message_imprint_true_for_fixture_data():
    assert verify_message_imprint(_granted_tst(), FIXTURE_DATA) is True


def test_verify_message_imprint_false_for_wrong_data():
    assert verify_message_imprint(_granted_tst(), b"other payload") is False


def test_message_imprint_matches():
    expected = compute_message_imprint(FIXTURE_DATA)
    assert message_imprint_matches(expected, _granted_tst().message_imprint) is True
    assert message_imprint_matches(
        compute_message_imprint(FIXTURE_DATA, "sha1"),
        _granted_tst().message_imprint) is False


# ---------------------------------------------------------------------------
# Token / response verification
# ---------------------------------------------------------------------------
def test_verify_token_full_verdict():
    ver = verify_time_stamp_token(
        _token(GRANTED), data=FIXTURE_DATA, expected_nonce=NONCE)
    assert ver.signature_status == "verified"
    assert ver.signature_detail == "RSA PKCS#1 v1.5 signature verified"
    assert ver.encap_content_type == OID_TST_INFO
    assert ver.imprint_matches is True
    assert ver.digest_valid is True
    assert ver.nonce_matches is True


def test_verify_token_wrong_data_fails_digest_and_imprint():
    ver = verify_time_stamp_token(
        _token(GRANTED), data=b"not the stamped payload", expected_nonce=NONCE)
    assert ver.digest_valid is False
    assert ver.imprint_matches is False
    assert ver.signature_status == "verified"  # the signature is still good


def test_verify_token_wrong_nonce_fails_echo():
    ver = verify_time_stamp_token(
        _token(GRANTED), data=FIXTURE_DATA, expected_nonce=NONCE + 1)
    assert ver.nonce_matches is False
    assert ver.tst_info.nonce == NONCE


def test_verify_token_explicit_imprint():
    ver = verify_time_stamp_token(
        _token(GRANTED),
        expected_message_imprint=compute_message_imprint(FIXTURE_DATA))
    assert ver.imprint_matches is True


def test_verify_token_signature_tamper_fails():
    token = _token(GRANTED)
    _, sd_content = _parse_content_info(token)
    sd = _parse_signed_data(sd_content)
    sig = _parse_signer_info(sd.signer_infos[0]).signature
    assert len(sig) == 256  # RSA-2048
    idx = token.find(sig)
    assert idx != -1 and token.count(sig) == 1
    flipped = bytes([sig[0] ^ 0xFF])
    tampered = token[:idx] + flipped + token[idx + 1:]
    ver = verify_time_stamp_token(tampered, data=FIXTURE_DATA,
                                  expected_nonce=NONCE)
    assert ver.signature_status == "invalid"
    assert ver.digest_valid is True  # the signature is independent of the checks


def test_verify_token_imprint_tamper_fails_digest_and_signature():
    token = _token(GRANTED)
    idx = token.find(FIXTURE_IMPRINT)
    assert idx != -1 and token.count(FIXTURE_IMPRINT) == 1
    flipped = bytes([FIXTURE_IMPRINT[0] ^ 0xFF])
    tampered = token[:idx] + flipped + token[idx + 1:]
    ver = verify_time_stamp_token(tampered, data=FIXTURE_DATA,
                                  expected_nonce=NONCE)
    assert ver.digest_valid is False
    assert ver.signature_status == "invalid"  # message-digest attr no longer matches


def test_verify_token_skip_signature():
    ver = verify_time_stamp_token(
        _token(GRANTED), data=FIXTURE_DATA, expected_nonce=NONCE,
        verify_signature=False)
    assert ver.signature_status == "not_verified"
    assert ver.imprint_matches is True and ver.digest_valid is True


def test_verify_token_unsupported_signature_algorithm_is_reported():
    ver = verify_time_stamp_token(ECDSA_CLAIM, data=FIXTURE_DATA,
                                  expected_nonce=NONCE)
    assert ver.signature_status == "unsupported_algorithm"
    assert "1.2.840.10045.4.3.2" in ver.signature_detail
    # The deterministic core still verifies — the gap is only the signature.
    assert ver.imprint_matches is True
    assert ver.digest_valid is True
    assert ver.nonce_matches is True


def test_verify_token_trusted_certificate_pinning():
    token = _token(GRANTED)
    assert verify_time_stamp_token(
        token, data=FIXTURE_DATA, trusted_certificates=(CERT,),
        expected_nonce=NONCE).signature_status == "verified"
    ver = verify_time_stamp_token(
        token, data=FIXTURE_DATA, expected_nonce=NONCE,
        trusted_certificates=(b"\x30\x03\x02\x01\x01",))
    assert ver.signature_status == "invalid"
    assert "trusted_certificates" in ver.signature_detail


def test_verify_response_full_with_freshness():
    now = GEN_TIME + timedelta(seconds=30)
    ver = verify_time_stamp_response(
        GRANTED, data=FIXTURE_DATA, expected_nonce=NONCE,
        max_age=timedelta(days=365 * 5), now=now)
    assert ver.resp.status.status == 0
    assert ver.token.signature_status == "verified"
    assert ver.fresh is True


def test_verify_response_stale():
    now = GEN_TIME + timedelta(seconds=30)
    ver = verify_time_stamp_response(
        GRANTED, data=FIXTURE_DATA, expected_nonce=NONCE,
        max_age=timedelta(seconds=10), now=now)
    assert ver.fresh is False


def test_verify_response_naive_now_treated_as_utc():
    ver = verify_time_stamp_response(
        GRANTED, data=FIXTURE_DATA, expected_nonce=NONCE,
        max_age=timedelta(seconds=60), now=datetime(2025, 6, 1, 12, 0, 30))
    assert ver.fresh is True


def test_verify_response_rejection_raises():
    with pytest.raises(TimeStampRejectedError) as exc:
        verify_time_stamp_response(REJECTED)
    assert exc.value.resp.status.status == 2
    assert "bad_alg" in str(exc.value)


def test_verify_response_granted_without_token_raises():
    with pytest.raises(DerError):
        verify_time_stamp_response(GRANTED_NO_TOKEN)


def test_timestamp_age_and_time_window():
    tst = _granted_tst()
    assert timestamp_age(tst, now=GEN_TIME + timedelta(seconds=30)) == timedelta(seconds=30)
    start, end = time_window(tst)
    assert start == GEN_TIME - timedelta(seconds=1.50025)
    assert end == GEN_TIME + timedelta(seconds=1.50025)


# ---------------------------------------------------------------------------
# Transport (urllib) — mocked, still hermetic
# ---------------------------------------------------------------------------
def test_send_request_mocked():
    seen = {}

    def fake_open(req, timeout):
        seen["req"] = req
        seen["timeout"] = timeout

        class _Resp:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b"RESP"

        return _Resp()

    with mock.patch("grasp.rfc3161._OPENER.open", side_effect=fake_open):
        out = send_timestamp_request("https://tsa.example/tsr", b"REQ",
                                     timeout=7, headers={"X-Trace": "t1"})
    assert out == b"RESP"
    req = seen["req"]
    assert seen["timeout"] == 7
    assert req.full_url == "https://tsa.example/tsr"
    assert req.get_method() == "POST"
    assert req.data == b"REQ"
    assert _header(req, "Content-Type") == "application/timestamp-query"
    assert _header(req, "Accept") == "application/timestamp-reply"
    assert _header(req, "User-Agent") == "grasp-rfc3161/1"
    assert _header(req, "X-Trace") == "t1"


def test_send_request_http_error_wrapped():
    import urllib.error

    def fake_open(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 500, "boom", {}, None)

    with mock.patch("grasp.rfc3161._OPENER.open", side_effect=fake_open):
        with pytest.raises(TsaRequestError) as exc:
            send_timestamp_request("https://tsa.example/tsr", b"REQ")
    assert "HTTP 500" in str(exc.value)


def test_send_request_unreachable_wrapped():
    import urllib.error

    def fake_open(req, timeout):
        raise urllib.error.URLError("connection refused")

    with mock.patch("grasp.rfc3161._OPENER.open", side_effect=fake_open):
        with pytest.raises(TsaRequestError) as exc:
            send_timestamp_request("https://tsa.example/tsr", b"REQ")
    assert "unreachable" in str(exc.value)


def test_send_request_timeout_wrapped():
    def fake_open(req, timeout):
        raise TimeoutError()

    with mock.patch("grasp.rfc3161._OPENER.open", side_effect=fake_open):
        with pytest.raises(TsaRequestError) as exc:
            send_timestamp_request("https://tsa.example/tsr", b"REQ")
    assert "timed out" in str(exc.value)


def test_send_request_rejects_non_https():
    with pytest.raises(ValueError):
        send_timestamp_request("http://tsa.example/tsr", b"REQ")
