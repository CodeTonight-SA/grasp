# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""RFC 3161 Time-Stamp Protocol (TSP) client — pure-Python standard library.

GRASP anchors Merkle roots to the Bitcoin blockchain via OpenTimestamps
('grasp.storage.ots'). That is decentralised proof of existence against the
Bitcoin clock, but it is NOT a qualified electronic timestamp under eIDAS
Article 42 — only a qualified trust service provider (a qualified TSA per
ETSI EN 319 422) confers the legal presumption of accuracy. This module is
roadmap item 7 of docs/THREAT-MODEL.md: an RFC 3161 co-timestamping client
so the same root can also be stamped by a statutory TSA. The two authorities
are complementary, exactly as the threat model states: Bitcoin for
decentralised verifiability, a TSA for statutory recognition.

The module is deliberately stdlib-only (hashlib, hmac, urllib, dataclasses):
GRASP's core has zero runtime dependencies and the test suite is hermetic
(no live TSA; canned DER fixtures, one of them a genuinely OpenSSL-signed
CMS token).

What is REAL here
-----------------
1. 'TimeStampReq' construction (RFC 3161 §2.4.1): version, 'messageImprint'
   (hash algorithm + digest), optional 'reqPolicy', 'nonce', 'certReq',
   'extensions' — canonical DER, hand-rolled.
2. 'TimeStampResp' parsing (§2.4.2): 'PKIStatusInfo' (status, 'PKIFreeText',
   'PKIFailureInfo' named bits per §2.4.3).
3. CMS structural parsing (RFC 5652): ContentInfo -> SignedData ->
   encapContentInfo/eContent, certificates, signerInfos.
4. 'TSTInfo' parsing: version, policy, 'messageImprint', serialNumber, genTime
   (GeneralizedTime — fractional seconds, Zulu or offset), accuracy, ordering,
   nonce, tsa, extensions.
5. The deterministic checks that make a token MEAN anything: the token's
   'messageImprint' matches the request's (algorithm OID + digest octets), the
   digest recomputed from the caller's data matches, the nonce echoes (a nonce
   in the request MUST be returned, RFC 3161 §2.4.2), and genTime sits within
   'accuracy' of the claimed instant.
6. RSA PKCS#1 v1.5 signature verification of the CMS token over the
   'signedAttrs' (RFC 5652 §5.4) for sha1/sha224/sha256/sha384/sha512. RSA
   verification is exactly modular exponentiation plus an EMSA padding check,
   which stdlib big integers and hmac.compare_digest cover, so it is
   implemented rather than outsourced. tests/test_rfc3161.py verifies a
   genuinely OpenSSL-signed CMS token end-to-end, and a flipped signature
   byte fails verification.

What still needs a dependency (pyasn1 + cryptography, or asn1crypto +
cryptography), and why
--------------------------------------------
The layers below are NOT implemented here. They are out because doing them
correctly in stdlib is a dependency-sized project, not a helper function;
'verify_time_stamp_token' reports the gap as an explicit status rather than
manufacturing a pass (the repo's monotone-toward-safe rule):

* ECDSA / DSA / EdDSA CMS signatures. stdlib has no elliptic-curve group
  arithmetic, so P-256/P-384/P-521 verification (the second most common TSA
  signing scheme, and one ETSI EN 319 422 profiles) cannot be computed at
  all. '_verify_signer' raises 'UnsupportedSignatureAlgorithm' and
  'verify_time_stamp_token' returns signature_status="unsupported_algorithm"
  — an honest "cannot check this scheme here", never a pass. The imprint,
  nonce and digest checks still run and are trustworthy regardless of the
  signing scheme, because they do not depend on the signature.
* X.509 certificate chain building, path validation and revocation
  (CRL/OCSP). 'trusted_certificates' only PINs the signer certificate (an
  exact-DER allowlist); there is no CA-hierarchy logic, so a token's
  embedded certificate is otherwise taken at its own word for the signing key.
* RSA-PSS signatures and policy enforcement against the TSA's published
  policy. eIDAS qualification itself (ETSI EN 319 422) is a property of the
  TSA and its certificate, which no client can assess for the operator.

Practical consequence: a token from an RSA-signing TSA is fully verified
here; a token from an ECDSA-signing TSA yields a fully verified
imprint/nonce/digest plus an explicit unsupported_algorithm signature
status. Deployments that must verify ECDSA or build certificate chains add
cryptography for the signature layer — not for the protocol.

Usage
-----
::

    from grasp import rfc3161

    payload = b"merkle-root-to-co-timestamp"
    req = rfc3161.build_timestamp_request(payload, nonce=12345, cert_req=True)
    resp_der = rfc3161.send_timestamp_request(
        "https://tsa.example.org/tsr", req)  # TSA URL is deployment config
    ver = rfc3161.verify_time_stamp_response(
        resp_der, data=payload, expected_nonce=12345, max_age=timedelta(days=1))
    ver.token.signature_status   # "verified" for an RSA-signing TSA
    ver.fresh                    # False once the token is older than max_age
"""
from __future__ import annotations

import hashlib
import hmac
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# OIDs (RFC 3161, RFC 5652, RFC 8017, RFC 5754, RFC 4055)
# ---------------------------------------------------------------------------
OID_MD5 = "1.2.840.113549.2.5"
OID_SHA1 = "1.3.14.3.2.26"
OID_SHA224 = "2.16.840.1.101.3.4.2.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_SHA3_224 = "2.16.840.1.101.3.4.2.7"
OID_SHA3_256 = "2.16.840.1.101.3.4.2.8"
OID_SHA3_384 = "2.16.840.1.101.3.4.2.9"
OID_SHA3_512 = "2.16.840.1.101.3.4.2.10"

OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1"
OID_RSA_PSS = "1.2.840.113549.1.1.10"
OID_SHA1_WITH_RSA = "1.2.840.113549.1.1.5"
OID_SHA224_WITH_RSA = "1.2.840.113549.1.1.14"
OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11"
OID_SHA384_WITH_RSA = "1.2.840.113549.1.1.12"
OID_SHA512_WITH_RSA = "1.2.840.113549.1.1.13"

OID_DATA = "1.2.840.113549.1.7.1"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

#: RFC 3161 §2.4.2 — PKIStatus values.
PKI_STATUS_NAMES = {
    0: "granted",
    1: "grantedWithMods",
    2: "rejection",
    3: "waiting",
    4: "revocationWarning",
    5: "revocationNotification",
}
#: Statuses that still carry a token worth verifying (RFC 3161 §2.4.2).
PKI_STATUS_GRANTED = (0, 1)

#: RFC 3161 §2.4.3 — PKIFailureInfo named bits (bit index -> name).
PKI_FAILURE_BITS = {
    0: "bad_alg",
    2: "bad_request",
    5: "bad_data_format",
    14: "time_not_available",
    15: "unaccepted_policy",
    16: "unaccepted_extension",
    17: "add_info_not_available",
    25: "system_failure",
}

#: OID -> hashlib algorithm name, for digest computation.
_DIGEST_OIDS = {
    OID_MD5: "md5",
    OID_SHA1: "sha1",
    OID_SHA224: "sha224",
    OID_SHA256: "sha256",
    OID_SHA384: "sha384",
    OID_SHA512: "sha512",
    OID_SHA3_224: "sha3_224",
    OID_SHA3_256: "sha3_256",
    OID_SHA3_384: "sha3_384",
    OID_SHA3_512: "sha3_512",
}
_DIGEST_NAMES = {name: oid for oid, name in _DIGEST_OIDS.items()}

#: RFC 5754: the SHA-2 family carries NO AlgorithmIdentifier parameters; the
#: legacy md5/sha1 conventionally carry NULL. The TSA side is free to differ;
#: imprint matching deliberately ignores parameters (see message_imprint_matches).
_NULL = b"\x05\x00"
_LEGACY_PARAMS = {OID_MD5: _NULL, OID_SHA1: _NULL}

#: signature-algorithm OID -> the digest OID it commits to (RSA PKCS#1 v1.5).
_RSA_WITH_DIGEST = {
    OID_SHA1_WITH_RSA: OID_SHA1,
    OID_SHA224_WITH_RSA: OID_SHA224,
    OID_SHA256_WITH_RSA: OID_SHA256,
    OID_SHA384_WITH_RSA: OID_SHA384,
    OID_SHA512_WITH_RSA: OID_SHA512,
}

#: RFC 8017 A.2.4 — DigestInfo prefixes (DigestAlgorithmIdentifier + length
#: header of the digest OCTET STRING) for EMSA-PKCS1-v1_5 encoding checks.
_DIGEST_INFO_PREFIX = {
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha224": bytes.fromhex("302d300d06096086480165030402040500041c"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}

#: User-facing hash names, normalised ("SHA-256" -> "sha256", "sha3-256" -> "sha3_256").
_HASH_ALIASES = {
    "md5": "md5",
    "sha_1": "sha1",
    "sha_224": "sha224",
    "sha_256": "sha256",
    "sha_384": "sha384",
    "sha_512": "sha512",
    "sha3_224": "sha3_224",
    "sha3_256": "sha3_256",
    "sha3_384": "sha3_384",
    "sha3_512": "sha3_512",
}

_GENERALIZED_TIME = re.compile(
    r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d+))?(Z|[+-]\d{4})$")

TSA_TIMEOUT_CAP = 30  # seconds any single TSA request may take


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------
class TimeStampError(Exception):
    """Base class for protocol-level failures (rejection, transport)."""


class DerError(ValueError):
    """Malformed or non-DER input — a parse that refuses rather than guesses."""


class UnsupportedHashAlgorithm(ValueError):
    """A MessageImprint names a hash OID stdlib hashlib cannot compute."""

    def __init__(self, oid: str) -> None:
        self.oid = oid
        super().__init__(f"no stdlib digest for hash algorithm OID {oid}")


class UnsupportedSignatureAlgorithm(ValueError):
    """The CMS signature scheme has no stdlib verifier (ECDSA/DSA/PSS/EdDSA).

    This is the documented dependency boundary: the rest of the token
    (imprint, nonce, digest) has already been checked by the time this is
    raised; only the signature itself needs cryptography."""

    def __init__(self, oid: str) -> None:
        self.oid = oid
        super().__init__(
            f"no stdlib verifier for signature algorithm OID {oid} — "
            "the imprint/nonce/digest checks still stand; add a dependency "
            "(e.g. cryptography) for the signature layer")


class TsaRequestError(TimeStampError):
    """The TSA endpoint could not be reached or answered non-2xx."""


class TimeStampRejectedError(TimeStampError):
    """The TSA answered with a status other than granted/grantedWithMods."""

    def __init__(self, resp: "TimeStampResp") -> None:
        self.resp = resp
        status = resp.status
        parts = [f"status {status.status} ({status.status_name})"]
        if status.status_string:
            parts.append("; ".join(status.status_string))
        if status.fail_info:
            parts.append("failInfo: " + ", ".join(sorted(status.fail_info)))
        super().__init__("TSA rejected the request: " + " — ".join(parts))


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class AlgorithmIdentifier:
    """One ASN.1 AlgorithmIdentifier: a dotted OID plus optional raw parameters."""

    algorithm: str
    parameters: bytes | None = None


@dataclass(frozen=True)
class MessageImprint:
    """RFC 3161 §2.4.1 — the hash algorithm and digest a request commits to."""

    hash_algorithm: AlgorithmIdentifier
    hashed_message: bytes


@dataclass(frozen=True)
class TimeStampReq:
    """A parsed RFC 3161 TimeStampReq."""

    version: int
    message_imprint: MessageImprint
    req_policy: str | None = None
    nonce: int | None = None
    cert_req: bool = False
    extensions: bytes | None = None


@dataclass(frozen=True)
class PkiStatusInfo:
    """RFC 3161 §2.4.2 — the status half of every TimeStampResp."""

    status: int
    status_string: tuple[str, ...] = ()
    fail_info: frozenset[str] = frozenset()

    @property
    def status_name(self) -> str:
        return PKI_STATUS_NAMES.get(self.status, f"unknown({self.status})")


@dataclass(frozen=True)
class TimeStampResp:
    """A parsed RFC 3161 TimeStampResp: status plus the raw CMS token (if any)."""

    status: PkiStatusInfo
    token_der: bytes | None = None


@dataclass(frozen=True)
class Accuracy:
    """RFC 3161 §2.4.2 — the TSA's claimed clock precision around genTime."""

    seconds: int = 0
    millis: int = 0
    micros: int = 0

    @property
    def total_seconds(self) -> float:
        return self.seconds + self.millis / 1000.0 + self.micros / 1_000_000.0


@dataclass(frozen=True)
class TstInfo:
    """A parsed RFC 3161 TSTInfo — the payload inside the CMS token."""

    version: int
    policy: str
    message_imprint: MessageImprint
    serial_number: int
    gen_time: datetime
    accuracy: Accuracy | None = None
    ordering: bool = False
    nonce: int | None = None
    tsa: bytes | None = None
    extensions: bytes | None = None


@dataclass(frozen=True)
class TimeStampTokenVerification:
    """The verdict for one time-stamp token, with every term named.

    signature_status is one of "verified", "invalid", "not_verified" (skipped
    on request) or "unsupported_algorithm" (the documented stdlib boundary).
    A token is only as strong as its weakest checked term;
    unsupported_algorithm is reported, never silently upgraded.
    """

    tst_info: TstInfo
    encap_content_type: str
    signature_status: str
    signature_detail: str
    imprint_matches: bool
    digest_valid: bool | None
    nonce_matches: bool | None


@dataclass(frozen=True)
class TimeStampRespVerification:
    """The verdict for a whole response: status gate + token + freshness."""

    resp: TimeStampResp
    token: TimeStampTokenVerification
    fresh: bool | None = None


# Internal CMS shapes (RFC 5652), not part of the public API.
@dataclass(frozen=True)
class _SignedData:
    version: int
    digest_algorithms: tuple[AlgorithmIdentifier, ...]
    encap_content_type: str
    e_content: bytes | None
    certificates: tuple[bytes, ...]
    signer_infos: tuple[bytes, ...]


@dataclass(frozen=True)
class _SignerInfo:
    version: int
    issuer: bytes
    serial_number: int
    digest_algorithm: AlgorithmIdentifier
    signed_attrs_der: bytes | None
    signed_attrs: tuple["_Attribute", ...]
    signature_algorithm: AlgorithmIdentifier
    signature: bytes


@dataclass(frozen=True)
class _Attribute:
    attr_type: str
    values: tuple[bytes, ...]

    def first_octet_value(self) -> bytes | None:
        """The first value that decodes as an OCTET STRING (e.g. message-digest)."""
        for raw in self.values:
            try:
                r = _Reader(raw)
                return _parse_octet_string(r.expect(0x04))
            except DerError:
                continue
        return None

    def first_oid_value(self) -> str | None:
        """The first value that decodes as an OID (e.g. content-type)."""
        for raw in self.values:
            try:
                r = _Reader(raw)
                return _parse_oid(r.expect(0x06))
            except DerError:
                continue
        return None


@dataclass(frozen=True)
class _CertInfo:
    subject_der: bytes
    serial_number: int
    public_key_algorithm: str
    rsa_key: tuple[int, int] | None  # (modulus n, public exponent e)


# ---------------------------------------------------------------------------
# DER encoding (canonical, minimal lengths, no indefinite forms)
# ---------------------------------------------------------------------------
def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes((n,))
    raw = bytearray()
    while n:
        raw.insert(0, n & 0xFF)
        n >>= 8
    return bytes((0x80 | len(raw),)) + bytes(raw)


def _der_tlv(tag: int, content: bytes) -> bytes:
    return bytes((tag,)) + _der_len(len(content)) + content


def _der_integer(i: int) -> bytes:
    if i < 0:
        raise ValueError("negative INTEGER encoding is not supported")
    if i == 0:
        return _der_tlv(0x02, b"\x00")
    raw = i.to_bytes((i.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:  # keep the sign bit free
        raw = b"\x00" + raw
    return _der_tlv(0x02, raw)


def _der_octet_string(b: bytes) -> bytes:
    return _der_tlv(0x04, b)


def _der_boolean(v: bool) -> bytes:
    return _der_tlv(0x01, b"\xff" if v else b"\x00")


def _der_sequence(*parts: bytes) -> bytes:
    return _der_tlv(0x30, b"".join(parts))


def _oid_bytes(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    if len(parts) < 2:
        raise ValueError(f"OID {dotted!r} needs at least two arcs")
    if parts[0] not in (0, 1, 2):
        raise ValueError(f"OID {dotted!r}: invalid first arc {parts[0]}")
    if parts[0] < 2 and parts[1] > 39:
        raise ValueError(
            f"OID {dotted!r}: second arc must be < 40 when the first arc is {parts[0]}")
    out = bytearray((40 * parts[0] + parts[1],))
    for value in parts[2:]:
        if value < 0:
            raise ValueError(f"OID {dotted!r}: negative arc {value}")
        chunks = [value & 0x7F]
        value >>= 7
        while value:
            chunks.append((value & 0x7F) | 0x80)
            value >>= 7
        out.extend(reversed(chunks))
    return bytes(out)


def _der_oid(dotted: str) -> bytes:
    return _der_tlv(0x06, _oid_bytes(dotted))


def _der_algorithm_identifier(oid: str, params: bytes | None = None) -> bytes:
    if params is None:
        return _der_sequence(_der_oid(oid))
    return _der_sequence(_der_oid(oid), params)


def _der_message_imprint(mi: MessageImprint) -> bytes:
    alg = _der_algorithm_identifier(mi.hash_algorithm.algorithm,
                                    mi.hash_algorithm.parameters)
    return _der_sequence(alg, _der_octet_string(mi.hashed_message))


# ---------------------------------------------------------------------------
# DER parsing
# ---------------------------------------------------------------------------
class _Reader:
    """Cursor over one DER buffer. Strict: rejects indefinite and non-minimal
    lengths, which DER forbids, so a malformed TSA reply fails loudly."""

    __slots__ = ("data", "pos")

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def read_tlv(self) -> tuple[int, bytes]:
        data, pos = self.data, self.pos
        if pos >= len(data):
            raise DerError("truncated DER: missing tag byte")
        tag = data[pos]
        pos += 1
        if tag & 0x1F == 0x1F:
            raise DerError("high-tag-number form is not used in this protocol")
        if pos >= len(data):
            raise DerError("truncated DER: missing length byte")
        first = data[pos]
        pos += 1
        if first & 0x80:
            count = first & 0x7F
            if count == 0:
                raise DerError("indefinite length is not DER")
            if count > 4:
                raise DerError("implausible length-of-length in DER")
            if pos + count > len(data):
                raise DerError("truncated DER: incomplete length")
            length = int.from_bytes(data[pos:pos + count], "big")
            pos += count
            if length < 0x80:
                raise DerError("non-minimal DER length")
        else:
            length = first
        end = pos + length
        if end > len(data):
            raise DerError("truncated DER: content overruns buffer")
        self.pos = end
        return tag, data[pos:end]

    def expect(self, tag: int) -> bytes:
        start = self.pos
        found, content = self.read_tlv()
        if found != tag:
            raise DerError(f"expected tag {tag:#04x}, found {found:#04x} "
                           f"at offset {start}")
        return content

    def peek_tag(self) -> int:
        saved = self.pos
        try:
            tag, _ = self.read_tlv()
            return tag
        finally:
            self.pos = saved

    def eof(self) -> bool:
        return self.pos >= len(self.data)


def _each_tlv(content: bytes):
    r = _Reader(content)
    while not r.eof():
        yield r.read_tlv()


def _parse_integer(content: bytes) -> int:
    if not content:
        raise DerError("empty INTEGER")
    if content[0] & 0x80:
        raise DerError("negative INTEGER is not valid in this protocol")
    if len(content) > 1 and content[0] == 0 and not (content[1] & 0x80):
        raise DerError("non-minimal INTEGER encoding")
    return int.from_bytes(content, "big")


def _parse_oid(content: bytes) -> str:
    if not content:
        raise DerError("empty OID")
    first = content[0]
    if first < 40:
        arcs = [0, first]
    elif first < 80:
        arcs = [1, first - 40]
    else:
        arcs = [2, first - 80]
    value = 0
    for byte in content[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            arcs.append(value)
            value = 0
    if value:
        raise DerError("truncated OID subidentifier")
    return ".".join(str(a) for a in arcs)


def _parse_boolean(content: bytes) -> bool:
    if content not in (b"\x00", b"\xff"):
        raise DerError("BOOLEAN must be a single 0x00 or 0xFF octet in DER")
    return content == b"\xff"


def _parse_octet_string(content: bytes) -> bytes:
    return content


def _parse_bit_string(content: bytes) -> tuple[int, bytes]:
    if not content:
        raise DerError("empty BIT STRING")
    unused = content[0]
    if unused > 7:
        raise DerError(f"invalid unused-bit count {unused}")
    payload = content[1:]
    if unused and (not payload or payload[-1] & ((1 << unused) - 1)):
        raise DerError("unused bits are not zero — not DER")
    return unused, payload


def _parse_utf8_string(tlv: tuple[int, bytes]) -> str:
    tag, content = tlv
    if tag != 0x0C:
        raise DerError(f"expected UTF8String (0x0c), found {tag:#04x}")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DerError(f"invalid UTF-8 in PKIFreeText: {exc}") from exc


def _parse_generalized_time(content: bytes) -> datetime:
    try:
        text = content.decode("ascii")
    except UnicodeDecodeError as exc:
        raise DerError(f"GeneralizedTime is not ASCII: {exc}") from exc
    m = _GENERALIZED_TIME.match(text)
    if not m:
        raise DerError(f"unparseable GeneralizedTime {text!r}")
    year, month, day, hour, minute, second = (int(g) for g in m.groups()[:6])
    micro = 0
    if m.group(7):
        micro = int(m.group(7)[:6].ljust(6, "0"))
    tz_text = m.group(8)
    if tz_text == "Z":
        tzinfo = timezone.utc
    else:
        sign = 1 if tz_text[0] == "+" else -1
        tzinfo = timezone(sign * timedelta(hours=int(tz_text[1:3]),
                                           minutes=int(tz_text[3:5])))
    try:
        return datetime(year, month, day, hour, minute, second, micro,
                        tzinfo=tzinfo)
    except ValueError as exc:
        raise DerError(f"impossible GeneralizedTime {text!r}: {exc}") from exc


def _parse_algorithm_identifier(der: bytes) -> AlgorithmIdentifier:
    """Parse the CONTENT of an AlgorithmIdentifier SEQUENCE: OID [+ params]."""
    r = _Reader(der)
    oid = _parse_oid(r.expect(0x06))
    params = None
    if not r.eof():
        tag, pcontent = r.read_tlv()
        params = _der_tlv(tag, pcontent)
    return AlgorithmIdentifier(algorithm=oid, parameters=params)


def _parse_message_imprint(der: bytes) -> MessageImprint:
    """Parse the CONTENT of a MessageImprint SEQUENCE (RFC 3161 §2.4.1)."""
    r = _Reader(der)
    alg = _parse_algorithm_identifier(r.expect(0x30))
    digest = _parse_octet_string(r.expect(0x04))
    if not r.eof():
        raise DerError("trailing data in MessageImprint")
    return MessageImprint(hash_algorithm=alg, hashed_message=digest)


# ---------------------------------------------------------------------------
# TimeStampReq
# ---------------------------------------------------------------------------
def _normalize_hash_name(name: str) -> str:
    key = name.strip().lower().replace("-", "_")
    normalized = _HASH_ALIASES.get(key, key)
    if normalized not in _DIGEST_NAMES or normalized not in hashlib.algorithms_available:
        raise ValueError(
            f"unsupported hash algorithm {name!r}; supported: "
            f"{sorted(_DIGEST_NAMES)}")
    return normalized


def compute_message_imprint(data: bytes, hash_algorithm: str = "sha256") -> MessageImprint:
    """Hash data into the RFC 3161 MessageImprint for a request.

    SHA-2 family parameters are omitted (RFC 5754); md5/sha1 carry NULL.
    """
    name = _normalize_hash_name(hash_algorithm)
    oid = _DIGEST_NAMES[name]
    return MessageImprint(
        hash_algorithm=AlgorithmIdentifier(algorithm=oid,
                                           parameters=_LEGACY_PARAMS.get(oid)),
        hashed_message=hashlib.new(name, data).digest(),
    )


def build_timestamp_request(
    data: bytes | None = None, *,
    message_imprint: MessageImprint | None = None,
    hash_algorithm: str = "sha256",
    req_policy: str | None = None,
    nonce: int | None = None,
    cert_req: bool = False,
    extensions: bytes | None = None,
) -> bytes:
    """Build a canonical-DER RFC 3161 TimeStampReq (RFC 3161 §2.4.1).

    Pass either data (hashed here with hash_algorithm) or a pre-computed
    message_imprint. nonce should be a fresh random integer per request: the
    TSA MUST echo it (RFC 3161 §2.4.2), which lets a verifier bind the reply
    to its own request. extensions, if given, is the raw DER of the
    Extensions value for the [0] IMPLICIT field.
    """
    if message_imprint is None:
        if data is None:
            raise ValueError("build_timestamp_request needs data= or message_imprint=")
        message_imprint = compute_message_imprint(data, hash_algorithm)
    parts = [_der_integer(1), _der_message_imprint(message_imprint)]
    if req_policy is not None:
        parts.append(_der_oid(req_policy))
    if nonce is not None:
        if nonce < 0:
            raise ValueError("nonce must be a non-negative integer")
        parts.append(_der_integer(nonce))
    if cert_req:  # DER omits BOOLEAN DEFAULT FALSE, so only True is emitted
        parts.append(_der_boolean(True))
    if extensions is not None:
        parts.append(_der_tlv(0xA0, extensions))
    return _der_sequence(*parts)


def parse_timestamp_request(der: bytes) -> TimeStampReq:
    """Parse a TimeStampReq. Raises DerError on anything non-DER."""
    r = _Reader(der)
    content = r.expect(0x30)
    sub = _Reader(content)
    version = _parse_integer(sub.expect(0x02))
    imprint = _parse_message_imprint(sub.expect(0x30))
    req_policy = nonce = None
    cert_req = False
    extensions = None
    if not sub.eof() and sub.peek_tag() == 0x06:
        req_policy = _parse_oid(sub.expect(0x06))
    if not sub.eof() and sub.peek_tag() == 0x02:
        nonce = _parse_integer(sub.expect(0x02))
    if not sub.eof() and sub.peek_tag() == 0x01:
        cert_req = _parse_boolean(sub.expect(0x01))
    if not sub.eof():
        tag, ext_content = sub.read_tlv()
        if tag != 0xA0:
            raise DerError(f"unexpected TimeStampReq field tag {tag:#04x}")
        extensions = ext_content
    if not sub.eof():
        raise DerError("trailing data in TimeStampReq")
    if not r.eof():
        raise DerError("trailing data after TimeStampReq")
    return TimeStampReq(version=version, message_imprint=imprint,
                        req_policy=req_policy, nonce=nonce,
                        cert_req=cert_req, extensions=extensions)


# ---------------------------------------------------------------------------
# TimeStampResp / CMS / TSTInfo
# ---------------------------------------------------------------------------
def parse_pki_status_info(der: bytes) -> PkiStatusInfo:
    """Parse the PKIStatusInfo half of a TimeStampResp (RFC 3161 §2.4.2)."""
    r = _Reader(der)
    content = r.expect(0x30)
    sub = _Reader(content)
    status = _parse_integer(sub.expect(0x02))
    strings: tuple[str, ...] = ()
    if not sub.eof() and sub.peek_tag() == 0x30:  # PKIFreeText
        free_text = sub.expect(0x30)
        strings = tuple(_parse_utf8_string(tlv) for tlv in _each_tlv(free_text))
    fail_info: frozenset[str] = frozenset()
    if not sub.eof() and sub.peek_tag() == 0x03:  # PKIFailureInfo (BIT STRING)
        unused, octets = _parse_bit_string(sub.expect(0x03))
        fail_info = _decode_fail_info(octets, unused)
    if not sub.eof():
        raise DerError("trailing data in PKIStatusInfo")
    if not r.eof():
        raise DerError("trailing data after PKIStatusInfo")
    return PkiStatusInfo(status=status, status_string=strings, fail_info=fail_info)


def _decode_fail_info(octets: bytes, unused: int) -> frozenset[str]:
    """Named bits per RFC 3161 §2.4.3; unknown bits are kept, never dropped."""
    names: set[str] = set()
    for byte_index, byte in enumerate(octets):
        for bit in range(8):
            if byte & (0x80 >> bit):
                index = byte_index * 8 + bit
                names.add(PKI_FAILURE_BITS.get(index, f"unknown_bit_{index}"))
    return frozenset(names)


def parse_timestamp_response(der: bytes) -> TimeStampResp:
    """Parse a TimeStampResp: status plus the raw CMS token (if the TSA sent one)."""
    r = _Reader(der)
    content = r.expect(0x30)
    sub = _Reader(content)
    status_tag, status_content = sub.read_tlv()
    if status_tag != 0x30:
        raise DerError(f"PKIStatusInfo must be a SEQUENCE, found {status_tag:#04x}")
    status = parse_pki_status_info(_der_tlv(status_tag, status_content))
    token_der: bytes | None = None
    if not sub.eof():
        tag, tcontent = sub.read_tlv()
        if tag != 0x30:
            raise DerError(f"timeStampToken must be a ContentInfo (SEQUENCE), "
                           f"found tag {tag:#04x}")
        token_der = _der_tlv(tag, tcontent)
    if not sub.eof():
        raise DerError("trailing data in TimeStampResp")
    if not r.eof():
        raise DerError("trailing data after TimeStampResp")
    return TimeStampResp(status=status, token_der=token_der)


def _parse_content_info(der: bytes) -> tuple[str, bytes | None]:
    """ContentInfo (RFC 5652 §5.2): (contentType, raw SignedData TLV or None)."""
    r = _Reader(der)
    content = r.expect(0x30)
    sub = _Reader(content)
    content_type = _parse_oid(sub.expect(0x06))
    if sub.eof():
        return content_type, None
    tag, ccontent = sub.read_tlv()
    if tag != 0xA0:  # content is [0] EXPLICIT
        raise DerError(f"ContentInfo content must be [0] EXPLICIT, found {tag:#04x}")
    return content_type, ccontent


def _parse_signed_data(der: bytes) -> _SignedData:
    """SignedData (RFC 5652 §5.1). Certificates and signerInfos kept raw."""
    r = _Reader(der)
    content = r.expect(0x30)
    sub = _Reader(content)
    version = _parse_integer(sub.expect(0x02))
    digest_algorithms = tuple(
        _parse_algorithm_identifier(content)
        for _, content in _each_tlv(sub.expect(0x31)))
    eci = sub.expect(0x30)
    esub = _Reader(eci)
    encap_content_type = _parse_oid(esub.expect(0x06))
    e_content: bytes | None = None
    if not esub.eof():
        tag, ccontent = esub.read_tlv()
        if tag != 0xA0:  # eContent is [0] EXPLICIT OCTET STRING
            raise DerError(f"eContent must be [0] EXPLICIT, found {tag:#04x}")
        inner = _Reader(ccontent)
        e_content = _parse_octet_string(inner.expect(0x04))
        if not inner.eof():
            raise DerError("trailing data in eContent")
    certificates: tuple[bytes, ...] = ()
    if not sub.eof() and sub.peek_tag() == 0xA0:  # certificates [0] IMPLICIT
        cert_set = sub.expect(0xA0)
        certificates = tuple(_der_tlv(*tlv) for tlv in _each_tlv(cert_set))
    if not sub.eof() and sub.peek_tag() == 0xA1:  # crls [1] IMPLICIT
        sub.expect(0xA1)  # structurally accepted, not interpreted
    signer_infos = tuple(_der_tlv(*tlv) for tlv in _each_tlv(sub.expect(0x31)))
    if not sub.eof():
        raise DerError("trailing data in SignedData")
    return _SignedData(version=version, digest_algorithms=digest_algorithms,
                       encap_content_type=encap_content_type, e_content=e_content,
                       certificates=certificates, signer_infos=signer_infos)


def _parse_attribute(der: bytes) -> _Attribute:
    """Parse the CONTENT of an Attribute SEQUENCE (RFC 5652 §5.3)."""
    r = _Reader(der)
    attr_type = _parse_oid(r.expect(0x06))
    values = tuple(_der_tlv(*tlv) for tlv in _each_tlv(r.expect(0x31)))
    return _Attribute(attr_type=attr_type, values=values)


def _parse_signer_info(der: bytes) -> _SignerInfo:
    """SignerInfo (RFC 5652 §5.3), with signedAttrs kept as the exact bytes
    that the signature is computed over (the [0] IMPLICIT SET OF Attribute)."""
    r = _Reader(der)
    content = r.expect(0x30)
    sub = _Reader(content)
    version = _parse_integer(sub.expect(0x02))
    sid = sub.expect(0x30)
    ssub = _Reader(sid)
    issuer_tag, issuer_content = ssub.read_tlv()
    if issuer_tag != 0x30:
        raise DerError("SignerIdentifier issuer is not a Name")
    issuer = _der_tlv(issuer_tag, issuer_content)
    serial = _parse_integer(ssub.expect(0x02))
    if not ssub.eof():
        raise DerError("trailing data in SignerIdentifier")
    digest_algorithm = _parse_algorithm_identifier(sub.expect(0x30))
    signed_attrs_der: bytes | None = None
    signed_attrs: tuple[_Attribute, ...] = ()
    if not sub.eof() and sub.peek_tag() == 0xA0:  # signedAttrs [0] IMPLICIT
        signed_attrs_der = sub.expect(0xA0)
        signed_attrs = tuple(_parse_attribute(content)
                             for _, content in _each_tlv(signed_attrs_der))
    signature_algorithm = _parse_algorithm_identifier(sub.expect(0x30))
    signature = _parse_octet_string(sub.expect(0x04))
    if not sub.eof():
        raise DerError("trailing data in SignerInfo")
    return _SignerInfo(version=version, issuer=issuer, serial_number=serial,
                       digest_algorithm=digest_algorithm,
                       signed_attrs_der=signed_attrs_der,
                       signed_attrs=signed_attrs,
                       signature_algorithm=signature_algorithm,
                       signature=signature)


def _parse_certificate(der: bytes) -> _CertInfo:
    """Minimal X.509 read: the fields a SignerInfo match and RSA verify need."""
    r = _Reader(der)
    cert_content = r.expect(0x30)  # Certificate
    t = _Reader(cert_content)
    tbs = t.expect(0x30)  # tbsCertificate
    u = _Reader(tbs)
    if u.peek_tag() == 0xA0:  # version [0]
        u.expect(0xA0)
    serial = _parse_integer(u.expect(0x02))
    u.expect(0x30)  # signature AlgorithmIdentifier
    u.expect(0x30)  # issuer Name
    u.expect(0x30)  # validity
    subject_tag, subject_content = u.read_tlv()
    if subject_tag != 0x30:
        raise DerError("certificate subject is not a Name")
    subject_der = _der_tlv(subject_tag, subject_content)
    spki = u.expect(0x30)
    s = _Reader(spki)
    spki_alg = _parse_algorithm_identifier(s.expect(0x30))
    unused, spk = _parse_bit_string(s.expect(0x03))
    rsa_key: tuple[int, int] | None = None
    if spki_alg.algorithm == OID_RSA_ENCRYPTION and spk:
        try:
            rr = _Reader(spk)
            rk = rr.expect(0x30)
            rs = _Reader(rk)
            n = _parse_integer(rs.expect(0x02))
            e = _parse_integer(rs.expect(0x02))
            if rs.eof():
                rsa_key = (n, e)
        except DerError:
            rsa_key = None
    return _CertInfo(subject_der=subject_der, serial_number=serial,
                     public_key_algorithm=spki_alg.algorithm, rsa_key=rsa_key)


def parse_tst_info(der: bytes) -> TstInfo:
    """Parse a TSTInfo (RFC 3161 §2.4.2). Raises DerError on anything else."""
    r = _Reader(der)
    content = r.expect(0x30)
    sub = _Reader(content)
    version = _parse_integer(sub.expect(0x02))
    policy = _parse_oid(sub.expect(0x06))
    imprint = _parse_message_imprint(sub.expect(0x30))
    serial = _parse_integer(sub.expect(0x02))
    gen_time = _parse_generalized_time(sub.expect(0x18))
    accuracy: Accuracy | None = None
    if not sub.eof() and sub.peek_tag() == 0x30:
        accuracy = _parse_accuracy(sub.expect(0x30))
    ordering = False
    if not sub.eof() and sub.peek_tag() == 0x01:
        ordering = _parse_boolean(sub.expect(0x01))
    nonce: int | None = None
    if not sub.eof() and sub.peek_tag() == 0x02:
        nonce = _parse_integer(sub.expect(0x02))
    tsa: bytes | None = None
    if not sub.eof() and sub.peek_tag() == 0xA0:  # tsa [0] GeneralName
        tag, tcontent = sub.read_tlv()
        tsa = _der_tlv(tag, tcontent)
    extensions: bytes | None = None
    if not sub.eof():
        tag, econtent = sub.read_tlv()
        if tag != 0xA1:  # extensions [1] IMPLICIT
            raise DerError(f"unexpected TSTInfo field tag {tag:#04x}")
        extensions = _der_tlv(tag, econtent)
    if not r.eof():
        raise DerError("trailing data after TSTInfo")
    return TstInfo(version=version, policy=policy, message_imprint=imprint,
                   serial_number=serial, gen_time=gen_time, accuracy=accuracy,
                   ordering=ordering, nonce=nonce, tsa=tsa,
                   extensions=extensions)


def _parse_accuracy(der: bytes) -> Accuracy:
    """Parse the CONTENT of an Accuracy SEQUENCE (RFC 3161 §2.4.2)."""
    r = _Reader(der)
    seconds = 0
    millis = 0
    micros = 0
    if not r.eof() and r.peek_tag() == 0x02:
        seconds = _parse_integer(r.expect(0x02))
    if not r.eof() and r.peek_tag() == 0x80:  # millis [0] IMPLICIT INTEGER
        millis = _parse_integer(r.expect(0x80))
    if not r.eof() and r.peek_tag() == 0x81:  # micros [1] IMPLICIT INTEGER
        micros = _parse_integer(r.expect(0x81))
    if not r.eof():
        raise DerError("trailing data in Accuracy")
    return Accuracy(seconds=seconds, millis=millis, micros=micros)


def extract_tst_info(token_der: bytes, *,
                     require_tstinfo_content_type: bool = True) -> TstInfo:
    """Reach inside the CMS token and return its TSTInfo.

    Walks ContentInfo -> SignedData -> encapContentInfo/eContent, then parses
    the eContent as TSTInfo. By default the SignedData eContentType must be
    id-ct-TSTInfo (what a conformant TSA emits); pass
    require_tstinfo_content_type=False to skip that check (used by tests and
    by integrations that know their TSA's encoding).
    """
    content_type, content = _parse_content_info(token_der)
    if content_type != OID_SIGNED_DATA:
        raise DerError(
            f"time-stamp token content type is {content_type}, "
            f"expected id-signedData ({OID_SIGNED_DATA})")
    sd = _parse_signed_data(content)
    if require_tstinfo_content_type and sd.encap_content_type != OID_TST_INFO:
        raise DerError(
            f"SignedData eContentType is {sd.encap_content_type}, "
            f"expected id-ct-TSTInfo ({OID_TST_INFO})")
    if sd.e_content is None:
        raise DerError("SignedData carries no eContent — nothing was timestamped")
    return parse_tst_info(sd.e_content)


# ---------------------------------------------------------------------------
# Deterministic checks: imprint, digest, nonce, time
# ---------------------------------------------------------------------------
def message_imprint_matches(expected: MessageImprint, actual: MessageImprint) -> bool:
    """RFC 3161 §2.4.2: the token's imprint must equal the request's imprint.

    Comparison is on hash-algorithm OID plus digest octets (constant-time on
    the digest). AlgorithmIdentifier parameters are ignored deliberately: a
    SHA-256 with NULL parameters and a SHA-256 with no parameters hash the
    same way, and TSAs differ on emitting them.
    """
    return (expected.hash_algorithm.algorithm == actual.hash_algorithm.algorithm
            and hmac.compare_digest(expected.hashed_message,
                                    actual.hashed_message))


def verify_message_imprint(target: TstInfo | MessageImprint, data: bytes) -> bool:
    """Recompute the digest of data with the imprint's own algorithm and
    compare it to the imprint's digest. False for wrong data; a hash algorithm
    this stdlib cannot compute raises UnsupportedHashAlgorithm instead."""
    mi = target.message_imprint if isinstance(target, TstInfo) else target
    name = _digest_name_for_oid(mi.hash_algorithm.algorithm)
    return hmac.compare_digest(hashlib.new(name, data).digest(),
                               mi.hashed_message)


def _digest_name_for_oid(oid: str) -> str:
    try:
        return _DIGEST_OIDS[oid]
    except KeyError:
        raise UnsupportedHashAlgorithm(oid) from None


def timestamp_age(tst_info: TstInfo, now: datetime | None = None) -> timedelta:
    """Age of the timestamp (now - genTime). now defaults to UTC now; a naive
    now is treated as UTC."""
    base = now if now is not None else datetime.now(timezone.utc)
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    return base - tst_info.gen_time


def time_window(tst_info: TstInfo) -> tuple[datetime, datetime]:
    """The instant the TSA certifies, bounded by its claimed accuracy:
    [genTime - accuracy, genTime + accuracy] (accuracy 0 when absent)."""
    half = (timedelta(seconds=tst_info.accuracy.total_seconds)
            if tst_info.accuracy is not None else timedelta(0))
    return tst_info.gen_time - half, tst_info.gen_time + half


# ---------------------------------------------------------------------------
# CMS signature verification (RSA PKCS#1 v1.5 only — see module docstring)
# ---------------------------------------------------------------------------
def _rsa_pkcs1_v15_verify(signature: bytes, n: int, e: int,
                          digest: bytes, digest_name: str) -> bool:
    """RFC 8017 §8.2.2 RSASSA-PKCS1-v1_5 verify: pow() + EMSA padding check."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    sig_int = int.from_bytes(signature, "big")
    if sig_int >= n:
        return False
    em = pow(sig_int, e, n).to_bytes(k, "big")
    expected = _DIGEST_INFO_PREFIX[digest_name] + digest
    if len(expected) > k:
        return False
    if em[0] != 0x00 or em[1] != 0x01:
        return False
    i = 2
    while i < k and em[i] == 0xFF:
        i += 1
    if i - 2 < 8 or i >= k or em[i] != 0x00:  # PS must be >= 8 octets
        return False
    body = em[i + 1:]
    return len(body) == len(expected) and hmac.compare_digest(body, expected)


def _verify_signer(sd: _SignedData, si: _SignerInfo,
                   trusted: tuple[bytes, ...]) -> tuple[bool, str]:
    """Verify one SignerInfo (RFC 5652 §5.4). RSA schemes verify; others raise
    UnsupportedSignatureAlgorithm — the documented dependency boundary."""
    pool = trusted if trusted else sd.certificates
    cert: _CertInfo | None = None
    for cder in pool:
        try:
            candidate = _parse_certificate(cder)
        except DerError:
            continue
        if (candidate.subject_der == si.issuer
                and candidate.serial_number == si.serial_number):
            cert = candidate
            break
    if cert is None:
        where = "among trusted_certificates" if trusted else "in the token"
        return False, f"signer certificate not found {where}"
    if cert.public_key_algorithm != OID_RSA_ENCRYPTION or cert.rsa_key is None:
        raise UnsupportedSignatureAlgorithm(cert.public_key_algorithm)
    if sd.e_content is None:
        return False, "SignedData carries no eContent to digest"

    digest_name = _digest_name_for_oid(si.digest_algorithm.algorithm)
    if si.signed_attrs_der is not None:
        # RFC 5652 §5.4: with signedAttrs present the signature covers the DER
        # of that SET OF Attribute, and the attributes must agree with eContent.
        content_type = next((a for a in si.signed_attrs
                             if a.attr_type == OID_CONTENT_TYPE), None)
        if content_type is not None:
            ct_oid = content_type.first_oid_value()
            if ct_oid is not None and ct_oid != sd.encap_content_type:
                return False, "content-type signed attribute contradicts eContentType"
        md = next((a for a in si.signed_attrs
                   if a.attr_type == OID_MESSAGE_DIGEST), None)
        if md is None:
            return False, "no message-digest signed attribute"
        md_bytes = md.first_octet_value()
        if md_bytes is None:
            return False, "message-digest attribute is not an OCTET STRING"
        if not hmac.compare_digest(
                md_bytes, hashlib.new(digest_name, sd.e_content).digest()):
            return False, "message-digest attribute does not match eContent"
        signed_bytes = si.signed_attrs_der
    else:
        signed_bytes = sd.e_content
    digest = hashlib.new(digest_name, signed_bytes).digest()

    sig_oid = si.signature_algorithm.algorithm
    if sig_oid in _RSA_WITH_DIGEST:
        rsa_digest_name = _digest_name_for_oid(_RSA_WITH_DIGEST[sig_oid])
    elif sig_oid == OID_RSA_ENCRYPTION:
        rsa_digest_name = digest_name
    else:
        raise UnsupportedSignatureAlgorithm(sig_oid)

    n, e = cert.rsa_key
    if _rsa_pkcs1_v15_verify(si.signature, n, e, digest, rsa_digest_name):
        return True, "RSA PKCS#1 v1.5 signature verified"
    return False, "RSA signature does not verify"


def _verify_cms_signature(sd: _SignedData,
                          trusted: tuple[bytes, ...] = ()) -> tuple[bool, str]:
    """Any signerInfo verifying is a pass; otherwise the strongest failure."""
    if not sd.signer_infos:
        return False, "SignedData has no signerInfos"
    last: tuple[bool, str] = (False, "no signerInfo verified")
    for sder in sd.signer_infos:
        try:
            si = _parse_signer_info(sder)
        except DerError as exc:
            last = (False, f"SignerInfo parse failure: {exc}")
            continue
        ok, detail = _verify_signer(sd, si, trusted)
        if ok:
            return True, detail
        last = (False, detail)
    return last


# ---------------------------------------------------------------------------
# Verification entry points
# ---------------------------------------------------------------------------
def verify_time_stamp_token(
    token_der: bytes, *,
    data: bytes | None = None,
    expected_message_imprint: MessageImprint | None = None,
    expected_nonce: int | None = None,
    verify_signature: bool = True,
    trusted_certificates: tuple[bytes, ...] = (),
    require_tstinfo_content_type: bool = True,
) -> TimeStampTokenVerification:
    """Verify one CMS time-stamp token and return the named verdict.

    Runs every check that does not depend on the signature (imprint match,
    digest recompute, nonce echo), then — unless verify_signature=False — the
    CMS signature. trusted_certificates pins the signer certificate (exact
    DER allowlist); when empty the token's own embedded certificate is used,
    which validates the key but not the chain (see module docstring).
    """
    content_type, content = _parse_content_info(token_der)
    if content_type != OID_SIGNED_DATA:
        raise DerError(
            f"time-stamp token content type is {content_type}, "
            f"expected id-signedData ({OID_SIGNED_DATA})")
    sd = _parse_signed_data(content)
    tst = extract_tst_info(token_der,
                           require_tstinfo_content_type=require_tstinfo_content_type)

    expected = expected_message_imprint
    if expected is None and data is not None:
        # Derive the request-side expectation from the data, using the TSA's
        # own imprint algorithm, so the RFC-required equality is still checked.
        name = _digest_name_for_oid(tst.message_imprint.hash_algorithm.algorithm)
        expected = MessageImprint(
            hash_algorithm=tst.message_imprint.hash_algorithm,
            hashed_message=hashlib.new(name, data).digest())
    imprint_matches = (message_imprint_matches(expected, tst.message_imprint)
                       if expected is not None else True)

    digest_valid: bool | None = None
    if data is not None:
        digest_valid = verify_message_imprint(tst.message_imprint, data)

    nonce_matches: bool | None = None
    if expected_nonce is not None:
        nonce_matches = tst.nonce == expected_nonce

    signature_status = "not_verified"
    signature_detail = "signature verification skipped (verify_signature=False)"
    if verify_signature:
        try:
            ok, detail = _verify_cms_signature(sd, trusted_certificates)
        except UnsupportedSignatureAlgorithm as exc:
            signature_status = "unsupported_algorithm"
            signature_detail = str(exc)
        except DerError as exc:
            signature_status = "invalid"
            signature_detail = f"CMS parse failure: {exc}"
        else:
            signature_status = "verified" if ok else "invalid"
            signature_detail = detail

    return TimeStampTokenVerification(
        tst_info=tst, encap_content_type=sd.encap_content_type,
        signature_status=signature_status, signature_detail=signature_detail,
        imprint_matches=imprint_matches, digest_valid=digest_valid,
        nonce_matches=nonce_matches)


def verify_time_stamp_response(
    der: bytes, *,
    data: bytes | None = None,
    expected_message_imprint: MessageImprint | None = None,
    expected_nonce: int | None = None,
    verify_signature: bool = True,
    trusted_certificates: tuple[bytes, ...] = (),
    max_age: timedelta | None = None,
    now: datetime | None = None,
    require_tstinfo_content_type: bool = True,
) -> TimeStampRespVerification:
    """Verify a whole TimeStampResp: status gate, then the token, then age.

    Raises TimeStampRejectedError when the TSA did not grant the request, and
    DerError when a granted response carries no token. max_age bounds
    now - genTime and is reported as fresh; now defaults to UTC now (a naive
    now is treated as UTC).
    """
    resp = parse_timestamp_response(der)
    if resp.status.status not in PKI_STATUS_GRANTED:
        raise TimeStampRejectedError(resp)
    if resp.token_der is None:
        raise DerError("response is granted but carries no timeStampToken")
    token = verify_time_stamp_token(
        resp.token_der, data=data,
        expected_message_imprint=expected_message_imprint,
        expected_nonce=expected_nonce, verify_signature=verify_signature,
        trusted_certificates=trusted_certificates,
        require_tstinfo_content_type=require_tstinfo_content_type)
    fresh: bool | None = None
    if max_age is not None:
        fresh = timestamp_age(token.tst_info, now=now) <= max_age
    return TimeStampRespVerification(resp=resp, token=token, fresh=fresh)


# ---------------------------------------------------------------------------
# Transport (urllib)
# ---------------------------------------------------------------------------
class _TsaRedirectRefused(urllib.error.HTTPError):
    """A redirect that would leave https — refused, not followed."""


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Hold the https guarantee across redirects, not just at the first hop:
    urlopen follows redirects itself, so re-testing the scheme on every hop
    stops a trusted TSA answering with a 302 to http:// or to an internal
    address from walking the request past the check."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise _TsaRedirectRefused(
                newurl, code, "refusing a redirect away from https", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects)


def _safe_url_label(url: str) -> str:
    """Scheme and host only — never userinfo or path, which can carry secrets."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unparseable url>"
    return f"{parts.scheme or '?'}://{parts.hostname or '?'}"


def send_timestamp_request(url: str, request_der: bytes, *,
                           timeout: float = TSA_TIMEOUT_CAP,
                           headers: dict[str, str] | None = None) -> bytes:
    """POST a TimeStampReq to a TSA and return the raw TimeStampResp bytes.

    RFC 3161 §3 / RFC 3161 Appendix C transport: application/timestamp-query
    in, application/timestamp-reply out. Only https is accepted (mirrors
    grasp.storage.ots); raise TsaRequestError on any transport or HTTP-status
    failure. headers are merged over the protocol defaults.
    """
    if not url.startswith("https://"):
        raise ValueError(
            f"TSA endpoints must be https: refusing {_safe_url_label(url)}")
    req = urllib.request.Request(
        url, data=request_der, method="POST",
        headers={
            "Content-Type": "application/timestamp-query",
            "Accept": "application/timestamp-reply",
            "User-Agent": "grasp-rfc3161/1",
        })
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    try:
        with _OPENER.open(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        raise TsaRequestError(f"TSA answered HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise TsaRequestError(f"TSA unreachable: {exc.reason}") from exc
    except TimeoutError as exc:
        raise TsaRequestError(f"TSA timed out after {timeout:g}s") from exc


__all__ = [
    "Accuracy", "AlgorithmIdentifier", "DerError", "MessageImprint",
    "OID_SHA1", "OID_SHA224", "OID_SHA256", "OID_SHA384", "OID_SHA512",
    "OID_SIGNED_DATA", "OID_TST_INFO", "PKI_FAILURE_BITS", "PKI_STATUS_GRANTED",
    "PKI_STATUS_NAMES", "PkiStatusInfo", "TimeStampError",
    "TimeStampRejectedError", "TimeStampReq", "TimeStampResp",
    "TimeStampRespVerification", "TimeStampTokenVerification",
    "TsaRequestError", "TstInfo", "UnsupportedHashAlgorithm",
    "UnsupportedSignatureAlgorithm", "build_timestamp_request",
    "compute_message_imprint", "extract_tst_info", "message_imprint_matches",
    "parse_pki_status_info", "parse_timestamp_request",
    "parse_timestamp_response", "parse_tst_info", "send_timestamp_request",
    "timestamp_age", "time_window", "verify_message_imprint",
    "verify_time_stamp_response", "verify_time_stamp_token",
]
