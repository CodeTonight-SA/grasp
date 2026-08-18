# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""C2PA bridge — carry GRASP content addresses inside C2PA manifests (roadmap item 6).

GRASP records are out-of-band: a bare artifact carries no pointer to its
decision record, so separation-from-artifact converts strip-risk into
linkage-risk. This bridge embeds an assertion — label "grasp.idr.addr", data
{content_addr, anchor_root, ts} — into a real C2PA manifest, so an artifact's
mark points at the decision chain behind it.

c2pa-python is an OPTIONAL dependency (extra: pip install grasp-provenance[c2pa]).
Without it this module still imports; every entry point raises a clear
C2paUnavailable error and the zero-dependency core is unaffected. Signing needs
a real C2PA signer credential (certificate chain PEM + private key PEM + signing
alg); VERIFYING the embedded binding needs no credential — it compares the
assertion against the caller-supplied content address, and reports the manifest
validation state separately. Monotone toward safe: a mismatch is False, an
unparseable asset is False — never a manufactured pass.

Proven end-to-end 2026-08-18 with c2pa-python 0.37.7 (c2pa-rs 0.90.14 core):
a signed PNG validates (is_valid True) and round-trips the grasp.idr.addr
assertion byte-for-byte.
"""

from __future__ import annotations

import io
from typing import Any

ASSERTION_LABEL = "grasp.idr.addr"
DEFAULT_CLAIM_GENERATOR = "grasp/0.3.0"

_ALG_MAP = {
    "es256": "ES256",
    "es384": "ES384",
    "es512": "ES512",
    "ps256": "PS256",
    "ps384": "PS384",
    "ps512": "PS512",
    "ed25519": "ED25519",
}

_MIME = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "webp": "image/webp",
    "svg": "image/svg+xml",
    "avif": "image/avif",
    "tif": "image/tiff",
    "tiff": "image/tiff",
    "gif": "image/gif",
    "mp3": "audio/mpeg",
    "wav": "audio/x-wav",
    "mp4": "video/mp4",
}


class C2paUnavailable(RuntimeError):
    """The c2pa-python package is not installed (pip install grasp-provenance[c2pa])."""


class C2paBridgeError(RuntimeError):
    """Signing or parsing failed inside the C2PA library."""


def _c2pa():
    """Lazily import the c2pa bindings; None when the optional dep is absent."""
    try:
        from c2pa import Builder, C2paSignerInfo, C2paSigningAlg, Reader, Signer, Stream
        return Builder, C2paSignerInfo, C2paSigningAlg, Reader, Signer, Stream
    except ImportError:  # pragma: no cover - exercised via the no-dep test path
        return None


def c2pa_available() -> bool:
    """True when the C2PA bridge can sign and parse in this environment."""
    return _c2pa() is not None


def _alg(alg: str):
    c = _c2pa()
    name = _ALG_MAP.get(alg.lower())
    if name is None:
        raise ValueError(
            "unknown C2PA signing algorithm {!r}; supported: {}".format(alg, sorted(_ALG_MAP)))
    try:
        return c[2][name]
    except KeyError:
        raise ValueError("c2pa-python does not expose algorithm {!r}".format(name)) from None


def _mime(fmt: str) -> str:
    m = _MIME.get(fmt.lower().lstrip("."))
    if m is None:
        raise ValueError(
            "unsupported asset format {!r}; supported: {}".format(fmt, sorted(_MIME)))
    return m


def build_manifest(
    content_addr: str,
    anchor_root: str | None,
    ts: str,
    *,
    claim_generator: str = DEFAULT_CLAIM_GENERATOR,
    extra_assertions: list[dict] | None = None,
) -> str:
    """Build the C2PA manifest JSON carrying the GRASP binding assertion.

    content_addr: the decision record's content address ("sha256:<hex>").
    anchor_root: the anchored Merkle root that covers it (or None if unanchored
    — the assertion then states anchor_root: null honestly).
    ts: the record timestamp, carried verbatim so the mark points at WHEN.
    """
    assertions = [{
        "label": ASSERTION_LABEL,
        "data": {
            "content_addr": content_addr,
            "anchor_root": anchor_root,
            "ts": ts,
        },
    }]
    if extra_assertions:
        assertions.extend(extra_assertions)
    import json
    return json.dumps({"claim_generator": claim_generator, "assertions": assertions})


def sign_asset(
    manifest_json: str,
    asset: bytes,
    fmt: str,
    *,
    alg: str = "es256",
    cert_pem: bytes,
    key_pem: bytes,
    ta_url: str | None = None,
) -> bytes:
    """Embed + sign the manifest into an asset; return the signed asset bytes.

    fmt is the bare format name ("png", "jpg", ...). cert_pem is the signer
    certificate CHAIN (PEM), key_pem the signer PRIVATE KEY (PEM). The caller
    owns credential custody — this function never stores them. Raises
    C2paUnavailable without the optional dep, C2paBridgeError on a library
    failure (e.g. a credential the C2PA validator rejects).
    """
    c = _c2pa()
    if c is None:
        raise C2paUnavailable(
            "the C2PA bridge requires c2pa-python (pip install grasp-provenance[c2pa])")
    Builder, C2paSignerInfo, _Alg, _Reader, Signer, _Stream = c
    try:
        info = C2paSignerInfo(_alg(alg), cert_pem, key_pem, ta_url)
        signer = Signer.from_info(info)
        dest = io.BytesIO()
        Builder(manifest_json).sign(signer, _mime(fmt), io.BytesIO(asset), dest)
        return dest.getvalue()
    except Exception as exc:  # the Rust core surfaces its own typed errors
        raise C2paBridgeError("C2PA signing failed: {}".format(exc)) from exc


def extract_assertion(signed_asset: bytes, *, label: str = ASSERTION_LABEL) -> dict | None:
    """Return the GRASP binding assertion data from a signed asset, or None.

    Reads the ACTIVE manifest's assertions and returns the first with the
    given label. No credential needed — this is a parse, not a trust decision.
    """
    c = _c2pa()
    if c is None:
        raise C2paUnavailable(
            "the C2PA bridge requires c2pa-python (pip install grasp-provenance[c2pa])")
    _Builder, _SignerInfo, _Alg, Reader, _Signer, _Stream = c
    try:
        reader = Reader(stream=io.BytesIO(signed_asset))
        active = reader.get_active_manifest()
    except Exception as exc:
        raise C2paBridgeError("C2PA parse failed: {}".format(exc)) from exc
    if not isinstance(active, dict):
        return None
    for assertion in active.get("assertions", []):
        if isinstance(assertion, dict) and assertion.get("label") == label:
            return assertion.get("data")
    return None


def manifest_validation(signed_asset: bytes) -> dict | None:
    """The C2PA library's own validation verdict for a signed asset.

    Returns None when the asset carries no parseable manifest. The dict reports
    is_valid plus the library's validation results — informational; the BINDING
    check below is the deterministic gate.
    """
    c = _c2pa()
    if c is None:
        raise C2paUnavailable(
            "the C2PA bridge requires c2pa-python (pip install grasp-provenance[c2pa])")
    _Builder, _SignerInfo, _Alg, Reader, _Signer, _Stream = c
    try:
        reader = Reader(stream=io.BytesIO(signed_asset))
        if reader.get_active_manifest() is None:
            return None
        return {"is_valid": bool(reader.is_valid),
                "validation_results": reader.get_validation_results()}
    except Exception as exc:
        raise C2paBridgeError("C2PA parse failed: {}".format(exc)) from exc


def verify_binding(
    signed_asset: bytes,
    *,
    content_addr: str,
    anchor_root: str | None,
    ts: str | None = None,
) -> bool:
    """True iff the embedded grasp.idr.addr assertion matches EXACTLY.

    Arithmetic, not judgement: content_addr and anchor_root must be verbatim
    equal; ts is checked when supplied. Anything else — missing assertion,
    mismatch, unparseable asset — is False. Never a manufactured pass.
    """
    try:
        data = extract_assertion(signed_asset)
    except (C2paBridgeError, C2paUnavailable):
        return False
    if not isinstance(data, dict):
        return False
    if data.get("content_addr") != content_addr:
        return False
    if data.get("anchor_root") != anchor_root:
        return False
    if ts is not None and data.get("ts") != ts:
        return False
    return True
