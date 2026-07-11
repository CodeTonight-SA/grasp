# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""IDR — Intent Decision Record envelope construction, signing, and chain I/O.

An IDR is a signed, flat-JSON record of one AI decision: what was decided
(``decision``), what went in (``inputs``), when (``ts``), and where it sits in
the chain (``predecessor_idr`` / ``depth``). Records are HMAC-SHA256 signed
over a canonical body digest; ``_sign_placeholder`` is retained only for
READING legacy placeholder-signed records — new records always sign for real.

Signing keys resolve through :func:`grasp.keys.signing_key` (env
``GRASP_SIGNING_KEY`` or a locally persisted key file); the key never enters a
record — only signatures and a short key fingerprint do. Asymmetric per-tenant
signing (e.g. Ed25519, post-quantum schemes) is an integration path for
deployments that provision key custody; this reference implementation signs
HMAC-SHA256 and its verifier marks unknown schemes DEGRADED, never VERIFIED.

Locking: ``fcntl.flock`` (POSIX) for concurrent-process append safety.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

from grasp.home import grasp_home
from grasp.keys import signing_key

HAPPI_VERSION = "1.3"


def _default_idr_path() -> Path:
    """Default decision-chain ledger: ``<grasp_home>/idr.jsonl``."""
    return grasp_home() / "idr.jsonl"


def _coerce_optional_path(path: Any) -> Path | None:
    """Validate + normalise an optional filesystem-path argument to ``Path | None``.

    Accepts ``None``, a ``str``, or any ``os.PathLike`` (→ ``Path``). ANY other
    type raises a clear ``TypeError`` naming the expected types — instead of
    crashing opaquely deep in the reader (``'list' object has no attribute
    'exists'``) the way a positional-arg mix-up like
    ``verify_context_chain(ctx_list, idr_list)`` does. The chokepoint that turns
    a mis-call into a readable error rather than an ``AttributeError`` traceback.
    """
    if path is None:
        return None
    if isinstance(path, Path):
        return path
    if isinstance(path, (str, os.PathLike)):
        return Path(path)
    raise TypeError(
        f"path must be a str, os.PathLike, or None — got {type(path).__name__}. "
        f"If you already loaded a chain and meant to verify it, pass the file "
        f"path (not the chain) and use keywords: verify_context_chain(path=..., "
        f"head=...)."
    )


@dataclass
class PrecogIDR:
    happi: str
    kind: str
    id: str
    predecessor_idr: str | None
    depth: int
    fingerprint: str
    ts: str
    decision: dict[str, Any]
    inputs: dict[str, Any]
    audit: dict[str, Any]
    # Decision anatomy — the delegated decision's "mind": why / confidence /
    # uncertainties / assumptions / falsification_criteria, as a mapping.
    # OPTIONAL + back-compat: defaults to ``None`` so a minimal IDR (and every
    # legacy record) is byte-unchanged. When present it is signed into the IDR
    # with the rest of the body. Excluded from ``content_addr`` when ``None`` so
    # a record without anatomy addresses identically to a pre-anatomy record
    # (see ``_CONTENT_ADDR_EXCLUDE`` / ``content_addr``).
    decision_anatomy: dict[str, Any] | None = None


def _canonical_json(obj: dict) -> str:
    """Deterministic JSON for signing — sorted keys, no whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


# Non-body metadata excluded from the signable entry hash: chain-position fields
# plus the signature fields the signer writes ONTO an entry AFTER the hash is
# computed. Sign and verify MUST hash the identical field set, else a legitimate
# entry false-fails BROKEN.
_CHAIN_FIELDS = {"entry_hash", "chain_hash", "sequence"}
_VERIFY_EXCLUDED_FIELDS = _CHAIN_FIELDS | {"signature", "key_fingerprint", "scheme"}


def compute_entry_hash(entry: dict) -> str:
    """SHA-256 of the entry's signable BODY — excludes the non-body metadata the
    signer writes onto an entry (``_VERIFY_EXCLUDED_FIELDS``).

    This is the SINGLE canonical hash domain shared by the sign path
    (:func:`_sign_real`) AND the verify path
    (:func:`grasp.idr_forest.verify_chain_integrity`). Sorting is belt-and-braces
    hash-stability on crypto-load-bearing code: ``json.dumps(sort_keys=True)``
    already canonicalises key order; the explicit ``sorted()`` keeps the hashed
    content stable even if the dumps call ever changes.
    """
    clean = {k: v for k, v in sorted(entry.items()) if k not in _VERIFY_EXCLUDED_FIELDS}
    content = json.dumps(clean, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(content.encode()).hexdigest()


# Volatile, non-content fields excluded from the content address: `id` and `ts`
# are wall-clock + random (build_idr), `audit` is the signature derived from
# them. The content coordinate is the SEMANTIC body (kind, predecessor_idr,
# depth, fingerprint, decision, inputs, happi).
_CONTENT_ADDR_EXCLUDE = ("id", "ts", "audit")


def content_addr(envelope: dict) -> str:
    """Content address of an IDR body — sha256 of the canonical body EXCLUDING
    the volatile fields (``id``, ``ts``, ``audit``).

    Two IDRs with byte-identical semantic content but different ``id`` + ``ts``
    (and therefore different ``audit`` signatures) share ONE content_addr — the
    addressed coordinate for dedup / Merkle linkage in the context memory-chain.
    The random ``id`` and wall-clock ``ts`` remain as non-addressed metadata.
    This mirrors git's tree-hash, which excludes the committer-date so identical
    trees share a hash.

    Accepts either a raw envelope dict or ``asdict(PrecogIDR)``. Pure (no I/O).
    Returns ``"sha256:<hex>"``.

    Back-compat: ``decision_anatomy`` is dropped from the addressed body ONLY
    when it is ``None`` (or absent) — so a record carrying no anatomy addresses
    BYTE-IDENTICALLY to a pre-anatomy record, and every already-chained content
    address is unchanged. When anatomy is PRESENT it is load-bearing decision
    content and IS addressed, so two records differing only in their anatomy get
    distinct addresses.
    """
    addressed = {k: v for k, v in envelope.items() if k not in _CONTENT_ADDR_EXCLUDE}
    if addressed.get("decision_anatomy") is None:
        addressed.pop("decision_anatomy", None)
    return "sha256:" + hashlib.sha256(_canonical_json(addressed).encode()).hexdigest()


def _sign_placeholder(envelope: dict) -> dict:
    """sha256 over the canonical envelope (audit field excluded).

    Retained for reading legacy records only. New records use ``_sign_real``.
    scheme='sha256-placeholder' is NOT tamper-evident — an attacker with
    filesystem write access can recompute a matching hash.
    """
    signing_body = {k: v for k, v in envelope.items() if k != "audit"}
    digest = hashlib.sha256(_canonical_json(signing_body).encode()).hexdigest()
    return {
        "scheme": "sha256-placeholder",
        "note": "Legacy placeholder — not tamper-evident. See _sign_real.",
        "key_fingerprint": None,
        "signature": digest,
        "chain_hash": digest,
        "sequence": envelope.get("depth", 0) + 1,
    }


def _sign_real(envelope: dict) -> dict:
    """Sign an IDR audit block with HMAC-SHA256 over the canonical body digest.

    The key resolves through :func:`grasp.keys.signing_key`; the audit block
    carries a short key fingerprint (sha256 of the key, first 8 hex chars) so a
    verifier can tell WHICH key signed without learning the key. Only
    ``signature`` is verified on read; ``chain_hash``/``sequence`` are not
    stored here because IDRs are independently signed (predecessor linkage is
    via ``predecessor_idr`` in the body, not a sequential chain hash).
    """
    body = {k: v for k, v in envelope.items() if k != "audit"}
    entry_hash = compute_entry_hash(body)
    key = signing_key()
    sig = hmac.new(key, entry_hash.encode(), hashlib.sha256).hexdigest()
    return {
        "scheme": "hmac-sha256",
        "key_fingerprint": hashlib.sha256(key).hexdigest()[:8],
        "signature": "hmac-sha256:" + sig,
    }


def _resolve_anatomy_dict(decision_anatomy: Any) -> dict[str, Any] | None:
    """Canonicalise a delegated decision's anatomy for signing.

    THE single chokepoint at the IDR build boundary — callers never re-validate
    the anatomy themselves. This reference implementation accepts a
    caller-validated mapping (or ``None`` for the minimal tier — byte-unchanged
    envelope); richer semantic validation of anatomy structure is an
    integration point for the calling system.
    """
    if decision_anatomy is None:
        return None
    if isinstance(decision_anatomy, dict):
        return dict(decision_anatomy)
    raise TypeError(
        "decision_anatomy must be a mapping or None — "
        f"got {type(decision_anatomy).__name__}"
    )


def build_idr(
    prompt: str,
    fingerprint: str,
    decision: dict[str, Any],
    predecessor_idr: str | None,
    depth: int,
    *,
    kind: str = "precog-decision",
    inputs: dict[str, Any] | None = None,
    decision_anatomy: Any = None,
) -> PrecogIDR:
    """Construct a PrecogIDR envelope with real HMAC-SHA256 signing.

    decision_anatomy: OPTIONAL delegated-decision "mind" as a mapping. When
    supplied it is SIGNED INTO the IDR with the rest of the body (so a tampered
    anatomy fails ``verify_chain_integrity``). When ``None`` (minimal tier) the
    envelope, signature, and ``content_addr`` are BYTE-IDENTICAL to a
    pre-anatomy IDR — existing callers are unchanged.
    """
    from datetime import datetime, timezone
    anatomy = _resolve_anatomy_dict(decision_anatomy)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # 4-byte random suffix avoids same-second collisions when build_idr is called
    # multiple times within one second (a real risk for concurrent writers).
    idr_id = f"precog-{int(time.time())}-{secrets.token_hex(4)}"

    envelope = {
        "happi": HAPPI_VERSION,
        "kind": kind,
        "id": idr_id,
        "predecessor_idr": predecessor_idr,
        "depth": depth,
        "fingerprint": fingerprint,
        "ts": ts,
        "decision": decision,
        "inputs": inputs or {},
    }
    # Add to the SIGNED body ONLY when present — keeps the minimal-tier
    # envelope (and therefore its signature) byte-identical to the legacy shape.
    if anatomy is not None:
        envelope["decision_anatomy"] = anatomy
    audit = _sign_real(envelope)
    return PrecogIDR(
        happi=HAPPI_VERSION,
        kind=kind,
        id=idr_id,
        predecessor_idr=predecessor_idr,
        depth=depth,
        fingerprint=fingerprint,
        ts=ts,
        decision=decision,
        inputs=inputs or {},
        audit=audit,
        decision_anatomy=anatomy,
    )


def append_idr(idr: PrecogIDR, path: Path | None = None) -> None:
    """Atomically append one IDR as a JSONL line.

    Uses ``fcntl.flock`` for POSIX concurrent-process safety.
    """
    target = path or _default_idr_path()
    target.parent.mkdir(parents=True, exist_ok=True)

    line = _canonical_json(asdict(idr)) + "\n"
    with open(target, "a", encoding="utf-8") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            fh.write(line)
            fh.flush()
            os.fsync(fh.fileno())
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def read_idr_chain(
    predecessor_id: str | None = None,
    path: Path | None = None,
) -> list[PrecogIDR]:
    """Read the predecessor chain starting from ``predecessor_id``.

    If ``predecessor_id`` is None, returns all IDRs in file order.
    Otherwise traverses the chain backwards from the named IDR.

    ``predecessor_id`` must be a str id or None; ``path`` a str/PathLike/None.
    A wrong type (e.g. a whole chain passed where a path/id was expected) raises
    a clear ``TypeError`` at the boundary instead of a downstream
    ``AttributeError``.
    """
    if predecessor_id is not None and not isinstance(predecessor_id, str):
        raise TypeError(
            f"predecessor_id must be a str id or None — got "
            f"{type(predecessor_id).__name__}"
        )
    target = _coerce_optional_path(path) or _default_idr_path()
    if not target.exists():
        return []
    all_idrs = _parse_idr_file(target)
    if predecessor_id is None:
        return all_idrs
    return _traverse_predecessor_chain(all_idrs, predecessor_id)


def _parse_idr_file(target: Path) -> list[PrecogIDR]:
    """Parse every JSONL line of ``target`` into a ``PrecogIDR`` (file order).

    ``if k in d`` is the back-compat key: legacy records predate optional fields
    (e.g. ``decision_anatomy``). Without the guard a missing key raises KeyError →
    the ``except`` below would SILENTLY DROP the legacy record from the chain.
    Optional fields fall back to their dataclass defaults instead.
    """
    all_idrs: list[PrecogIDR] = []
    with open(target, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                all_idrs.append(PrecogIDR(**{
                    k: d[k] for k in PrecogIDR.__dataclass_fields__ if k in d
                }))
            except (json.JSONDecodeError, KeyError, TypeError):
                continue
    return all_idrs


def _traverse_predecessor_chain(
    all_idrs: list[PrecogIDR], predecessor_id: str
) -> list[PrecogIDR]:
    """Walk backwards from ``predecessor_id`` via ``predecessor_idr`` links and
    return the chain root→leaf. Cycle-safe (a ``visited`` set); stops at the
    first id absent from the file."""
    by_id = {idr.id: idr for idr in all_idrs}
    chain: list[PrecogIDR] = []
    current_id: str | None = predecessor_id
    visited: set[str] = set()
    while current_id and current_id not in visited:
        idr = by_id.get(current_id)
        if idr is None:
            break
        chain.append(idr)
        visited.add(current_id)
        current_id = idr.predecessor_idr
    chain.reverse()
    return chain
