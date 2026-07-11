# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Context memory-chain — write / read / verify over signed IDR deltas.

The chain is a linear sequence of ``context-delta`` IDRs (:mod:`grasp.idr`),
each HMAC-SHA256-signed and linking its predecessor via ``predecessor_idr``.
The genesis delta links to an exogenous anchor
(``council:context-chain-genesis``) so ``verify_chain_integrity`` can root the
forest. Append is build → append → atomic HEAD swap; read resolves HEAD and
traverses; verify rebuilds the forest and returns the tri-state ``Verdict``.

Five operations: write, read, replay (read + re-fold), audit (this module's
``verify_context_chain``), modify (``context-supersede`` — a forward-only
correction; a fold masks the old delta, it is never rewritten). This module is
the WRITE+VERIFY side; signing lives in :mod:`grasp.idr`, verification in
:mod:`grasp.idr_forest` — neither imports any model/LLM machinery (the
import-isolation test makes that a compile-time fact).
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from grasp.context_head import _session_path, read_head, write_head
from grasp.home import grasp_home
from grasp.idr_forest import (
    IdrForestError,
    ReplayResult,
    build_chain_forest,
    replay_chain,
    verify_chain_integrity,
)
from grasp.idr import (
    PrecogIDR,
    _canonical_json,
    _coerce_optional_path,
    append_idr,
    build_idr,
    content_addr,
    read_idr_chain,
)
from grasp.verdict import Verdict

# Public API: the re-export of IdrForestError — and the ReplayResult / Verdict
# types the replay+verify contract returns — is EXPLICIT, rather than an
# implicit import-coupling consumers reach via the module object.
__all__ = [
    "chain_path",
    "append_context",
    "read_context_chain",
    "verify_context_chain",
    "context_addr",
    "checkpoint",
    "replay_context",
    "resolve_citation",
    "blob_path",
    "chain_head_stamp",
    "stamp_view_header",
    "IdrForestError",
    "ReplayResult",
    "Verdict",
]

# The genesis delta's predecessor — an admissible exogenous anchor (council:
# prefix) so the chain roots into a Forest. The chain is signature-verified
# regardless; the anchor gives it an exogenous root.
_GENESIS_ANCHOR = "council:context-chain-genesis"


def _default_chain_path() -> Path:
    return grasp_home() / "context.jsonl"


def chain_path(path: Path | None = None) -> Path:
    # Per-session namespacing — resolve the session-scoped sibling of the base
    # (``context.jsonl`` -> ``context-a7b2.jsonl``) via the shared
    # ``context_head._session_path`` helper (chain + HEAD use ONE namespacing
    # rule, so they never disagree on the session segment). Unchanged path when
    # no session id is set. ``path`` is type-guarded (_coerce_optional_path): a
    # wrong type — e.g. a whole chain passed positionally into
    # verify_context_chain(ctx, idrs) — raises a clear TypeError here instead of
    # crashing opaquely with "'list' object has no attribute 'exists'".
    return _coerce_optional_path(path) or _session_path(_default_chain_path())


def blob_path(addr: str, *, path: Path | None = None) -> Path:
    """On-disk location of a content-addressed kernel blob. The store is a
    ``blobs/`` sibling of the chain file — so it follows the state home AND a
    test's tmp chain path identically — but is NOT session-namespaced: a blob is
    addressed purely by the SHA-256 of its bytes, so two sessions that fold to
    the same kernel share one blob (content-addressed, git-tree style). ``path``
    (the chain file) only fixes the parent directory; the session segment in its
    filename is irrelevant to ``.parent``."""
    return chain_path(path).parent / "blobs" / addr


def append_context(
    decision: dict[str, Any],
    *,
    fingerprint: str,
    kind: str = "context-delta",
    inputs: dict[str, Any] | None = None,
    model_versions: list[str] | None = None,
    records_idr: str | None = None,
    path: Path | None = None,
    head_pointer: Path | None = None,
) -> PrecogIDR:
    """Append one context delta and atomically swap HEAD to it. Returns the new
    node. The genesis delta (no prior HEAD) links to the exogenous genesis
    anchor so the chain is rooted; later deltas link to the prior context node.

    ``records_idr`` (the cross-reference): the ``content_addr`` of the signed
    *decision-IDR* (in the separate decision ledger, ``idr.jsonl``) that THIS
    context delta records. It is a CROSS-REFERENCE between two chains, NOT the
    temporal spine — ``predecessor_idr`` remains the same-file root→leaf link
    and is never reused for this. The citation is folded INTO ``decision``
    BEFORE signing, so a tampered ``records_idr`` byte fails
    ``verify_context_chain`` (BROKEN). Strictly additive: when ``None`` the
    decision body — and therefore the node's ``content_addr`` — is
    BYTE-IDENTICAL to an uncited record (back-compat). The caller's dict is
    never mutated (a shallow copy carries the citation).
    """
    cpath = chain_path(path)
    prev = read_head(head_pointer)
    if prev is None:
        predecessor, depth = _GENESIS_ANCHOR, 0
    else:
        predecessor = prev
        depth = len(read_idr_chain(predecessor_id=prev, path=cpath))
    inp = dict(inputs or {})
    if model_versions:
        inp.setdefault("model_versions", list(model_versions))
    # Citation folded into the signed body. Copy-on-cite (never mutate the caller's
    # dict); omit the key entirely when uncited so content_addr is byte-unchanged.
    body = decision if records_idr is None else {**decision, "records_idr": records_idr}
    idr = build_idr(
        prompt="",
        fingerprint=fingerprint,
        decision=body,
        predecessor_idr=predecessor,
        depth=depth,
        kind=kind,
        inputs=inp,
    )
    append_idr(idr, path=cpath)
    write_head(idr.id, head_pointer)
    return idr


def read_context_chain(head: str | None = None, path: Path | None = None,
                       head_pointer: Path | None = None) -> list[PrecogIDR]:
    """Resolve HEAD (explicit ``head`` wins; otherwise read the ``head_pointer``
    file) and return the chain root→leaf. Empty list when the chain has no head."""
    cpath = chain_path(path)
    resolved = head if head is not None else read_head(head_pointer)
    if resolved is None:
        return []
    return read_idr_chain(predecessor_id=resolved, path=cpath)


def verify_context_chain(path: Path | None = None, head: str | None = None) -> Verdict:
    """Rebuild the forest from the chain and return the integrity ``Verdict``.

    TWO axes, both required for ``VERIFIED``:
      (a) **spine HMAC** — every node's HMAC matches its body; a flipped delta
          byte drives it to ``BROKEN`` (``verify_chain_integrity``, pure-HMAC,
          no model on the verify path).
      (b) **blob-presence** — a ``context-snapshot`` that carries a kernel blob
          reference (``decision.kernel_blob_addr``) is ``BROKEN`` unless that
          blob EXISTS on disk AND its bytes hash back to the recorded address.
          This closes the dangling-pointer class: a reaped/deleted snapshot blob
          would otherwise read ``VERIFIED`` (the address is signed, not the
          bytes) while rehydration finds nothing — VERIFIED-but-gone. A SHA-256
          is tamper-*evidence*, not tamper-*recovery*; (b) adds the existence
          proof.

    Axis (b) is **monotone-toward-safe and inert by construction**: it can only
    turn a spine-VERIFIED-but-dangling result ``BROKEN``, never a sound node
    broken, and a snapshot WITHOUT a ``kernel_blob_addr`` is not blob-backed →
    not checked → its verdict is unchanged. So no existing chain regresses. An
    empty chain is vacuously ``VERIFIED``.

    Reaped-chain boundary: after a garbage-collector archives the pre-snapshot
    prefix, the live root is a ``context-snapshot`` whose predecessor was moved
    to the cold archive. A verified fold IS an exogenous checkpoint, so that
    archived predecessor is admitted as a boundary root — but ONLY when the
    root node is a ``context-snapshot``; a non-snapshot dangling predecessor
    stays a real ``BROKEN`` (genuine missing-link corruption). Forest edges are
    structural only — ``verify_chain_integrity`` checks each node's own HMAC,
    so admitting the boundary never weakens tamper-detection.
    """
    chain = read_context_chain(head=head, path=path)
    if not chain:
        return Verdict.VERIFIED
    try:
        forest = _forest_from_chain(chain)
    except IdrForestError:
        return Verdict.BROKEN  # a dangling mid-chain link is genuine corruption
    verdict = verify_chain_integrity(forest)  # axis (a) — spine HMAC (unchanged)
    if not _snapshot_blobs_present(chain, path):  # axis (b) — blob-presence
        return Verdict.BROKEN  # a dangling/corrupt referenced blob dominates
    return verdict


def _snapshot_blobs_present(chain: list[PrecogIDR], path: Path | None) -> bool:
    """True iff every BLOB-BACKED ``context-snapshot`` in the chain has its
    referenced kernel blob present-and-intact on disk. A snapshot is blob-backed
    iff its ``decision`` carries a non-empty ``kernel_blob_addr``; snapshots
    without it are skipped → inert. Pure read; never raises (a probe never
    breaks the verify path — a read error counts as a missing blob, i.e.
    ``False``, which is the safe direction)."""
    return all(
        _snapshot_blob_intact(node, path)
        for node in chain
        if node.kind == "context-snapshot"
    )


def _snapshot_blob_intact(node: PrecogIDR, path: Path | None) -> bool:
    """Per-snapshot axis-(b) check. ``True`` when the snapshot is NOT blob-backed
    (no ``kernel_blob_addr`` — the inert default), OR its blob file exists and its
    bytes hash (SHA-256) back to the recorded address. ``False`` (→ ``BROKEN``)
    when a recorded blob is missing or its bytes do not match the address
    (corruption). The recorded address is what the spine HMAC signs, so a tampered
    address is already caught by axis (a); axis (b) covers EXISTENCE of the bytes
    that address points at."""
    addr = (node.decision or {}).get("kernel_blob_addr")
    if not addr:
        return True  # not blob-backed → inert, never checked
    try:
        blob = blob_path(str(addr), path=path)
        if not blob.is_file():
            return False  # recorded blob is gone — the dangling-pointer class
        return hashlib.sha256(blob.read_bytes()).hexdigest() == addr
    except OSError:
        return False  # unreadable counts as missing — the safe direction


def resolve_citation(delta: PrecogIDR, idr_path: Path | None = None) -> str:
    """Read-side resolver for a context delta's cross-reference citation.

    Returns ``"RESOLVED"`` when the delta's ``decision[records_idr]`` names a
    ``content_addr`` present in the decision-IDR ledger (``idr.jsonl``),
    ``"DANGLING"`` when the cited address is absent. An UNCITED delta (no
    ``records_idr``) is vacuously ``"RESOLVED"`` — there is no reference to
    dangle.

    Fail-open by contract — NEVER raises: any ledger read error / malformed
    node / missing field degrades to ``"RESOLVED"`` (the citation is treated as
    not-yet-refutable, never as a hard failure). This is a pure,
    signature-INDEPENDENT cross-reference probe: a ``DANGLING`` citation does
    NOT make the chain ``BROKEN`` (the signed link is ``predecessor_idr``; the
    citation is a separate axis), so ``verify_context_chain`` stays
    ``VERIFIED`` even when ``resolve_citation`` is ``DANGLING``. Imports no
    model/LLM machinery (preserves the import-isolation property).
    """
    try:
        cited = (delta.decision or {}).get("records_idr")
        if not cited:
            return "RESOLVED"  # uncited — nothing to dangle
        ledger = read_idr_chain(predecessor_id=None, path=idr_path)
        present = {content_addr(asdict(node)) for node in ledger}
        return "RESOLVED" if cited in present else "DANGLING"
    except Exception:  # fail-open: a probe never breaks the read path
        return "RESOLVED"


def context_addr(idr: PrecogIDR) -> str:
    """Content address of a context node — the dedup/Merkle coordinate. Thin
    re-export of ``grasp.idr.content_addr`` over the node's envelope
    (excludes the volatile id/ts/audit fields)."""
    return content_addr(asdict(idr))


def checkpoint(
    next_step: dict | None,
    summary: str = "",
    *,
    title: str | None = None,
    tier: str = "feedback",
    paramount: bool = False,
    records_idr: str | None = None,
    path: Path | None = None,
    head_pointer: Path | None = None,
    model_versions: list[str] | None = None,
) -> PrecogIDR:
    """Write ONE signed ``context-delta`` carrying the volatile ``next_step`` BY
    VALUE + a kernel ``summary``, threading the predecessor — the
    read-from-previous chain: each delta links the one before, which linked ITS
    predecessor. The genesis call (no prior HEAD) roots at the exogenous anchor
    via ``append_context``, so the FIRST checkpoint seeds the chain.

    HARNESS-NEUTRAL: imports no model/LLM machinery and takes no
    framework-specific object — any harness invokes this on its own checkpoint
    cadence (a save, an end-of-request, an explicit user checkpoint). The
    "turn" notion lives only in the per-harness caller. ``next_step`` is stored
    by VALUE (the small volatile mental-model summary a warm-start reads); a
    bulk kernel is carried BY REFERENCE on a periodic snapshot
    (``kernel_blob_addr``), never embedded here (read-by-reference).
    """
    decision = {
        "next_step": next_step if isinstance(next_step, dict) else {},
        "summary": str(summary or "")[:600],
        "title": title or "context checkpoint",
        "tier": tier,
        "paramount": bool(paramount),
    }
    fingerprint = hashlib.sha256(_canonical_json(decision).encode("utf-8")).hexdigest()
    return append_context(
        decision,
        fingerprint=fingerprint,
        kind="context-delta",
        records_idr=records_idr,
        model_versions=model_versions,
        path=path,
        head_pointer=head_pointer,
    )


def _forest_from_chain(chain: list[PrecogIDR]):
    """Build the verified forest from a context chain — shared by verify + replay.
    Admits a reaped ``context-snapshot`` as the lone sanctioned non-genesis
    boundary root: a reaped chain's root is a snapshot whose archived
    predecessor is gone from the file. ``build_chain_forest`` encapsulates that
    lone admission (no raw ``Forest(...)`` at the call site); a non-snapshot
    dangling predecessor is NOT named, so ``add_idr`` raises ``IdrForestError``
    → the caller maps it to ``BROKEN`` (genuine mid-chain corruption)."""
    first = chain[0]
    present = {n.id for n in chain}
    snapshot_boundary = (
        first.predecessor_idr
        if (first.predecessor_idr not in (None, _GENESIS_ANCHOR)
            and first.predecessor_idr not in present
            and first.kind == "context-snapshot")
        else None
    )
    return build_chain_forest(
        chain, genesis_anchor=_GENESIS_ANCHOR, snapshot_boundary=snapshot_boundary
    )


def replay_context(head: str | None = None, path: Path | None = None) -> ReplayResult | None:
    """Deterministically REPLAY the context memory chain root→HEAD — the audit /
    replay / analyse primitive over the signed memory substrate. Pure +
    PROVIDER-AGNOSTIC (no model on the path): replay is re-derivation from the
    signed chain, which is why it is byte-stable and reproducible
    (``ReplayResult.replay_digest``).

    Returns ``None`` when the chain is empty/unresolvable OR structurally
    unbuildable — a dangling non-snapshot link makes ``_forest_from_chain``
    raise ``IdrForestError``; we map that to ``None`` to honour the documented
    contract, rather than leak an unhandled exception. A chain that BUILDS but
    fails its HMAC surfaces ``BROKEN`` in the verdict via ``replay_chain``.
    Proves the chain's purpose: the memory is auditable (verdict), replayable
    (digest stable across runs) and analysable (the reconstructed sequence)."""
    resolved = head if head is not None else read_head()
    if resolved is None:
        return None
    chain = read_context_chain(head=resolved, path=path)
    if not chain:
        return None
    try:
        forest = _forest_from_chain(chain)
    except IdrForestError:
        return None  # structurally-unbuildable chain → nothing to replay (contract)
    return replay_chain(forest, resolved)


# ---------------------------------------------------------------------------
# Freshness stamp (write-side)
# ---------------------------------------------------------------------------

# Matches a single stamp comment line so ``stamp_view_header`` is idempotent:
# re-stamping a view replaces the prior stamp rather than accreting copies.
_STAMP_RE = re.compile(r"^<!-- chain-HEAD:.*?-->\n", re.MULTILINE)


def chain_head_stamp(node_id: str, ts: str | None = None) -> str:
    """The freshness-stamp comment line a derived view carries so a later reader
    can tell whether the view is current (its stamped HEAD == ``read_head``)
    or stale → re-fold. ``ts`` defaults to an ISO-8601 UTC instant."""
    when = ts or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"<!-- chain-HEAD: {node_id} · folded-at: {when} -->"


def stamp_view_header(text: str, node_id: str, ts: str | None = None) -> str:
    """Return ``text`` with the freshness stamp as its FIRST line — idempotently
    (any existing ``chain-HEAD`` stamp lines are stripped first, so repeated
    stamping never accretes). Pure."""
    stripped = _STAMP_RE.sub("", text)
    return f"{chain_head_stamp(node_id, ts)}\n{stripped}"
