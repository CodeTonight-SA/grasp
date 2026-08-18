"""Continuity receipts — so VERIFIED means complete-or-fail.

The defect this closes (internal red-team, 2026-08-13): ``grasp verify``
recomputes the Merkle root over whatever the ledger currently contains, so
deleting the newest records — or rewriting one and re-sealing it with the
local key — yields a smaller or different chain that is internally consistent
and still reads VERIFIED. The anchor proof for the OLD root then merely reads
"no proof on disk" for the new root, which is indistinguishable from "never
anchored". A verifier that prints VERIFIED over a truncated log is not a
known limitation; it is a false claim emitted by the tool itself.

A continuity receipt closes the loop. At anchor time, next to the stamped
root file, we write the full sorted leaf set (content addresses) that the
root commits to, plus the chain tip. At verify time the anchored set must be
a SUBSET of the current set: an anchored record that has vanished
(truncation) or changed (its content address moved — including a key-holder
rewrite that re-seals correctly) fails loudly.

The receipt inherits the anchor's integrity rather than adding a new trust
root: its ``merkle_root`` must recompute exactly from its own ``leaves``
(arithmetic, not judgement), and its filename is derived from that root by
the same digest rule as the stamped ``root-*.txt`` / ``.ots`` pair — so a
doctored leaf list breaks the recompute, and a doctored root no longer names
its own proof.

Trust honesty, stated once and surfaced by the verifier:

- Receipts protect records that were anchored. Records appended after the
  newest receipt are covered by the NEXT anchor — the window between anchors
  is a stated limit, not a hidden one.
- No receipts on disk (a legacy anchor, a fresh install) reports
  ``no-receipts`` — never a manufactured pass, never a manufactured failure.
- A receipt that fails its own arithmetic reports ``receipt-corrupt`` and
  takes ``ok`` away: a corrupt integrity artefact is itself a red flag.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from grasp.idr_forest import _forest_leaves, _forest_leaves_ts, forest_merkle_root_ts
from grasp.merkle import merkle_root as _merkle_root

RECEIPT_KIND = "grasp-continuity-receipt"
RECEIPT_SUFFIX = ".receipt.json"
_MISSING_SAMPLE_CAP = 3


def current_leaf_set(forest: Any) -> set:
    """The forest's leaf set, for callers that must not touch private names."""
    return set(_forest_leaves(forest))


def _root_digest12(merkle_root_hex: str) -> str:
    """The same locator rule as ``BitcoinOTSAdapter._proof_path`` — one root,
    one family of files: ``root-<d12>.txt`` / ``.txt.ots`` / ``.receipt.json``."""
    return hashlib.sha256(merkle_root_hex.encode("utf-8")).hexdigest()[:12]


def receipt_path(merkle_root_hex: str, storage_root: Path) -> Path:
    return storage_root / "ots" / (
        f"root-{_root_digest12(merkle_root_hex)}{RECEIPT_SUFFIX}")


def build_receipt(forest: Any, chain: list) -> dict:
    """A pure snapshot of what this anchor commits to. No I/O.

    Leaf version 2: leaves are timestamp-aware (content address + recorded ts),
    so the stamped root commits to record TIMES as well as record content —
    roadmap item 2."""
    leaves = _forest_leaves_ts(forest)
    return {
        "kind": RECEIPT_KIND,
        "leaf_version": 2,
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "merkle_root": forest_merkle_root_ts(forest),
        "leaf_count": len(leaves),
        "leaves": leaves,
        "tip_id": chain[-1].id if chain else None,
        "tip_ts": chain[-1].ts if chain else None,
    }


def write_receipt(receipt: dict, storage_root: Path) -> Path:
    """Atomic write (tmp + rename), so a crash never leaves a half receipt."""
    target = receipt_path(receipt["merkle_root"], storage_root)
    target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(json.dumps(receipt, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, target)
    return target


def _recomputes(receipt: dict) -> bool:
    """Does the receipt's root recompute from its own leaves? Arithmetic only."""
    leaves = receipt.get("leaves")
    if not isinstance(leaves, list) or not all(isinstance(x, str) for x in leaves):
        return False
    recomputed = _merkle_root([x.encode("utf-8") for x in sorted(leaves)])
    return recomputed == receipt.get("merkle_root")


def load_receipts(storage_root: Path) -> tuple[list[dict], list[str]]:
    """(parseable receipts sorted oldest→newest, unparseable file names)."""
    ots_dir = storage_root / "ots"
    receipts: list[dict] = []
    unreadable: list[str] = []
    if not ots_dir.is_dir():
        return receipts, unreadable
    for path in sorted(ots_dir.glob(f"root-*{RECEIPT_SUFFIX}")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("receipt is not an object")
        except (OSError, ValueError, json.JSONDecodeError):
            unreadable.append(path.name)
            continue
        data["_path"] = str(path)
        receipts.append(data)
    receipts.sort(key=lambda r: str(r.get("created_utc", "")))
    return receipts, unreadable


EXPECTED_ROOT_FILE = "expected-root.json"


def pinned_expected_root(storage_root: Path) -> str | None:
    """The out-of-band pinned latest anchored root, if the deployment declared
    one. Sources: ``GRASP_EXPECTED_ROOT`` env, else ``<storage>/ots/expected-
    root.json`` (``{"merkle_root": "<hex>"}``). A pinned root turns missing and
    rolled-back receipts into hard failures (roadmap item 3)."""
    env = os.environ.get("GRASP_EXPECTED_ROOT", "").strip()
    if env:
        return env
    path = storage_root / "ots" / EXPECTED_ROOT_FILE
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            root = data.get("merkle_root") if isinstance(data, dict) else None
            if isinstance(root, str) and root:
                return root
        except (OSError, ValueError, json.JSONDecodeError):
            return None
    return None


def refuse_on_gap_requested() -> bool:
    """Has the deployment demanded that 'no receipts' FAIL verification?"""
    env = os.environ.get("GRASP_REFUSE_ON_GAP", "").strip().lower()
    return env in ("1", "true", "yes", "on")



def check_continuity(
    current_leaves: set[str],
    storage_root: Path,
    *,
    expected_root: str | None = None,
    refuse_on_gap: bool | None = None,
    current_leaves_ts: set[str] | None = None,
) -> dict:
    """Is every anchored record still present, byte-for-byte, in the ledger?

    ``expected_root`` (or the out-of-band pin) turns missing receipts and
    rolled-back receipts into hard failures — closing the 'delete the receipts
    too' residual (roadmap items 3-4). ``refuse_on_gap`` makes 'no receipts'
    fail instead of being reported.

    Judged against the NEWEST receipt — the strongest commitment made. The
    verdict never blends axes: ``no-receipts`` is absence of a commitment,
    ``receipt-corrupt`` is a commitment that fails its own arithmetic,
    ``broken`` is a commitment the current ledger no longer honours, and
    ``ok`` carries the counts that prove it.
    """
    receipts, unreadable = load_receipts(storage_root)
    out: dict[str, Any] = {"current_leaf_count": len(current_leaves)}
    if unreadable:
        out["unreadable_receipts"] = unreadable
    if expected_root is None:
        expected_root = pinned_expected_root(storage_root)
    if refuse_on_gap is None:
        refuse_on_gap = refuse_on_gap_requested()
    if not receipts:
        if unreadable:
            out["status"] = "receipt-corrupt"
            out["detail"] = "a continuity receipt exists but cannot be read — treat as tamper"
        elif expected_root is not None:
            out["status"] = "expected-root-missing"
            out["expected_root"] = expected_root
            out["detail"] = ("an anchored root is pinned out-of-band, but no continuity "
                             "receipts exist on disk — the receipts were deleted, so "
                             "completeness since the pinned anchor cannot be checked")
        elif refuse_on_gap:
            out["status"] = "refuse-on-gap"
            out["detail"] = ("no continuity receipts on disk and refuse-on-gap is set — "
                             "completeness since an anchor cannot be established, so "
                             "verification refuses instead of passing")
        else:
            out["status"] = "no-receipts"
            out["detail"] = ("no continuity receipts on disk — nothing was anchored with a "
                             "receipt yet, so completeness since an anchor cannot be checked")
        return out
    newest = receipts[-1]
    out["receipt"] = newest.get("_path")
    out["receipt_created_utc"] = newest.get("created_utc")
    if expected_root is not None and newest.get("merkle_root") != expected_root:
        out["status"] = "expected-root-mismatch"
        out["expected_root"] = expected_root
        out["detail"] = ("the pinned expected root does not match the newest receipt's "
                         "root — the receipt set was rolled back or replaced")
        return out
    if not _recomputes(newest):
        out["status"] = "receipt-corrupt"
        out["detail"] = ("the newest continuity receipt does not recompute to "
                         "its own merkle_root — the receipt was altered")
        return out
    # Compare in the receipt's own leaf domain: version-2 receipts commit to
    # timestamp-aware leaves, version-1 (legacy) to bare content addresses.
    compare = (
        current_leaves_ts
        if newest.get("leaf_version") == 2 and current_leaves_ts is not None
        else current_leaves
    )
    anchored = set(newest["leaves"])
    out["anchored_leaf_count"] = len(anchored)
    missing = sorted(anchored - compare)
    if missing:
        out["status"] = "broken"
        out["missing"] = len(missing)
        out["missing_sample"] = missing[:_MISSING_SAMPLE_CAP]
        out["detail"] = (
            f"{len(missing)} anchored record(s) are no longer in the ledger — "
            "the chain was truncated or a record was rewritten since the "
            f"anchor of {newest.get('created_utc')}")
        return out
    out["status"] = "ok"
    out["detail"] = (
        f"all {len(anchored)} anchored records are present; "
        f"{len(current_leaves) - len(anchored)} newer record(s) await the "
        "next anchor")
    return out
