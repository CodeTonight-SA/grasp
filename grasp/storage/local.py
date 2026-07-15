"""Local-filesystem storage backend — the default, always-available floor.

Blobs land under ``$GRASP_HOME/storage/`` (atomic tmp+rename writes);
anchors append to ``anchors.jsonl`` under the same ``fcntl.flock``
discipline as the IDR ledger.

Anchor honesty: a local anchor is durable PERSISTENCE of the root, not an
external witness — nothing outside this machine attests to it. Deployments
wanting an independent witness pair this backend with an anchoring one
(e.g. Bitcoin OpenTimestamps).
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import time
from pathlib import Path

from grasp.home import grasp_home
from grasp.storage import ProbeResult

_SLUG = re.compile(r"[^A-Za-z0-9._-]+")


def _filename(record_id: str) -> str:
    """Collision-proof, path-safe blob name: readable slug + id digest."""
    slug = _SLUG.sub("_", record_id)[:40].strip("_") or "record"
    digest = hashlib.sha256(record_id.encode("utf-8")).hexdigest()[:8]
    return f"{slug}-{digest}.bin"


class LocalAdapter:
    name = "local"

    def __init__(self, root: str | os.PathLike | None = None) -> None:
        self._root = Path(root) if root is not None else grasp_home() / "storage"

    def put(self, record_id: str, blob: bytes) -> str:
        self._root.mkdir(parents=True, exist_ok=True)
        path = self._root / _filename(record_id)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, path)  # atomic on POSIX
        return f"file://{path}"

    def get(self, record_id: str) -> bytes | None:
        path = self._root / _filename(record_id)
        return path.read_bytes() if path.exists() else None

    def anchor(self, merkle_root: str) -> str | None:
        """Persist the root locally (no external witness — see module doc)."""
        self._root.mkdir(parents=True, exist_ok=True)
        ledger = self._root / "anchors.jsonl"
        entry = json.dumps(
            {"root": merkle_root, "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
            sort_keys=True,
        )
        with open(ledger, "a", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                fh.write(entry + "\n")
                fh.flush()
                line_no = sum(1 for _ in open(ledger, encoding="utf-8"))
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)
        return f"file://{ledger}#L{line_no}"

    def probe(self) -> ProbeResult:
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            marker = self._root / ".probe"
            marker.write_bytes(b"ok")
            marker.unlink()
        except OSError as exc:
            return ProbeResult(
                name=self.name,
                ready=False,
                detail=f"storage dir not writable: {exc}",
                remedy=f"make {self._root} writable, or point GRASP_HOME elsewhere",
            )
        return ProbeResult(
            name=self.name,
            ready=True,
            detail=f"records persist under {self._root} (local only — no external witness)",
        )
