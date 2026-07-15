"""Bitcoin OpenTimestamps backend — anchor roots to the Bitcoin blockchain.

Anchor-first backend: record blobs persist locally (composes
``LocalAdapter`` — "records live locally; roots witness externally"), and
``anchor`` commits the Merkle root via the upstream ``ots`` client — the
same deployment step the README documents ("not our code at all"). The
proven path: pilot chains anchored in real Bitcoin blocks (953968 et al.).

Runtime dependency, honestly detected: the ``ots`` CLI
(``pipx install opentimestamps-client``). ``probe()`` reports it live.
``ots stamp`` submits to public calendar servers (network); the returned
proof file upgrades to a Bitcoin attestation later via ``ots upgrade``.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path

from grasp.home import grasp_home
from grasp.storage import ProbeResult
from grasp.storage.local import LocalAdapter


class BitcoinOTSAdapter:
    name = "bitcoin-ots"

    def __init__(self, root: str | Path | None = None) -> None:
        self._root = Path(root) if root is not None else grasp_home() / "storage"
        self._blobs = LocalAdapter(root=self._root)

    # -- blob persistence delegates to the local floor -------------------
    def put(self, record_id: str, blob: bytes) -> str:
        return self._blobs.put(record_id, blob)

    def get(self, record_id: str) -> bytes | None:
        return self._blobs.get(record_id)

    # -- the witness surface ---------------------------------------------
    def anchor(self, merkle_root: str) -> str | None:
        """Stamp the root via ``ots``; return the proof-file locator."""
        if shutil.which("ots") is None:
            return None
        ots_dir = self._root / "ots"
        ots_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(merkle_root.encode("utf-8")).hexdigest()[:12]
        root_file = ots_dir / f"root-{digest}.txt"
        root_file.write_text(merkle_root + "\n", encoding="utf-8")
        proof = root_file.with_suffix(".txt.ots")
        try:
            done = subprocess.run(
                ["ots", "stamp", str(root_file)],
                capture_output=True, text=True, timeout=60, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if done.returncode != 0 or not proof.exists():
            return None
        return f"file://{proof}"

    def probe(self) -> ProbeResult:
        if shutil.which("ots") is None:
            return ProbeResult(
                name=self.name,
                ready=False,
                detail="the OpenTimestamps client is not on PATH",
                remedy="pipx install opentimestamps-client",
            )
        blobs = self._blobs.probe()
        if not blobs.ready:
            return ProbeResult(name=self.name, ready=False,
                               detail=blobs.detail, remedy=blobs.remedy)
        return ProbeResult(
            name=self.name,
            ready=True,
            detail="roots stamp to Bitcoin via ots (calendar submission now, "
                   "block attestation upgrades later); blobs persist locally",
        )
