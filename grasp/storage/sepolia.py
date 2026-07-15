"""Sepolia-testnet backend — anchor roots via a configured signer command.

Anchor-first backend (blobs persist locally, like the Bitcoin backend).
Transaction signing is deliberately NOT reimplemented here: rolling your
own secp256k1 in a provenance package is a security smell. Instead the
adapter shells out to a configured signer command — the proven Alchemy-CLI
path already used for Sepolia publishing — passing the Merkle root as the
final argument and reading the transaction hash from stdout.

Runtime dependency, honestly detected: the signer command (constructor arg
or the ``GRASP_SEPOLIA_SIGNER`` environment variable), e.g. a thin wrapper
around your Alchemy CLI account. ``probe()`` reports it live.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from grasp.home import grasp_home
from grasp.storage import ProbeResult
from grasp.storage.local import LocalAdapter

_TX_HASH = re.compile(r"0x[0-9a-fA-F]{64}")
_EXPLORER = "https://sepolia.etherscan.io/tx/"


class SepoliaAdapter:
    name = "sepolia"

    def __init__(self, signer_cmd: str | None = None,
                 root: str | Path | None = None) -> None:
        self._signer_cmd = signer_cmd or os.environ.get("GRASP_SEPOLIA_SIGNER", "")
        self._blobs = LocalAdapter(
            root=Path(root) if root is not None else grasp_home() / "storage")

    def put(self, record_id: str, blob: bytes) -> str:
        return self._blobs.put(record_id, blob)

    def get(self, record_id: str) -> bytes | None:
        return self._blobs.get(record_id)

    def anchor(self, merkle_root: str) -> str | None:
        """Run the signer with the root; return the explorer URL for the tx."""
        if not self._signer_cmd:
            return None
        try:
            done = subprocess.run(
                [*shlex.split(self._signer_cmd), merkle_root],
                capture_output=True, text=True, timeout=120, check=False,
            )
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return None
        if done.returncode != 0:
            return None
        match = _TX_HASH.search(done.stdout)
        return f"{_EXPLORER}{match.group(0)}" if match else None

    def probe(self) -> ProbeResult:
        if not self._signer_cmd:
            return ProbeResult(
                name=self.name,
                ready=False,
                detail="no Sepolia signer command configured",
                remedy="set the Sepolia signer env var to your signing CLI "
                       "(it receives the Merkle root as its final argument "
                       "and prints the tx hash)",
            )
        binary = shlex.split(self._signer_cmd)[0]
        if shutil.which(binary) is None:
            return ProbeResult(
                name=self.name,
                ready=False,
                detail=f"signer binary {binary!r} is not on PATH",
                remedy=f"install {binary!r} or fix the configured command",
            )
        return ProbeResult(
            name=self.name,
            ready=True,
            detail=f"roots anchor to Sepolia via {binary!r}; "
                   "blobs persist locally",
        )
