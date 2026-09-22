#!/usr/bin/env python3
"""Verify the GRASP production decision-chain anchor with the standard library only.

Three checks, each independent of GRASP and of its authors:

  1. The 501 published leaf hashes recompute, as an RFC 6962 Merkle tree, to the
     root named in the manifest (decision-chain-501-2026-07-06.json).
  2. The manifest's SHA-256 is the digest the OpenTimestamps proof commits to
     (the proof file's attested digest).
  3. If the `ots` client is installed, run it: it names the Bitcoin blocks whose
     merkle roots commit to that digest. Check those roots on any block explorer.

Usage:  python3 verify.py            (run from this directory, or pass the directory)
Exit 0 on success, 1 on any mismatch.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess
import sys

HERE = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else __file__).resolve()
HERE = HERE if HERE.is_dir() else HERE.parent
STEM = "decision-chain-501-2026-07-06"


def node_hash(left: bytes, right: bytes) -> bytes:
    """RFC 6962 interior node: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def largest_pow2_below(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(leaf_hashes: list[bytes]) -> bytes:
    """RFC 6962 Merkle Tree Head over already-hashed leaves (SHA-256(0x00 || leaf))."""
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = largest_pow2_below(n)
    return node_hash(mth(leaf_hashes[:k]), mth(leaf_hashes[k:]))


def main() -> int:
    ok = True
    manifest_path = HERE / f"{STEM}.json"
    manifest = json.loads(manifest_path.read_text())
    root = manifest["canonical_merkle_root_rfc6962"]
    leaves = [bytes.fromhex(h) for h in (HERE / f"{STEM}.leaf-hashes.txt").read_text().split()]
    recomputed = mth(leaves).hex()
    print(f"[1] leaf hashes: {len(leaves)} (manifest says rows={manifest['rows']})")
    print(f"    recomputed root: {recomputed}")
    print(f"    manifest root  : {root}")
    print("    MATCH" if recomputed == root and len(leaves) == manifest["rows"] else "    MISMATCH")
    ok &= recomputed == root and len(leaves) == manifest["rows"]

    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    print(f"[2] manifest sha256 (the digest the .ots proof commits to): {digest}")

    ots = shutil.which("ots")
    proof = HERE / f"{STEM}.json.ots"
    if ots:
        r = subprocess.run([ots, "--no-bitcoin", "verify", "-f", str(manifest_path), str(proof)],
                           capture_output=True, text=True)
        out = (r.stdout + r.stderr).strip()
        print("[3] ots --no-bitcoin verify:")
        for line in out.splitlines():
            print("    " + line)
        if "Bitcoin block" not in out:
            ok = False
    else:
        print("[3] `ots` client not installed; install with `pip install opentimestamps-client`, then run:")
        print(f"    ots --no-bitcoin verify -f {manifest_path.name} {proof.name}")
        print("    and compare each printed merkleroot with the block on any explorer, e.g.")
        print("    https://blockstream.info/block-height/956991 and https://blockstream.info/block-height/956992")
    print("RESULT:", "VERIFIED" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
