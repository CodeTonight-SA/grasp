#!/usr/bin/env python3
"""Verify the GRASP production decision-chain anchor with the standard library only.

Three checks, reported separately, each independent of GRASP and of its authors:

  1. ROOT   the 501 published leaf hashes recompute, as an RFC 6962 Merkle tree, to
            the root named in the manifest (decision-chain-501-2026-07-06.json).
  2. PROOF  the OpenTimestamps proof commits to the manifest's SHA-256 and carries
            Bitcoin block-header attestations (needs the `ots` client; with
            --no-bitcoin the client prints the block heights and merkle roots to check).
  3. CHAIN  each attested block really has that merkle root. This script does NOT
            trust itself for this step: pass --explorer to fetch the block headers
            from blockstream.info, or check the printed roots against a node or
            another explorer yourself.

Usage:  python3 verify.py [directory] [--explorer]
Exit 0 only when every check that was run passed AND the chain check was performed;
exit 2 when the result is INCOMPLETE (a step could not run); exit 1 on any mismatch.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re
import shutil
import subprocess
import sys
import urllib.request

STEM = "decision-chain-501-2026-07-06"
EXPLORER = "https://blockstream.info/api"


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


def check_root(here: pathlib.Path) -> bool:
    manifest = json.loads((here / f"{STEM}.json").read_text())
    root = manifest["canonical_merkle_root_rfc6962"]
    leaves = [bytes.fromhex(h) for h in (here / f"{STEM}.leaf-hashes.txt").read_text().split()]
    recomputed = mth(leaves).hex()
    ok = recomputed == root and len(leaves) == manifest["rows"]
    print(f"[1 ROOT ] leaf hashes: {len(leaves)} (manifest rows={manifest['rows']})")
    print(f"          recomputed: {recomputed}")
    print(f"          manifest  : {root}")
    print(f"          {'PASS' if ok else 'FAIL'}")
    return ok


def check_proof(here: pathlib.Path) -> tuple[str, dict[int, str]]:
    """Returns (status, {block_height: merkle_root}) where status is PASS, FAIL or SKIPPED."""
    manifest_path, proof = here / f"{STEM}.json", here / f"{STEM}.json.ots"
    digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    print(f"[2 PROOF] manifest sha256 (the digest the proof commits to): {digest}")
    ots = shutil.which("ots")
    if not ots:
        print("          SKIPPED: `ots` client not installed (pip install opentimestamps-client), then run")
        print(f"          ots --no-bitcoin verify -f {manifest_path.name} {proof.name}")
        return "SKIPPED", {}
    r = subprocess.run([ots, "--no-bitcoin", "verify", "-f", str(manifest_path), str(proof)],
                       capture_output=True, text=True)
    out = (r.stdout + r.stderr).strip()
    for line in out.splitlines():
        print("          " + line)
    blocks = {int(h): m for h, m in re.findall(r"Bitcoin block (\d+) has merkleroot ([0-9a-f]{64})", out)}
    # Under --no-bitcoin the client deliberately exits 1 ("Not checking Bitcoin
    # attestation"), so its exit code cannot mean success here. The proof check is:
    # the client accepted the proof FOR THIS FILE (a wrong file fails with no
    # attestation lines) and produced at least one Bitcoin attestation to confirm
    # in step 3. Anything else is FAIL.
    ok = bool(blocks) and "does not match" not in out.lower() and "bad" not in out.lower()
    print(f"          ots exit code {r.returncode} (1 is expected under --no-bitcoin); "
          f"attestations parsed: {sorted(blocks)} -> {'PASS' if ok else 'FAIL'}")
    return ("PASS" if ok else "FAIL"), blocks


def check_chain(blocks: dict[int, str], use_explorer: bool) -> str:
    """PASS / FAIL / SKIPPED. Only --explorer performs the check; otherwise it is the reader's."""
    if not blocks:
        print("[3 CHAIN] SKIPPED: no attestations to check")
        return "SKIPPED"
    if not use_explorer:
        print("[3 CHAIN] NOT PERFORMED by this script. Compare each root above on an explorer or a node:")
        for h in sorted(blocks):
            print(f"          https://blockstream.info/block-height/{h}   expected merkleroot {blocks[h]}")
        print("          (or re-run with --explorer to fetch the block headers from blockstream.info)")
        return "SKIPPED"
    all_ok = True
    for h in sorted(blocks):
        try:
            with urllib.request.urlopen(f"{EXPLORER}/block-height/{h}", timeout=20) as r:
                block_hash = r.read().decode().strip()
            with urllib.request.urlopen(f"{EXPLORER}/block/{block_hash}", timeout=20) as r:
                header = json.loads(r.read())
            ok = header.get("merkle_root") == blocks[h]
        except Exception as exc:  # network failure is an incomplete check, not a pass
            print(f"[3 CHAIN] block {h}: explorer fetch failed ({type(exc).__name__}: {exc})")
            return "SKIPPED"
        all_ok &= ok
        print(f"[3 CHAIN] block {h}: explorer merkle_root {header.get('merkle_root')} "
              f"timestamp {header.get('timestamp')} -> {'PASS' if ok else 'FAIL'}")
    return "PASS" if all_ok else "FAIL"


def main(argv: list[str]) -> int:
    use_explorer = "--explorer" in argv
    args = [a for a in argv if a != "--explorer"]
    here = pathlib.Path(args[0] if args else __file__).resolve()
    here = here if here.is_dir() else here.parent

    root_ok = check_root(here)
    proof_status, blocks = check_proof(here)
    chain_status = check_chain(blocks, use_explorer)

    statuses = {"ROOT": "PASS" if root_ok else "FAIL", "PROOF": proof_status, "CHAIN": chain_status}
    print("RESULT:", "  ".join(f"{k}={v}" for k, v in statuses.items()))
    if "FAIL" in statuses.values():
        print("        FAILED: at least one check contradicts the anchor claim")
        return 1
    if "SKIPPED" in statuses.values():
        print("        INCOMPLETE: every check that ran passed, but not every check ran (see above)")
        return 2
    print("        VERIFIED: root rebuilt, proof parsed, and each attested block's merkle root confirmed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
