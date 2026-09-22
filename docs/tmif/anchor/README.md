# Production decision-chain anchor — the replay bundle

This directory is the evidence behind the TMIF Claimant's level-4 claim that the
production decision-chain root is committed to Bitcoin. Everything needed to
re-derive that commitment is here; nothing requires trusting GRASP or its authors,
and the one step our code cannot vouch for (that the attested blocks are real
Bitcoin blocks) is left to a view of the chain you choose.

| File | What it is |
|---|---|
| `decision-chain-501-2026-07-06.json` | The anchor manifest: the RFC 6962 root (`0bba0792…1fcb4`), row count 501, chain head, leaf definition. Its SHA-256 (`5d5e8854…45b9`) is the digest the OpenTimestamps proof commits to — the bytes must not change. |
| `decision-chain-501-2026-07-06.json.ots` | The OpenTimestamps proof for that digest, upgraded: it carries Bitcoin block-header attestations for blocks **956991** and **956992**. |
| `decision-chain-501-2026-07-06.leaf-hashes.txt` | The 501 leaf hashes, one per line, in chain order: `SHA-256(0x00 ‖ record)` per RFC 6962 §2.1. From these the root recomputes without the records themselves. |
| `verify.py` | Standard-library verifier for the three checks below. |

## Verify it yourself

`python3 verify.py --explorer` runs all three checks and prints one line per check:

1. **ROOT** — rebuilds the RFC 6962 Merkle Tree Head from the 501 leaf hashes and
   compares it with the manifest root.
2. **PROOF** — hands the manifest and the `.ots` file to the upstream OpenTimestamps
   client (`pip install opentimestamps-client`), which refuses a proof that does not
   match the file (`File does not match original!`) and otherwise prints the Bitcoin
   blocks it attests. The client exits 1 under `--no-bitcoin` by design, so the
   script keys this check on the parsed attestations, not on the exit code.
3. **CHAIN** — with `--explorer`, fetches each attested block's header from
   blockstream.info and compares its merkle root with the proof's. Without the flag
   the script prints the expected roots and stops, reporting `INCOMPLETE`, because
   this step should be done against a source you trust — a node, or an explorer of
   your choosing:

   ```
   https://blockstream.info/block-height/956991   expected merkleroot 1b42ef4dab12c64e003e09a4678c07873b734b6785ff7a6186ae63dca0b9395c
   https://blockstream.info/block-height/956992   expected merkleroot b3f15c0140222a08dd0bf6772c1c5296f121dd635a9097f2f4f0adb5fdb73c49
   ```

   Block 956992 was mined at Unix time 1783395287 (2026-07-07 03:34:47 UTC). With a
   Bitcoin node, `ots verify` without `--no-bitcoin` checks the headers itself.

Result line and exit code: `VERIFIED` (exit 0) only when all three checks ran and
passed; `INCOMPLETE` (exit 2) when a check could not run; `FAILED` (exit 1) when any
check contradicts the claim. A missing `ots` client is reported as `PROOF=SKIPPED`,
never as success.

## What is deliberately not here

- **The records themselves.** The 501 leaves are the exact lines of an internal
  ledger whose subjects name people, groups and clients. Publishing their hashes
  proves the commitment (any holder of a record can check inclusion against these
  hashes and the root); publishing the lines would leak operational text. The
  manifest's `leaf_definition` still describes how each leaf hash was formed from
  its line, so a party holding a record can reproduce its hash exactly.
- **A second stamp.** The same digest was also submitted to the OpenTimestamps
  calendars a few minutes earlier; that proof completed in blocks 956948, 956963
  and 956970. Both stamps are valid for the same digest. The Claimant names this
  bundle's proof (956991/956992) so that "the proof" is one file, not a family.

## What this proves, and what it does not

It proves that the manifest bytes, and therefore the root, existed before block
956991 was mined, and that the root is a well-formed RFC 6962 tree over exactly 501
leaves. It does not prove what the records say, that they are complete, or that
the engine behaved correctly — a record is not a promise. The signing of
individual records, and the replay of a decision from its record, are engine
features verified against the engine's own tests, not by this bundle.

Provenance: prepared by V>> (Laurie Scheepers, CodeTonight) with assistance of
Claude Fable 5.1; independently re-derived by DeepSeek V4 Pro (via OpenCode) and
reviewed by two non-Anthropic council sittings (GRASP sovereign-council seals
`ecaac9358fd8185e` and `e035becedaadb57a`, the second of which found the earlier
verifier's false-success branch) on 2026-09-22.
