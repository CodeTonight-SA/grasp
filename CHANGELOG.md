# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Continuity receipts — VERIFIED now means complete-or-fail** (#13). `grasp
  anchor` (CLI and MCP `grasp_anchor`) stamps the current Merkle root via
  OpenTimestamps **and** writes a receipt of the exact leaf set that root
  commits to. `grasp verify` then checks every anchored leaf is still present:
  a ledger truncated or rewritten since its last anchor fails loudly
  (`VERIFY FAILED: CONTINUITY`), instead of the smaller, internally consistent
  history reading VERIFIED. Found by internal red-team, 2026-08-13.
- **Malformed ledger lines are counted, never silent** (#13). `grasp verify`
  reports `malformed_lines`; with a receipt present, a corrupted line surfaces
  as a missing anchored leaf and breaks the verdict.
- **`grasp anchor` refuses a chain that does not verify** (#13) — you cannot
  anchor yourself an alibi.
- **Threat model published** — [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md):
  the six adversaries considered, what the arithmetic defeats vs merely
  bounds (the symmetric-key custody boundary, the Bitcoin clock vs eIDAS),
  and the ordered hardening roadmap. Linked from the README.

## [0.2.0] - 2026-08-01

Closes the loop on the anchor. GRASP could stamp a Merkle root into Bitcoin,
but could not tell you whether that root ever actually **landed in a block**.
Anchoring and confirming are different questions, and the second is the one a
skeptic cares about.

### Added

- **`BitcoinOTSAdapter.verify(merkle_root)`** — did this root reach a block?
  Returns an `AnchorVerdict` carrying the block height, block hash, block
  time, *which tier answered*, and *what that verdict trusts*. Symmetric with
  `anchor()`: it locates the proof by the same deterministic rule.
- **`grasp verify --anchor`** and **`grasp_verify {"anchor": true}`** (MCP) —
  the same check from the CLI and from any MCP host. Opt-in, because plain
  `verify` promises an offline re-check and this is the one step that uses the
  network.
- **Tiered verification, with the tier always reported.** A reachable Bitcoin
  node (`GRASP_BITCOIN_NODE`) needs no trust at all. Failing that, two or more
  independent block-header sources must return the *identical* header, and the
  result states plainly that those operators would have to collude — so header
  agreement can never be mistaken for a full node. With neither available the
  verdict is *not confirmed*; one is never manufactured.

### Why not simply require a Bitcoin node

`prune=` caps what a node **retains**, not what it downloads — a pruned node
still performs a full initial block download, 758 GB as of 2026-08-01. And a
node you run convinces only you: whoever you are proving something to checks
the anchor against theirs. The lighter tier is sound because the cryptography
stays local — `ots --no-bitcoin verify` binds your digest and *computes* the
merkle root from it, so only the block lookup is outsourced and a forged proof
fails before any lookup. Moving up to the trustless tier needs no code change.

### Honesty properties, each with a test that fails without it

- One responding source is not agreement; two or more, or no verdict.
- Sources that disagree are refused outright rather than out-voted.
- A merkle root the real block does not carry is a **disproof**: reported as
  such, and it takes `ok` away even on an otherwise untampered chain.
- A proof still waiting on a block is ordinary and does **not** take `ok`
  away — "not yet" is not failure.
- `grasp verify` without `--anchor` makes no network call at all.
- A source that renamed its fields is distinguishable from one that is down.
- One deadline budgets the whole check, so a slow source cannot multiply total
  latency across attestations and sources.

## [0.1.0] - 2026-07-03

Initial public release of **GRASP — Governed Reasoning And Signable
Provenance**, a reference implementation of cryptographic causation for AI
systems: tamper-evident, replayable, externally-anchorable records that let a
skeptic independently refute or confirm what an AI decided, what it believed
when it decided, and whether every claim it made checks out against its source.

### Added

- **The three legs of cryptographic causation.**
  - *Decision record* — `grasp.idr`: signed Intent Decision Records
    (flat-JSON envelopes, HMAC-SHA256 over a canonical body digest,
    predecessor hash-chaining, content addressing that excludes volatile
    metadata, POSIX-locked JSONL persistence).
  - *Belief record* — `grasp.context_chain` / `grasp.context_head`: an
    append-only signed memory/belief chain with an atomic HEAD pointer,
    two-axis verification (per-node signatures + content-addressed blob
    presence), and a signed cross-reference into the decision chain.
  - *Claim record* — `grasp.prove_it`: the deterministic citation floor —
    every claim carries a verbatim quote and the engine verifies each quote
    exists in its cited source (exact → whitespace/typographic-flexible →
    not found), records exact character offsets, and renders a self-contained
    HTML artifact where a fabricated citation renders red.
- **`cite.verify` + HAPPI twin** — `grasp.cite_verify`: the protocol twin of
  the citation floor, the same ladder as the `cite.verify` verb of the
  [HAPPI](https://happi.md) protocol (`happi/1.3`), pinned byte-compatible by
  a cross-implementation agreement test.
- **Merkle forest** — `grasp.idr_forest` + `grasp.merkle`: IDRs organised into
  a provenance graph rooted at exogenous anchors only (CI runs, human commits,
  cross-provider verdicts, pre-registered hypotheses), with an RFC-6962
  (Certificate Transparency) Merkle root, `O(log N)` inclusion proofs,
  tamper-detecting verification, and deterministic replay.
- **Signed legal receipt** — `grasp.legal_receipt`: a signed filing gate built
  on the citation floor. A legal deliverable is SAFE TO FILE only when every
  quote is provably present in its cited source; any fabricated citation makes
  the CLI exit 1. Never file a red.
- **Composition** — `grasp.provenance`: one prove-it run writes an IDR leaf
  into the decision chain **and** a cross-referencing node into the memory
  chain, fail-open so recording problems never block the artifact.
- **CLI entry points** — `grasp-prove-it` and `grasp-legal-receipt`.
- **116 hermetic, mutation-sensitive conformance tests** — run green in
  isolation against a throwaway `GRASP_HOME` and a fixed test signing key,
  with no external dependencies. They are deliberately falsifiable: mutate the
  verifier to always-pass and the fabricated-quote tests fail; skip signature
  verification and the tamper tests fail.

[0.1.0]: https://github.com/CodeTonight-SA/grasp/releases/tag/v0.1.0
