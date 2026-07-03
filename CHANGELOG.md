# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
