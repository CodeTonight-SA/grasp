# GRASP — Governed Reasoning And Signable Provenance

[![CI](https://github.com/CodeTonight-SA/grasp/actions/workflows/ci.yml/badge.svg)](https://github.com/CodeTonight-SA/grasp/actions/workflows/ci.yml)

**Try it in your browser:** <https://grasp-web-chi.vercel.app>

**Reference implementation of cryptographic causation for AI systems.**

When an AI makes a decision that matters, three questions decide whether anyone
can trust the record of it: *what did it decide*, *what did it believe when it
decided*, and *can every claim it made be checked against its source*? GRASP
answers all three with tamper-evident, replayable, externally-anchorable
records — **what an AI decided** (a signed decision chain), **what it believed
when it decided** (a signed memory chain), and **every outward claim it makes**
(a deterministic citation-provenance floor) — bound together and falsifiable by
construction, so a *skeptic* (a regulator, opposing counsel, an auditor) can
independently refute or confirm them. The verifier is the math plus an external
party, never the AI. Don't trust it — witness it.

## What is in the box

| Module | What it does |
|---|---|
| `grasp.idr` | Signed Intent Decision Records (IDRs): flat-JSON envelopes, HMAC-SHA256 over a canonical body digest, predecessor hash-chaining, content addressing that excludes volatile metadata, JSONL persistence with POSIX locking. |
| `grasp.idr_forest` | The forest that organises IDRs into a provenance graph **rooted at exogenous anchors only** (CI runs, human commits, cross-provider verdicts, pre-registered hypotheses), with an RFC-6962 Merkle root, `O(log N)` inclusion proofs, tamper-detecting verification, and deterministic replay. |
| `grasp.merkle` | The RFC-6962 (Certificate Transparency) Merkle primitive: domain-separated leaf/node hashing, inclusion proofs, verification. |
| `grasp.context_chain` / `grasp.context_head` | The signed memory/belief chain: append-only `context-delta` records with an atomic HEAD pointer, two-axis verification (per-node signatures + content-addressed blob presence), and a signed cross-reference (`records_idr`) into the decision chain. |
| `grasp.prove_it` | The deterministic citation floor: every claim carries a verbatim quote; the engine verifies each quote exists in its cited source (exact → whitespace/typographic-flexible → not found), records exact character offsets, and renders a self-contained HTML artifact where every citation is clickable and a fabricated one renders **red**. |
| `grasp.cite_verify` | The protocol twin of that floor — the same ladder as the `cite.verify` verb of the [HAPPI](https://happi.md) protocol (happi/1.3), pinned byte-compatible by a cross-implementation agreement test. |
| `grasp.provenance` | The composition: one prove-it run writes an IDR leaf into the decision chain **and** a cross-referencing node into the memory chain — fail-open, so recording problems never block the artifact. |
| `grasp.legal_receipt` | A signed filing gate built on the floor: a legal deliverable is SAFE TO FILE only when every quote is provably present in its cited source; any fabricated citation makes the CLI exit 1. **Never file a red.** |

## The three legs, and why they compose

1. **Decision record** — `grasp.idr` + `grasp.idr_forest`: signed envelopes
   (what/why/how/when), predecessor-chained, organised into a forest whose
   roots must be *exogenous* — something the AI does not control. A record set
   that only confirms itself is theatre; exogenous rooting is what lets a
   skeptic independently check the chain.
2. **Belief record** — `grasp.context_chain`: an append-only signed chain of
   the evolving mental model, so the record carries what the system believed
   *at decision time*, not just its output.
3. **Claim record** — `grasp.prove_it` / `grasp.cite_verify`: deterministic
   verbatim-quote provenance. A hallucinated quote resolves to `not_found` and
   renders red — it cannot earn a pass, because the check is arithmetic string
   matching, not judgement.

They compositionally close: `grasp.provenance.record_proveit_provenance` writes
one prove-it run into **both** chains, and the memory node cites the decision
leaf by content address *inside its signed body* — flip a byte of the citation
and chain verification returns `BROKEN`. The conformance tests anchor this.

**Scope honesty:** the citation floor proves a quote is **verbatim in the
supplied source** — not that the source is authentic, and not that the quote
*supports* the claim. Support-checking is a caller-side layer (the L2 seam on
`Citation.support`), and it must be fail-open: the deterministic floor is the
guarantee; anything above it is recall.

## Signing, honestly stated

Records are hash-chained and Merkle-rooted; signed **HMAC-SHA256 by default**
over a locally held key (`GRASP_SIGNING_KEY` env var, or a key file created on
first use under `~/.grasp/keys/` with 0600 permissions — the key never enters a
record; only signatures and a short key fingerprint do). Asymmetric per-tenant
signing (Ed25519, post-quantum schemes) is an integration path for deployments
that provision key custody: this verifier deliberately marks schemes it cannot
check as `DEGRADED` — monotone toward safe, never upgraded to `VERIFIED`.

## Anchored in the real world

The approach this package implements runs in production pilots whose Merkle
roots are anchored into the **public Bitcoin blockchain**, independently
checkable on any explorer:

- Pilot decision chain — committed via an OpenTimestamps proof to block
  **953968**: <https://mempool.space/block/953968>
- Post-quantum finance pilot (Ed25519 + ML-DSA-65) — dual-signed and anchored
  via the same OpenTimestamps path; its anchor block details are shared in
  evaluation materials on request rather than listed here.

Check it yourself — that is the point. To be precise about what this means:
those anchors witness *pilot deployments* of the approach; this package does
not anchor anything to Bitcoin on install. Anchoring is a deployment step you
add on top (commit `forest_merkle_root(...)` via OpenTimestamps or the
timestamping service of your choice).

## Install and run the conformance tests

```bash
git clone https://github.com/CodeTonight-SA/grasp
cd grasp
python3 -m venv .venv && .venv/bin/pip install -e . pytest
.venv/bin/python -m pytest tests -q
```

The tests are hermetic (a throwaway `GRASP_HOME`, a fixed test signing key) and
run green in isolation — a fresh virtualenv with nothing else on the path. They
are deliberately mutation-sensitive: mutate the verifier to always-pass and the
fabricated-quote tests fail; skip signature verification and the tamper tests
fail.

Requires Python ≥ 3.10 on a POSIX system (file locking uses `fcntl`).

## Quickstart

Verify a claim's citation, then record the run into both signed chains:

```python
from grasp.prove_it import render
from grasp.provenance import record_proveit_provenance

spec = {
    "title": "Limitation analysis",
    "response": "The claim is time-barred [[cite:c1]].",
    "sources": [{"id": "act", "label": "Limitation Act",
                 "text": "An action shall not be brought after six years."}],
    "citations": [{"id": "c1", "claim": "Time-barred after six years.",
                   "source_id": "act", "quote": "not be brought after six years"}],
}

html, prov = render(spec)          # deterministic verification + HTML artifact
print(prov["grounding_rate"])      # 1.0 — the quote is really there

rec = record_proveit_provenance(spec, prov)   # IDR leaf + memory-chain node
print(rec["idr_addr"])             # sha256:… — the signed decision record
```

Gate a legal deliverable on its citations (exit 1 on any fabricated quote):

```bash
grasp-legal-receipt spec.json --deliverable memo.md --out receipt.json
```

Prove one decision is committed by a single Merkle root without revealing the
others:

```python
from grasp.idr_forest import forest_inclusion_proof, verify_forest_inclusion

out = forest_inclusion_proof(forest, node_id)
assert verify_forest_inclusion(out["content_addr"], out["proof"], out["forest_root"])
```

## Shipped here vs. deployment concerns

Shipped in this package: the three legs, their composition, RFC-6962 Merkle
commitment + inclusion proofs, deterministic replay, the signed legal filing
gate, and the conformance tests. Deployment concerns intentionally **not**
bundled: external timestamping/Bitcoin anchoring (a deployment step, as above),
asymmetric/post-quantum key custody (an integration path), and any L2
LLM-based support checking (caller-side, fail-open by design).

## Licence

**AGPL-3.0-only** (see `LICENSE`). A provenance floor earns trust only if the
verifier itself is inspectable — anyone relying on a GRASP record must be able
to read, run, and modify the exact code that produced and verifies it, including
when it is offered as a network service. Copyleft keeps that loop closed.

Copyright (C) 2026 [CodeTonight SA](https://github.com/CodeTonight-SA).
