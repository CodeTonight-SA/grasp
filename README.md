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

## Where GRASP sits (the open-core family)

GRASP is the **open proof layer** of a wider stack. The position is open-core:
*open-source the tools, licence the engine.*

| Piece | What it is | Licence |
|---|---|---|
| **GRASP** (this repo) | The proof layer — the reference implementation of cryptographic causation (signed decision chain, signed memory chain, deterministic citation floor). | **AGPL-3.0-only** — open |
| **HAPPI** | The open protocol the stack speaks — a specification, not a black box. GRASP's `cite.verify` is pinned byte-compatible to the HAPPI `cite.verify` verb (happi/1.3). | Open standard ([happi.md](https://happi.md)) |
| **GRIP + HAL** | The reasoning + provenance engine (GRIP) and the LLM-agnostic multi-provider substrate (HAL). Not required to produce *or* verify a GRASP record. | Licensed / private |

The load-bearing consequence for anyone relying on a record: **GRASP records are
produced and re-verified by this open package alone** — no GRIP runtime, no HAL,
no network, no account (see *Verify a receipt* below). The engine is licensed;
the tool that lets a skeptic check its work is not. Deeds, not words.

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
  **956992**: <https://mempool.space/block/956992>
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

## Use it from any MCP host

GRASP ships an MCP server (`grasp-mcp`, standard library only), and this
repository is simultaneously a **Claude Code plugin + one-plugin marketplace**
(`.claude-plugin/`), a **Gemini CLI extension** (`gemini-extension.json`), and
an **Antigravity plugin**. One prerequisite for every local host:

```bash
pipx install "git+https://github.com/CodeTonight-SA/grasp"   # puts grasp-mcp on PATH
```

| Host | Install | Guide |
|---|---|---|
| Claude Code | `claude plugin marketplace add CodeTonight-SA/grasp` then `claude plugin install grasp@CodeTonight-SA/grasp` | [docs/install/claude-code.md](docs/install/claude-code.md) |
| Gemini CLI | `gemini extensions install https://github.com/CodeTonight-SA/grasp` | [docs/install/gemini-cli.md](docs/install/gemini-cli.md) |
| Antigravity (`agy`) | `agy plugin install https://github.com/CodeTonight-SA/grasp` | [docs/install/antigravity.md](docs/install/antigravity.md) |
| Claude Desktop | one `mcpServers` entry in `claude_desktop_config.json` | [docs/install/claude-desktop.md](docs/install/claude-desktop.md) |
| OpenAI Codex CLI | `[mcp_servers.grasp]` in `~/.codex/config.toml` | [docs/install/codex.md](docs/install/codex.md) |
| xAI Grok Build | `grok mcp add grasp grasp-mcp` | [docs/install/grok-build.md](docs/install/grok-build.md) |
| Claude for Work / Cowork | remote-only — self-hosted bridge required | [docs/install/claude-for-work.md](docs/install/claude-for-work.md) |
| ChatGPT (Developer mode) | remote-only — self-hosted bridge required | [docs/install/chatgpt.md](docs/install/chatgpt.md) |

Any other MCP host registers the same server with one settings entry:

```json
{ "mcpServers": { "grasp": { "command": "grasp-mcp" } } }
```

The behaviour contract travels with the install (`GEMINI.md` for Gemini CLI;
the `grasp-provenance` skill for the Claude Code plugin): call
`grasp_record_decision` before consequential actions, `grasp_record_belief`
at checkpoints, and `grasp_prove_claim` before asserting any sourced
quotation (a fabricated quote returns `not_found` — it cannot pass). Ask the
model to run `grasp_verify` at any time: every signature, the chain linkage,
and the Merkle root re-check offline, and the verdict comes back exactly as
the arithmetic found it (`verified` / `degraded` / `broken`).

**How to use it — just ask.** You are already running GRASP the moment the
server is registered; there is nothing to invoke by hand. Ask the model in plain
words and it reaches for the right verb — and every result comes back as one
portable, glanceable card (box-drawing, no colour, offline-verifiable), the same
shape in any harness:

- **Record a decision** — before a consequential step: *"record this decision"*
  → `grasp_record_decision` writes a signed IDR (what / why / how).
- **Record a belief** — at a checkpoint: *"checkpoint what we believe"* →
  `grasp_record_belief` snapshots the mental model into the signed memory chain.
- **Prove a claim** — after any sourced assertion: *"prove that quote"* →
  `grasp_prove_claim` verifies the quote is verbatim in its source; a fabricated
  one returns `not_found` and cannot pass.
- **Verify integrity** — any time: *"verify the chain"* → `grasp_verify`
  re-checks every signature, the linkage, and the Merkle root offline.

Prefer your own terminal? The same records verify with the Python package or the
`tools/grasp-verify-receipt` script — no server, no network (see *Verify a
receipt* below). Deeds, not words — *facta, non verba*.

Records land in `~/.grasp/` (`idr.jsonl`, `context.jsonl`) — or wherever
`GRASP_HOME` points — and re-verify with this package alone, no server and no
network.

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

## Activate a deployment

`grasp activate` walks three acts and closes on the chain's birth certificate:

1. **Tier** — `public` (records may be published), `private` (zero-egress by
   construction: egress-capable backends are refused outright and the storage
   self-check runs under an in-process socket blocker), or `combination`
   (records stay private; only content hashes go to public witnesses).
2. **Storage** — a live-probed picker over the six built-in backends (local,
   bitcoin-ots, s3, sepolia, ipfs, website). Every probe is a real check with
   a one-line remedy when a runtime dependency is missing — never a greyed
   "coming soon".
3. **Terms + access** — activation refuses until the install's license/terms
   files are accepted; acceptance is a signed record bound to each file's
   sha256, so changed terms honestly demand re-acceptance. Private and
   combination modes collect a signed visibility allowlist and report whether
   a PII-redaction seam is wired (`GRASP_REDACTION_CMD`).

```text
╭─ GRASP ● activated — chain born ───────────────────────────╮
│ id         precog-1784069403-…                             │
│ mode       private                                         │
│ acl        true                                            │
│ backends   local                                           │
│ count      1                                               │
╰─ facta, non verba ─────────────────────────────────────────╯
```

The activation itself is the deployment's first signed decision record — the
zero-telemetry claim ships with its own falsifier (`egress_guard()`), not an
adjective.

## Per-response prove-it footer

A response whose claims are bound to sources (`[[cite:ID]]`) can close on a
compact provenance card — the moat proving the model's own claims, every
turn. Three modes (`salient` default, `always`, `off`); the fineprint rows
are plain URLs, so modern terminals link them with zero escape codes, and
`grasp open <id>` is the fallback:

```text
╭─ GRASP ✓ prove-it — this response ─────────────────────────╮
│ model      ◆ claude-fable-5                                │
│ verified   true                                            │
│ claims     2 — ✓2 ≈0 ✗0                                    │
│ grounding  ██████████ 1.00                                 │
╰─ facta, non verba ─────────────────────────────────────────╯
┆ inspect  file:///…/prove-it/41e3e9c8bc90.html
┆ or run   grasp open 41e3e9c8bc90
```

A fabricated quote cannot pass: it renders ✗ and flips the card's glyph.

## Provider honesty — the floor that refuses to lie

When a provider's salient claims fail the deterministic floor, GRASP blocks
the send, fails over down your provider ladder (nothing unproven is ever
emitted), and records a signed event in the PRIVATE honesty ledger.
`grasp honesty` renders the scoreboard; `grasp attest` re-proves the
deployment's own configuration guarantees and exits non-zero if any fails:

```text
╭─ GRASP ● provider honesty — floor-hold scoreboard ─────────╮
│ ●          ██████████ 1.00  gemini-3.1-pro  ✓1 ✗0          │
│ ✗          ░░░░░░░░░░ 0.00  grok-4  ✓0 ✗1                  │
╰─ facta, non verba ─────────────────────────────────────────╯
```

The public "flagged providers" view exists but ships OFF by construction —
it activates only behind an enterprise switch AND a legal acknowledgement
file, and a test pins that default.

## Shipped here vs. deployment concerns

Shipped in this package: the three legs, their composition, RFC-6962 Merkle
commitment + inclusion proofs, deterministic replay, the signed legal filing
gate, and the conformance tests. Deployment concerns intentionally **not**
bundled: external timestamping/Bitcoin anchoring (a deployment step, as above),
asymmetric/post-quantum key custody (an integration path), and any L2
LLM-based support checking (caller-side, fail-open by design).

## Verify a receipt (without trusting us)

Every GRASP receipt can be re-checked with one command and nothing but Python's
standard library — no GRIP runtime, no network, no account:

```
python3 tools/grasp-verify-receipt SPEC.json RECEIPT.json --root .
```

It re-hashes the deliverable and every pinned source, re-reads each citation
quote at its recorded offsets (verbatim for `verified`; whitespace-only
tolerance for `fuzzy`; `not_found` always fails), and recomputes the tally. Any
tampered byte, shifted offset, or missing quote exits 1, loudly. The script is
~200 readable lines — audit it in one sitting, or write your own from the spec:
the JavaScript and Python verifiers byte-agree on shared vectors, so you never
have to trust a single implementation. Bitcoin anchors verify through the
upstream OpenTimestamps client (`pip install opentimestamps-client && ots
verify <proof>.ots`) — not our code at all.

## TMIF (declaration layer)

GRASP's claims are also published as a signed
[TMIF Claimant document](docs/tmif.md) —
[`draft-laurie-tmif-01`](https://datatracker.ietf.org/doc/draft-laurie-tmif/),
*A Standard for Claiming Transparency and Falsifiability*. To be precise
about the relationship: GRASP is **not** an implementation of TMIF. GRASP
is the engine that produces tamper-evident records; TMIF is a declaration
format above it, and GRASP makes a natural reference Claimant because its
artifacts (signed chain, in-browser verifier, Bitcoin anchor) are exactly
what TMIF directs evaluators to verify. Where TMIF Claimants self-assert
transparency levels, GRASP under-claims by policy — see
[`docs/tmif.md`](docs/tmif.md) for the signed document, the verifying key,
and a copy-paste verification snippet.

## Licence

**AGPL-3.0-only** (see `LICENSE`). A provenance floor earns trust only if the
verifier itself is inspectable — anyone relying on a GRASP record must be able
to read, run, and modify the exact code that produced and verifies it, including
when it is offered as a network service. Copyleft keeps that loop closed.

Copyright (C) 2026 [CodeTonight SA](https://github.com/CodeTonight-SA).
