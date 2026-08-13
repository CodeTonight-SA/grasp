# What GRASP proves — and what it doesn't

This is GRASP's trust-boundary document. It names the adversaries the design
considers, states exactly which attacks the arithmetic defeats, and — the part
most provenance tools omit — states plainly which attacks it does **not**
defeat yet, and in what order those gaps close.

We publish this deliberately. A verifier you cannot threat-model is marketing.
GRASP's claim has never been "unbreakable"; it is that every record is
**tamper-evident, replayable, and externally checkable**, with the boundary of
that guarantee written down. This page is that boundary.

Terminology is deliberate throughout: records are **sealed** (MAC-chained with
HMAC-SHA256 by default), not "signed" in the asymmetric, third-party-attributable
sense — see adversary A3. We do not use the words *non-repudiable*, *tamper-proof*,
or *guaranteed* anywhere, because under the default scheme they would be false.

## The adversaries considered

| # | Adversary | Verdict |
|---|---|---|
| A1 | An outsider editing records without the key | **Defeated** |
| A2 | Truncating or rolling back the ledger | **Defeated once anchored** (residual below) |
| A3 | The key holder rewriting their own history | **Bounded, not defeated** — the custody boundary |
| A4 | Feeding the verifier a damaged ledger | **Defeated** |
| A5 | Disputing *when* a record existed | **Bounded by the Bitcoin clock** |
| A6 | Scheme confusion / downgrade | **Defeated** (monotone toward safe) |

### A1 — An outsider without the key

Anyone who can write to the ledger file but does not hold the sealing key.
Every record's `audit` block is an HMAC-SHA256 over the canonical body — which
includes the timestamp — and each record chains to its predecessor by hash.
Flip any byte of any sealed field and `grasp verify` returns **BROKEN**. The
conformance tests pin this with a live tamper (change one character of a
recorded decision; the verdict must flip), and they are mutation-sensitive:
weaken the verifier and the tests fail.

### A2 — Truncation and rollback

Delete the newest records, or restore an older copy of the ledger, and what
remains is internally consistent — every seal still checks, the chain still
links. Before continuity receipts, that smaller history read VERIFIED. This
was found by our own internal red-team (2026-08-13) and closed in the same
release cycle.

Now, `grasp anchor` stamps the current Merkle root via OpenTimestamps **and**
writes a local continuity receipt recording the exact leaf set that root
commits to. From then on, `grasp verify` checks that every anchored leaf is
still present: a truncated or rewritten-since-anchor ledger returns
**BROKEN — CONTINUITY**, with a count and sample of the missing records. The
tamper axis and the continuity axis are reported separately, because "a byte
was forged" and "history was shortened" are different accusations.

**Residual, stated honestly:** receipts are local files. An attacker with
enough filesystem access to delete ledger lines can delete the receipts too,
returning the deployment to the "no receipts" state — which `verify` reports
but does not fail, for backward compatibility with never-anchored ledgers.
Mitigation today: receipts are small JSON files under
`$GRASP_HOME/storage/ots/`; copy them off-host, commit them to a repository,
or publish them. Roadmap items 3–4 (expected-root pinning, refuse-on-gap mode)
close this residual by letting a deployment declare out-of-band that receipts
**must** exist.

### A3 — The key holder (the custody boundary)

The most important limit on this page. The default scheme is **symmetric**
HMAC-SHA256: whoever holds the sealing key can rewrite a record and re-seal
it, and the arithmetic cannot tell. GRASP under symmetric default therefore
protects against *everyone except the operator* — it is an integrity system,
and it becomes an attribution system only when key custody is split.

One consequence is worth spelling out because it is subtle. A record's
content address — the coordinate the Merkle tree commits to — deliberately
excludes the volatile fields `id`, `ts`, and `audit`
(`_CONTENT_ADDR_EXCLUDE` in `grasp/idr.py`), so that semantically identical
records deduplicate, exactly as git's tree hash excludes the committer date.
The honest flip side: a key holder can alter a record's **timestamp** and
re-seal it, and the anchored Merkle root does not change, because the root
never committed to the timestamp. Within an anchored set, recorded times are
operator-attested metadata, not anchored facts.

What the anchor bounds even against the key holder: **existence by time**.
A leaf committed under a Bitcoin-anchored root provably existed before that
block's time, and no record can be inserted into an already-anchored root it
was never part of. The key holder can lie about *when within* the anchored
window a record was made; they cannot move it *across* an anchor boundary.
Frequent anchoring shrinks the window the lie can live in.

Closing this properly is roadmap items 1–2: Ed25519 as the default scheme
with a published verification key (so re-sealing requires a private key the
verifying public no longer needs to trust the operator to withhold), and
timestamps promoted into the anchored leaf. The verifier already treats
asymmetric schemes as first-class: a scheme it cannot check reads DEGRADED,
never VERIFIED.

### A4 — A damaged or doctored ledger fed to the verifier

A corrupt line in the JSONL ledger used to be skipped silently — the verifier
would happily grade the records it could parse. A skipped line is never
silent now: `grasp verify` reports `malformed_lines`, and when a continuity
receipt exists, a corrupted line surfaces as a missing anchored leaf and the
verdict is **BROKEN**. Likewise a doctored receipt: each receipt's Merkle
root must recompute from its own recorded leaves, so an edited receipt reads
**receipt-corrupt** rather than being believed. And `grasp anchor` refuses
outright to notarise a chain that does not currently verify — you cannot
anchor yourself an alibi.

### A5 — Disputing when a record existed

GRASP's timestamping authority is the Bitcoin blockchain, reached through
OpenTimestamps. That gives decentralised, fee-free proof of existence against
the Bitcoin clock — with the verification tier always named (`bitcoin-node`,
`multi-source-header`, or a refusal; a verdict is never manufactured). What it
is **not**: a qualified electronic timestamp under eIDAS Article 42, which
some EU regulatory and evidentiary contexts expect from a qualified trust
service provider. Deployments that need one should co-timestamp the same
Merkle root with an RFC 3161 / qualified TSA — roadmap item 7. The two are
complementary: Bitcoin for decentralised verifiability, a TSA for statutory
recognition.

### A6 — Scheme confusion

A record claiming a scheme this build cannot check is marked **DEGRADED**,
never upgraded to VERIFIED — the verifier is monotone toward safe. The legacy
`sha256-placeholder` scheme is retained for reading old records only and its
docstring says what it is: not tamper-evident. Scheme identifiers are being
tightened so that no placeholder can be mistaken for a sealing scheme.

## What a GRASP record proves

Calibrated positive claims — each one is what the arithmetic checks, nothing
more:

- **Integrity**: no sealed field of any record has changed since sealing,
  unless the sealing key itself was used (A3).
- **Linkage**: each record chains to its predecessor; the history is ordered
  and rooted at exogenous anchors (CI runs, human commits, cross-provider
  verdicts, pre-registered hypotheses) — something the AI does not control.
- **Completeness since anchoring**: every record committed under an anchored
  root is still present (A2), receipts permitting.
- **Existence by time**: anchored roots existed before their Bitcoin block's
  time, checkable on any explorer without trusting us (A5's bound).
- **Citation floor**: every claim carrying a quote is verbatim in its cited
  source at recorded offsets. A fabricated quote resolves `not_found` and
  renders red — it cannot pass, because the check is string arithmetic, not
  judgement.

## What it does not prove

- **Authorship of ideas.** A record proves what was *recorded*, not who
  originated the underlying content or whether an AI was involved at all.
- **Source authenticity.** The citation floor proves a quote is verbatim in
  the *supplied* source — not that the source is genuine, and not that the
  quote *supports* the claim (support-checking is a caller-side layer, and
  fail-open by design).
- **Operator honesty under symmetric keys.** See A3. Say "sealed", not
  "signed", until Ed25519 custody is deployed.
- **That any given model output came from this ledger.** GRASP records
  decisions, beliefs, and claims *about* work; it does not yet bind the hash
  of an arbitrary output artifact into the chain. Roadmap item 5
  (output-hash binding) adds that binding.
- **Regulatory compliance.** GRASP is designed to help evidence
  record-keeping and explanation duties of the kind the EU AI Act describes
  (logging under Articles 12, 19 and 26(6); explanation of individual
  decisions under Article 86). It does not, by itself, make any deployment
  compliant with anything, and we will never claim otherwise.

### Relation to content marks (watermarks and C2PA)

Providers are beginning to mark AI-generated content — under the EU AI Act's
Article 50(2) Code of Practice, model-level text watermarks and C2PA-signed
file metadata. Those marks and GRASP answer **different questions**. A mark
answers *"did an AI process this artifact?"* — probabilistically, in-band,
usually detected by the provider. Anthropic's own documentation is candid
that a detected mark "does not, on its own, confirm the full provenance of
the content". GRASP answers the question marks leave open: *what was recorded
as decided, believed, and claimed* — deterministically, out-of-band,
checkable by anyone against Bitcoin without the vendor's cooperation. The two
compose: a C2PA manifest can carry a GRASP record's content address (roadmap
item 6), so an artifact's mark points at the decision chain behind it.

## Hardening roadmap (in order)

1. **Ed25519 default + published verification key** — split custody; move
   from sealed to signed.
2. **Timestamp in the anchored leaf** — make record time an anchored fact,
   not operator-attested metadata.
3. **Expected-root continuity** — pin the latest anchored root out-of-band so
   deleted receipts cannot silence the continuity check.
4. **Refuse-on-gap mode** — an opt-in policy where "no receipts" fails
   verification instead of being reported.
5. **Output-hash binding** — bind delivered artifacts by hash into the
   decision chain.
6. **C2PA bridge** — carry GRASP content addresses inside C2PA manifests.
7. **RFC 3161 / eIDAS co-timestamping** — statutory-grade time alongside the
   Bitcoin anchor.

## Reporting

Found a way past any "Defeated" row above? That is exactly what this document
is for: open an issue at
<https://github.com/CodeTonight-SA/grasp/issues>, or write to
security@codetonight.co.za. A confirmed break of a stated guarantee gets a
test named after it.

---

*Provenance: internal red-team of 2026-08-13, run by Claude Fable 5 inside
the GRIP engine and adjudicated by a cross-provider council (Gemini 3.1 Pro
judging; Grok 4.5, Llama 3.3 70B and DeepSeek speakers, with a Kimi K3
dissent adopted — it promoted the continuity fix from roadmap to
pre-release). Findings verified against the code by hand before publication.
Author: Lourens Cornelius "Laurie" Scheepers / CodeTonight.*
