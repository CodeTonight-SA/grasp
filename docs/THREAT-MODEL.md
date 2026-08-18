# What GRASP proves — and what it doesn't

This is GRASP's trust-boundary document. It names the adversaries the design
considers, states exactly which attacks the arithmetic defeats, and — the part
most provenance tools omit — states plainly which attacks it does **not**
defeat yet, and in what order those gaps close.

We publish this deliberately. A verifier you cannot threat-model is marketing.
GRASP's claim has never been "unbreakable"; it is that every record is
**tamper-evident, replayable, and externally checkable**, with the boundary of
that guarantee written down. This page is that boundary.

**Status 2026-08-18: all seven roadmap items shipped** — Ed25519 / ML-DSA-65
signing, timestamp-aware anchored leaves, expected-root continuity +
refuse-on-gap, output-hash binding, strict scheme mode, the C2PA bridge, and
the RFC 3161 client. Each adversary section still names the residual
boundaries that remain by design.

Terminology is deliberate throughout. The default scheme remains **sealed**
(MAC-chained with HMAC-SHA256); first-class asymmetric signing — **Ed25519**,
post-quantum **ML-DSA-65** (FIPS 204), and the dual **ed25519+ml-dsa-65** hybrid —
is now shipped and selected via ``GRASP_SIGNING_SCHEME`` (see adversary A3). We
still do not use the words *non-repudiable*, *tamper-proof*, or *guaranteed*
anywhere, because each scheme's exact guarantee is what the table below states,
no more.

## The adversaries considered

| # | Adversary | Verdict |
|---|---|---|
| A1 | An outsider editing records without the key | **Defeated** |
| A2 | Truncating or rolling back the ledger | **Defeated once anchored** (residual below) |
| A3 | The key holder rewriting their own history | **Bounded by key custody; asymmetric schemes enable the split** — see A3 |
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

**CLOSED (items 3–4).** The residual is closed by two shipped mechanisms:
``grasp verify --expected-root <hex>`` (or ``GRASP_EXPECTED_ROOT`` /
``expected-root.json``) pins the latest anchored root out-of-band — deleted
receipts then read ``expected-root-missing`` and a rolled-back receipt set reads
``expected-root-mismatch``, both hard failures; and ``--refuse-on-gap`` (or
``GRASP_REFUSE_ON_GAP=1``) makes "no receipts" fail outright. A deployment that
declares completeness out-of-band can no longer be silently returned to the
weaker no-receipts state.

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

**SHIPPED (items 1–2).** Ed25519 and ML-DSA-65 (FIPS 204) — plus the dual
``ed25519+ml-dsa-65`` hybrid — are first-class signing schemes: ``grasp keygen``
generates the keypair, the audit block carries only the public-key fingerprint,
and the verifier resolves the published verification key from ``GRASP_*_PUB`` /
``GRASP_VERIFY_KEYS`` / ``<home>/keys/<scheme>.pub`` — so re-sealing requires a
private key the verifying public no longer needs to trust the operator to
withhold. The private seed is never in a record. Timestamps are promoted into
the anchored leaf (leaf version 2: the stamped root commits to content address
+ recorded time), so a key-holder rewriting a timestamp moves the anchored leaf
and continuity fails. The default scheme remains HMAC-SHA256 for
byte-compatible deployments; a scheme the verifier cannot check still reads
DEGRADED, never VERIFIED.

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

**SHIPPED (item 7, client).** ``grasp.rfc3161`` is a pure-stdlib RFC 3161
client: TimeStampReq build, TimeStampResp / TSTInfo parse, imprint + digest +
nonce checks, and RSA PKCS#1 v1.5 CMS signature verification (proven against a
genuinely OpenSSL-signed fixture). Honest boundary, stated in the module:
ECDSA signature verification and X.509 chain building need the ``cryptography``
dependency, and eIDAS qualification itself is a property of the TSA — no
client can assess it. A scheme it cannot check reports
``unsupported_algorithm``, never a manufactured pass.

### A6 — Scheme confusion

A record claiming a scheme this build cannot check is marked **DEGRADED**,
never upgraded to VERIFIED — the verifier is monotone toward safe. The legacy
`sha256-placeholder` scheme is retained for reading old records only and its
docstring says what it is: not tamper-evident. ``grasp verify --strict`` (or
``GRASP_STRICT=1``) now refuses loudly on any unverifiable record and reports a
per-scheme histogram naming exactly which records a migration must replace —
the F4 gate for deployments leaving the placeholder scheme behind.

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
- **Operator honesty under the deployed scheme.** Under HMAC-SHA256 the
  record is "sealed" (see A3). Under Ed25519 / ML-DSA-65 with the verification
  key published and the private seed held outside the operator's reach, the
  record is "signed" in the third-party-attributable sense.
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
compose: a C2PA manifest can carry a GRASP record's content address (shipped:
grasp.c2pa), so an artifact's mark points at the decision chain behind it.

## Hardening roadmap (in order)

1. **~~Ed25519 default + published verification key~~ SHIPPED** — Ed25519,
   ML-DSA-65 and the dual hybrid sign + verify; ``grasp keygen`` publishes keys.
2. **~~Timestamp in the anchored leaf~~ SHIPPED** — leaf version 2 commits to
   content address + recorded time; timestamp-rewrite attacks break continuity.
3. **~~Expected-root continuity~~ SHIPPED** — ``--expected-root`` /
   ``GRASP_EXPECTED_ROOT`` / ``expected-root.json`` pinning; deleted receipts fail.
4. **~~Refuse-on-gap mode~~ SHIPPED** — ``--refuse-on-gap`` / ``GRASP_REFUSE_ON_GAP=1``.
5. **~~Output-hash binding~~ SHIPPED** — ``build_idr(output_hash=...)`` signs the
   delivered artifact's hash into the record.
6. **~~C2PA bridge~~ SHIPPED** — grasp.c2pa embeds the grasp.idr.addr
   assertion (content address, anchor root, timestamp) into real C2PA
   manifests; optional c2pa-python extra; proven end-to-end against c2pa-rs.
7. **RFC 3161 / eIDAS co-timestamping** — client SHIPPED (``grasp.rfc3161``,
   pure stdlib: request build, response/TSTInfo parse, imprint+digest+nonce,
   RSA signature verification; ECDSA + chain validation documented as the
   dependency boundary). Statutory-grade time alongside the Bitcoin anchor.

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
Roadmap items 1–5 shipped 2026-08-17 by an overnight AFK session (V>> with
DeepSeek V4 Pro assistance); items 6–7 in flight.
Author: Lourens Cornelius "Laurie" Scheepers / CodeTonight.*
