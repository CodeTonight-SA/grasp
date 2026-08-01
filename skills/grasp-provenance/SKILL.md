---
name: grasp-provenance
description: Behaviour contract for sessions where the GRASP provenance tools (grasp_record_decision, grasp_record_belief, grasp_prove_claim, grasp_verify, grasp_status) are available. Use whenever the session takes consequential actions, quotes a source, or is asked whether the record is intact.
license: AGPL-3.0-only
---

# GRASP — record what you decide, believe, and claim

This session has the GRASP provenance tools available (MCP server `grasp`).
GRASP keeps a signed, hash-chained, tamper-evident ledger of your conduct that
a third party can verify offline — the arithmetic, not you, is the judge.
Follow these rules:

1. **Decisions.** Whenever you take a consequential action — editing a file,
   running a state-changing command, choosing between approaches, sending
   anything — first call `grasp_record_decision` with `what` (the action,
   plainly) and `why` (the reasoning). Keep both to one or two sentences.

2. **Beliefs.** At natural checkpoints (start of a task, after a significant
   discovery, before ending), call `grasp_record_belief` with a one-paragraph
   `belief` summary of your current understanding and `next_step`. When the
   checkpoint follows a recorded decision, pass that decision's
   `content_addr` as `records_idr` so the two chains cross-link.

3. **Claims.** Before asserting that a source says something — quoting a file,
   a document, a spec — call `grasp_prove_claim` with the verbatim `quote` and
   the `source_path`. If the result is `not_found`, do NOT assert the claim;
   say plainly that you could not verify it. A fabricated citation cannot
   pass this check, and that is the point.

4. **Verification.** When the user asks whether the record is intact, or at
   the end of a substantial session, call `grasp_verify` and report the
   verdicts exactly as returned (VERIFIED / DEGRADED / BROKEN). Never
   paraphrase a BROKEN verdict as anything softer.

5. **The external anchor.** When the user asks whether the record is anchored
   in Bitcoin — or whether a date can be *proved* rather than asserted — call
   `grasp_verify` with `anchor: true`. This is the only call here that uses
   the network, so ask for it deliberately rather than by habit. Report three
   things together, never the first alone:
   - whether it is `confirmed`;
   - `verified_by` — a Bitcoin node, or agreement between independent
     block-header sources;
   - `trust` — what that verdict rests on, verbatim.

   Header agreement is **not** a local full node, and saying "confirmed"
   without saying which tier answered misrepresents it. If the result is not
   confirmed, say so plainly and distinguish the two reasons: a proof still
   waiting on a block is ordinary ("not yet"), while a merkleroot the real
   block does not carry is a **disproof** — report that as a failure, never
   as pending.

Do not narrate these calls at length — record, then continue the work. An
unrecorded consequential decision is treated as theatre, not evidence.
