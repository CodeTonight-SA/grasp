# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""GRASP — Governed Reasoning And Signable Provenance.

Reference implementation of cryptographic causation for AI systems:

- ``grasp.idr`` / ``grasp.idr_forest`` — signed Intent Decision Records,
  hash-chained and organised into a Merkle-rooted forest (what was decided).
- ``grasp.context_chain`` / ``grasp.context_head`` — the signed memory/belief
  chain (what was believed when it was decided).
- ``grasp.prove_it`` / ``grasp.cite_verify`` — the deterministic citation
  provenance floor (every outward claim carries a verifiable verbatim quote).
- ``grasp.provenance`` — the composition: one provenance run writes into both
  the decision chain and the memory chain.
- ``grasp.legal_receipt`` — a signed filing gate built on the floor above.

Import the submodules directly; this package intentionally keeps the top-level
namespace minimal.
"""

__version__ = "0.1.0"
