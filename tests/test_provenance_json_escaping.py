# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""The provenance JSON embedded in a prove-it page cannot break out of its <script> element.

The page carries its provenance as JSON inside ``<script type='application/json'>``.
A source label or a support attestation holding ``</script>`` used to end that
element early, and whatever followed became live markup. Each test names the
mutation of ``grasp/prove_it.py`` that turns it red.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from grasp import prove_it as pi

SOURCE = "An action founded on simple contract shall not be brought after the expiration of six years."
HOSTILE = "x</script><img src=x onerror=alert(1)>&amp;"


def _spec(label: str, precision_ref: str) -> dict:
    question = hashlib.sha256(b"Does the quote support the claim? (fictional)").hexdigest()
    reading = {"provider": "typesafe", "model": "jev-1.13.0", "question_sha256": question,
               "verdict": "supports", "calibrated": False, "machine_reading": True,
               "probabilities": {"supports": 0.93, "contradicts": 0.04, "says_nothing": 0.03},
               "precision_ref": precision_ref}
    return {"title": "Escape test (fictional)",
            "response": "Barred after six years [[cite:c1]].",
            "sources": [{"id": "act", "label": label, "text": SOURCE}],
            "citations": [{"id": "c1", "claim": "Contract claims are barred after six years.",
                           "source_id": "act", "quote": "shall not be brought after the expiration of six years",
                           "support_attestation": reading}]}


def _embedded(page: str) -> str:
    start = page.index("id='provenance'>") + len("id='provenance'>")
    return page[start:page.index("</script>", start)]


@pytest.mark.parametrize("label, precision_ref", [(HOSTILE, "unmeasured"), ("Example Act", HOSTILE)],
                         ids=["hostile-source-label", "hostile-attestation-text"])
def test_a_hostile_string_cannot_close_the_script_element(label, precision_ref):
    """Mutation: embed ``json.dumps(prov)`` unescaped."""
    page, prov = pi.render(_spec(label, precision_ref))
    embedded = _embedded(page)
    assert "<" not in embedded and ">" not in embedded
    assert json.loads(embedded) == json.loads(json.dumps(prov)), "the escapes decode to the same values"
    assert "<img src=x" not in page.split("id='provenance'>", 1)[1]
