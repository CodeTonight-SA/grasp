# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Tests for how a prove-it artifact draws a support attestation: as a machine
reading, beside the quote check and never over it.

Each test names the mutation of ``grasp/prove_it.py`` that turns it red. Every
mutation was applied once to the saved bytes of the file, the test was seen to
fail, and the file was restored byte for byte.
"""
from __future__ import annotations

import hashlib

import pytest

from grasp import prove_it as pi

SOURCE = ("An action founded on simple contract shall not be brought after the expiration "
          "of six years from the date on which the cause of action accrued.")
QUESTION = hashlib.sha256(b"Does the quote support the claim? (fictional test question)").hexdigest()


def _reading(**over) -> dict:
    reading = {
        "provider": "typesafe",
        "model": "jev-1.13.0",
        "question_sha256": QUESTION,
        "verdict": "supports",
        "probabilities": {"supports": 0.93, "contradicts": 0.04, "says_nothing": 0.03},
        "calibrated": True,
        "machine_reading": True,
        "precision_ref": "unmeasured",
    }
    reading.update(over)
    return reading


def _spec(c1: dict | None = None, c2: dict | None = None,
          c1_quote: str = "shall not be brought after the expiration of six years") -> dict:
    citations = [
        {"id": "c1", "claim": "Contract claims are barred after six years.",
         "source_id": "act", "quote": c1_quote},
        {"id": "c2", "claim": "Time runs from accrual.",
         "source_id": "act", "quote": "from the date on which the cause of action accrued"},
    ]
    for citation, reading in zip(citations, (c1, c2)):
        if reading is not None:
            citation["support_attestation"] = reading
    return {"title": "Limitation memo (fictional)",
            "response": "Barred after six years [[cite:c1]], counted from accrual [[cite:c2]].",
            "sources": [{"id": "act", "label": "Example Limitation Act", "text": SOURCE}],
            "citations": citations}


def test_reading_is_drawn_as_a_machine_reading():
    """The artifact names the model, the verdict in words, the top probability and
    the precision, under a "machine reading" label.

    Mutation: ``_precision_words`` prints the bare reference, so "unmeasured" loses
    its "precision unmeasured" wording.
    """
    html, _prov = pi.render(_spec(c1=_reading(),
                                  c2=_reading(precision_ref="fictional-corpus@p=0.91")))
    assert "Machine readings" in html and "machine reading" in html
    assert "jev-1.13.0 (typesafe)" in html
    assert "supports the claim" in html
    assert "0.93 (calibrated)" in html
    assert "precision unmeasured" in html
    assert "precision: fictional-corpus@p=0.91" in html


def test_unsure_reading_adds_an_amber_review_flag():
    """A reading that does not clearly back the claim puts an amber "review" badge
    after its citation; a clear reading does not.

    Mutation: the citation chip never draws the badge.
    """
    unsure = _reading(verdict="says_nothing", probabilities={"says_nothing": 0.9, "supports": 0.1})
    html, _prov = pi.render(_spec(c1=unsure, c2=_reading()))
    assert '[1✓]</a><span class="review"' in html
    assert '[2✓]</a><span class="review"' not in html
    assert ".review{" in html  # the amber style ships with the badge


@pytest.mark.parametrize("verdict", ["supports", "contradicts", "says_nothing"])
def test_red_citation_is_drawn_red_whatever_its_reading_says(verdict):
    """A quote that is not in its source keeps its red chip, gets no amber flag, and
    its reading is shown as not used.

    Mutation: ``_review_flag`` lets the flag onto a red citation too.
    """
    reading = _reading(verdict=verdict, probabilities={verdict: 0.99})
    html, prov = pi.render(_spec(c1=reading, c1_quote="the limitation period is twenty years"))
    assert prov["citations"][0]["status"] == pi.STATUS_NOT_FOUND
    assert 'class="cite bad" data-cite="c1"' in html
    assert '[1✗]</a><span class="review"' not in html
    assert "not used: the quote is not in its source" in html
    assert pi._VERDICT_WORDS[verdict] not in html


def test_artifact_without_readings_has_no_reading_parts():
    """A page with no reading is drawn as before: no readings table, no badge and no
    reading styles.

    Mutation: the reading styles are always added to the page.
    """
    html, _prov = pi.render(_spec())
    assert "Machine readings" not in html
    assert 'class="review"' not in html
    assert ".review{" not in html
    assert "p.note" not in html
