# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Goodhart-resistant tests for grasp/cite_verify.py — the protocol twin.

THE falsifier: a quote absent from its source MUST resolve not_found. Mutate
the verifier to always-pass and test_fabricated_quote_is_not_found fails. A
hallucinated citation cannot be proven.

The cross-implementation agreement battery pins the twin against
grasp.prove_it.verify_quote: identical (quote, source) cases MUST produce the
same verdict AND the same offsets in both engines."""
from __future__ import annotations

import hashlib

import pytest

from grasp import prove_it as pi
from grasp.cite_verify import CiteVerifyNotFound, process, verify

SRC = "The Limitation Act 1980 bars the claim after six years."


def test_verified_quote_carries_real_offsets():
    record = process(
        [{"id": "c1", "source_id": "s1", "quote": "bars the claim after six years"}],
        [{"id": "s1", "text": SRC}],
    )
    c1 = record["citations"][0]
    assert c1["status"] == "verified"
    assert SRC[c1["start"]:c1["end"]] == "bars the claim after six years"


def test_fabricated_quote_is_not_found():
    # THE falsifier — mutate the verifier to always-pass and this fails.
    record = process(
        [{"id": "c1", "source_id": "s1", "quote": "bars the claim after three years"}],
        [{"id": "s1", "text": SRC}],
    )
    assert record["citations"][0]["status"] == "not_found"
    assert record["tally"]["not_found"] == 1
    assert record["grounding_rate"] == 0.0


def test_unknown_source_is_not_found():
    record = process(
        [{"id": "c1", "source_id": "nope", "quote": "anything"}],
        [{"id": "s1", "text": SRC}],
    )
    assert record["citations"][0]["status"] == "not_found"


def test_whitespace_variant_is_fuzzy():
    record = process(
        [{"id": "c1", "source_id": "s1", "quote": "bars the claim after"}],
        [{"id": "s1", "text": "bars the\nclaim after six years"}],
    )
    assert record["citations"][0]["status"] == "fuzzy"


def test_per_source_sha256_and_chars():
    record = process(
        [{"id": "c1", "source_id": "s1", "quote": "Limitation Act"}],
        [{"id": "s1", "text": SRC}],
    )
    src = record["sources"]["s1"]
    assert src["sha256"] == hashlib.sha256(SRC.encode("utf-8")).hexdigest()
    assert src["chars"] == len(SRC)


def test_strict_mode_raises_on_any_not_found():
    with pytest.raises(CiteVerifyNotFound):
        process(
            [{"id": "c1", "source_id": "s1", "quote": "gamma delta"}],
            [{"id": "s1", "text": "alpha beta"}],
            strict=True,
        )


def test_malformed_sources_raise_value_error():
    with pytest.raises(ValueError):
        process([], "notalist")
    with pytest.raises(ValueError):
        process([], [{"id": "s1"}])  # source without text


def test_malformed_citation_raises_value_error():
    with pytest.raises(ValueError):
        process([{"id": "c1"}], [{"id": "s1", "text": SRC}])


def test_typographic_variant_is_fuzzy_with_original_offsets():
    src_typo = "The deed is “binding” — clause 4.4 applies."
    status, s, e = verify('The deed is "binding" - clause 4.4 applies.', src_typo)
    assert status == "fuzzy"
    assert src_typo[s:e] == src_typo  # offsets index the ORIGINAL text


# ---------------------------------------------------------------------------
# Cross-implementation agreement — the conformance property of the twin
# ---------------------------------------------------------------------------

_AGREEMENT_CASES = [
    # (quote, source) — exact, whitespace-variant, typographic, fabricated,
    # truncated-beyond-source, empty
    ("bars the claim after six years", SRC),
    ("bars the claim after", "bars the\nclaim after six years"),
    ('The deed is "binding" - clause 4.4 applies.',
     "The deed is “binding” — clause 4.4 applies."),
    ("bars the claim after three years", SRC),
    ("six years. And then some words the source never had", SRC),
    ("", SRC),
]


def test_cross_implementation_agreement_with_prove_it():
    """The twin and grasp.prove_it.verify_quote MUST agree on every case —
    same verdict AND same offsets. The two ladders are one specification."""
    for quote, source in _AGREEMENT_CASES:
        twin_status, twin_start, twin_end = verify(quote, source)
        pi_status, pi_start, pi_end = pi.verify_quote(quote, source)
        assert twin_status == pi_status, (quote, twin_status, pi_status)
        assert (twin_start, twin_end) == (pi_start, pi_end), (quote,)


def test_status_tokens_match_prove_it_constants():
    """The twin's status strings ARE prove_it's constants — no mapping layer."""
    assert pi.STATUS_VERIFIED == "verified"
    assert pi.STATUS_FUZZY == "fuzzy"
    assert pi.STATUS_NOT_FOUND == "not_found"
