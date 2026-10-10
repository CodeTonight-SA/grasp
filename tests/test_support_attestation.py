# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Tests for grasp.prove_it.SupportAttestation: a caller's typed machine reading.

GRASP never makes a reading. It checks the shape of the one a caller hands it,
so these tests feed it good and bad shapes and expect a clear refusal for every
bad one.

Each test names the mutation of ``grasp/prove_it.py`` that turns it red. Every
mutation was applied once to the saved bytes of the file, the test was seen to
fail, and the file was restored byte for byte.
"""
from __future__ import annotations

import hashlib
import json

import pytest

from grasp import prove_it as pi

QUESTION = hashlib.sha256(b"Does the quote support the claim? (fictional test question)").hexdigest()


def _fields(**over) -> dict:
    """A valid reading's fields, with any of them replaced."""
    fields = {
        "provider": "typesafe",
        "model": "jev-1.13.0",
        "question_sha256": QUESTION,
        "verdict": "supports",
        "probabilities": {"supports": 0.93, "contradicts": 0.04, "says_nothing": 0.03},
        "calibrated": True,
        "machine_reading": True,
        "precision_ref": "unmeasured",
    }
    fields.update(over)
    return fields


def test_valid_reading_round_trips_through_json():
    """A reading survives the receipt's JSON unchanged, field for field.

    Mutation: ``to_dict`` leaves out ``precision_ref``.
    """
    att = pi.SupportAttestation(**_fields())
    assert att.to_dict() == _fields()
    back = pi.SupportAttestation.from_dict(json.loads(json.dumps(att.to_dict())))
    assert back == att


@pytest.mark.parametrize("value", [False, None, 1, "true"])
def test_machine_reading_must_be_true(value):
    """A reading not marked as a machine reading is refused. GRASP will not store
    a model's answer dressed up as a proof or as a person's judgement.

    Mutation: the ``machine_reading is not True`` check is skipped.
    """
    with pytest.raises(ValueError, match="machine_reading"):
        pi.SupportAttestation(**_fields(machine_reading=value))


@pytest.mark.parametrize("verdict", ["supported", "SUPPORTS", "maybe", ""])
def test_unknown_verdict_is_refused(verdict):
    """Only supports, contradicts and says_nothing are verdicts. "supported" is the
    older free-text L2 word, so it is the likeliest mix-up.

    Mutation: the ``verdict not in SUPPORT_VERDICTS`` check is skipped.
    """
    with pytest.raises(ValueError, match="verdict must be one of"):
        pi.SupportAttestation(**_fields(verdict=verdict))


@pytest.mark.parametrize("value", [-0.01, 1.01, float("nan"), float("inf"), float("-inf")])
def test_probability_outside_zero_to_one_is_refused(value):
    """Mutation: the ``0.0 <= value <= 1.0`` range check is skipped."""
    with pytest.raises(ValueError, match="between 0 and 1"):
        pi.SupportAttestation(**_fields(probabilities={"supports": value}))


@pytest.mark.parametrize("value", [True, False, "0.9", None])
def test_probability_must_be_a_number(value):
    """A flag or a string is not a probability, although Python counts True as 1.

    Mutation: the type check stops excluding bool.
    """
    with pytest.raises(ValueError, match="must be a number"):
        pi.SupportAttestation(**_fields(probabilities={"supports": value}))


@pytest.mark.parametrize("probabilities", [{}, [], None, "supports"])
def test_probabilities_must_be_a_non_empty_mapping(probabilities):
    """Mutation: the emptiness test (``or not probabilities``) is dropped."""
    with pytest.raises(ValueError, match="non-empty mapping"):
        pi.SupportAttestation(**_fields(probabilities=probabilities))


def test_probabilities_must_name_known_verdicts():
    """Mutation: the unknown-verdict check on the probability keys is skipped."""
    with pytest.raises(ValueError, match="unknown verdict"):
        pi.SupportAttestation(**_fields(probabilities={"supports": 0.9, "supported": 0.1}))


@pytest.mark.parametrize("value", ["abc", QUESTION.upper(), QUESTION[:-1], QUESTION + "0", 123, None])
def test_question_hash_must_be_sha256_hex(value):
    """Mutation: the ``question_sha256`` check is skipped."""
    with pytest.raises(ValueError, match="question_sha256"):
        pi.SupportAttestation(**_fields(question_sha256=value))


@pytest.mark.parametrize("value", ["", "   ", None, 7])
@pytest.mark.parametrize("name", ["provider", "model", "precision_ref"])
def test_identity_fields_must_be_non_empty_text(name, value):
    """Mutation: ``_require_text`` stops checking."""
    with pytest.raises(ValueError, match=name):
        pi.SupportAttestation(**_fields(**{name: value}))


@pytest.mark.parametrize("value", ["yes", 1, None])
def test_calibrated_must_be_true_or_false(value):
    """Mutation: the ``calibrated`` check is skipped."""
    with pytest.raises(ValueError, match="calibrated"):
        pi.SupportAttestation(**_fields(calibrated=value))


def test_from_dict_wants_every_field_and_no_other():
    """Mutation: ``from_dict`` ignores unknown fields (``or unknown`` dropped)."""
    without = {k: v for k, v in _fields().items() if k != "calibrated"}
    with pytest.raises(ValueError, match="missing fields"):
        pi.SupportAttestation.from_dict(without)
    with pytest.raises(ValueError, match="unknown fields"):
        pi.SupportAttestation.from_dict({**_fields(), "confidence_note": "very sure"})
    with pytest.raises(ValueError, match="JSON object"):
        pi.SupportAttestation.from_dict(["not", "an", "object"])


def test_reading_changed_in_place_cannot_be_written_out():
    """The dataclass is frozen, but its probabilities are a dict. A change made to
    that dict in place is caught when the reading is written out to be sealed.

    Mutation: ``to_dict`` stops checking the reading again.
    """
    att = pi.SupportAttestation(**_fields())
    att.probabilities["supports"] = 4.2
    with pytest.raises(ValueError, match="between 0 and 1"):
        att.to_dict()


def test_reading_owns_its_probabilities():
    """Mutation: ``__post_init__`` keeps the caller's own dict instead of a copy."""
    probabilities = {"supports": 1, "contradicts": 0}
    att = pi.SupportAttestation(**_fields(probabilities=probabilities))
    probabilities["supports"] = 0.1
    assert att.probabilities == {"supports": 1.0, "contradicts": 0.0}
    assert all(type(v) is float for v in att.probabilities.values())


@pytest.mark.parametrize("verdict, probabilities, flagged", [
    ("supports", {"supports": 0.93, "contradicts": 0.07}, False),
    ("supports", {"supports": 0.8, "contradicts": 0.2}, False),     # exactly on the line
    ("supports", {"supports": 0.79, "contradicts": 0.21}, True),    # top probability below 0.8
    ("contradicts", {"contradicts": 0.97, "supports": 0.03}, True),
    ("says_nothing", {"says_nothing": 0.95, "supports": 0.05}, True),
    ("supports", {"supports": 0.85, "says_nothing": 0.9}, True),    # another answer on top
])
def test_review_flag(verdict, probabilities, flagged):
    """The amber flag is raised unless the reading clearly backs the claim.

    Mutations: (a) the review line moves from 0.8 to 0.75; (b) the
    ``verdict != "supports"`` test is dropped; (c) the "another answer on top"
    test is dropped.
    """
    att = pi.SupportAttestation(**_fields(verdict=verdict, probabilities=probabilities))
    assert att.needs_review is flagged
