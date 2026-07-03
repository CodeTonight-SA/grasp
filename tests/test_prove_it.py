# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Goodhart-resistant tests for the prove-it deterministic provenance engine.

The load-bearing test: a FABRICATED quote (not in the source) MUST resolve to
NOT_FOUND. If verify_quote is mutated to always pass, that test fails — which is
the whole point: a hallucinated citation cannot be proven.
"""
from grasp import prove_it as pi

SRC = pi.Source(
    id="doc",
    label="Sample",
    text="The quick brown fox\njumps over the lazy dog. Clause 4.4 is BINDING.",
)


def _cite(quote, sid="doc"):
    return pi.Citation(id="c1", claim="x", source_id=sid, quote=quote)


def test_exact_quote_is_verified_with_real_offsets():
    status, start, end = pi.verify_quote("Clause 4.4 is BINDING.", SRC.text)
    assert status == pi.STATUS_VERIFIED
    assert SRC.text[start:end] == "Clause 4.4 is BINDING."


def test_whitespace_variant_is_fuzzy_and_maps_back_to_source():
    # quote uses a single space where the source has a newline
    status, start, end = pi.verify_quote("brown fox jumps over", SRC.text)
    assert status == pi.STATUS_FUZZY
    # the matched span normalises to the quote (whitespace-only difference)
    assert " ".join(SRC.text[start:end].split()) == "brown fox jumps over"


def test_fabricated_quote_is_not_found():
    # THE falsifier — a quote that is NOT in the source must fail loudly.
    status, start, end = pi.verify_quote("the parties assign all rights outright", SRC.text)
    assert status == pi.STATUS_NOT_FOUND
    assert start == -1 and end == -1


def test_empty_quote_is_not_found():
    assert pi.verify_quote("", SRC.text)[0] == pi.STATUS_NOT_FOUND
    assert pi.verify_quote("   ", SRC.text)[0] == pi.STATUS_NOT_FOUND


def test_verify_all_marks_unknown_source_not_found():
    c = _cite("anything", sid="nope")
    pi.verify_all([c], [SRC])
    assert c.status == pi.STATUS_NOT_FOUND


def test_verify_all_populates_matched_text():
    c = _cite("lazy dog")
    pi.verify_all([c], [SRC])
    assert c.status == pi.STATUS_VERIFIED
    assert c.matched == "lazy dog"


def test_provenance_sha_is_deterministic_and_tallies():
    cites = [_cite("lazy dog"), pi.Citation("c2", "y", "doc", "NOT IN SOURCE AT ALL")]
    pi.verify_all(cites, [SRC])
    p1 = pi.provenance([SRC], cites)
    p2 = pi.provenance([SRC], cites)
    assert p1["sources"]["doc"]["sha256"] == p2["sources"]["doc"]["sha256"]
    assert p1["tally"][pi.STATUS_VERIFIED] == 1
    assert p1["tally"][pi.STATUS_NOT_FOUND] == 1
    assert p1["grounding_rate"] == 0.5


def test_html_contains_quote_clickable_chip_and_highlight():
    spec = {
        "title": "T",
        "response": "The clause holds the deciding vote [[cite:c1]].",
        "sources": [{"id": "doc", "label": "Sample", "text": SRC.text}],
        "citations": [{"id": "c1", "claim": "deciding vote", "source_id": "doc",
                       "quote": "Clause 4.4 is BINDING."}],
    }
    out, prov = pi.render(spec)
    assert 'data-cite="c1"' in out          # clickable chip wired to the source
    assert 'id="src-c1"' in out             # scroll/highlight target exists
    assert "Clause 4.4 is BINDING." in out  # the exact source quote is shown
    assert prov["tally"][pi.STATUS_VERIFIED] == 1


def test_html_flags_not_found_citation_visibly():
    spec = {
        "title": "T",
        "response": "A fabricated claim [[cite:bad]].",
        "sources": [{"id": "doc", "label": "Sample", "text": SRC.text}],
        "citations": [{"id": "bad", "claim": "fabricated", "source_id": "doc",
                       "quote": "this text was never in the source"}],
    }
    out, prov = pi.render(spec)
    assert prov["tally"][pi.STATUS_NOT_FOUND] == 1
    assert 'class="cite bad"' in out  # rendered red as unproven, not silently dropped
    assert 'id="src-bad"' not in out  # a not-found citation has NO highlight anchor


def test_render_from_file_path_source(tmp_path):
    f = tmp_path / "s.txt"
    f.write_text(SRC.text, encoding="utf-8")
    spec = {
        "title": "T",
        "response": "x [[cite:c1]]",
        "sources": [{"id": "doc", "label": "FromFile", "path": str(f)}],
        "citations": [{"id": "c1", "claim": "x", "source_id": "doc", "quote": "lazy dog"}],
    }
    out, prov = pi.render(spec)
    assert prov["tally"][pi.STATUS_VERIFIED] == 1
    assert "FromFile" in out


# Source with unicode smart-quotes + em-dash (as PDF/docx extraction produces)
_SRC_TYPO = "The deed is “binding” — clause 4.4 applies."


def test_typographic_variant_matches_with_original_offsets():
    # ASCII quotes + hyphen quote against unicode smart-quotes + em-dash source
    q = 'The deed is "binding" - clause 4.4 applies.'
    status, s, e = pi.verify_quote(q, _SRC_TYPO)
    assert status == pi.STATUS_FUZZY
    # the highlighted span is the ORIGINAL text (unicode preserved) — offsets intact
    assert _SRC_TYPO[s:e] == _SRC_TYPO
    assert "—" in _SRC_TYPO[s:e]  # em-dash survived in the matched original


def test_typographic_normalisation_does_not_create_false_matches():
    # Normalisation must not let unrelated text match — content tolerance is zero
    assert pi.verify_quote("a totally different sentence", _SRC_TYPO)[0] == pi.STATUS_NOT_FOUND


def test_exact_still_wins_over_typo_when_byte_identical():
    # When the quote matches byte-for-byte, it is VERIFIED (exact), not fuzzy
    status, s, e = pi.verify_quote("clause 4.4 applies.", _SRC_TYPO)
    assert status == pi.STATUS_VERIFIED
    assert _SRC_TYPO[s:e] == "clause 4.4 applies."
