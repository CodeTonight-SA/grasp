# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""cite_verify — the protocol twin of the deterministic citation floor.

This module mirrors the ``cite.verify`` verb of the HAPPI protocol (happi/1.3):
the same deterministic ladder as :func:`grasp.prove_it.verify_quote` — exact
substring → whitespace + length-preserving typographic-flexible → not_found —
reimplemented standalone so the protocol surface and the library surface can be
pinned against each other. Cross-runtime agreement is a conformance property:
``tests/test_cite_verify.py`` runs an identical case battery through BOTH
implementations and asserts the verdicts and offsets agree.

The envelope plumbing of the protocol runtime (event emission, exit codes) is
replaced by a plain-Python surface: malformed input raises ``ValueError`` (the
protocol's ``parse_error``), and ``strict=True`` raises
:class:`CiteVerifyNotFound` when any citation is unproven (the protocol's
``runtime_error`` gate any harness can fail a build on).

Scope honesty: this proves a quote is **verbatim in the supplied source** —
not that the source is authentic, and not that the quote supports the claim.
"""
from __future__ import annotations

import hashlib
import re

__all__ = ["verify", "process", "CiteVerifyNotFound"]

_CV_WS = re.compile(r"\s+")
# Length-preserving typographic normalisation (single-char -> single-char), so a
# match found in normalised text still indexes the ORIGINAL source verbatim.
_CV_TYPO = {
    0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-", 0x2014: "-", 0x2015: "-",
    0x2018: "'", 0x2019: "'", 0x201B: "'",
    0x201C: '"', 0x201D: '"', 0x201F: '"',
    0x00A0: " ", 0x2007: " ", 0x2009: " ", 0x202F: " ",
}


class CiteVerifyNotFound(RuntimeError):
    """Raised by ``process(strict=True)`` when any citation is NOT verbatim in
    its source — the mechanical gate a caller can fail a build on."""


def _cv_typo(s):
    return s.translate(_CV_TYPO)


def verify(quote, source_text):
    """(status, start, end) for `quote` in `source_text`. Deterministic ladder:
    exact substring -> whitespace+typographic-flexible -> not_found. Offsets index
    the original source verbatim (normalisation is length-preserving)."""
    q = (quote or "").strip()
    if not q:
        return "not_found", -1, -1
    idx = source_text.find(q)
    if idx != -1:
        return "verified", idx, idx + len(q)
    toks = [re.escape(t) for t in _CV_WS.split(_cv_typo(q)) if t]
    if not toks:
        return "not_found", -1, -1
    m = re.compile(r"\s+".join(toks)).search(_cv_typo(source_text))
    if m:
        return "fuzzy", m.start(), m.end()
    return "not_found", -1, -1


def _index_sources(sources):
    """Map source id -> text. Raises ValueError on a malformed source entry."""
    by_id = {}
    for s in sources:
        if (not isinstance(s, dict) or not isinstance(s.get("id"), str)
                or not isinstance(s.get("text"), str)):
            raise ValueError("cite.verify: each source needs string id and text")
        by_id[s["id"]] = s["text"]
    return by_id


def _citation_ok(c):
    """True iff citation carries the required string fields id, source_id, quote."""
    return (isinstance(c, dict) and isinstance(c.get("id"), str)
            and isinstance(c.get("source_id"), str) and isinstance(c.get("quote"), str))


def process(citations, sources, *, strict: bool = False) -> dict:
    """Verify each citation against its source. Returns the provenance record:
    per-source sha256+chars, per-citation status+offsets, tally, grounding_rate —
    the same shape as ``grasp.prove_it.provenance`` produces, so the two engines
    interoperate.

    Raises ``ValueError`` on malformed inputs (a non-list, a source without
    string id/text, a citation without string id/source_id/quote). With
    ``strict=True``, raises :class:`CiteVerifyNotFound` when any citation is
    not_found — the never-ship-an-unproven-quote gate.
    """
    if not isinstance(sources, list) or not isinstance(citations, list):
        raise ValueError("cite.verify: requires sources[] and citations[]")
    by_id = _index_sources(sources)
    tally = {"verified": 0, "fuzzy": 0, "not_found": 0}
    results = []
    for c in citations:
        if not _citation_ok(c):
            raise ValueError("cite.verify: each citation needs string id, source_id, quote")
        src = by_id.get(c["source_id"])
        status, start, end = verify(c["quote"], src) if src is not None \
            else ("not_found", -1, -1)
        tally[status] += 1
        results.append({"id": c["id"], "source_id": c["source_id"],
                        "status": status, "start": start, "end": end})
    grounded = tally["verified"] + tally["fuzzy"]
    record = {
        "sources": {sid: {"sha256": hashlib.sha256(txt.encode("utf-8")).hexdigest(),
                          "chars": len(txt)} for sid, txt in by_id.items()},
        "citations": results,
        "tally": tally,
        "grounding_rate": round(grounded / max(len(citations), 1), 3),
    }
    if strict and tally["not_found"] > 0:
        raise CiteVerifyNotFound(
            str(tally["not_found"]) + " citation(s) NOT verbatim in source — unproven")
    return record
