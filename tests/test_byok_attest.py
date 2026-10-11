# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Tests for the bring-your-own-key TypeSafe/Jev attestation example.

Every test stubs ``urllib.request.urlopen`` itself -- the shared module
attribute, never a name imported out of it -- so none of these can reach the
real network, whatever path the code takes to call it.

Each test here was shown failing first against a real mutation of
``examples/byok_attest.py``'s saved bytes, the file was then restored byte for
byte, and the mutation is named in the test's docstring. See the PR body for
the mutation log (never undone with ``git checkout``, per the task brief).
"""
from __future__ import annotations

import ast
import email.message
import importlib
import io
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
if str(REPO_ROOT / "examples") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "examples"))

import examples.byok_attest as byok  # noqa: E402
from grasp import prove_it  # noqa: E402

CANARY = "canary-DO-NOT-LEAK-f0d9b2"


# ---------------------------------------------------------------------------
# helpers: a fake transport that never touches a socket
# ---------------------------------------------------------------------------

class _FakeResponse:
    """A context-manager stand-in for ``http.client.HTTPResponse``."""

    def __init__(self, status: int, headers: dict, body: bytes):
        self.status, self.headers, self._body = status, headers, body

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *exc) -> bool:
        return False


def _http_error(code: int, body: bytes = b"", headers: dict | None = None) -> urllib.error.HTTPError:
    hdrs = email.message.Message()
    for k, v in (headers or {}).items():
        hdrs[k] = v
    return urllib.error.HTTPError(byok.ENDPOINT, code, "", hdrs, io.BytesIO(body))


def _sequenced_urlopen(outcomes: list):
    """``urllib.request.urlopen`` replaced by one that plays back ``outcomes`` in
    order -- a ``_FakeResponse`` is returned, an exception instance is raised."""
    calls: list = []

    def fake(request, timeout=None):
        calls.append(request)
        outcome = outcomes[len(calls) - 1]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    return fake, calls


def _ok_answers(forward: dict, reversed_: dict) -> bytes:
    body = {"model": "jev-1.13.0", "usage": {"input_tokens": 300},
            "answers": {"forward": {"type": "choice", "choice": "supports", "probabilities": forward,
                                    "confidence": 0.9},
                       "reversed": {"type": "choice", "choice": "supports", "probabilities": reversed_,
                                   "confidence": 0.9}}}
    return json.dumps(body).encode("utf-8")


SUPPORTS_FORWARD = {"supports": 0.90, "contradicts": 0.06, "says_nothing": 0.04}
SUPPORTS_REVERSED = {"supports": 0.86, "contradicts": 0.09, "says_nothing": 0.05}


def _spec() -> dict:
    text = ("Intro paragraph, unrelated to the claim below.\n\n"
            "The quick brown fox jumps over the lazy dog.\n\n"
            "Closing paragraph, also unrelated.")
    return {
        "title": "byok test spec",
        "response": "An animal jumps over another. [[cite:c1]]",
        "sources": [{"id": "s1", "label": "Source One", "text": text}],
        "citations": [
            {"id": "c1", "claim": "An animal jumps over another.", "source_id": "s1",
             "quote": "The quick brown fox jumps over the lazy dog."},
            {"id": "c2", "claim": "A fox jumps, written with extra spaces.", "source_id": "s1",
             "quote": "The   quick brown fox jumps over the lazy dog."},
            {"id": "c3", "claim": "Something never said.", "source_id": "s1",
             "quote": "this text is not present anywhere in the source"},
        ],
    }


def _fake_clock():
    """A clock that advances a fixed amount on every read, so the retry budget
    check is exercised without any real time passing."""
    state = {"t": 0.0}

    def clock():
        state["t"] += 0.01
        return state["t"]

    return clock


# ---------------------------------------------------------------------------
# the pinned question
# ---------------------------------------------------------------------------

def test_question_sha256_matches_grips():
    """GRASP's BYOK example asks GRIP's own question, byte for byte -- a
    precision measurement taken on one side transfers to the other.

    Mutation: reorder ``OPTIONS`` (moves ``contradicts`` before ``supports``).
    """
    assert byok.QUESTION_SHA256 == "f2ca11414fa9889c0a1f2300be1fe7fd0c0e553a89b39d407e948400eb9e94a3"


def test_questions_carry_both_orders():
    """Mutation: ``QUESTIONS`` built from the same order twice (no ``[::-1]``)."""
    forward = list(byok.QUESTIONS["forward"]["criteria"])
    reversed_ = list(byok.QUESTIONS["reversed"]["criteria"])
    assert forward == reversed_[::-1]
    assert forward != reversed_


# ---------------------------------------------------------------------------
# the window
# ---------------------------------------------------------------------------

def test_window_is_the_paragraph_not_the_bare_quote():
    """The quote sits in the middle of a three-paragraph source; a window
    expanded by one paragraph either way covers all three.

    Mutation: ``_extract_window`` returns ``text[start:end]`` (the bare quote).
    """
    spec = _spec()
    sources = [byok._load_source(s) for s in spec["sources"]]
    cites = [prove_it.Citation(id=c["id"], claim=c["claim"], source_id=c["source_id"], quote=c["quote"])
             for c in spec["citations"]]
    prove_it.verify_all(cites, sources)
    by_id = {s.id: s for s in sources}
    window = byok._window(cites[0], by_id)
    assert window.strip() == sources[0].text.strip()
    assert "Intro paragraph" in window and "Closing paragraph" in window


def test_window_falls_back_to_bare_quote_when_source_missing():
    """Mutation: the ``or c.quote`` fallback in ``_window`` is dropped."""
    c = prove_it.Citation(id="x", claim="k", source_id="missing", quote="the bare quote")
    assert byok._window(c, {}) == "the bare quote"


# ---------------------------------------------------------------------------
# averaging the two orders
# ---------------------------------------------------------------------------

def test_complete_reading_averages_both_orders():
    """Mutation: ``_averaged`` sums instead of averaging (divides by 1, not 2)."""
    probs = byok._averaged({"forward": {"probabilities": SUPPORTS_FORWARD},
                            "reversed": {"probabilities": SUPPORTS_REVERSED}})
    assert probs["supports"] == pytest.approx((0.90 + 0.86) / 2)
    assert abs(sum(probs.values()) - 1.0) < 0.02


def test_single_order_answer_is_never_a_reading():
    """One complete order plus a missing one carries exactly the first-listed
    bias the pair exists to cancel, so it must not become a reading.

    Mutation: ``_averaged`` accepts ``any(readings)`` instead of ``all(readings)``.
    """
    probs = byok._averaged({"forward": {"probabilities": SUPPORTS_FORWARD}, "reversed": {}})
    assert probs == {}


def test_distribution_outside_tolerance_is_incomplete():
    """Three in-range probabilities that do not sum to 1 are not a distribution.

    Mutation: ``_complete`` drops the ``abs(sum(...) - 1.0)`` tolerance check.
    """
    skewed = {"supports": 0.5, "contradicts": 0.5, "says_nothing": 0.5}
    assert byok._complete({"probabilities": skewed}) == {}


# ---------------------------------------------------------------------------
# verify_all stays sovereign
# ---------------------------------------------------------------------------

def test_not_found_citation_gets_no_reading(monkeypatch):
    """A fabricated quote is never asked about -- the deterministic floor stays
    sovereign over a model's opinion.

    Mutation: ``attest_spec`` asks about every citation, not just
    ``STATUS_VERIFIED``/``STATUS_FUZZY``.
    """
    fake, calls = _sequenced_urlopen([])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    spec = _spec()
    spec["citations"] = [spec["citations"][2]]  # the not_found one, alone
    report = byok.attest_spec(spec, model="jev-latest", key="k")
    assert report == {"attested": 0, "flagged": 0, "not_found": 1, "no_reading": {}}
    assert calls == []
    assert "support_attestation" not in spec["citations"][0]


def test_verified_and_fuzzy_citations_both_get_attested(monkeypatch):
    """Mutation: ``attest_spec`` only asks about ``STATUS_VERIFIED`` (fuzzy excluded).

    This is also the canonical shape test: the resulting ``support_attestation``
    is exactly a valid ``SupportAttestation.to_dict()`` -- ``calibrated`` False,
    ``machine_reading`` True, ``precision_ref`` 'unmeasured', the pinned hash.
    """
    fake, calls = _sequenced_urlopen([
        _FakeResponse(200, {}, _ok_answers(SUPPORTS_FORWARD, SUPPORTS_REVERSED)),
        _FakeResponse(200, {}, _ok_answers(SUPPORTS_FORWARD, SUPPORTS_REVERSED)),
    ])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    spec = _spec()
    spec["citations"] = spec["citations"][:2]  # verified + fuzzy, no not_found
    report = byok.attest_spec(spec, model="jev-latest", key="k")
    assert report["attested"] == 2 and report["not_found"] == 0
    for cite in spec["citations"]:
        att = cite["support_attestation"]
        assert att["provider"] == "typesafe"
        assert att["model"] == "jev-1.13.0"
        assert att["question_sha256"] == byok.QUESTION_SHA256
        assert att["verdict"] == "supports"
        assert att["calibrated"] is False
        assert att["machine_reading"] is True
        assert att["precision_ref"] == "unmeasured"
        prove_it.SupportAttestation.from_dict(att)  # raises if the shape is wrong
    assert len(calls) == 2


def test_both_orders_travel_in_one_call(monkeypatch):
    """Mutation: ``decide`` narrows the sent ``questions`` to just the forward
    order, dropping the reversed one from the single batched call."""
    fake, calls = _sequenced_urlopen([_FakeResponse(200, {}, _ok_answers(SUPPORTS_FORWARD, SUPPORTS_REVERSED))])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    result = byok.decide("state", byok.QUESTIONS, model="jev-latest", key="k")
    assert result["ok"] is True
    assert len(calls) == 1
    sent = json.loads(calls[0].data.decode("utf-8"))
    assert set(sent["questions"]) == {"forward", "reversed"}


def test_low_confidence_reading_is_flagged_for_review(monkeypatch):
    """Mutation: ``attest_spec`` never counts ``reading.needs_review``."""
    unsure = {"supports": 0.5, "contradicts": 0.3, "says_nothing": 0.2}
    fake, _ = _sequenced_urlopen([_FakeResponse(200, {}, _ok_answers(unsure, unsure))])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    spec = _spec()
    spec["citations"] = [spec["citations"][0]]
    report = byok.attest_spec(spec, model="jev-latest", key="k")
    assert report["attested"] == 1
    assert report["flagged"] == 1


# ---------------------------------------------------------------------------
# retries and backoff (lib/hal/decide/typesafe.py's own shape)
# ---------------------------------------------------------------------------

def test_connection_failure_is_retried_then_succeeds(monkeypatch):
    """Mutation: ``_attempt`` re-raises instead of returning ``(None, {}, ...)``."""
    fake, calls = _sequenced_urlopen([ConnectionRefusedError("refused"),
                                      _FakeResponse(200, {}, _ok_answers(SUPPORTS_FORWARD, SUPPORTS_REVERSED))])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    outcome = byok._send_with_retries(byok.ENDPOINT, b"{}", {}, sleep=lambda s: None,
                                      clock=_fake_clock(), jitter=lambda: 0.0)
    assert outcome[0] == 200
    assert len(calls) == 2


def test_5xx_is_retried_honouring_retry_after(monkeypatch):
    """Mutation: ``_retry_after`` ignores the header and always falls back to backoff."""
    fake, calls = _sequenced_urlopen([
        _http_error(503, headers={"Retry-After": "2"}),
        _FakeResponse(200, {}, _ok_answers(SUPPORTS_FORWARD, SUPPORTS_REVERSED)),
    ])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    sleeps: list = []
    outcome = byok._send_with_retries(byok.ENDPOINT, b"{}", {}, sleep=sleeps.append,
                                      clock=_fake_clock(), jitter=lambda: 0.0)
    assert outcome[0] == 200 and len(calls) == 2
    assert sleeps == [2.0]


def test_400_is_never_retried(monkeypatch):
    """Mutation: ``_retryable`` treats ``status >= 400`` as retryable."""
    fake, calls = _sequenced_urlopen([_http_error(400, body=b'{"detail": "bad request"}')])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    outcome = byok._send_with_retries(byok.ENDPOINT, b"{}", {}, sleep=lambda s: None,
                                      clock=_fake_clock(), jitter=lambda: 0.0)
    assert outcome[0] == 400
    assert len(calls) == 1


def test_at_most_two_retries(monkeypatch):
    """Three failures in a row (the initial attempt plus two retries) and no more.

    Mutation: ``MAX_RETRIES`` raised from 2 to 3.
    """
    fake, calls = _sequenced_urlopen([_http_error(503)] * 5)
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    outcome = byok._send_with_retries(byok.ENDPOINT, b"{}", {}, sleep=lambda s: None,
                                      clock=_fake_clock(), jitter=lambda: 0.0)
    assert outcome[0] == 503
    assert len(calls) == 3


def test_over_budget_is_refused_locally_never_sent(monkeypatch):
    """An over-sized request is refused before anything is sent -- refused, never
    truncated, matching the vendor's own ``max_tokens_exceeded`` behaviour.

    Mutation: the local byte-ceiling check in ``decide`` is removed.
    """
    fake, calls = _sequenced_urlopen([])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setattr(byok, "MAX_REQUEST_BYTES", 10)
    result = byok.decide("a state far larger than ten bytes", byok.QUESTIONS, model="jev-latest", key="k")
    assert result["ok"] is False
    assert result["reason"] == "over_budget"
    assert calls == []


# ---------------------------------------------------------------------------
# the key: environment only, never argv, never leaked
# ---------------------------------------------------------------------------

def test_no_cli_flag_can_carry_the_key():
    """Mutation: a ``--key`` option is added to the argument parser."""
    with pytest.raises(SystemExit):
        byok._parse_args(["--input", "x.json", "--key", "should-not-exist"])


def test_missing_key_refuses_before_any_send(monkeypatch, tmp_path):
    """A VALID spec is on disk, so the only thing stopping a send is the key
    check: if it were skipped, ``main`` would reach ``attest_spec`` and attempt
    one.

    Mutation: ``main`` falls through to ``attest_spec`` when the key is empty.
    """
    fake, calls = _sequenced_urlopen([])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.delenv("TYPESAFE_API_KEY", raising=False)
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(_spec()), encoding="utf-8")
    rc = byok.main(["--input", str(spec_path)])
    assert rc == 2
    assert calls == []


@pytest.mark.parametrize("mode", ["auth_failed", "server_error", "timeout"])
def test_canary_key_never_appears_anywhere(monkeypatch, tmp_path, capsys, mode):
    """A fake key runs the real CLI through three failure shapes; the key is
    never in stdout, stderr, or any raised exception's text.

    Mutation: ``main`` prints the resolved key to stderr right after reading it
    (the shape a stray debug line would actually take).
    """
    if mode == "auth_failed":
        outcomes = [_http_error(401, body=f"key was {CANARY}".encode())]
    elif mode == "server_error":
        outcomes = [_http_error(500)] * 3
    else:
        outcomes = [TimeoutError("timed out")] * 3
    fake, calls = _sequenced_urlopen(outcomes)
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setattr(time, "sleep", lambda s: None)
    monkeypatch.setenv("TYPESAFE_API_KEY", CANARY)
    spec_path = tmp_path / "spec.json"
    out_path = tmp_path / "out.json"
    spec = _spec()
    spec["citations"] = [spec["citations"][0]]
    spec_path.write_text(json.dumps(spec), encoding="utf-8")

    raised = None
    try:
        rc = byok.main(["--input", str(spec_path), "--out", str(out_path)])
    except Exception as exc:  # noqa: BLE001 -- the canary check needs the text even on a crash
        raised, rc = str(exc), 1
    captured = capsys.readouterr()
    assert CANARY not in captured.out
    assert CANARY not in captured.err
    assert CANARY not in (raised or "")
    assert rc == 0  # a per-citation failure never crashes the run
    assert len(calls) >= 1


def test_canary_key_builds_the_request_header_but_nothing_else(monkeypatch):
    """The key is used for exactly one thing: the Authorization header of the
    one request actually sent. Nothing else in the body carries it.

    Mutation: the key is interpolated into the ``User-Agent`` header too.
    """
    fake, calls = _sequenced_urlopen([_FakeResponse(200, {}, _ok_answers(SUPPORTS_FORWARD, SUPPORTS_REVERSED))])
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    byok.decide("state", byok.QUESTIONS, model="jev-latest", key=CANARY)
    request = calls[0]
    assert request.get_header("Authorization") == f"Bearer {CANARY}"
    other_headers = {k: v for k, v in request.header_items() if k.lower() != "authorization"}
    assert all(CANARY not in str(v) for v in other_headers.values())
    assert CANARY not in request.data.decode("utf-8")


# ---------------------------------------------------------------------------
# output: --out or stdout, same spec shape
# ---------------------------------------------------------------------------

def test_output_goes_to_out_file_when_given(monkeypatch, tmp_path):
    """Mutation: ``_write`` ignores ``out_path`` and always prints to stdout."""
    fake, _ = _sequenced_urlopen([_FakeResponse(200, {}, _ok_answers(SUPPORTS_FORWARD, SUPPORTS_REVERSED))] * 2)
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    spec_path = tmp_path / "in.json"
    out_path = tmp_path / "out.json"
    spec_path.write_text(json.dumps(_spec()), encoding="utf-8")
    rc = byok.main(["--input", str(spec_path), "--out", str(out_path)])
    assert rc == 0
    written = json.loads(out_path.read_text(encoding="utf-8"))
    assert written["citations"][0]["support_attestation"]["provider"] == "typesafe"


def test_output_goes_to_stdout_without_out(monkeypatch, tmp_path, capsys):
    """Mutation: ``main`` requires ``--out`` instead of defaulting to stdout."""
    fake, _ = _sequenced_urlopen([_FakeResponse(200, {}, _ok_answers(SUPPORTS_FORWARD, SUPPORTS_REVERSED))] * 2)
    monkeypatch.setattr(urllib.request, "urlopen", fake)
    monkeypatch.setenv("TYPESAFE_API_KEY", "k")
    spec_path = tmp_path / "in.json"
    spec_path.write_text(json.dumps(_spec()), encoding="utf-8")
    rc = byok.main(["--input", str(spec_path)])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["citations"][0]["support_attestation"]["verdict"] == "supports"


# ---------------------------------------------------------------------------
# grasp stays model-free
# ---------------------------------------------------------------------------

def _imports_examples_package(path: Path) -> bool:
    """True if the module at ``path`` imports anything from the top-level
    ``examples`` package, by name (``import examples...``) or by origin
    (``from examples... import ...``)."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(n.name.split(".")[0] == "examples" for n in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and node.module and node.module.split(".")[0] == "examples":
            return True
    return False


def test_nothing_under_grasp_imports_examples():
    """Mutation: ``grasp/prove_it.py`` gains ``import examples.byok_attest``."""
    grasp_py_files = sorted((REPO_ROOT / "grasp").rglob("*.py"))
    offenders = [str(p) for p in grasp_py_files if _imports_examples_package(p)]
    assert offenders == []


def test_verify_path_still_imports_no_provider_code():
    """The BYOK example must not have widened grasp's own model-free guarantee.
    Re-imports the existing guard test module, so a regression in it is caught
    by this file too, not only by its own suite.

    Mutation: the imported module name is misspelled (a real rename of the
    guard module -- or of this import -- would otherwise go unnoticed here)."""
    mod = importlib.import_module("tests.test_support_attestation_seal")
    assert hasattr(mod, "test_verify_path_imports_no_provider_code")
