#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""byok_attest -- bring-your-own-key support attestations for a prove-it spec.

GRASP never calls a model (``grasp/honesty.py``): it defines and verifies a
caller's typed machine reading of whether a quote supports its claim
(``grasp.prove_it.SupportAttestation``, GRASP#22), but it never produces one
itself. This script is that caller, for a GRASP customer who wants readings
without sending their own claim text through CodeTonight: it reads
``TYPESAFE_API_KEY`` from THIS machine's own environment and talks to
TypeSafe's Jev model directly, with no GRIP or HAL runtime in the path. The
customer's text goes only to their own TypeSafe account (the Jev integration
plan's decision D-3: "bring your own key" --
``~/.grip/plans/snug-questing-quill.md`` Phase 3.5).

It lives OUTSIDE the ``grasp`` package on purpose, so "grasp never imports a
provider SDK" keeps holding for the library itself -- only this example reaches
the network (``tests/test_byok_attest.py::test_nothing_under_grasp_imports_examples``
pins the direction). It is stdlib-only: the only non-stdlib import is
``grasp.prove_it`` itself, which is also stdlib-only, so running this needs no
dependency beyond the GRASP checkout (or ``pip install grasp-provenance``) it
ships beside.

What it does, in order:

1. Load a prove-it spec (the JSON ``grasp.prove_it.render`` takes: ``sources``
   and ``citations``, each citation a claim/source/quote triple).
2. Run GRASP's deterministic floor (``verify_all``) FIRST. A citation whose
   quote is not found in its source gets no reading at all -- the floor stays
   sovereign; a model's opinion can never rescue a quote that was not there.
3. For every citation the floor DID locate (verified, or a whitespace/
   typographic variant), ask Jev one question: does the quote -- read inside
   its source paragraph, not as a bare fragment -- support the claim,
   contradict it, or say nothing about it? The same question GRIP asks
   (``lib/prove_it_decide.py``), byte-identical: both option orders in one
   call, averaged, so the model's own first-listed-option bias cancels rather
   than silently picking a side (``QUESTION_SHA256`` below is pinned to GRIP's
   own hash by a test).
4. Attach every complete reading to its citation as a ``support_attestation``.
   GRASP itself draws the amber "review" flag below 80% confidence when the
   spec is later rendered or sealed -- this script asks the question and
   reports it, nothing more.
5. Write the enriched spec back out -- to ``--out``, or to stdout -- in the
   same shape ``grasp.prove_it.render`` and ``grasp.legal_receipt`` read, so it
   can be rendered or sealed next.

What an attestation is NOT: proof. It is one model's machine reading, with a
measured precision on file or "unmeasured" (almost always the latter, until a
customer runs their own calibration). It can flag a citation for review. It
can never turn a fabricated quote into a verified one, and the deterministic
floor's verdict never changes because of it.

Usage::

    TYPESAFE_API_KEY=... python3 examples/byok_attest.py --input spec.json --out attested.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from grasp import prove_it  # noqa: E402 -- after the sys.path shim above

# --- the question: byte-identical to GRIP's (lib/prove_it_decide.py) --------
#
# The wording and the per-option meanings are copied verbatim, because the
# pinned hash below is GRIP's QUESTION_SHA256 -- this is deliberately the SAME
# question, not a similar one, so a precision measurement taken on one side
# transfers to the other. ``prove_it.SUPPORT_VERDICTS`` (GRASP's own constant)
# already names the same three verdicts in the same order.

OPTIONS: dict[str, str] = {
    "supports": "the quote states what the claim asserts",
    "contradicts": "the quote states the opposite of the claim, or something incompatible with it",
    "says_nothing": "the quote does not address what the claim asserts",
}
_QUESTION_TEXT = "Does the quoted text support the claim?"


def _choice(order: list[str]) -> dict:
    return {"type": "choice", "instructions": _QUESTION_TEXT, "criteria": {v: OPTIONS[v] for v in order}}


#: Both option orders, asked together in one call (GRIP's ``QUESTIONS``).
QUESTIONS: dict[str, dict] = {"forward": _choice(list(OPTIONS)), "reversed": _choice(list(OPTIONS)[::-1])}


def question_digest(questions: dict) -> str:
    """SHA-256 of ``questions`` with option ORDER kept, exactly as GRIP's
    ``lib/prove_it_decide.py::question_digest`` computes it: a sorted-keys dump
    would erase the order this scheme exists to balance, hashing the forward
    and reversed questions alike."""
    ordered = [[name, q.get("type", ""), q.get("instructions", ""), list(map(list, q.get("criteria", {}).items()))]
               for name, q in questions.items()]
    return hashlib.sha256(json.dumps(ordered).encode("utf-8")).hexdigest()


#: Pinned to GRIP's own QUESTION_SHA256 -- a test asserts this literal value,
#: so drift on either side of the GRIP/GRASP boundary is caught.
QUESTION_SHA256 = question_digest(QUESTIONS)

# A model that rounds to two decimals can answer 0.99 or 1.01: the same
# tolerance GRIP uses, and numerically the one grasp.prove_it already names
# for the same reason (``PROBABILITY_SUM_TOLERANCE``), reused rather than
# redeclared.
_DISTRIBUTION_TOLERANCE = prove_it.PROBABILITY_SUM_TOLERANCE

# --- wiring: mirrors lib/hal/decide/typesafe.py, minus HAL's spend guard and ---
# --- GRIP's redaction shield -- the customer's own key, the customer's own  ---
# --- account, nothing of CodeTonight's in the path.                        ---

ENDPOINT = "https://api.typesafe.ai/v1/systemone"
DEFAULT_MODEL = "jev-latest"
#: A local ceiling only (config/decision_models.yaml's own figure for this
#: provider): the API enforces its own token budgets and REFUSES an
#: over-budget request with ``max_tokens_exceeded`` rather than truncating it
#: (measured 2026-10-10), so there is nothing to gain by uploading a request
#: this large in the first place.
MAX_REQUEST_BYTES = 524_288
MAX_RETRIES = 2
INITIAL_BACKOFF_S, MAX_BACKOFF_S, JITTER = 0.5, 5.0, 0.25
ATTEMPT_TIMEOUT_S, TOTAL_BUDGET_S = 10.0, 30.0
#: A retry is only attempted when this much of the budget would still be left
#: for it; each attempt's own timeout is cut to whatever remains.
MIN_ATTEMPT_S = 1.0
#: TypeSafe's own key shape, scrubbed from any vendor text before it is ever
#: printed -- belt-and-braces: the key itself never reaches this function.
_KEY_SHAPE = re.compile(r"apikey_[A-Za-z0-9_]+")

#: ``(status, headers, body)``; ``(None, {}, "timeout"|"unreachable")`` when no answer came.
Outcome = tuple[Optional[int], dict, Any]
#: ``send(state, questions, model=..., key=...) -> dict`` -- ``decide``'s own shape.
Send = Callable[..., dict]


def _attempt(endpoint: str, data: bytes, headers: dict, timeout: float) -> Outcome:
    """One POST. ``urllib.request.urlopen`` is called through the module, not
    imported by name, so a test can stub the one shared object and nothing
    here can reach the network regardless of how it was called."""
    request = urllib.request.Request(endpoint, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), exc.read()
    except Exception as exc:  # noqa: BLE001 -- a connection failure or timeout, never the request itself
        timed_out = isinstance(exc, TimeoutError) or isinstance(getattr(exc, "reason", None), TimeoutError)
        return None, {}, "timeout" if timed_out else "unreachable"


def _retryable(status: Optional[int]) -> bool:
    return status is None or status in (408, 429) or status >= 500


def _retry_after(headers: Mapping) -> Optional[float]:
    """The server's own wait, from ``retry-after-ms`` or ``retry-after`` (seconds); None if absent or absurd."""
    lowered = {str(k).lower(): v for k, v in (headers or {}).items()}
    for name, scale in (("retry-after-ms", 0.001), ("retry-after", 1.0)):
        try:
            seconds = float(lowered[name]) * scale
        except (KeyError, TypeError, ValueError):
            continue
        if 0 <= seconds <= 60:
            return seconds
    return None


def _retry_delay(outcome: Outcome, attempt: int, elapsed: float, jitter: Callable[[], float]) -> Optional[float]:
    status, headers, _ = outcome
    if attempt > MAX_RETRIES or not _retryable(status):
        return None
    delay = _retry_after(headers)
    if delay is None:
        backoff = min(INITIAL_BACKOFF_S * 2 ** (attempt - 1), MAX_BACKOFF_S)
        delay = backoff * (1 - JITTER * jitter())
    return None if elapsed + delay + MIN_ATTEMPT_S > TOTAL_BUDGET_S else delay


def _send_with_retries(endpoint: str, data: bytes, headers: dict, *, sleep: Callable[[float], None] = time.sleep,
                       clock: Callable[[], float] = time.monotonic,
                       jitter: Callable[[], float] = random.random) -> Outcome:
    """TypeSafe's own SDK retry shape: at most 2 retries, on a connection
    failure, 408, 429 or any 5xx, honouring ``retry-after``, 10 s per attempt,
    30 s in all (``lib/hal/decide/typesafe.py::_send``)."""
    started, attempt = clock(), 0
    while True:
        attempt += 1
        left = TOTAL_BUDGET_S - (clock() - started)
        outcome = _attempt(endpoint, data, headers, min(ATTEMPT_TIMEOUT_S, left))
        delay = _retry_delay(outcome, attempt, clock() - started, jitter)
        if delay is None:
            return outcome
        sleep(delay)


def _json(raw: Any) -> dict:
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _vendor_error(raw: Any) -> tuple[str, str]:
    detail = _json(raw).get("detail")
    if isinstance(detail, dict):
        return str(detail.get("error_type") or ""), str(detail.get("message") or "")
    return "", str(detail or "")


def _reason(status: Optional[int], raw: Any) -> str:
    if status is None:
        return raw if raw in ("timeout", "unreachable") else "unreachable"
    if status in (400, 422):
        return "over_budget" if _vendor_error(raw)[0] == "max_tokens_exceeded" else "invalid_request"
    if status in (401, 403):
        return "auth_failed"
    if status == 429:
        return "rate_limited"
    if status == 529:
        return "overloaded"
    return "server_error" if status >= 500 else "bad_response"


def _detail(status: Optional[int], raw: Any) -> str:
    """The vendor's own explanation, short, with anything key-shaped removed."""
    if status is None:
        return ""
    text = ": ".join(part for part in _vendor_error(raw) if part) or f"HTTP {status}"
    return _KEY_SHAPE.sub("[key]", text)[:200]


def decide(state: str, questions: Mapping[str, dict], *, model: str, key: str, endpoint: str = ENDPOINT) -> dict:
    """One decision call. Returns ``{"ok": True, "answers": ..., "model": ...}``
    or ``{"ok": False, "reason": ..., "detail": ...}`` -- never raises, and the
    key is never in the result, a log line, or an exception (it is a local
    parameter used once, to build one header, in this one function)."""
    body = json.dumps({"state": state, "model": model, "questions": dict(questions)},
                      ensure_ascii=False).encode("utf-8")
    if len(body) > MAX_REQUEST_BYTES:
        return {"ok": False, "reason": "over_budget",
                "detail": f"{len(body)} bytes is over the {MAX_REQUEST_BYTES}-byte local ceiling"}
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json",
               "Accept": "application/json", "User-Agent": "grasp-byok-attest/1"}
    status, _, raw = _send_with_retries(endpoint, body, headers)
    if status != 200:
        return {"ok": False, "reason": _reason(status, raw), "detail": _detail(status, raw)}
    payload = _json(raw)
    answers = payload.get("answers") if isinstance(payload.get("answers"), dict) else {}
    return {"ok": True, "answers": answers, "model": str(payload.get("model") or "")}


# --- the window: mirrors lib/prove_it_decide.py::_window + ------------------
# --- lib/prove_it_council.py::_extract_window                              ---

def _extract_window(text: str, start: int, end: int, num_paragraphs: int = 1) -> str:
    """The citation's source paragraph, not the bare quote: a fragment such as
    "the drug is safe" can sit inside "The assertion that the drug is safe is
    false", and only the paragraph shows that. Reproduced verbatim from GRIP's
    ``lib/prove_it_council.py::_extract_window`` (Codex, GRIP#7991)."""
    if start == -1 or end == -1 or not text:
        return ""
    paras = [(m.start(0), m.end(0), m.group(0)) for m in re.finditer(r"(?s).*?(?:\n\n+|$)", text)]
    if not paras:
        return text[max(0, start - 500):min(len(text), end + 500)].strip()
    idx_start, idx_end = 0, len(paras) - 1
    for i, (p_start, p_end, _) in enumerate(paras):
        if p_end > start and (i == 0 or paras[i - 1][1] <= start):
            idx_start = i
        if p_start <= end:
            idx_end = i
    idx_start = max(0, idx_start - num_paragraphs)
    idx_end = min(len(paras) - 1, idx_end + num_paragraphs)
    return text[paras[idx_start][0]: paras[idx_end][1]].strip()


def _window(c: "prove_it.Citation", by_id: dict) -> str:
    """The quote in its source paragraph, falling back to the bare quote only
    when there is no located source (``lib/prove_it_decide.py::_window``)."""
    src = by_id.get(c.source_id)
    return (_extract_window(src.text, c.start, c.end, 1) if src else "") or c.quote


# --- averaging the two option orders (lib/prove_it_decide.py) --------------

def _complete(answer: Any) -> dict[str, float]:
    """One order's probability per verdict, or ``{}`` if any is missing,
    malformed, or the three do not sum to 1 within tolerance -- three values of
    0.9 are each in range and are not a distribution (Codex, GRIP#7991)."""
    probs = answer.get("probabilities") if isinstance(answer, dict) else None
    probs = probs if isinstance(probs, dict) else {}
    valid = {v: float(probs[v]) for v in prove_it.SUPPORT_VERDICTS
             if isinstance(probs.get(v), (int, float)) and not isinstance(probs.get(v), bool)
             and 0 <= probs[v] <= 1}
    if len(valid) != len(prove_it.SUPPORT_VERDICTS) or abs(sum(valid.values()) - 1.0) > _DISTRIBUTION_TOLERANCE:
        return {}
    return valid


def _averaged(answers: dict) -> dict[str, float]:
    """The mean of both orders, or ``{}`` when either is incomplete. ONE
    complete answer is never enough: it is a single option order, carrying the
    first-listed lean the two orders exist to cancel (Codex, GRIP#7991)."""
    readings = [_complete(answers.get(q)) for q in QUESTIONS]
    if all(readings):
        return {v: sum(r[v] for r in readings) / len(readings) for v in prove_it.SUPPORT_VERDICTS}
    return {}


def support_reading(claim: str, quote: str, *, model: str, key: str,
                    send: Send = decide) -> tuple[Optional["prove_it.SupportAttestation"], str]:
    """Jev's order-balanced reading of whether ``quote`` supports ``claim``.
    ``(None, reason)`` when there is no usable reading; ``send`` is injectable
    for tests (DIP), so no test needs the real network."""
    state = f"CLAIM: {claim}\nQUOTE: {quote}"
    result = send(state, QUESTIONS, model=model, key=key)
    if not result.get("ok"):
        return None, result.get("reason", "unavailable")
    probs = _averaged(result.get("answers") or {})
    if not probs:
        return None, "incomplete_answer"
    verdict = max(prove_it.SUPPORT_VERDICTS, key=lambda v: probs[v])
    reading = prove_it.SupportAttestation(
        provider="typesafe", model=str(result.get("model") or model), question_sha256=QUESTION_SHA256,
        verdict=verdict, probabilities=probs, calibrated=False, machine_reading=True,
        precision_ref=prove_it.PRECISION_UNMEASURED)
    return reading, "ok"


# --- the spec: load, enrich, write -----------------------------------------

def _load_source(s: dict) -> "prove_it.Source":
    if s.get("text") is not None:
        return prove_it.Source(id=s["id"], label=s.get("label", s["id"]), text=s["text"])
    p = Path(s["path"]).expanduser()
    return prove_it.Source(id=s["id"], label=s.get("label", p.name),
                           text=p.read_text(encoding="utf-8", errors="replace"))


def attest_spec(spec: dict, *, model: str, key: str, send: Send = decide) -> dict:
    """``spec`` (a prove-it spec dict) enriched in place with a
    ``support_attestation`` on every citation Jev gave a complete reading for.
    Returns a report: ``attested``, ``flagged`` (needs review), ``not_found``
    (the floor never located the quote, so no reading was asked), and
    ``no_reading`` (a reason -> count map for a verifiable citation Jev could
    not settle). Never raises on a per-citation failure -- one bad reading
    never costs the rest of the spec."""
    sources = [_load_source(s) for s in spec["sources"]]
    cites = [prove_it.Citation(id=str(c["id"]), claim=c["claim"], source_id=c["source_id"], quote=c["quote"])
             for c in spec["citations"]]
    prove_it.verify_all(cites, sources)
    by_id = {s.id: s for s in sources}
    report = {"attested": 0, "flagged": 0, "not_found": 0, "no_reading": {}}
    for cite_dict, c in zip(spec["citations"], cites):
        if c.status not in (prove_it.STATUS_VERIFIED, prove_it.STATUS_FUZZY):
            report["not_found"] += 1
            continue
        reading, why = support_reading(c.claim, _window(c, by_id), model=model, key=key, send=send)
        if reading is None:
            report["no_reading"][why] = report["no_reading"].get(why, 0) + 1
            continue
        cite_dict["support_attestation"] = reading.to_dict()
        report["attested"] += 1
        report["flagged"] += int(reading.needs_review)
    return report


def _write(spec: dict, out_path: Optional[str]) -> None:
    text = json.dumps(spec, indent=2, ensure_ascii=False) + "\n"
    if out_path:
        Path(out_path).expanduser().write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)


def _summarise(report: dict, total: int, *, file) -> None:
    verifiable = total - report["not_found"]
    print(f"byok_attest: {report['attested']} of {verifiable} verifiable citation(s) attested "
          f"({report['flagged']} flagged for review); {report['not_found']} quote(s) not found "
          "in their source (no reading attempted)", file=file)
    for why, n in sorted(report["no_reading"].items()):
        print(f"  {n} verifiable citation(s) not attested: {why}", file=file)


def _parse_args(argv: Optional[list]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Attach bring-your-own-key TypeSafe/Jev support attestations to a prove-it spec.")
    ap.add_argument("--input", required=True, help="the prove-it spec JSON (grasp.prove_it.render format)")
    ap.add_argument("--out", help="write the enriched spec JSON here; default stdout")
    ap.add_argument("--model", default=DEFAULT_MODEL, help=f"the decision model id (default {DEFAULT_MODEL!r})")
    return ap.parse_args(argv)


def main(argv: Optional[list] = None) -> int:
    ns = _parse_args(argv)
    key = os.environ.get("TYPESAFE_API_KEY", "").strip()
    if not key:
        print("TYPESAFE_API_KEY is not set in the environment -- no key, no send.", file=sys.stderr)
        return 2
    try:
        spec = json.loads(Path(ns.input).expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"could not read {ns.input}: {exc}", file=sys.stderr)
        return 2
    report = attest_spec(spec, model=ns.model, key=key)
    _write(spec, ns.out)
    _summarise(report, len(spec.get("citations", [])), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
