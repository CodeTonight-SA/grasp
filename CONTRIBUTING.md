# Contributing to GRASP

Thanks for your interest in GRASP. This is a provenance floor: it earns trust
only if the verifier itself is inspectable and every change keeps it honest.
The bar for contributions is therefore correctness and falsifiability, not
volume. Please read this before opening a pull request.

## Running the tests

The test suite is hermetic — it runs against a throwaway `GRASP_HOME` and a
fixed test signing key (set by `tests/conftest.py`), with no external
dependencies and no network. It must pass in a clean, isolated virtualenv:

```bash
python3 -m venv .venv
.venv/bin/pip install -e . pytest
.venv/bin/python -m pytest tests -q
```

Requires Python ≥ 3.10 on a POSIX system (file locking uses `fcntl`). CI runs
this same command on Python 3.10, 3.11, and 3.12 — see
`.github/workflows/ci.yml`. A change is not ready until the suite is green in
isolation on all three.

Do **not** rely on your shell environment to make tests pass. `conftest.py`
sets `GRASP_HOME` and `GRASP_SIGNING_KEY` itself; if a test only passes because
of something already in your environment, that is a bug in the test.

## Licence and file headers

GRASP is licensed **AGPL-3.0-only** (see `LICENSE`). By contributing you agree
that your contribution is licensed under the same terms.

Every new source file (`.py`) MUST begin with the two-line SPDX/copyright
header, byte-for-byte:

```python
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
```

(YAML and Markdown files do not carry the header.)

## Code expectations

- **No stubs.** Every symbol you add is fully implemented. A hollow
  placeholder that names a capability it does not provide is a false-
  completeness signal — a later reader assumes it works and builds on it.
  If something is genuinely out of scope, leave it out and say so; do not ship
  a `raise NotImplementedError("wired later")` or a fake return.
- **Keep the floor deterministic.** The citation floor is arithmetic string
  matching, not judgement. Any LLM-assisted layer (e.g. support-checking on
  `Citation.support`) is a caller-side L2 seam and MUST be fail-open — it may
  only ever move a verdict toward *safe*, never upgrade an unproven record.
- **Verification stays monotone toward safe.** A scheme the verifier cannot
  check is marked `DEGRADED`, never silently upgraded to `VERIFIED`.

## Tests must be mutation-sensitive

A test that cannot fail is worse than no test — it manufactures false
confidence. Every test you add or change must be able to fail when the logic is
wrong:

- Verify actual output values, offsets, and verdicts — not just that a function
  was called.
- A fabricated quote must render `not_found` / red and fail the grounding
  assertion. Mutating the verifier to always-pass must break your test.
- A flipped byte in a signed record, a citation, or a chain link must make
  verification return `BROKEN` / fail. Mutating away a signature check must
  break your test.

If a mutation to the code under test would leave your test green, tighten the
test.

## `cite.verify` and the HAPPI twin

`grasp.cite_verify` is the protocol twin of the `cite.verify` verb of the
[HAPPI](https://happi.md) protocol at version `happi/1.3`. It is pinned
byte-compatible to that specification by a cross-implementation agreement test.

Any change to `grasp.cite_verify` (or to the shared verification ladder beneath
it) MUST keep it **byte-agreeing** with the `happi/1.3` twin. If a change would
diverge from the pinned protocol output, it is a protocol change: it belongs
upstream in HAPPI first, and the agreement test must be updated in lock-step —
never loosened to hide a divergence.

## Pull requests

- Keep changes atomic — one logical change per PR.
- Explain, in plain language, *what the change does and why* before any jargon.
- Confirm `python -m pytest tests -q` is green in a clean virtualenv.
- Do not change library behaviour and tooling in the same PR unless they are
  genuinely one change.
