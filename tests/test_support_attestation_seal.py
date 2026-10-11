# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Tests for sealing support attestations into a receipt's signed decision record.

A support attestation is a caller's machine reading. GRASP seals it into the
IDR leaf that ``grasp.provenance.record_proveit_provenance`` signs for a receipt
(as ``decision.support_attestations_sha256``), and
``grasp.legal_receipt.verify_receipt`` re-checks a receipt against that leaf,
offline.

The files in ``tests/fixtures/support_attestation/`` were made by GRASP at
commit 7e2e62f, before attestations existed, with this suite's test signing
key: the spec, the receipt it produced, and the signed ledger line. They prove
that an old receipt still verifies, and that a new receipt without readings is
the same as before.

Each test names the mutation that turns it red. Every mutation was applied once
to the saved bytes of its target file, the test was seen to fail, and the file
was restored byte for byte.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

import grasp.idr as idr_mod
import grasp.legal_receipt as lr
import grasp.provenance as pvp
from grasp import prove_it as pi

FIXTURES = Path(__file__).parent / "fixtures" / "support_attestation"
REPO_ROOT = Path(__file__).resolve().parent.parent
QUESTION = hashlib.sha256(b"Does the quote support the claim? (fictional test question)").hexdigest()
FABRICATED = "the limitation period is twenty years"  # not in the fixture source

READING = {
    "provider": "typesafe",
    "model": "jev-1.13.0",
    "question_sha256": QUESTION,
    "verdict": "supports",
    "probabilities": {"supports": 0.93, "contradicts": 0.04, "says_nothing": 0.03},
    "calibrated": True,
    "machine_reading": True,
    "precision_ref": "unmeasured",
}


def _spec() -> dict:
    return json.loads((FIXTURES / "spec.json").read_text(encoding="utf-8"))


def _attested_spec(reading: dict | None = None) -> dict:
    spec = _spec()
    spec["citations"][0]["support_attestation"] = copy.deepcopy(reading or READING)
    return spec


def _ledgers(tmp_path: Path) -> dict:
    return {"path": tmp_path / "context.jsonl", "idr_path": tmp_path / "idr.jsonl",
            "head_pointer": tmp_path / "HEAD"}


def _as_written(receipt: dict) -> dict:
    """The receipt after a round trip through the JSON form the CLI writes."""
    return json.loads(json.dumps(receipt, indent=2, ensure_ascii=False) + "\n")


def _sealed(tmp_path: Path, spec: dict) -> dict:
    receipt, _html = lr.build_legal_receipt(spec, **_ledgers(tmp_path))
    assert receipt["chain"]["recorded"] is True
    return _as_written(receipt)


def _verify(receipt: dict, tmp_path: Path) -> dict:
    return lr.verify_receipt(receipt, idr_path=tmp_path / "idr.jsonl")


def _ledger_line(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "idr.jsonl").read_text(encoding="utf-8").strip())


def _rewrite_ledger(tmp_path: Path, line: dict) -> None:
    (tmp_path / "idr.jsonl").write_text(json.dumps(line) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# A sealed reading verifies, and every edit to it is caught
# ---------------------------------------------------------------------------

def test_receipt_with_attestation_verifies_offline(tmp_path, monkeypatch):
    """A sealed receipt carrying a reading re-checks with no network at all, after a
    round trip through the receipt's JSON, and its signed record commits to the reading.

    Mutation: the verifier rebuilds the sealed decision without the receipt's
    readings, so an honest attested receipt no longer matches its record.
    """
    receipt = _sealed(tmp_path, _attested_spec())
    assert receipt["citations"][0]["support_attestation"] == READING
    assert "support_attestation" not in receipt["citations"][1]
    assert len(_ledger_line(tmp_path)["decision"]["support_attestations_sha256"]) == 64

    def no_network(*_args, **_kwargs):
        raise AssertionError("verification tried to open a network connection")

    monkeypatch.setattr(socket, "socket", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    assert _verify(receipt, tmp_path) == {"ok": True, "problems": []}


EDITS = [
    ("provider", "another-provider"),
    ("model", "jev-1.14.0"),
    ("question_sha256", hashlib.sha256(b"a different fictional question").hexdigest()),
    ("verdict", "contradicts"),
    ("probabilities", {"supports": 0.94, "contradicts": 0.03, "says_nothing": 0.03}),
    ("calibrated", False),
    ("machine_reading", False),
    ("precision_ref", "fictional-corpus@p=0.91"),
]


@pytest.mark.parametrize("field, new_value", EDITS, ids=[name for name, _ in EDITS])
def test_editing_any_attestation_field_after_sealing_fails(tmp_path, field, new_value):
    """Every field of a reading is under the seal, so any edit after sealing is caught.

    Mutation: the seal leaves the readings out (``_idr_decision`` no longer adds
    ``support_attestations_sha256``).
    """
    receipt = _sealed(tmp_path, _attested_spec())
    assert _verify(receipt, tmp_path)["ok"] is True  # control: it verified before the edit
    reading = receipt["citations"][0]["support_attestation"]
    assert reading[field] != new_value
    reading[field] = new_value
    result = _verify(receipt, tmp_path)
    assert result["ok"] is False
    assert any("support_attestations_sha256" in p for p in result["problems"])


def _remove(receipt: dict) -> None:
    del receipt["citations"][0]["support_attestation"]


def _move(receipt: dict) -> None:
    receipt["citations"][1]["support_attestation"] = receipt["citations"][0].pop("support_attestation")


def _add(receipt: dict) -> None:
    receipt["citations"][1]["support_attestation"] = copy.deepcopy(READING)


@pytest.mark.parametrize("change", [_remove, _move, _add], ids=["remove", "move", "add"])
def test_removing_moving_or_adding_a_reading_after_sealing_fails(tmp_path, change):
    """Each reading is sealed beside its citation id, so it cannot be dropped, given
    to another citation, or joined by a new one.

    Mutation: the digest leaves out the citation ids.
    """
    receipt = _sealed(tmp_path, _attested_spec())
    change(receipt)
    result = _verify(receipt, tmp_path)
    assert result["ok"] is False
    assert any("support_attestations_sha256" in p for p in result["problems"])


def test_rewriting_the_sealed_record_without_the_key_fails(tmp_path):
    """Someone without the signing key edits the reading AND rewrites the ledger
    record to match it. The record's signature no longer holds, so verification
    still fails.

    Mutation: the verifier stops checking signatures (``_signature_problems``
    returns no problem).
    """
    receipt = _sealed(tmp_path, _attested_spec())
    receipt["citations"][0]["support_attestation"]["verdict"] = "contradicts"
    line = _ledger_line(tmp_path)
    line["decision"]["support_attestations_sha256"] = pvp._attestations_digest(receipt["citations"])
    _rewrite_ledger(tmp_path, line)
    receipt["chain"]["idr_addr"] = idr_mod.content_addr(line)
    result = _verify(receipt, tmp_path)
    assert result["ok"] is False
    assert not any("these differ" in p for p in result["problems"])  # the body now matches...
    assert any("signature does not match" in p for p in result["problems"])  # ...the signature does not


def test_signature_that_cannot_be_checked_does_not_verify(tmp_path):
    """A record whose signature this machine cannot check is unverified, never verified.

    Mutation: ``_signature_problems`` accepts a record it could not check.
    """
    receipt = _sealed(tmp_path, _attested_spec())
    line = _ledger_line(tmp_path)
    line["audit"] = {"scheme": "ed25519", "key_fingerprint": "0" * 16, "signature": "00" * 64}
    _rewrite_ledger(tmp_path, line)  # the audit block is outside the address, so it is still found
    result = _verify(receipt, tmp_path)
    assert result["ok"] is False
    assert any("could not be checked" in p for p in result["problems"])


def test_unsealed_receipt_does_not_verify(tmp_path):
    """A preview built with ``record=False`` signs nothing, so its reading is unverified.

    Mutation: the never-sealed branch of ``verify_receipt`` reports no problem.
    """
    receipt, _html = lr.build_legal_receipt(_attested_spec(), record=False)
    result = lr.verify_receipt(_as_written(receipt), idr_path=tmp_path / "idr.jsonl")
    assert result["ok"] is False
    assert any("never sealed" in p for p in result["problems"])


def test_receipt_naming_a_missing_record_does_not_verify(tmp_path):
    """Mutation: ``verify_proveit_provenance`` reports no problem when the ledger
    holds no record at the receipt's address."""
    receipt = _sealed(tmp_path, _attested_spec())
    result = lr.verify_receipt(receipt, idr_path=tmp_path / "another-ledger.jsonl")
    assert result["ok"] is False
    assert any("no signed decision record" in p for p in result["problems"])


def test_attested_receipt_says_how_its_readings_are_sealed(tmp_path):
    """Mutation: ``_verify_howto`` never adds the step about readings."""
    receipt = _sealed(tmp_path, _attested_spec())
    assert receipt["verify_howto"][:-1] == lr._VERIFY_HOWTO
    assert "support_attestations_sha256" in receipt["verify_howto"][-1]


# ---------------------------------------------------------------------------
# Red stays red
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("verdict", ["supports", "contradicts", "says_nothing"])
def test_red_citation_stays_red_whatever_its_attestation_says(tmp_path, verdict):
    """A quote that is not in its source stays not_found, the receipt still says do
    not file, and that honest receipt still verifies.

    Mutation: ``render`` lets a "supports" reading lift a citation's status to
    verified after ``verify_all`` has run.
    """
    spec = _attested_spec({**READING, "verdict": verdict, "probabilities": {verdict: 0.99}})
    spec["citations"][0]["quote"] = FABRICATED
    receipt = _sealed(tmp_path, spec)
    first = receipt["citations"][0]
    assert first["status"] == pi.STATUS_NOT_FOUND
    assert first["support_attestation"]["verdict"] == verdict
    assert receipt["tally"][pi.STATUS_NOT_FOUND] == 1
    assert receipt["filed_safe"] is False
    assert "never file a red" in receipt["filed_safe_reason"]
    assert _verify(receipt, tmp_path) == {"ok": True, "problems": []}


def test_red_receipt_marked_safe_to_file_fails(tmp_path):
    """Mutation: ``verify_receipt`` stops working ``filed_safe`` out again from the
    citations."""
    spec = _attested_spec()
    spec["citations"][0]["quote"] = FABRICATED
    receipt = _sealed(tmp_path, spec)
    receipt["filed_safe"] = True
    result = _verify(receipt, tmp_path)
    assert result["ok"] is False
    assert any("never file a red" in p.lower() for p in result["problems"])


def test_status_changed_without_its_tally_fails(tmp_path):
    """Turning a red citation green in the receipt, without touching the sealed
    tally, is caught.

    Mutation: ``verify_receipt`` skips ``_tally_problems``.
    """
    spec = _attested_spec()
    spec["citations"][0]["quote"] = FABRICATED
    receipt = _sealed(tmp_path, spec)
    receipt["citations"][0]["status"] = pi.STATUS_VERIFIED
    result = _verify(receipt, tmp_path)
    assert result["ok"] is False
    assert any("does not count" in p for p in result["problems"])


# ---------------------------------------------------------------------------
# A receipt without readings is unchanged
# ---------------------------------------------------------------------------

def _old_receipt() -> dict:
    return json.loads((FIXTURES / "pre-attestation-receipt.json").read_text(encoding="utf-8"))


def _stable_text(receipt: dict) -> str:
    """The receipt as written, less what differs on every run: its creation time and
    the ids of the two records it names (the ledger records are compared on their own)."""
    out = copy.deepcopy(receipt)
    out.pop("created_utc")
    out["chain"].pop("idr_addr")
    out["chain"].pop("memory_head")
    return json.dumps(out, indent=2, ensure_ascii=False)


def test_old_receipt_without_attestation_still_verifies():
    """A receipt made before attestations existed verifies against its own ledger line.

    Mutation: the seal always carries a readings digest, even an empty one (the
    ``if digest:`` guard in ``_idr_decision`` always passes).
    """
    result = lr.verify_receipt(_old_receipt(), idr_path=FIXTURES / "pre-attestation-idr.jsonl")
    assert result == {"ok": True, "problems": []}


def test_new_receipt_without_attestation_is_unchanged(tmp_path):
    """The same spec, with no reading, writes the same receipt and seals the same
    decision as GRASP did before attestations existed.

    Mutation: ``provenance()`` writes a ``support_attestation`` key on every
    citation, as None when there is no reading.
    """
    old = _old_receipt()
    new, _html = lr.build_legal_receipt(_spec(), matter=old["matter"],
                                        jurisdiction=old["jurisdiction"], **_ledgers(tmp_path))
    assert _stable_text(_as_written(new)) == _stable_text(old)
    old_leaf = idr_mod.read_idr_chain(path=FIXTURES / "pre-attestation-idr.jsonl")[0]
    new_leaf = idr_mod.read_idr_chain(path=tmp_path / "idr.jsonl")[0]
    assert (new_leaf.kind, new_leaf.fingerprint, new_leaf.decision, new_leaf.inputs) == \
        (old_leaf.kind, old_leaf.fingerprint, old_leaf.decision, old_leaf.inputs)
    assert _verify(_as_written(new), tmp_path) == {"ok": True, "problems": []}


# ---------------------------------------------------------------------------
# The verify path never touches a model provider
# ---------------------------------------------------------------------------

PROVIDER_MODULES = ("openai", "anthropic", "typesafe", "google.genai", "httpx", "requests")

_CHILD = r"""
import importlib.util, json, sys
from pathlib import Path
from grasp.legal_receipt import verify_receipt
receipt = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
result = verify_receipt(receipt, idr_path=Path(sys.argv[2]))
names = json.loads(sys.argv[3])
loaded = sorted(m for m in sys.modules for n in names if m == n or m.startswith(n + "."))
findable = all(importlib.util.find_spec(n) is not None for n in names)
print(json.dumps({"ok": result["ok"], "loaded": loaded, "findable": findable}))
"""


def _plant_provider_stand_ins(root: Path) -> None:
    """An importable, empty stand-in for each provider package. With these on the
    path, an import of any of them, even one wrapped in ``try/except ImportError``,
    would succeed and show up in ``sys.modules``."""
    for name in PROVIDER_MODULES:
        package = root.joinpath(*name.split("."))
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_text("", encoding="utf-8")


def test_verify_path_imports_no_provider_code(tmp_path):
    """Verifying a sealed receipt never imports a model provider's code.

    Mutation: ``grasp/legal_receipt.py`` gains a guarded ``import typesafe``.
    """
    receipt = _sealed(tmp_path, _attested_spec())
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
    stand_ins = tmp_path / "stand-ins"
    _plant_provider_stand_ins(stand_ins)
    env = {**os.environ, "PYTHONPATH": os.pathsep.join([str(stand_ins), str(REPO_ROOT)])}
    proc = subprocess.run(
        [sys.executable, "-c", _CHILD, str(receipt_path), str(tmp_path / "idr.jsonl"),
         json.dumps(PROVIDER_MODULES)],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout.strip().splitlines()[-1])
    assert report["findable"] is True  # the stand-ins really were importable
    assert report["ok"] is True        # and the verification really ran
    assert report["loaded"] == []
