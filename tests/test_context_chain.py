# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""Context memory-chain write/read/verify tests + import-isolation lints.

Goodhart-proof: ``verify`` returns BROKEN on a tampered delta (not just on a
broken-by-construction input); round-trip asserts content; the lint asserts
the verify path imports no model/LLM package — a compile-time fact.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path

import pytest

import grasp.context_chain as cc
import grasp.context_head as ch
from grasp.verdict import Verdict
from grasp.context_chain import (
    append_context,
    blob_path,
    chain_head_stamp,
    chain_path,
    context_addr,
    read_context_chain,
    resolve_citation,
    stamp_view_header,
    verify_context_chain,
)
from grasp.context_head import head_path, read_head, read_latest, write_head
from grasp.idr import append_idr, build_idr, content_addr
from dataclasses import asdict

_PKG = Path(cc.__file__).resolve().parent


@pytest.fixture
def chain(tmp_path):
    return tmp_path / "context.jsonl"


@pytest.fixture
def head(tmp_path):
    return tmp_path / "context-HEAD.txt"


def _append(chain, head, decision, **kw):
    return append_context(decision, fingerprint="f" * 64, path=chain, head_pointer=head, **kw)


# ---------- write / read round-trip --------------------------------------

def test_append_then_read_round_trip(chain, head):
    d1 = _append(chain, head, {"learned": "X"})
    nodes = read_context_chain(head=d1.id, path=chain)
    assert [n.id for n in nodes] == [d1.id]
    assert nodes[0].decision == {"learned": "X"}
    assert read_head(head) == d1.id


def test_chain_links_and_depths(chain, head):
    d1 = _append(chain, head, {"a": 1})
    d2 = _append(chain, head, {"a": 2})
    d3 = _append(chain, head, {"a": 3})
    nodes = read_context_chain(head=read_head(head), path=chain)
    assert [n.id for n in nodes] == [d1.id, d2.id, d3.id]  # root→leaf
    assert [n.depth for n in nodes] == [0, 1, 2]
    assert d2.predecessor_idr == d1.id
    assert d3.predecessor_idr == d2.id


def test_genesis_links_to_exogenous_anchor(chain, head):
    d1 = _append(chain, head, {"a": 1})
    assert d1.predecessor_idr == "council:context-chain-genesis"


def test_head_atomic_swap(head):
    write_head("precog-AAA", head)
    assert read_head(head) == "precog-AAA"
    write_head("precog-BBB", head)
    assert read_head(head) == "precog-BBB"  # replaced in place, not appended


def test_read_latest_returns_leaf(chain, head):
    _append(chain, head, {"a": 1})
    d2 = _append(chain, head, {"a": 2})
    latest = read_latest(chain_path=chain, head_pointer=head)
    assert latest is not None and latest.id == d2.id


def test_empty_chain_reads_empty_and_verifies(chain, head):
    assert read_context_chain(head=None, path=chain) == []
    assert verify_context_chain(path=chain, head=None) is Verdict.VERIFIED  # vacuous


# ---------- verify (the integrity anchor) --------------------------------

def test_verify_clean_chain_is_verified(chain, head):
    _append(chain, head, {"a": 1})
    _append(chain, head, {"a": 2})
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.VERIFIED


def test_verify_broken_on_tampered_delta(chain, head):
    """THE Goodhart anchor: flip a byte in a delta's signed body → verify BROKEN.
    Mutation killed: skipping per-node signature verification."""
    _append(chain, head, {"a": 1})
    _append(chain, head, {"secret": "original"})
    rows = [json.loads(ln) for ln in chain.read_text().splitlines() if ln.strip()]
    rows[1]["decision"] = {"secret": "TAMPERED"}  # leaves the stale signature behind
    chain.write_text("\n".join(json.dumps(r, separators=(",", ":")) for r in rows) + "\n")
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.BROKEN


# ---------- content address ----------------------------------------------

def test_context_addr_excludes_id_ts(tmp_path):
    """Two genesis deltas with identical decision + fingerprint but different
    random id/ts share ONE content address (id/ts excluded — the dedup coord)."""
    d1 = append_context({"a": 1}, fingerprint="f" * 64,
                        path=tmp_path / "c1.jsonl", head_pointer=tmp_path / "h1.txt")
    d2 = append_context({"a": 1}, fingerprint="f" * 64,
                        path=tmp_path / "c2.jsonl", head_pointer=tmp_path / "h2.txt")
    assert d1.id != d2.id  # different random suffix
    assert context_addr(d1).startswith("sha256:")
    assert context_addr(d1) == context_addr(d2)


# ---------- IDR <-> context-chain cross-reference citation ----------------

@pytest.fixture
def ledger(tmp_path):
    return tmp_path / "idr.jsonl"


def _record_decision_idr(ledger, decision):
    """Sign + append a decision-IDR into the ledger; return its content_addr —
    the coordinate a context delta cites via ``records_idr``."""
    idr = build_idr(prompt="", fingerprint="d" * 64, decision=decision,
                    predecessor_idr=None, depth=0, kind="precog-decision")
    append_idr(idr, path=ledger)
    return content_addr(asdict(idr))


def test_uncited_delta_content_addr_byte_identical(tmp_path):
    """Back-compat: an uncited delta addresses EXACTLY as an explicit
    ``records_idr=None`` one — no key enters the body when the citation is
    omitted."""
    base = append_context({"a": 1}, fingerprint="f" * 64,
                          path=tmp_path / "c1.jsonl", head_pointer=tmp_path / "h1.txt")
    none_cite = append_context({"a": 1}, fingerprint="f" * 64, records_idr=None,
                               path=tmp_path / "c2.jsonl", head_pointer=tmp_path / "h2.txt")
    assert "records_idr" not in base.decision
    assert context_addr(base) == context_addr(none_cite)


def test_citation_does_not_mutate_caller_decision(chain, head, ledger):
    """Copy-on-cite: the caller's dict is never mutated by the citation fold."""
    addr = _record_decision_idr(ledger, {"choice": "x"})
    caller = {"learned": "Y"}
    _append(chain, head, caller, records_idr=addr)
    assert caller == {"learned": "Y"}  # untouched


def test_resolved_citation_when_decision_idr_present(chain, head, ledger):
    addr = _record_decision_idr(ledger, {"choice": "x"})
    d = _append(chain, head, {"learned": "Y"}, records_idr=addr)
    assert d.decision["records_idr"] == addr
    assert resolve_citation(d, idr_path=ledger) == "RESOLVED"


def test_uncited_delta_resolves_vacuously(chain, head, ledger):
    """No citation → vacuously RESOLVED (nothing to dangle)."""
    d = _append(chain, head, {"learned": "Y"})
    assert resolve_citation(d, idr_path=ledger) == "RESOLVED"


def test_verify_broken_on_tampered_records_idr(chain, head, ledger):
    """Goodhart anchor #1: the citation is INSIDE the signed body — flip a byte
    of ``records_idr`` and ``verify_context_chain`` returns BROKEN. Mutation
    killed: moving the citation outside the signed envelope."""
    addr = _record_decision_idr(ledger, {"choice": "x"})
    _append(chain, head, {"a": 1})
    _append(chain, head, {"learned": "Y"}, records_idr=addr)
    rows = [json.loads(ln) for ln in chain.read_text().splitlines() if ln.strip()]
    rows[1]["decision"]["records_idr"] = "sha256:" + "0" * 64  # stale signature
    chain.write_text("\n".join(json.dumps(r, separators=(",", ":")) for r in rows) + "\n")
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.BROKEN


def test_dangling_citation_does_not_break_chain(chain, head, ledger):
    """Goodhart anchor #2: a citation to an ABSENT content_addr is DANGLING, yet
    the chain stays VERIFIED — the cross-reference axis is independent of the
    signed temporal spine (predecessor_idr). Mutation killed: conflating a
    dangling cross-ref with signature corruption."""
    absent = "sha256:" + "a" * 64  # never written to the ledger
    _append(chain, head, {"a": 1})
    d = _append(chain, head, {"learned": "Y"}, records_idr=absent)
    assert resolve_citation(d, idr_path=ledger) == "DANGLING"
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.VERIFIED


# ---------- axis (b): blob-presence ---------------------------------------

def _write_blob(chain: Path, payload: bytes) -> str:
    """Write a kernel blob into the chain's content-addressed ``blobs/`` store and
    return its address (SHA-256 hex of the bytes — the same hash axis (b) checks)."""
    addr = hashlib.sha256(payload).hexdigest()
    p = blob_path(addr, path=chain)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(payload)
    return addr


def _blob_backed_snapshot(chain, head, payload: bytes = b"kernel-text-v1"):
    """Append a delta then a BLOB-BACKED ``context-snapshot`` (decision carries a
    real ``kernel_blob_addr``) with its matching blob on disk. Returns the addr."""
    _append(chain, head, {"a": 1})
    addr = _write_blob(chain, payload)
    _append(chain, head, {"kernel_blob_addr": addr, "folded_nodes": 1},
            kind="context-snapshot")
    return addr


def test_blob_verified_when_referenced_blob_present(chain, head):
    """No false-positive: a blob-backed snapshot whose blob is present-and-intact
    verifies (axis (b) does not break a sound chain)."""
    _blob_backed_snapshot(chain, head)
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.VERIFIED


def test_blob_broken_when_referenced_blob_deleted(chain, head):
    """THE blob anchor: delete a live-referenced snapshot blob → verify returns
    BROKEN (was VERIFIED with the blob present). Mutation killed: removing the
    blob-presence check (verify would stay VERIFIED on the gone blob —
    VERIFIED-but-rehydrates-nothing, the exact silent failure)."""
    addr = _blob_backed_snapshot(chain, head)
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.VERIFIED
    blob_path(addr, path=chain).unlink()  # a reaper/disk-cleanup deletes it
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.BROKEN


def test_blob_broken_when_referenced_blob_corrupted(chain, head):
    """Axis (b) checks CONTENT, not just existence: a present blob whose bytes no
    longer hash to the recorded address → BROKEN. Mutation killed: a presence
    check that asserts ``exists()`` but never re-hashes the bytes."""
    addr = _blob_backed_snapshot(chain, head)
    blob_path(addr, path=chain).write_bytes(b"corrupted-bytes")  # addr no longer matches
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.BROKEN


def test_blob_inert_snapshot_without_blob_ref_stays_verified(chain, head):
    """INERT proof: a ``context-snapshot`` WITHOUT a ``kernel_blob_addr`` is not
    blob-backed → axis (b) skips it → VERIFIED unchanged. Mutation killed:
    checking blob-presence unconditionally (which would flip every legacy chain
    BROKEN — the regression the INERT invariant forbids)."""
    _append(chain, head, {"a": 1})
    _append(chain, head, {"kernel_sha256": "deadbeef", "folded_nodes": 1},
            kind="context-snapshot")  # legacy shape: digest only, no blob ref
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.VERIFIED


def test_blob_plain_delta_chain_unaffected(chain, head):
    """Axis (b) never touches a chain with no snapshot node — a delta-only chain
    verifies exactly as before."""
    _append(chain, head, {"a": 1})
    _append(chain, head, {"a": 2})
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.VERIFIED


def test_blob_spine_tamper_still_dominates_with_blob_present(chain, head):
    """Axis (a) is unchanged and still bites: a blob-backed snapshot with its blob
    intact is STILL BROKEN if a delta's signed body is tampered. Proves axis (b)
    EXTENDS — never replaces — the HMAC path."""
    _blob_backed_snapshot(chain, head)
    rows = [json.loads(ln) for ln in chain.read_text().splitlines() if ln.strip()]
    rows[0]["decision"] = {"a": 999}  # tamper the first delta, leave stale signature
    chain.write_text("\n".join(json.dumps(r, separators=(",", ":")) for r in rows) + "\n")
    assert verify_context_chain(path=chain, head=read_head(head)) is Verdict.BROKEN


def test_blob_path_is_content_addressed_sibling_not_session_scoped(chain):
    """``blob_path`` resolves under the chain file's ``blobs/`` sibling and is keyed
    purely by the byte-address (no session prefix in the blob filename)."""
    p = blob_path("abc123", path=chain)
    assert p == chain.parent / "blobs" / "abc123"
    assert p.name == "abc123"  # content address verbatim, never namespaced


# ---------- write-side freshness stamp ------------------------------------

def test_stamp_is_first_line_and_well_formed():
    out = stamp_view_header("# Title\nbody\n", "precog-XYZ", ts="2026-06-23T00:00:00Z")
    first = out.splitlines()[0]
    assert first == "<!-- chain-HEAD: precog-XYZ · folded-at: 2026-06-23T00:00:00Z -->"
    assert out.endswith("# Title\nbody\n")  # body preserved verbatim below the stamp


def test_stamp_is_idempotent_replaces_never_accretes():
    """Re-stamping replaces the prior stamp (one line, latest HEAD) — never stacks
    copies. Mutation killed: appending instead of replacing the stamp."""
    once = stamp_view_header("body\n", "A", ts="2026-06-23T00:00:00Z")
    twice = stamp_view_header(once, "B", ts="2026-06-23T01:00:00Z")
    stamps = [ln for ln in twice.splitlines() if ln.startswith("<!-- chain-HEAD:")]
    assert len(stamps) == 1
    assert stamps[0] == chain_head_stamp("B", "2026-06-23T01:00:00Z")
    assert twice.endswith("body\n")


# ---------- import-isolation lint ------------------------------------------

def _imported_modules(module_file: str) -> set[str]:
    tree = ast.parse((_PKG / module_file).read_text(encoding="utf-8"))
    mods: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            mods.add(node.module)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                mods.add(alias.name)
    return mods


def test_verify_path_imports_no_model_or_llm():
    """'No model on the crypto verify path' as a compile-time fact: the
    verify-path modules import no LLM provider package."""
    forbidden = {"hal", "llm", "anthropic", "openai", "gemini", "litellm", "groq"}
    for mod in ("context_chain.py", "context_head.py", "idr_forest.py", "idr.py"):
        for imported in _imported_modules(mod):
            segments = set(imported.lower().split("."))
            assert not (segments & forbidden), f"{mod} imports forbidden module {imported!r}"


# ---------- per-session chain/HEAD namespacing ------------------------------


def _set_base(monkeypatch, tmp_path):
    """Point the chain + HEAD default-path resolvers at a tmp dir so the
    session-suffix is computed off a deterministic base. Returns the
    (chain_base, head_base) the resolvers derive from."""
    chain_base = tmp_path / "context.jsonl"
    head_base = tmp_path / "context-HEAD.txt"
    monkeypatch.setattr(cc, "_default_chain_path", lambda: chain_base)
    monkeypatch.setattr(ch, "_default_head_path", lambda: head_base)
    return chain_base, head_base


def test_two_sessions_get_independent_non_interleaving_chains(tmp_path, monkeypatch):
    """The namespacing Goodhart anchor: two DISTINCT ``GRASP_SESSION_ID``s drive
    two INDEPENDENT chains+HEADs. Each session appends through the default-path
    resolvers (no explicit path), and neither sees the other's node — so a revert
    to a single shared default braids them into one chain and FAILS this test."""
    _set_base(monkeypatch, tmp_path)

    from grasp.context_head import _session_prefix

    monkeypatch.setenv("GRASP_SESSION_ID", "session-aaa")
    a = append_context({"x": "from-A"}, fingerprint="fa",
                       path=chain_path(), head_pointer=head_path())
    a_chain, a_head = chain_path(), head_path()
    pa = _session_prefix("session-aaa")

    monkeypatch.setenv("GRASP_SESSION_ID", "session-bbb")
    b = append_context({"x": "from-B"}, fingerprint="fb",
                       path=chain_path(), head_pointer=head_path())
    b_chain, b_head = chain_path(), head_path()
    pb = _session_prefix("session-bbb")

    # Distinct files per session (the namespacing itself).
    assert a_chain != b_chain and a_head != b_head
    assert pa != pb
    assert a_chain.name == f"context-{pa}.jsonl"
    assert b_chain.name == f"context-{pb}.jsonl"
    assert a_head.name == f"context-HEAD-{pa}.txt"

    # Non-interleaving: each chain holds ONLY its own session's single node.
    nodes_a = read_context_chain(head=read_head(a_head), path=a_chain)
    nodes_b = read_context_chain(head=read_head(b_head), path=b_chain)
    assert len(nodes_a) == 1 and nodes_a[0].id == a.id
    assert len(nodes_b) == 1 and nodes_b[0].id == b.id
    assert a.id != b.id
    # B's append did not extend A's HEAD, and vice-versa.
    assert read_head(a_head) == a.id and read_head(b_head) == b.id
    # Both independently verify.
    assert verify_context_chain(path=a_chain, head=read_head(a_head)) is Verdict.VERIFIED
    assert verify_context_chain(path=b_chain, head=read_head(b_head)) is Verdict.VERIFIED


def test_no_session_id_resolves_legacy_path_byte_identical(tmp_path, monkeypatch):
    """Back-compat safety contract: with NO session id the resolvers return the
    base default path UNCHANGED (single-session behaviour) — a suffix here would
    silently migrate every existing single-session chain."""
    chain_base, head_base = _set_base(monkeypatch, tmp_path)
    monkeypatch.delenv("GRASP_SESSION_ID", raising=False)
    assert chain_path() == chain_base
    assert head_path() == head_base


def test_explicit_path_arg_bypasses_session_namespacing(tmp_path, monkeypatch):
    """An explicit path always wins verbatim — session namespacing only ever
    applies to the DEFAULT path (callers pinning a path are unaffected)."""
    _set_base(monkeypatch, tmp_path)
    monkeypatch.setenv("GRASP_SESSION_ID", "session-aaa")
    explicit_c = tmp_path / "explicit.jsonl"
    explicit_h = tmp_path / "explicit-HEAD.txt"
    assert chain_path(explicit_c) == explicit_c
    assert head_path(explicit_h) == explicit_h
