"""Storage-backend contract: honest registry, safe local persistence.

Falsifiers each test enforces: a registry naming an unbuilt backend breaks
the feature-complete promise; a hostile record id escaping the storage root
is a path traversal; two ids colliding on one filename silently overwrite
records; a probe that cannot report not-ready makes the wizard's live
picker theatre.
"""
from __future__ import annotations

import json

import pytest

from grasp.storage import ProbeResult, StorageAdapter, adapter_names, get_adapter, probe_all
from grasp.storage.local import LocalAdapter, _filename


def test_registry_names_only_built_backends():
    names = adapter_names()
    assert "local" in names
    for name in names:  # every registered name constructs + satisfies the contract
        adapter = get_adapter(name)
        assert isinstance(adapter, StorageAdapter)


def test_unknown_backend_fails_with_full_menu():
    with pytest.raises(ValueError) as err:
        get_adapter("carrier-pigeon")
    assert "carrier-pigeon" in str(err.value)
    assert "local" in str(err.value)  # the menu travels with the error


def test_put_get_round_trip(tmp_path):
    adapter = LocalAdapter(root=tmp_path)
    locator = adapter.put("sha256:abc123", b"\x00\x01provenance")
    assert locator.startswith("file://")
    assert adapter.get("sha256:abc123") == b"\x00\x01provenance"


def test_get_missing_returns_none(tmp_path):
    assert LocalAdapter(root=tmp_path).get("sha256:missing") is None


def test_hostile_record_ids_stay_inside_root(tmp_path):
    adapter = LocalAdapter(root=tmp_path)
    adapter.put("../../etc/passwd", b"nope")
    escaped = tmp_path.parent / "etc" / "passwd"
    assert not escaped.exists()
    assert all(p == tmp_path or tmp_path in p.parents
               for p in tmp_path.rglob("*"))


def test_ids_with_same_slug_do_not_collide():
    assert _filename("a:b") != _filename("a/b")  # digest suffix disambiguates


def test_anchor_appends_locatable_ledger_lines(tmp_path):
    adapter = LocalAdapter(root=tmp_path)
    first = adapter.anchor("deadbeef" * 8)
    second = adapter.anchor("cafef00d" * 8)
    assert first.endswith("#L1") and second.endswith("#L2")
    lines = (tmp_path / "anchors.jsonl").read_text().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["root"] == "deadbeef" * 8
    assert "ts" in json.loads(lines[1])


def test_probe_ready_in_writable_root(tmp_path):
    result = LocalAdapter(root=tmp_path).probe()
    assert result == ProbeResult(name="local", ready=True, detail=result.detail)
    assert result.ready and result.remedy is None


def test_probe_reports_not_ready_with_remedy(tmp_path):
    blocker = tmp_path / "blocker"
    blocker.write_bytes(b"a file where a dir must go")
    result = LocalAdapter(root=blocker / "storage").probe()
    assert not result.ready
    assert result.remedy  # the picker shows the one-line fix


def test_probe_all_covers_every_registered_backend(monkeypatch, tmp_path):
    monkeypatch.setenv("GRASP_HOME", str(tmp_path))
    # hermetic: ambient cloud credentials must never make tests network-probe
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "GRASP_S3_BUCKET", "GRASP_S3_ENDPOINT", "GRASP_SEPOLIA_SIGNER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GRASP_IPFS_API", "http://127.0.0.1:1")  # closed port: instant refusal
    results = probe_all()
    assert [r.name for r in results] == list(adapter_names())
    assert all(isinstance(r, ProbeResult) for r in results)
