"""Website backend contract: deterministic render, gated publish, no XSS.

Falsifiers: a render-time clock breaks byte-identical idempotence; a
``put``/``anchor`` that auto-publishes violates the operator gate; an
unescaped record id is stored XSS on a public page; a publish without a
configured command must be a refusal, not a crash.
"""
from __future__ import annotations

import subprocess

import pytest

from grasp.storage import adapter_names, get_adapter
from grasp.storage.website import WebsiteAdapter


def test_registry_now_carries_all_six():
    assert set(adapter_names()) == {
        "local", "bitcoin-ots", "s3", "sepolia", "ipfs", "website"}
    assert isinstance(get_adapter("website"), WebsiteAdapter)


def test_put_updates_site_and_round_trips(tmp_path):
    adapter = WebsiteAdapter(site_dir=tmp_path)
    adapter.put("sha256:rec1", b"blob-bytes")
    page = (tmp_path / "index.html").read_text()
    assert "sha256:rec1" in page and "1 record(s)" in page
    assert adapter.get("sha256:rec1") == b"blob-bytes"


def test_anchor_lists_root_and_ethos_footer(tmp_path):
    adapter = WebsiteAdapter(site_dir=tmp_path)
    locator = adapter.anchor("deadbeef" * 8)
    assert locator.endswith("#anchor-1")
    page = (tmp_path / "index.html").read_text()
    assert "deadbeef" in page
    assert "facta, non verba" in page


def test_render_is_deterministic_idempotent(tmp_path):
    adapter = WebsiteAdapter(site_dir=tmp_path)
    adapter.put("sha256:rec1", b"x")
    first = (tmp_path / "index.html").read_bytes()
    adapter.put("sha256:rec1", b"x")  # same state in -> same bytes out
    assert (tmp_path / "index.html").read_bytes() == first


def test_hostile_record_id_renders_escaped(tmp_path):
    adapter = WebsiteAdapter(site_dir=tmp_path)
    adapter.put("<script>alert(1)</script>", b"x")
    page = (tmp_path / "index.html").read_text()
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_put_and_anchor_never_auto_publish(monkeypatch, tmp_path):
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: pytest.fail("auto-publish attempted"))
    adapter = WebsiteAdapter(site_dir=tmp_path, publish_cmd="fake-push")
    adapter.put("sha256:rec1", b"x")
    adapter.anchor("ab" * 32)  # neither call may touch the publish command


def test_publish_refuses_without_command(tmp_path):
    assert WebsiteAdapter(site_dir=tmp_path).publish() is None


def test_publish_runs_configured_command_with_site_dir(monkeypatch, tmp_path):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("grasp.storage.website.subprocess.run", fake_run)
    result = WebsiteAdapter(site_dir=tmp_path, publish_cmd="site-push --safe").publish()
    assert result == str(tmp_path)
    assert seen["argv"][0] == "site-push" and seen["argv"][-1] == str(tmp_path)


def test_probe_ready_names_publish_posture(tmp_path):
    bare = WebsiteAdapter(site_dir=tmp_path).probe()
    assert bare.ready and "local only" in bare.detail
    gated = WebsiteAdapter(site_dir=tmp_path, publish_cmd="site-push").probe()
    assert gated.ready and "operator-gated" in gated.detail
