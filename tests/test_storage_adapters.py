"""Anchor/remote backend contracts: honest runtime-dep detection, no network.

Falsifiers each test enforces: a probe that reports ready without its
runtime dependency makes the wizard's live picker lie; an anchor that
returns a locator when the underlying tool failed fabricates a witness;
an adapter that does not pass the Merkle root to its signer anchors
nothing; a signed S3 request without the SigV4 Authorization shape would
never be accepted by a real endpoint. All tests are hermetic — network
and external binaries are faked at the module seam.
"""
from __future__ import annotations

import hashlib
import hmac as hmac_mod
import io
import json
import subprocess
import urllib.error
import urllib.request

import pytest

from grasp.storage import adapter_names
from grasp.storage.ipfs import IPFSAdapter, _multipart
from grasp.storage.ots import BitcoinOTSAdapter
from grasp.storage.s3 import S3Adapter, derive_signing_key
from grasp.storage.sepolia import SepoliaAdapter

ROOT64 = "ab" * 32


class _Response(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


# ---------------------------------------------------------------- registry

def test_all_five_backends_registered():
    assert set(adapter_names()) == {"local", "bitcoin-ots", "s3", "sepolia", "ipfs"}


# ---------------------------------------------------------------- bitcoin-ots

def test_ots_probe_not_ready_without_client(monkeypatch, tmp_path):
    monkeypatch.setattr("grasp.storage.ots.shutil.which", lambda _: None)
    result = BitcoinOTSAdapter(root=tmp_path).probe()
    assert not result.ready
    assert "opentimestamps" in result.remedy


def test_ots_anchor_none_without_client(monkeypatch, tmp_path):
    monkeypatch.setattr("grasp.storage.ots.shutil.which", lambda _: None)
    assert BitcoinOTSAdapter(root=tmp_path).anchor(ROOT64) is None


def test_ots_anchor_returns_proof_locator(monkeypatch, tmp_path):
    monkeypatch.setattr("grasp.storage.ots.shutil.which", lambda _: "/usr/bin/ots")

    def fake_run(argv, **kwargs):
        assert argv[:2] == ["ots", "stamp"]
        stamped = argv[2]
        with open(stamped + ".ots", "wb") as fh:  # ots writes <file>.ots
            fh.write(b"proof-bytes")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr("grasp.storage.ots.subprocess.run", fake_run)
    locator = BitcoinOTSAdapter(root=tmp_path).anchor(ROOT64)
    assert locator.startswith("file://") and locator.endswith(".txt.ots")


def test_ots_anchor_none_when_stamp_fails(monkeypatch, tmp_path):
    monkeypatch.setattr("grasp.storage.ots.shutil.which", lambda _: "/usr/bin/ots")
    monkeypatch.setattr(
        "grasp.storage.ots.subprocess.run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 1, stdout="", stderr="boom"))
    assert BitcoinOTSAdapter(root=tmp_path).anchor(ROOT64) is None


def test_ots_blobs_round_trip_locally(tmp_path):
    adapter = BitcoinOTSAdapter(root=tmp_path)
    adapter.put("sha256:abc", b"payload")
    assert adapter.get("sha256:abc") == b"payload"


# ---------------------------------------------------------------- s3

def _clear_s3_env(monkeypatch):
    for name in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                 "GRASP_S3_BUCKET", "GRASP_S3_ENDPOINT", "GRASP_S3_REGION"):
        monkeypatch.delenv(name, raising=False)


def test_sigv4_derivation_matches_independent_chain():
    secret, date, region = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "20150830", "us-east-1"
    expected = ("AWS4" + secret).encode()
    for part in (date, region, "s3", "aws4_request"):  # independent re-chain
        expected = hmac_mod.new(expected, part.encode(), hashlib.sha256).digest()
    assert derive_signing_key(secret, date, region) == expected


def test_s3_probe_unconfigured_no_network(monkeypatch):
    _clear_s3_env(monkeypatch)
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("network attempted while unconfigured"))
    result = S3Adapter().probe()
    assert not result.ready and "credentials" in result.detail


def _configure_s3(monkeypatch):
    _clear_s3_env(monkeypatch)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY")
    return S3Adapter(bucket="proofs", region="eu-west-1")


def test_s3_put_sends_sigv4_authorization(monkeypatch):
    adapter = _configure_s3(monkeypatch)
    seen = {}

    def fake_urlopen(request, timeout=0):
        seen["url"] = request.full_url
        seen["auth"] = request.get_header("Authorization")
        return _Response(b"")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    locator = adapter.put("sha256:abc", b"blob")
    assert locator.startswith("https://proofs.s3.eu-west-1.amazonaws.com/records/")
    assert seen["url"] == locator
    auth = seen["auth"]
    assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    assert "/eu-west-1/s3/aws4_request" in auth
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in auth
    signature = auth.rsplit("Signature=", 1)[1]
    assert len(signature) == 64 and set(signature) <= set("0123456789abcdef")


def test_s3_get_missing_returns_none(monkeypatch):
    adapter = _configure_s3(monkeypatch)

    def raise_404(request, timeout=0):
        raise urllib.error.HTTPError(request.full_url, 404, "NoSuchKey", None, None)

    monkeypatch.setattr(urllib.request, "urlopen", raise_404)
    assert adapter.get("sha256:missing") is None


def test_s3_probe_ready_when_signed_round_trip_reaches_endpoint(monkeypatch):
    adapter = _configure_s3(monkeypatch)

    def raise_403(request, timeout=0):  # any HTTP status = the endpoint answered
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", None, None)

    monkeypatch.setattr(urllib.request, "urlopen", raise_403)
    assert adapter.probe().ready


# ---------------------------------------------------------------- sepolia

def test_sepolia_probe_not_ready_without_signer(monkeypatch, tmp_path):
    monkeypatch.delenv("GRASP_SEPOLIA_SIGNER", raising=False)
    result = SepoliaAdapter(root=tmp_path).probe()
    assert not result.ready and "signer" in result.detail


def test_sepolia_probe_not_ready_when_binary_missing(tmp_path):
    result = SepoliaAdapter(signer_cmd="no-such-signer-xyz --send", root=tmp_path).probe()
    assert not result.ready and "no-such-signer-xyz" in result.detail


def test_sepolia_anchor_passes_root_and_parses_tx_hash(monkeypatch, tmp_path):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout=f"submitted tx: 0x{ROOT64}\n", stderr="")

    monkeypatch.setattr("grasp.storage.sepolia.subprocess.run", fake_run)
    adapter = SepoliaAdapter(signer_cmd="fake-signer --network sepolia", root=tmp_path)
    locator = adapter.anchor("rootvalue")
    assert locator == f"https://sepolia.etherscan.io/tx/0x{ROOT64}"
    assert seen["argv"][-1] == "rootvalue"  # the root really reaches the signer


def test_sepolia_anchor_none_on_garbage_stdout(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "grasp.storage.sepolia.subprocess.run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout="no hash here", stderr=""))
    assert SepoliaAdapter(signer_cmd="fake-signer", root=tmp_path).anchor("r") is None


def test_sepolia_blobs_round_trip_locally(tmp_path):
    adapter = SepoliaAdapter(root=tmp_path)
    adapter.put("sha256:xyz", b"data")
    assert adapter.get("sha256:xyz") == b"data"


# ---------------------------------------------------------------- ipfs

def test_multipart_carries_payload_and_boundary():
    body, content_type = _multipart(b"PAYLOAD", "blob.bin")
    boundary = content_type.rsplit("boundary=", 1)[1]
    assert boundary.encode() in body and b"PAYLOAD" in body and b"blob.bin" in body


def _fake_kubo(monkeypatch, store):
    def fake_urlopen(request, timeout=0):
        url = request.full_url
        if "/api/v0/version" in url:
            return _Response(json.dumps({"Version": "0.29.0"}).encode())
        if "/api/v0/add" in url:
            cid = "QmFake" + hashlib.sha256(request.data).hexdigest()[:6]
            store[cid] = request.data
            return _Response(json.dumps({"Hash": cid}).encode())
        if "/api/v0/cat" in url:
            cid = url.rsplit("arg=", 1)[1]
            for payload_cid, body in store.items():
                if payload_cid == cid:
                    return _Response(body)
            raise urllib.error.HTTPError(url, 500, "not found", None, None)
        raise AssertionError(f"unexpected url {url}")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)


def test_ipfs_put_get_round_trip(monkeypatch, tmp_path):
    store: dict[str, bytes] = {}
    _fake_kubo(monkeypatch, store)
    adapter = IPFSAdapter(index_path=tmp_path / "index.json")
    locator = adapter.put("sha256:abc", b"ipfs-payload")
    assert locator.startswith("ipfs://Qm")
    fetched = adapter.get("sha256:abc")
    assert fetched is not None and b"ipfs-payload" in fetched


def test_ipfs_get_unknown_id_returns_none(monkeypatch, tmp_path):
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda *a, **k: pytest.fail("network for an unindexed id"))
    assert IPFSAdapter(index_path=tmp_path / "index.json").get("sha256:none") is None


def test_ipfs_anchor_returns_cid_locator(monkeypatch, tmp_path):
    store: dict[str, bytes] = {}
    _fake_kubo(monkeypatch, store)
    locator = IPFSAdapter(index_path=tmp_path / "i.json").anchor(ROOT64)
    assert locator.startswith("ipfs://Qm")


def test_ipfs_probe_not_ready_without_daemon(monkeypatch, tmp_path):
    def refuse(*args, **kwargs):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    result = IPFSAdapter(index_path=tmp_path / "i.json").probe()
    assert not result.ready and "daemon" in result.remedy
