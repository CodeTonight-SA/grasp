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
from grasp.storage import ots as ots_mod
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

def test_anchor_and_remote_backends_registered():
    # exact whole-domain census lives in test_storage_website.py
    assert {"local", "bitcoin-ots", "s3", "sepolia", "ipfs"} <= set(adapter_names())


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


# -- anchor verification: did the root actually land in a Bitcoin block? -----
#
# Falsifiers each test enforces: a verdict that reads "confirmed" without
# naming which tier produced it lets header agreement pass as a full node; a
# single responding source is trust rather than corroboration; out-voting a
# disagreeing source would confirm a header nobody agrees on; accepting a
# merkleroot the real block does not carry would confirm a forged proof; and a
# per-request timeout inside the attestation loop would let one slow source
# multiply the caller's whole budget.

def _stub_ots(monkeypatch, present=True):
    monkeypatch.setattr("grasp.storage.ots.shutil.which",
                        lambda _: "/usr/bin/ots" if present else None)


def _stub_proof(tmp_path, root=ROOT64):
    """Put a proof on disk exactly where anchor() would have left it."""
    adapter = BitcoinOTSAdapter(root=tmp_path)
    root_file, proof = adapter._proof_path(root)
    root_file.parent.mkdir(parents=True, exist_ok=True)
    root_file.write_text(root + "\n", encoding="utf-8")
    proof.write_bytes(b"proof-bytes")
    return adapter


def _header(source, block_hash="ab" * 32, merkleroot="cd" * 32, time=1783480961):
    return {"source": source, "ok": True, "block_hash": block_hash,
            "merkleroot": merkleroot, "time": time}


TWO_SOURCES = (("a", "{height}", "{block_hash}"), ("b", "{height}", "{block_hash}"))


def test_ots_verify_unconfirmed_without_a_proof_on_disk(monkeypatch, tmp_path):
    _stub_ots(monkeypatch)
    verdict = BitcoinOTSAdapter(root=tmp_path).verify(ROOT64)
    assert verdict.confirmed is False
    assert "no proof on disk" in verdict.detail


def test_ots_verify_unconfirmed_without_the_client(monkeypatch, tmp_path):
    _stub_ots(monkeypatch, present=False)
    verdict = BitcoinOTSAdapter(root=tmp_path).verify(ROOT64)
    assert verdict.confirmed is False
    assert verdict.verified_by is None


def test_ots_verify_pending_proof_says_so(monkeypatch, tmp_path):
    """A calendar commitment is not yet a block. Saying 'unconfirmed' without
    that distinction would read as failure rather than 'not yet'."""
    _stub_ots(monkeypatch)
    adapter = _stub_proof(tmp_path)
    monkeypatch.setattr(BitcoinOTSAdapter, "_verify_via_node",
                        lambda *a, **k: None)
    monkeypatch.setattr(BitcoinOTSAdapter, "_attested_heights",
                        lambda *a, **k: [])
    verdict = adapter.verify(ROOT64, header_sources=TWO_SOURCES)
    assert verdict.confirmed is False
    assert "no Bitcoin attestation yet" in verdict.detail


def test_ots_verify_node_tier_is_marked_trustless(monkeypatch, tmp_path):
    _stub_ots(monkeypatch)
    adapter = _stub_proof(tmp_path)
    monkeypatch.setattr(
        "grasp.storage.ots.subprocess.run",
        lambda argv, **kw: subprocess.CompletedProcess(
            argv, 0, stdout="Success! Bitcoin block 957120 attests existence",
            stderr=""))
    verdict = adapter.verify(ROOT64, bitcoin_node="http://node/")
    assert verdict.confirmed is True
    assert verdict.verified_by == "bitcoin-node"
    assert verdict.block == 957120
    assert verdict.trust == ots_mod._TRUST_NODE


def test_ots_verify_header_tier_states_its_trust(monkeypatch, tmp_path):
    """A pass must name the tier and its assumption — never a bare 'confirmed'."""
    _stub_ots(monkeypatch)
    adapter = _stub_proof(tmp_path)
    monkeypatch.setattr(BitcoinOTSAdapter, "_verify_via_node", lambda *a, **k: None)
    monkeypatch.setattr(BitcoinOTSAdapter, "_attested_heights",
                        lambda *a, **k: [(957120, "cd" * 32)])
    monkeypatch.setattr("grasp.storage.ots.fetch_block_header",
                        lambda s, h, t=15, *, deadline=None: _header(s[0]))
    verdict = adapter.verify(ROOT64, header_sources=TWO_SOURCES)
    assert verdict.confirmed is True
    assert verdict.verified_by == "multi-source-header"
    assert verdict.block == 957120
    assert verdict.block_hash == "ab" * 32
    assert "NOT a local full node" in verdict.trust
    assert verdict.sources == ("a", "b")


def test_ots_verify_refuses_a_merkleroot_mismatch(monkeypatch, tmp_path):
    """The forgery vector: the proof commits to a root the real block does not
    carry. Confirming that would make the whole anchor worthless."""
    _stub_ots(monkeypatch)
    adapter = _stub_proof(tmp_path)
    monkeypatch.setattr(BitcoinOTSAdapter, "_verify_via_node", lambda *a, **k: None)
    monkeypatch.setattr(BitcoinOTSAdapter, "_attested_heights",
                        lambda *a, **k: [(957120, "11" * 32)])
    monkeypatch.setattr("grasp.storage.ots.fetch_block_header",
                        lambda s, h, t=15, *, deadline=None:
                        _header(s[0], merkleroot="99" * 32))
    verdict = adapter.verify(ROOT64, header_sources=TWO_SOURCES)
    assert verdict.confirmed is False
    assert "MISMATCH" in verdict.detail


def test_ots_verify_header_tier_can_be_refused(monkeypatch, tmp_path):
    """Requiring a node is a supported stance, and must not silently downgrade."""
    _stub_ots(monkeypatch)
    adapter = _stub_proof(tmp_path)
    monkeypatch.setattr(BitcoinOTSAdapter, "_verify_via_node", lambda *a, **k: None)
    verdict = adapter.verify(ROOT64, header_sources=())
    assert verdict.confirmed is False
    assert "disabled" in verdict.detail


def test_single_source_is_not_agreement(monkeypatch):
    monkeypatch.setattr(
        "grasp.storage.ots.fetch_block_header",
        lambda s, h, t=15, *, deadline=None:
        _header("a") if s[0] == "a" else {"source": s[0], "ok": False,
                                          "error": "unreachable (stub)"})
    out = ots_mod.agree_on_block_header(957120, sources=TWO_SOURCES)
    assert out["agreed"] is False
    assert "agreeing sources are required" in out["reason"]


def test_disagreeing_sources_are_refused_not_out_voted(monkeypatch):
    """Two agree and one differs. A majority vote accepts this; exact
    agreement must not."""
    three = TWO_SOURCES + (("c", "{height}", "{block_hash}"),)
    roots = {"a": "11" * 32, "b": "11" * 32, "c": "99" * 32}
    monkeypatch.setattr("grasp.storage.ots.fetch_block_header",
                        lambda s, h, t=15, *, deadline=None:
                        _header(s[0], merkleroot=roots[s[0]]))
    out = ots_mod.agree_on_block_header(957120, sources=three)
    assert out["agreed"] is False
    assert "DISAGREE" in out["reason"]


def test_a_changed_api_is_distinguishable_from_an_outage(monkeypatch):
    """A source that answers but renamed its fields is BROKEN, not merely down."""
    monkeypatch.setattr(
        "grasp.storage.ots._http_get",
        lambda url, timeout: "ab" * 32 if "height" in url
        else '{"mrkl_root": "x", "timestamp": 1}')
    answer = ots_mod.fetch_block_header(
        ("s", "https://x/height/{height}", "https://x/b/{block_hash}"), 957120)
    assert answer["ok"] is False
    assert "missing the field" in answer["error"] and "merkle_root" in answer["error"]


def test_only_https_sources_are_fetched():
    """Nothing untrusted reaches header_sources today, but a caller could plumb
    it from config — at which point file:// or an http:// metadata endpoint
    would be reachable. Refusing now is one comparison."""
    for bad in ("http://blockstream.info/api/block-height/{height}",
                "file:///etc/passwd",
                "http://169.254.169.254/latest/meta-data/{height}"):
        answer = ots_mod.fetch_block_header(("x", bad, bad), 957120)
        assert answer["ok"] is False
        assert "ValueError" in answer["error"] or "https" in answer["error"]


def test_https_survives_a_redirect_not_just_the_first_hop():
    """Checking the URL we were handed is not enough — urlopen follows
    redirects itself, so a trusted host answering 302 to http:// would walk
    the request straight past the check."""
    handler = ots_mod._HttpsOnlyRedirects()
    with pytest.raises(urllib.error.HTTPError):
        handler.redirect_request(
            urllib.request.Request("https://blockstream.info/api/x"),
            None, 302, "Found", {}, "http://169.254.169.254/latest/meta-data/")


def test_a_refusal_never_echoes_credentials_from_the_url():
    """A source URL can carry credentials in its userinfo. Echoing even a
    truncated prefix would put the secret into the returned error field."""
    secret = "https://user:sup3rs3cret@evil.internal/api/{height}"
    answer = ots_mod.fetch_block_header(
        ("x", secret.replace("https", "http"), secret), 957120)
    assert answer["ok"] is False
    assert "sup3rs3cret" not in answer["error"]
    assert "user:" not in answer["error"]
    # the host is still named, so the failure stays diagnosable
    assert "evil.internal" in answer["error"]


def test_a_refused_redirect_reports_the_reason_not_a_status_code():
    """The refusal is raised as an HTTPError so urllib unwinds properly, but
    describing it as one would surface a security block as a bland 'HTTP 302'
    and the operator would never learn a redirect was refused."""
    refusal = ots_mod._RefusedRedirect(
        "http://evil.internal/", 302,
        "refusing a redirect to http://evil.internal — header sources must "
        "stay https://…", {}, None)
    described = ots_mod._describe_error(refusal)
    assert "refusing a redirect" in described and described != "HTTP 302"
    genuine = urllib.error.HTTPError("https://x/", 503, "busy", {}, None)
    assert ots_mod._describe_error(genuine) == "HTTP 503"


def test_an_https_redirect_is_still_followed():
    """The guard must not break ordinary redirects between https hosts."""
    handler = ots_mod._HttpsOnlyRedirects()
    out = handler.redirect_request(
        urllib.request.Request("https://blockstream.info/api/x"),
        None, 302, "Found", {}, "https://blockstream.info/api/y")
    assert out is not None and out.full_url == "https://blockstream.info/api/y"


def test_a_broken_parser_does_not_masquerade_as_a_pending_proof(monkeypatch, tmp_path):
    """If the ots client rewords its output, every proof would silently read as
    'still waiting on a block'. A broken parser must not wear that costume."""
    monkeypatch.setattr(
        "grasp.storage.ots.subprocess.run",
        lambda argv, **kw: subprocess.CompletedProcess(
            argv, 1,
            stdout="Not checking Bitcoin attestation; Bitcoin disabled\n"
                   "To verify manually, look at block 957120 somehow",
            stderr=""))
    adapter = BitcoinOTSAdapter(root=tmp_path)
    assert adapter._attested_heights(tmp_path / "r.txt", tmp_path / "p.ots", 10) is None


def test_a_genuinely_pending_proof_still_reads_as_empty(monkeypatch, tmp_path):
    """The other side of that discriminator: a proof with no Bitcoin
    attestation at all is an empty list, not a parse failure."""
    monkeypatch.setattr(
        "grasp.storage.ots.subprocess.run",
        lambda argv, **kw: subprocess.CompletedProcess(
            argv, 1, stdout="Pending confirmation in calendar https://alice", stderr=""))
    adapter = BitcoinOTSAdapter(root=tmp_path)
    assert adapter._attested_heights(tmp_path / "r.txt", tmp_path / "p.ots", 10) == []


def test_spent_budget_issues_no_http_request(monkeypatch):
    """The caller's timeout budgets the WHOLE check. Sources are queried once
    per attestation, so a per-request timeout would multiply total latency."""
    calls = []
    monkeypatch.setattr("grasp.storage.ots._http_get",
                        lambda url, timeout: calls.append(url) or "")
    answer = ots_mod.fetch_block_header(
        TWO_SOURCES[0], 957120, deadline=ots_mod.time.monotonic() - 1)
    assert answer["ok"] is False
    assert "budget" in answer["error"]
    assert calls == []


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
