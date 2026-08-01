"""Bitcoin OpenTimestamps backend — anchor roots to the Bitcoin blockchain.

Anchor-first backend: record blobs persist locally (composes
``LocalAdapter`` — "records live locally; roots witness externally"), and
``anchor`` commits the Merkle root via the upstream ``ots`` client — the
same deployment step the README documents ("not our code at all"). The
proven path: pilot chains anchored in real Bitcoin blocks (956992 et al.).

Runtime dependency, honestly detected: the ``ots`` CLI
(``pipx install opentimestamps-client``). ``probe()`` reports it live.
``ots stamp`` submits to public calendar servers (network); the returned
proof file upgrades to a Bitcoin attestation later via ``ots upgrade``.

``verify`` closes the loop: it answers whether a stamped root actually
LANDED in a Bitcoin block, which anchoring alone never establishes. Doing
that the orthodox way needs a Bitcoin node, and a node is not free — even a
pruned one performs a full initial block download (758 GB as of 2026-08-01;
``prune=`` caps what is RETAINED, not what is downloaded). More to the
point, your node convinces only you: whoever you are proving something to
checks the anchor against THEIR node either way.

So verification is tiered, and the tier is always reported next to the
verdict rather than hidden behind a bare "confirmed":

  bitcoin-node          a reachable node answered. No trust assumption.
  multi-source-header   >= 2 independent block-header sources returned the
                        IDENTICAL header. Trust: they would have to collude.
  neither               NOT confirmed. A verdict is never manufactured.

The lighter tier is sound rather than a shortcut because the cryptography
still happens locally: ``ots --no-bitcoin verify`` binds the target digest
to the proof and then COMPUTES the merkle root up from it through the
proof's own operations. Only the "does block N really carry that root?"
lookup is outsourced, so a forged proof fails here before any lookup. And
any node serves that lookup, pruned or not: the client asks only for
``getblockcount``, ``getblockhash`` and ``getblockheader``, and
``getblockheader`` reads the block index rather than block data, which
pruning never discards.

Point ``GRASP_BITCOIN_NODE`` at an RPC URL to use the trustless tier; no
code change is needed to move up to it.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from grasp.home import grasp_home
from grasp.storage import ProbeResult
from grasp.storage.local import LocalAdapter

#: Independent block-header sources. Two operators, queried separately; a
#: verdict needs them to AGREE EXACTLY. Override for a different pair.
DEFAULT_HEADER_SOURCES: tuple[tuple[str, str, str], ...] = (
    ("blockstream.info",
     "https://blockstream.info/api/block-height/{height}",
     "https://blockstream.info/api/block/{block_hash}"),
    ("mempool.space",
     "https://mempool.space/api/block-height/{height}",
     "https://mempool.space/api/block/{block_hash}"),
)
MIN_AGREEING_SOURCES = 2
HTTP_TIMEOUT_CAP = 15  # seconds any single HTTP request may take
_TRUST_NODE = "none — a Bitcoin node validated the chain locally"
_ATTESTATION_RE = re.compile(
    r"Bitcoin block (\d+) has merkleroot ([0-9a-fA-F]{64})")
_BLOCK_HASH_RE = re.compile(r"[0-9a-f]{64}")
_SUCCESS_RE = re.compile(r"Success!\s*Bitcoin block (\d+)", re.IGNORECASE)
#: The client names its Bitcoin attestations even when told not to check them.
#: Seeing that while parsing zero attestations means the PARSER failed — not
#: that the proof is still waiting on a block. Without this discriminator a
#: reworded client would make every proof read as "still pending": a broken
#: parser wearing the costume of a proof that simply has not landed yet.
_ATTESTATION_MENTION_RE = re.compile(r"Bitcoin attestation", re.IGNORECASE)
#: Header sources are fetched over the network, so only https is accepted.
#: Nothing untrusted reaches ``header_sources`` today, but a caller could plumb
#: it from config — and then file://, an http:// metadata endpoint, or a
#: private host would all be reachable. Cheap to refuse now.
_ALLOWED_SOURCE_SCHEME = "https://"


@dataclass(frozen=True)
class AnchorVerdict:
    """One anchor's real state, in plain language, with its trust named.

    ``confirmed`` never stands alone: ``verified_by`` says which tier
    produced it and ``trust`` states what you are relying on, so a
    header-agreement verdict can never be mistaken for a full node.
    """

    confirmed: bool
    detail: str
    verified_by: str | None = None
    trust: str | None = None
    block: int | None = None
    block_hash: str | None = None
    block_time: int | None = None
    sources: tuple[str, ...] = field(default_factory=tuple)


# A caller's timeout budgets the WHOLE verification, not each request inside
# it. Without one deadline the cost multiplies out — attestations x sources x
# two requests each, every one waiting the full timeout — so a single slow
# source could stall a 40 s check for minutes.
def _remaining(deadline: float | None) -> float:
    return float("inf") if deadline is None else max(0.0, deadline - time.monotonic())


def _budget(cap: float, deadline: float | None) -> float:
    return min(cap, _remaining(deadline))


def _describe_error(exc: Exception) -> str:
    """Say WHY a source failed, so a changed API is not read as an outage."""
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return f"unreachable ({exc.reason})"
    if isinstance(exc, json.JSONDecodeError):
        return "malformed JSON"
    if isinstance(exc, KeyError):
        return f"response is missing the field {exc}"
    if isinstance(exc, TimeoutError):
        return "timed out"
    return type(exc).__name__


class _HttpsOnlyRedirects(urllib.request.HTTPRedirectHandler):
    """Hold the https guarantee across redirects, not just at the first hop.

    Checking the URL we were handed is not enough: urlopen follows redirects
    on its own, so a trusted host answering with a 302 to ``http://`` — or to
    an internal address — would walk the request straight past the check. The
    scheme is re-tested on every hop, and a failing one is refused rather than
    followed."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith(_ALLOWED_SOURCE_SCHEME):
            raise urllib.error.HTTPError(
                newurl, code, f"refusing a redirect to {newurl[:40]!r} — header "
                f"sources must stay {_ALLOWED_SOURCE_SCHEME}…", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_HttpsOnlyRedirects)


def _http_get(url: str, timeout: float) -> str:
    if not url.startswith(_ALLOWED_SOURCE_SCHEME):
        raise ValueError(f"header sources must be {_ALLOWED_SOURCE_SCHEME}… — "
                         f"refusing {url[:40]!r}")
    req = urllib.request.Request(url, headers={"User-Agent": "grasp-ots/1"})
    with _OPENER.open(req, timeout=timeout) as resp:  # noqa: S310
        return resp.read().decode("utf-8", "replace").strip()


def fetch_block_header(source: tuple[str, str, str], height: int,
                       timeout: float = HTTP_TIMEOUT_CAP, *,
                       deadline: float | None = None) -> dict:
    """One source's view of a block header. Always returns a dict.

    ``ok`` False carries an ``error`` saying why, so a source that renamed
    its fields is distinguishable from one that is simply down.
    """
    name, height_url, block_url = source
    if _budget(timeout, deadline) <= 0:
        return {"source": name, "ok": False, "error": "no time left in the budget"}
    try:
        block_hash = _http_get(height_url.format(height=height),
                               _budget(timeout, deadline))
        if not _BLOCK_HASH_RE.fullmatch(block_hash):
            return {"source": name, "ok": False,
                    "error": f"expected a block hash, got {block_hash[:32]!r}"}
        data = json.loads(_http_get(block_url.format(block_hash=block_hash),
                                    _budget(timeout, deadline)))
        return {"source": name, "ok": True, "block_hash": block_hash,
                "merkleroot": str(data["merkle_root"]).lower(),
                "time": int(data["timestamp"])}
    except Exception as exc:  # noqa: BLE001 - classified, never silently dropped
        return {"source": name, "ok": False, "error": _describe_error(exc)}


def agree_on_block_header(height: int, *,
                          sources: tuple = DEFAULT_HEADER_SOURCES,
                          timeout: float = HTTP_TIMEOUT_CAP,
                          min_sources: int = MIN_AGREEING_SOURCES,
                          deadline: float | None = None) -> dict:
    """Independent sources must agree EXACTLY. Disagreement is a red flag.

    Deliberately not a majority vote: if two operators report different
    headers for one height something is wrong, and the honest answer is
    "unverified" rather than "the more popular one wins".
    """
    answers = [fetch_block_header(s, height, timeout, deadline=deadline)
               for s in sources]
    seen = [a for a in answers if a["ok"]]
    if len(seen) < min_sources:
        why = "; ".join(f"{a['source']}: {a['error']}" for a in answers if not a["ok"])
        return {"agreed": False, "headers": seen,
                "reason": (f"only {len(seen)} of {len(sources)} header sources "
                           f"answered; {min_sources} agreeing sources are required"
                           + (f" ({why})" if why else ""))}
    key = ("block_hash", "merkleroot", "time")
    first = seen[0]
    if any(tuple(h[k] for k in key) != tuple(first[k] for k in key) for h in seen[1:]):
        return {"agreed": False, "headers": seen,
                "reason": (f"header sources DISAGREE about block {height} — "
                           "refusing to treat this as verified")}
    return {"agreed": True, "headers": seen, "reason": "",
            "block_hash": first["block_hash"], "merkleroot": first["merkleroot"],
            "time": first["time"]}


class BitcoinOTSAdapter:
    name = "bitcoin-ots"

    def __init__(self, root: str | Path | None = None) -> None:
        self._root = Path(root) if root is not None else grasp_home() / "storage"
        self._blobs = LocalAdapter(root=self._root)

    # -- blob persistence delegates to the local floor -------------------
    def put(self, record_id: str, blob: bytes) -> str:
        return self._blobs.put(record_id, blob)

    def get(self, record_id: str) -> bytes | None:
        return self._blobs.get(record_id)

    # -- the witness surface ---------------------------------------------
    def anchor(self, merkle_root: str) -> str | None:
        """Stamp the root via ``ots``; return the proof-file locator."""
        if shutil.which("ots") is None:
            return None
        ots_dir = self._root / "ots"
        ots_dir.mkdir(parents=True, exist_ok=True)
        digest = hashlib.sha256(merkle_root.encode("utf-8")).hexdigest()[:12]
        root_file = ots_dir / f"root-{digest}.txt"
        root_file.write_text(merkle_root + "\n", encoding="utf-8")
        proof = root_file.with_suffix(".txt.ots")
        try:
            done = subprocess.run(
                ["ots", "stamp", str(root_file)],
                capture_output=True, text=True, timeout=60, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if done.returncode != 0 or not proof.exists():
            return None
        return f"file://{proof}"

    def _proof_path(self, merkle_root: str) -> tuple[Path, Path]:
        """Where ``anchor`` put this root's target and proof. Same rule both ways."""
        digest = hashlib.sha256(merkle_root.encode("utf-8")).hexdigest()[:12]
        root_file = self._root / "ots" / f"root-{digest}.txt"
        return root_file, root_file.with_suffix(".txt.ots")

    def verify(self, merkle_root: str, *, timeout: float = 40,
               bitcoin_node: str | None = None,
               header_sources: tuple = DEFAULT_HEADER_SOURCES,
               min_sources: int = MIN_AGREEING_SOURCES) -> AnchorVerdict:
        """Did this root actually land in a Bitcoin block? Answer honestly.

        Tries a Bitcoin node first (no trust assumption). Failing that, checks
        the merkle root the proof commits to against independent block-header
        sources, which IS reported as confirmed but always carries the trust
        that made it possible. With neither available the verdict is NOT
        confirmed — never manufactured.

        ``timeout`` budgets the whole call. Pass ``header_sources=()`` to
        refuse the lighter tier and require a node.
        """
        deadline = time.monotonic() + timeout
        if shutil.which("ots") is None:
            return AnchorVerdict(
                confirmed=False,
                detail="the OpenTimestamps client is not on PATH, so the proof "
                       "cannot be read (pipx install opentimestamps-client)")
        root_file, proof = self._proof_path(merkle_root)
        if not proof.exists():
            return AnchorVerdict(
                confirmed=False,
                detail=f"no proof on disk for this root — expected {proof}; "
                       "anchor() has not run, or ran on another machine")
        node = bitcoin_node or os.environ.get("GRASP_BITCOIN_NODE") or ""
        by_node = self._verify_via_node(proof, node, _budget(timeout, deadline))
        if by_node is not None:
            return by_node
        if not header_sources:
            return AnchorVerdict(
                confirmed=False,
                detail="no Bitcoin node reachable and block-header lookup is "
                       "disabled, so this anchor is unverified here")
        return self._verify_via_headers(root_file, proof, header_sources,
                                        min_sources, timeout, deadline)

    def _verify_via_node(self, proof: Path, node: str,
                         timeout: float) -> AnchorVerdict | None:
        """Tier 1 — a reachable node. None when it could not confirm."""
        argv = ["ots"] + (["--bitcoin-node", node] if node else []) \
            + ["verify", str(proof)]
        try:
            done = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=max(1, int(timeout)), check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        hit = _SUCCESS_RE.search((done.stdout or "") + (done.stderr or ""))
        if not hit:
            return None
        return AnchorVerdict(
            confirmed=True, block=int(hit.group(1)),
            verified_by="bitcoin-node", trust=_TRUST_NODE,
            detail=f"a Bitcoin node confirmed this root in block {hit.group(1)}")

    def _attested_heights(self, root_file: Path, proof: Path,
                          timeout: float) -> list | None:
        """(height, merkleroot) pairs the client COMPUTES from our target.

        None means the client could not run, OR it ran and clearly HAD Bitcoin
        attestations this parser failed to read — both fail to establish
        anything. An empty list is the honestly different case: it ran and the
        proof genuinely carries no Bitcoin attestation yet.
        """
        argv = ["ots", "--no-bitcoin", "verify", "-f", str(root_file), str(proof)]
        try:
            done = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=max(1, int(timeout)), check=False)
        except (OSError, subprocess.TimeoutExpired):
            return None
        text = (done.stdout or "") + (done.stderr or "")
        pairs = [(int(h), r.lower()) for h, r in _ATTESTATION_RE.findall(text)]
        if not pairs and _ATTESTATION_MENTION_RE.search(text):
            return None
        return pairs

    def _verify_via_headers(self, root_file: Path, proof: Path, sources: tuple,
                            min_sources: int, timeout: float,
                            deadline: float) -> AnchorVerdict:
        """Tier 2 — the computed root, checked against independent headers."""
        pairs = self._attested_heights(root_file, proof, _budget(timeout, deadline))
        if pairs is None:
            return AnchorVerdict(confirmed=False,
                                 detail="the ots client could not be run")
        if not pairs:
            return AnchorVerdict(
                confirmed=False,
                detail="this proof carries no Bitcoin attestation yet — it is "
                       "still a calendar commitment; run `ots upgrade` once a "
                       "block has included it")
        notes: list[str] = []
        for height, merkleroot in sorted(pairs):
            if _remaining(deadline) <= 0:
                notes.append(f"block {height}: ran out of the time budget")
                break
            found = agree_on_block_header(
                height, sources=sources, timeout=min(HTTP_TIMEOUT_CAP, timeout),
                min_sources=min_sources, deadline=deadline)
            if not found["agreed"]:
                notes.append(f"block {height}: {found['reason']}")
            elif found["merkleroot"] != merkleroot:
                notes.append(
                    f"block {height}: MERKLEROOT MISMATCH — the proof commits to "
                    f"{merkleroot} but block {height} really carries "
                    f"{found['merkleroot']}")
            else:
                return self._confirmed_by_headers(height, merkleroot, found)
        return AnchorVerdict(
            confirmed=False,
            detail="not confirmed against block headers: " + "; ".join(notes))

    @staticmethod
    def _confirmed_by_headers(height: int, merkleroot: str,
                              found: dict) -> AnchorVerdict:
        names = tuple(h["source"] for h in found["headers"])
        return AnchorVerdict(
            confirmed=True, block=height, block_hash=found["block_hash"],
            block_time=found["time"], verified_by="multi-source-header",
            sources=names,
            trust=(f"{len(names)} independent block-header sources "
                   f"({', '.join(names)}) returned the identical header, and "
                   "they would have to collude to forge it. This is NOT a "
                   "local full node."),
            detail=(f"block {height} ({found['block_hash']}) carries merkleroot "
                    f"{merkleroot}, which this proof commits to"))

    def probe(self) -> ProbeResult:
        if shutil.which("ots") is None:
            return ProbeResult(
                name=self.name,
                ready=False,
                detail="the OpenTimestamps client is not on PATH",
                remedy="pipx install opentimestamps-client",
            )
        blobs = self._blobs.probe()
        if not blobs.ready:
            return ProbeResult(name=self.name, ready=False,
                               detail=blobs.detail, remedy=blobs.remedy)
        return ProbeResult(
            name=self.name,
            ready=True,
            detail="roots stamp to Bitcoin via ots (calendar submission now, "
                   "block attestation upgrades later); blobs persist locally",
        )
