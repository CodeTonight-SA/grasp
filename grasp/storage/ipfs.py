"""IPFS backend — content-addressed storage via a local kubo daemon.

Talks to the kubo HTTP API (default ``http://127.0.0.1:5001``, override
with ``GRASP_IPFS_API``) using only the standard library — including a
minimal multipart/form-data builder for ``/api/v0/add``. A record-id → CID
index persists locally (flocked JSON) so ``get`` can resolve ids back to
content addresses.

Runtime dependency, honestly detected: a running IPFS daemon.
``probe()`` reports it live.
"""
from __future__ import annotations

import fcntl
import json
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from grasp.home import grasp_home
from grasp.storage import ProbeResult


def _multipart(payload: bytes, filename: str) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    head = (f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n").encode()
    tail = f"\r\n--{boundary}--\r\n".encode()
    return head + payload + tail, f"multipart/form-data; boundary={boundary}"


class IPFSAdapter:
    name = "ipfs"

    def __init__(self, api: str | None = None,
                 index_path: str | Path | None = None) -> None:
        self._api = (api or os.environ.get("GRASP_IPFS_API", "")
                     or "http://127.0.0.1:5001").rstrip("/")
        self._index_path = (Path(index_path) if index_path is not None
                            else grasp_home() / "storage" / "ipfs-index.json")

    # -- kubo HTTP API ------------------------------------------------------
    def _call(self, path: str, payload: bytes | None = None,
              filename: str = "blob", timeout: int = 15, **params) -> bytes:
        query = urllib.parse.urlencode(params)
        url = f"{self._api}{path}" + (f"?{query}" if query else "")
        if payload is None:
            request = urllib.request.Request(url, data=b"", method="POST")
        else:
            body, content_type = _multipart(payload, filename)
            request = urllib.request.Request(url, data=body, method="POST")
            request.add_header("Content-Type", content_type)
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()

    def _add(self, payload: bytes, filename: str) -> str:
        raw = self._call("/api/v0/add", payload, filename)
        last = raw.decode("utf-8").strip().splitlines()[-1]
        return json.loads(last)["Hash"]

    # -- record-id -> CID index ----------------------------------------------
    def _index_update(self, record_id: str, cid: str) -> None:
        self._index_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._index_path, "a+", encoding="utf-8") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            try:
                fh.seek(0)
                raw = fh.read().strip()
                index = json.loads(raw) if raw else {}
                index[record_id] = cid
                fh.seek(0)
                fh.truncate()
                fh.write(json.dumps(index, sort_keys=True, indent=0))
            finally:
                fcntl.flock(fh, fcntl.LOCK_UN)

    def _index_lookup(self, record_id: str) -> str | None:
        if not self._index_path.exists():
            return None
        raw = self._index_path.read_text(encoding="utf-8").strip()
        return (json.loads(raw) if raw else {}).get(record_id)

    # -- StorageAdapter --------------------------------------------------------
    def put(self, record_id: str, blob: bytes) -> str:
        cid = self._add(blob, filename=record_id[:40] or "record")
        self._index_update(record_id, cid)
        return f"ipfs://{cid}"

    def get(self, record_id: str) -> bytes | None:
        cid = self._index_lookup(record_id)
        if cid is None:
            return None
        return self._call("/api/v0/cat", arg=cid)

    def anchor(self, merkle_root: str) -> str | None:
        try:
            cid = self._add(merkle_root.encode("utf-8"), filename="merkle-root")
        except (urllib.error.URLError, OSError):
            return None
        return f"ipfs://{cid}"

    def probe(self) -> ProbeResult:
        try:
            raw = self._call("/api/v0/version", timeout=2)
            version = json.loads(raw.decode("utf-8")).get("Version", "unknown")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            return ProbeResult(
                name=self.name,
                ready=False,
                detail=f"no IPFS daemon at {self._api}: {exc}",
                remedy="start a local kubo daemon (`ipfs daemon`) or point "
                       "GRASP_IPFS_API at one",
            )
        return ProbeResult(
            name=self.name,
            ready=True,
            detail=f"kubo {version} at {self._api} (content-addressed, "
                   "pinned locally by the daemon)",
        )
