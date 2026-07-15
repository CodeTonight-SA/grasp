"""Website backend — a live, auto-updating static site of records + anchors.

Every ``put``/``anchor`` regenerates a self-contained ``index.html`` (inline
CSS, no external assets, no scripts) listing the deployment's records and
anchored Merkle roots — the "live auto-updating public website" storage
member. The render is DETERMINISTIC: the same ledger state produces
byte-identical HTML (no render-time clocks), so re-rendering is an
idempotent no-op — testable as f(f(x)) == f(x).

Publish honesty: the adapter only ever writes the LOCAL site directory.
Pushing it anywhere public is a separate, operator-gated ``publish()`` call
running a configured command — never automatic (public-publish discipline:
sweep, then push, fail closed). ``put``/``anchor`` never publish.
"""
from __future__ import annotations

import html
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from grasp.home import grasp_home
from grasp.storage import ProbeResult
from grasp.storage.local import LocalAdapter

_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>GRASP provenance — public chain site</title>
<style>
 body{{background:#0e0e10;color:#e8e6e3;font:15px/1.55 -apple-system,system-ui,sans-serif;
      max-width:52rem;margin:3rem auto;padding:0 1rem}}
 h1{{font-size:1.3rem;letter-spacing:.04em}} h2{{font-size:1rem;margin-top:2rem}}
 code{{background:#1b1b1f;padding:.1rem .35rem;border-radius:3px}}
 li{{margin:.3rem 0;list-style:none}} ul{{padding:0}}
 footer{{margin-top:3rem;border-top:1px solid #2a2a2e;padding-top:.8rem;
        font-style:italic;color:#8a8782}}
</style></head><body>
<h1>GRASP — signed provenance, publicly witnessable</h1>
<p>{record_count} record(s) · {anchor_count} anchored Merkle root(s).
Every entry re-verifies offline with the open GRASP package alone.</p>
<h2>Anchored roots</h2>
<ul>{anchors}</ul>
<h2>Records</h2>
<ul>{records}</ul>
<footer>facta, non verba — deeds, not words.</footer>
</body></html>
"""


class WebsiteAdapter:
    name = "website"

    def __init__(self, site_dir: str | Path | None = None,
                 publish_cmd: str | None = None) -> None:
        env_dir = os.environ.get("GRASP_WEBSITE_DIR", "")
        self._site = (Path(site_dir) if site_dir is not None
                      else Path(env_dir) if env_dir else grasp_home() / "site")
        self._publish_cmd = publish_cmd or os.environ.get("GRASP_WEBSITE_PUBLISH_CMD", "")
        self._blobs = LocalAdapter(root=self._site / "records")

    # -- ledger state ------------------------------------------------------
    def _anchors(self) -> list[dict]:
        ledger = self._site / "anchors.json"
        if not ledger.exists():
            return []
        raw = ledger.read_text(encoding="utf-8").strip()
        return json.loads(raw) if raw else []

    def _record_ids(self) -> list[str]:
        index = self._site / "records-index.json"
        if not index.exists():
            return []
        raw = index.read_text(encoding="utf-8").strip()
        return json.loads(raw) if raw else []

    # -- deterministic render ----------------------------------------------
    def _render(self) -> None:
        anchors = "".join(
            f"<li><code>{html.escape(entry['root'])}</code> · {html.escape(entry['ts'])}</li>"
            for entry in self._anchors()) or "<li>none yet</li>"
        records = "".join(
            f"<li><code>{html.escape(record_id)}</code></li>"
            for record_id in self._record_ids()) or "<li>none yet</li>"
        page = _PAGE.format(record_count=len(self._record_ids()),
                            anchor_count=len(self._anchors()),
                            anchors=anchors, records=records)
        (self._site / "index.html").write_text(page, encoding="utf-8")

    # -- StorageAdapter -------------------------------------------------------
    def put(self, record_id: str, blob: bytes) -> str:
        locator = self._blobs.put(record_id, blob)
        ids = self._record_ids()
        if record_id not in ids:
            ids.append(record_id)
            (self._site / "records-index.json").write_text(
                json.dumps(sorted(ids)), encoding="utf-8")
        self._render()
        return locator

    def get(self, record_id: str) -> bytes | None:
        return self._blobs.get(record_id)

    def anchor(self, merkle_root: str) -> str | None:
        self._site.mkdir(parents=True, exist_ok=True)
        entries = self._anchors()
        entries.append({"root": merkle_root,
                        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        (self._site / "anchors.json").write_text(
            json.dumps(entries, indent=0, sort_keys=True), encoding="utf-8")
        self._render()
        return f"file://{self._site / 'index.html'}#anchor-{len(entries)}"

    def publish(self) -> str | None:
        """Operator-gated push of the site dir via the configured command."""
        if not self._publish_cmd:
            return None
        try:
            done = subprocess.run(
                [*shlex.split(self._publish_cmd), str(self._site)],
                capture_output=True, text=True, timeout=300, check=False)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return None
        return str(self._site) if done.returncode == 0 else None

    def probe(self) -> ProbeResult:
        blobs = self._blobs.probe()
        if not blobs.ready:
            return ProbeResult(name=self.name, ready=False,
                               detail=blobs.detail, remedy=blobs.remedy)
        publish_note = (f"publish via {shlex.split(self._publish_cmd)[0]!r} (operator-gated)"
                        if self._publish_cmd else "no publish command configured (local only)")
        return ProbeResult(
            name=self.name,
            ready=True,
            detail=f"static chain-site auto-updates at {self._site}; {publish_note}",
        )
