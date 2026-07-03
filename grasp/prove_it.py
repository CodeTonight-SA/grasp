# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 CodeTonight SA
"""prove_it — deterministic citation-provenance engine.

Every claim in a response carries a citation = (source, verbatim quote). The
engine VERIFIES, deterministically, that each quote actually exists in its
cited source (exact, or whitespace-flexible), records the exact character span,
and renders a self-contained HTML artifact whose clickable citations highlight
the quoted span inside the embedded source document.

This is the **L1 deterministic floor** of citation falsification: a quote
either appears in the source or it does not — a hallucinated citation CANNOT
pass; it renders RED as NOT-FOUND. An optional **L2 layer** (does the quote
SUPPORT the claim?) is a caller-side integration seam: populate each
``Citation.support`` / ``Citation.support_detail`` before ``build_html`` and
the artifact renders the council table. The deterministic floor is the
guarantee; any L2 is recall on top and must be fail-open.

Scope honesty: the floor proves a quote is **verbatim in the supplied source**
— not that the source is authentic, and not that the quote supports the claim.

No third-party dependencies (stdlib only).
"""
from __future__ import annotations

import argparse
import hashlib
import html
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

STATUS_VERIFIED = "verified"   # exact substring present in source
STATUS_FUZZY = "fuzzy"         # present modulo whitespace runs
STATUS_NOT_FOUND = "not_found"  # NOT present — possible fabrication (the falsifier)

_STATUS_GLYPH = {STATUS_VERIFIED: "✓", STATUS_FUZZY: "≈", STATUS_NOT_FOUND: "✗"}
_STATUS_CLASS = {STATUS_VERIFIED: "ok", STATUS_FUZZY: "fuzzy", STATUS_NOT_FOUND: "bad"}
_WS_RE = re.compile(r"\s+")

# 1:1 (length-preserving) typographic normalisation — unicode dashes/hyphens,
# smart quotes, and exotic spaces map to ASCII. Because every mapping is a single
# char, offsets are preserved exactly, so a match found in normalised text indexes
# the ORIGINAL source verbatim. Extraction tools (PDF/docx) routinely insert these,
# so without it a genuinely-present quote fails on a cosmetic difference.
_TYPO_MAP = {
    0x2010: "-", 0x2011: "-", 0x2012: "-", 0x2013: "-", 0x2014: "-", 0x2015: "-",
    0x2018: "'", 0x2019: "'", 0x201B: "'",
    0x201C: '"', 0x201D: '"', 0x201F: '"',
    0x00A0: " ", 0x2007: " ", 0x2009: " ", 0x202F: " ",
}


def _typo(s: str) -> str:
    """Length-preserving typographic normalisation (offsets unchanged)."""
    return s.translate(_TYPO_MAP)


@dataclass
class Source:
    """A source document a citation can quote from."""
    id: str
    label: str
    text: str


@dataclass
class Citation:
    """A claim → verbatim-quote → source link, resolved by verify_all()."""
    id: str
    claim: str
    source_id: str
    quote: str
    status: str = STATUS_NOT_FOUND
    start: int = -1
    end: int = -1
    matched: str = ""
    support: str = ""  # L2 verdict: "" | supported | partial | unsupported | unavailable | n/a
    support_detail: str = ""  # L2 judge one-liner + agreement


# ---------------------------------------------------------------------------
# L1 — deterministic verification (the un-fakeable floor)
# ---------------------------------------------------------------------------

def _ws_flexible_pattern(quote: str) -> re.Pattern:
    """A regex matching `quote` where any whitespace run matches any whitespace run.

    Lets a quote pasted with different line-wrapping than the source still resolve
    to its true character offsets. Whitespace is the ONLY tolerance — content
    differences still fail (that is the point).
    """
    toks = [re.escape(t) for t in _WS_RE.split(quote.strip()) if t]
    return re.compile(r"\s+".join(toks)) if toks else re.compile(r"(?!x)x")


def verify_quote(quote: str, source_text: str) -> tuple[str, int, int]:
    """Locate `quote` in `source_text`. Returns (status, start, end) into source_text.

    Deterministic ladder: exact substring → whitespace-flexible → not found. Both
    hit paths return real offsets so the span can be highlighted verbatim.
    """
    q = (quote or "").strip()
    if not q:
        return STATUS_NOT_FOUND, -1, -1
    idx = source_text.find(q)
    if idx != -1:
        return STATUS_VERIFIED, idx, idx + len(q)
    # Fuzzy: tolerate whitespace runs AND 1:1 typographic variants (unicode
    # dashes/hyphens, smart quotes, nbsp). Normalisation is length-preserving, so
    # a match in normalised space indexes the ORIGINAL source verbatim.
    m = _ws_flexible_pattern(_typo(q)).search(_typo(source_text))
    if m:
        return STATUS_FUZZY, m.start(), m.end()
    return STATUS_NOT_FOUND, -1, -1


def verify_all(citations: list[Citation], sources: list[Source]) -> list[Citation]:
    """Resolve every citation against its source in place. Pure, deterministic."""
    by_id = {s.id: s for s in sources}
    for c in citations:
        src = by_id.get(c.source_id)
        if src is None:
            c.status, c.start, c.end, c.matched = STATUS_NOT_FOUND, -1, -1, ""
            continue
        c.status, c.start, c.end = verify_quote(c.quote, src.text)
        c.matched = src.text[c.start:c.end] if c.start != -1 else ""
    return citations


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def provenance(sources: list[Source], citations: list[Citation]) -> dict:
    """Verifiable provenance record (decision-chain/memory-chain ready):
    per-source SHA-256, per-citation status + offsets, and the grounding rate."""
    tally = {STATUS_VERIFIED: 0, STATUS_FUZZY: 0, STATUS_NOT_FOUND: 0}
    for c in citations:
        tally[c.status] = tally.get(c.status, 0) + 1
    grounded = tally[STATUS_VERIFIED] + tally[STATUS_FUZZY]
    return {
        "generated": datetime.now(timezone.utc).isoformat(),
        "sources": {
            s.id: {"label": s.label, "sha256": _sha256(s.text), "chars": len(s.text)}
            for s in sources
        },
        "citations": [
            {"id": c.id, "source_id": c.source_id, "status": c.status,
             "start": c.start, "end": c.end, "support": c.support}
            for c in citations
        ],
        "tally": tally,
        "grounding_rate": round(grounded / max(len(citations), 1), 3),
    }


# ---------------------------------------------------------------------------
# Rendering — self-contained HTML artifact with clickable, highlighting citations
# ---------------------------------------------------------------------------

def _esc(s: str) -> str:
    return html.escape(s, quote=True)


_HEADING_RE = re.compile(r"^(#{1,4})\s+(.*)$")
_BOLD_RE = re.compile(r"\*\*(.+?)\*\*")
_CITE_RE = re.compile(r"\[\[cite:([^\]]+)\]\]")


def _inline(text: str, idx: dict) -> str:
    out = _esc(text)
    out = _BOLD_RE.sub(lambda m: f"<strong>{m.group(1)}</strong>", out)

    def chip(m: re.Match) -> str:
        cid = m.group(1)
        meta = idx.get(cid)
        if not meta:
            return f"[[cite:{_esc(cid)}]]"
        glyph = _STATUS_GLYPH.get(meta["status"], "?")
        cls = _STATUS_CLASS.get(meta["status"], "")
        sup = f' · {meta["support"]}' if meta.get("support") else ""
        return (f'<a class="cite {cls}" data-cite="{_esc(cid)}" '
                f'title="{meta["status"]}{sup}">[{meta["n"]}{glyph}]</a>')

    return _CITE_RE.sub(chip, out)


def _md_to_html(md: str, idx: dict) -> str:
    parts: list[str] = []
    buf: list[str] = []
    in_ul = False

    def flush_p() -> None:
        nonlocal buf
        if buf:
            parts.append("<p>" + _inline(" ".join(buf), idx) + "</p>")
            buf = []

    def close_ul() -> None:
        nonlocal in_ul
        if in_ul:
            parts.append("</ul>")
            in_ul = False

    for raw in md.split("\n"):
        s = raw.rstrip()
        hm = _HEADING_RE.match(s)
        if hm:
            flush_p(); close_ul()
            lvl = len(hm.group(1))
            parts.append(f"<h{lvl}>" + _inline(hm.group(2), idx) + f"</h{lvl}>")
        elif s.lstrip().startswith("- "):
            flush_p()
            if not in_ul:
                parts.append("<ul>"); in_ul = True
            parts.append("<li>" + _inline(s.lstrip()[2:], idx) + "</li>")
        elif not s.strip():
            flush_p(); close_ul()
        else:
            close_ul()
            buf.append(s.strip())
    flush_p(); close_ul()
    return "\n".join(parts)


def _render_source_html(source: Source, cites: list[Citation]) -> str:
    """Escape source text and splice in <mark> highlights (or zero-width anchors
    for overlapping cites) so every resolved citation has a scroll target."""
    spans = sorted([(c.start, c.end, c.id) for c in cites if c.start != -1],
                   key=lambda x: (x[0], -x[1]))
    inserts: list[tuple[str, int, int, str]] = []
    last_end = -1
    for st, en, cid in spans:
        if st >= last_end:
            inserts.append(("mark", st, en, cid)); last_end = en
        else:
            inserts.append(("anchor", st, st, cid))
    inserts.sort(key=lambda x: x[1])
    out: list[str] = []
    pos = 0
    text = source.text
    for kind, st, en, cid in inserts:
        st = max(st, pos)
        out.append(_esc(text[pos:st]))
        if kind == "mark":
            out.append(f'<mark id="src-{_esc(cid)}" class="hl">' + _esc(text[st:en]) + "</mark>")
            pos = en
        else:
            out.append(f'<span id="src-{_esc(cid)}" class="anchor"></span>')
            pos = st
    out.append(_esc(text[pos:]))
    return "".join(out)


_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--ink:#e6edf3;--mut:#8b949e;--line:#30363d;
--ok:#3fb950;--fuzzy:#d29922;--bad:#f85149;--accent:#58a6ff}
*{box-sizing:border-box}body{margin:0;font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--ink)}
header{padding:18px 24px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:5}
header h1{margin:0 0 6px;font-size:18px}
.banner{font-size:13px;color:var(--mut)}
.banner b{color:var(--ink)}.pill{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;margin-right:6px}
.pill.ok{background:rgba(63,185,80,.15);color:var(--ok)}.pill.fuzzy{background:rgba(210,153,34,.15);color:var(--fuzzy)}
.pill.bad{background:rgba(248,81,73,.18);color:var(--bad)}
.wrap{display:flex;gap:0;height:calc(100vh - 78px)}
.pane{overflow:auto;padding:22px 26px}.left{flex:1;border-right:1px solid var(--line)}
.right{flex:1;background:var(--panel)}
.right h2{font-size:13px;text-transform:uppercase;letter-spacing:.5px;color:var(--mut);margin:22px 0 8px}
.right .doc{white-space:pre-wrap;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;
background:#0d1117;border:1px solid var(--line);border-radius:8px;padding:14px}
h1,h2,h3,h4{line-height:1.3}.left h2{font-size:17px;margin-top:26px}.left h3{font-size:15px;color:var(--accent)}
a.cite{cursor:pointer;text-decoration:none;font-weight:600;font-size:.82em;padding:0 4px;border-radius:5px;
vertical-align:super;white-space:nowrap}
a.cite.ok{color:var(--ok);background:rgba(63,185,80,.12)}
a.cite.fuzzy{color:var(--fuzzy);background:rgba(210,153,34,.12)}
a.cite.bad{color:#fff;background:var(--bad)}
mark.hl{background:rgba(88,166,255,.22);color:inherit;border-radius:3px;padding:1px 0;scroll-margin:40vh}
.anchor{scroll-margin:40vh}
mark.flash,.flash{animation:fl 1.4s ease}@keyframes fl{0%{background:var(--accent);color:#0d1117}100%{}}
footer{border-top:1px solid var(--line);padding:14px 24px;color:var(--mut);font-size:12px}
code{background:#0d1117;border:1px solid var(--line);border-radius:4px;padding:1px 5px;font-size:.85em}
table.council{border-collapse:collapse;width:100%;margin:10px 0 26px;font-size:13px}
table.council th,table.council td{border:1px solid var(--line);padding:6px 9px;text-align:left;vertical-align:top}
table.council th{color:var(--mut);font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.4px}
.sup-supported{color:var(--ok)}.sup-partial{color:var(--fuzzy)}.sup-unsupported{color:var(--bad)}
.sup-na,.sup-unavailable{color:var(--mut)}
td.ok{color:var(--ok)}td.fuzzy{color:var(--fuzzy)}td.bad{color:var(--bad)}
"""

_JS = """
document.querySelectorAll('a.cite').forEach(function(a){
  a.addEventListener('click',function(e){
    e.preventDefault();
    var el=document.getElementById('src-'+a.dataset.cite);
    if(!el){return;}
    document.querySelectorAll('.flash').forEach(function(x){x.classList.remove('flash');});
    el.scrollIntoView({behavior:'smooth',block:'center'});
    el.classList.add('flash');
  });
});
"""


def _sup_class(support: str) -> str:
    return "sup-" + re.sub(r"[^a-z]", "", (support or "").lower())


def _council_table(citations: list[Citation], idx: dict) -> str:
    """L2 council readout — shown only when citations carry support verdicts."""
    if not any(c.support for c in citations):
        return ""
    rows = ["<h2>Citation council — L1 (quote is real) + L2 (quote supports the claim)</h2>",
            "<table class='council'><tr><th>#</th><th>L1 verbatim</th>"
            "<th>L2 support</th><th>judge synthesis</th></tr>"]
    for c in citations:
        if not c.support:
            continue
        n = idx[c.id]["n"]
        l1 = f'{_STATUS_GLYPH.get(c.status, "?")} {c.status}'
        rows.append(
            f'<tr><td>{n}</td>'
            f'<td class="{_STATUS_CLASS.get(c.status, "")}">{l1}</td>'
            f'<td class="{_sup_class(c.support)}">{_esc(c.support)}</td>'
            f'<td>{_esc(c.support_detail)}</td></tr>'
        )
    rows.append("</table>")
    return "".join(rows)


def build_html(title: str, response_md: str, citations: list[Citation],
               sources: list[Source], prov: dict) -> str:
    idx = {}
    for n, c in enumerate(citations, 1):
        idx[c.id] = {"n": n, "status": c.status, "support": c.support}
    body = _md_to_html(response_md, idx)

    cites_by_src: dict[str, list[Citation]] = {}
    for c in citations:
        cites_by_src.setdefault(c.source_id, []).append(c)
    src_html = []
    for s in sources:
        src_html.append(f'<h2>{_esc(s.label)} '
                        f'<span style="font-weight:400;text-transform:none">'
                        f'sha256 {prov["sources"][s.id]["sha256"][:12]}…</span></h2>')
        src_html.append('<div class="doc">' + _render_source_html(s, cites_by_src.get(s.id, [])) + "</div>")

    t = prov["tally"]
    banner = (f'<span class="pill ok">{t[STATUS_VERIFIED]} verified</span>'
              f'<span class="pill fuzzy">{t[STATUS_FUZZY]} fuzzy</span>'
              f'<span class="pill bad">{t[STATUS_NOT_FOUND]} not found</span>'
              f'&nbsp; grounding <b>{int(prov["grounding_rate"]*100)}%</b> '
              f'&nbsp; click any <b>[n]</b> to see the exact source quote')

    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        f"<title>{_esc(title)}</title><style>{_CSS}</style></head><body>"
        f"<header><h1>{_esc(title)}</h1><div class='banner'>{banner}</div></header>"
        f"<div class='wrap'><div class='pane left'>{body}{_council_table(citations, idx)}</div>"
        f"<div class='pane right'>{''.join(src_html)}</div></div>"
        f"<footer>prove-it deterministic provenance · generated {_esc(prov['generated'])} · "
        f"every citation verified verbatim against its source (L1). "
        f"<a class='cite ok' style='vertical-align:baseline'>[n✓]</a> exact "
        f"<a class='cite fuzzy' style='vertical-align:baseline'>[n≈]</a> whitespace-variant "
        f"<a class='cite bad' style='vertical-align:baseline'>[n✗]</a> NOT in source (possible fabrication)"
        f"<script type='application/json' id='provenance'>{json.dumps(prov)}</script></footer>"
        f"<script>{_JS}</script></body></html>"
    )


# ---------------------------------------------------------------------------
# Spec loading + CLI
# ---------------------------------------------------------------------------

def _load_source(s: dict) -> Source:
    if s.get("text") is not None:
        return Source(id=s["id"], label=s.get("label", s["id"]), text=s["text"])
    p = Path(s["path"]).expanduser()
    return Source(id=s["id"], label=s.get("label", p.name),
                  text=p.read_text(encoding="utf-8", errors="replace"))


def render(spec: dict) -> tuple[str, dict]:
    """Render a prove-it spec → (html, provenance). spec keys: title, response
    (markdown with [[cite:ID]] tokens), sources[], citations[].

    L2 seam: to add support verdicts, resolve citations yourself
    (``verify_all``), populate ``Citation.support`` / ``support_detail``, then
    call ``provenance`` + ``build_html`` directly.
    """
    sources = [_load_source(s) for s in spec["sources"]]
    cites = [Citation(id=str(c["id"]), claim=c["claim"], source_id=c["source_id"], quote=c["quote"])
             for c in spec["citations"]]
    verify_all(cites, sources)
    prov = provenance(sources, cites)
    return build_html(spec.get("title", "prove-it artifact"), spec["response"], cites, sources, prov), prov


def main() -> None:
    ap = argparse.ArgumentParser(description="Deterministic citation-provenance artifact builder")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("render", help="render a citations spec to a self-contained HTML artifact")
    r.add_argument("--input", required=True, help="path to citations.json spec")
    r.add_argument("--out", required=True, help="output .html path")
    args = ap.parse_args()

    spec = json.loads(Path(args.input).expanduser().read_text(encoding="utf-8"))
    htmlout, prov = render(spec)
    out = Path(args.out).expanduser()
    out.write_text(htmlout, encoding="utf-8")
    t = prov["tally"]
    print(f"prove-it: {out}")
    print(f"  {t[STATUS_VERIFIED]} verified, {t[STATUS_FUZZY]} fuzzy, "
          f"{t[STATUS_NOT_FOUND]} NOT-FOUND  (grounding {int(prov['grounding_rate']*100)}%)")
    if t[STATUS_NOT_FOUND]:
        print("  WARNING: not-found citations are unproven — possible fabrication or paste error.")
    # Cryptographic causation: record a signed IDR + memory-chain node for this
    # artifact. FAIL-OPEN — any recording failure is logged to stderr; the artifact
    # has already been written and this call NEVER re-raises.
    try:
        from grasp.provenance import record_proveit_provenance
        rec = record_proveit_provenance(spec, prov)
        if rec.get("ok"):
            print(f"  recorded: IDR {rec['idr_addr'][:24]}… memory {rec['memory_head'][:8]}…")
    except Exception as _exc:  # noqa: BLE001
        print(f"  [prove-it-provenance] recording degraded (artifact unaffected): {_exc}",
              file=sys.stderr)


if __name__ == "__main__":
    main()
