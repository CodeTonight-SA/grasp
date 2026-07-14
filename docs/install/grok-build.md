# Install GRASP in xAI Grok Build

Grok Build manages MCP servers with the `grok mcp` command group and
launches stdio servers directly. Verified against grok 0.2.101.

## 1. Put `grasp-mcp` on PATH

```bash
pipx install "git+https://github.com/CodeTonight-SA/grasp"
```

## 2. Add the server

```bash
grok mcp add grasp grasp-mcp
```

Check the wiring:

```bash
grok mcp list
grok mcp doctor
```

## 3. Behaviour contract

Grok Build reads `AGENTS.md` project rules (and, with Claude
compatibility enabled — the default — `CLAUDE.md` files too). Add the
GRASP contract to the `AGENTS.md` of any project where conduct should
be recorded:

```markdown
## GRASP conduct records
- Record consequential decisions with grasp_record_decision (what/why/how).
- Record reasoning-state changes with grasp_record_belief.
- Before asserting a verbatim quote from a file, prove it with
  grasp_prove_claim — a fabricated quote returns not_found and cannot pass.
```

## 4. Where records land

Records land in `~/.grasp/` (`idr.jsonl`, `context.jsonl`) — or wherever
`GRASP_HOME` points — and re-verify offline with this package alone:

```bash
grasp verify
```

Note on sandboxes: if you run Grok Build with `--sandbox read-only` or
`--sandbox strict`, writes outside the working directory are blocked and
the ledger cannot be appended. Either run without a sandbox profile for
recorded sessions, or point `GRASP_HOME` inside the session's working
directory.

## Why this pairing matters

After the July 2026 Grok Build repository-upload incident, the case for
signed, third-party-verifiable records of an agent's own conduct is not
theoretical. GRASP records what the agent decided, believed, and claimed
— locally, tamper-evidently, verifiable offline by anyone with this
package. The point is not trust in any vendor; it is that a skeptic can
check.
