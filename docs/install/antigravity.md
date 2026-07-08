# Install GRASP in Antigravity (agy)

Antigravity's `agy` CLI installs GRASP straight from this repository — this
exact flow was verified working live on 2026-07-08:

```bash
pipx install "git+https://github.com/CodeTonight-SA/grasp"   # puts grasp-mcp on PATH
agy plugin install https://github.com/CodeTonight-SA/grasp
```

The plugin registers the `grasp` MCP server (stdio, command `grasp-mcp`) with
the five tools: `grasp_record_decision`, `grasp_record_belief`,
`grasp_prove_claim`, `grasp_verify`, `grasp_status`.

The behaviour contract is the same on every host: record decisions before
consequential actions, checkpoint beliefs, prove quotes before asserting them
(a fabricated quote returns `not_found` — it cannot pass), and report
`grasp_verify` verdicts exactly as returned (VERIFIED / DEGRADED / BROKEN).

Records land in `~/.grasp/` (`idr.jsonl`, `context.jsonl`) — or wherever
`GRASP_HOME` points — and re-verify offline with this package alone.
