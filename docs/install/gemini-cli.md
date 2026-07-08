# Install GRASP in Gemini CLI

This repository doubles as a Gemini CLI extension (`gemini-extension.json` +
`GEMINI.md`). Two commands and the agent records what it decides, believes,
and claims:

```bash
pipx install "git+https://github.com/CodeTonight-SA/grasp"   # puts grasp-mcp on PATH
gemini extensions install https://github.com/CodeTonight-SA/grasp
```

That is the whole install. The extension registers the `grasp` MCP server
(stdio, command `grasp-mcp`), and its `GEMINI.md` context file instructs the
model to:

- call `grasp_record_decision` before consequential actions,
- call `grasp_record_belief` at checkpoints (cross-linking the decision chain
  via `records_idr`),
- call `grasp_prove_claim` before asserting any sourced quotation — a
  fabricated quote returns `not_found` and cannot pass,
- report `grasp_verify` verdicts exactly as returned
  (VERIFIED / DEGRADED / BROKEN).

Records land in `~/.grasp/` (`idr.jsonl`, `context.jsonl`) — or wherever
`GRASP_HOME` points — and re-verify with this package alone, no server and no
network.
