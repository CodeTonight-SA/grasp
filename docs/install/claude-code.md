# Install GRASP in Claude Code

GRASP ships as a Claude Code plugin. This repository is both the plugin
(`.claude-plugin/plugin.json`) and a one-plugin marketplace
(`.claude-plugin/marketplace.json`), so it installs straight from GitHub.

## 1. Put `grasp-mcp` on PATH

The plugin launches the MCP server by command name, so install the package
first:

```bash
pipx install "git+https://github.com/CodeTonight-SA/grasp"
```

## 2. Install the plugin

```bash
claude plugin marketplace add CodeTonight-SA/grasp
claude plugin install grasp@CodeTonight-SA/grasp
```

That registers:

- the `grasp` MCP server (stdio, command `grasp-mcp`) with the five tools —
  `grasp_record_decision`, `grasp_record_belief`, `grasp_prove_claim`,
  `grasp_verify`, `grasp_status`;
- the `grasp-provenance` skill (`skills/grasp-provenance/SKILL.md`) carrying
  the behaviour contract: record decisions before consequential actions,
  checkpoint beliefs, prove quotes before asserting them, and report
  `grasp_verify` verdicts exactly as returned (VERIFIED / DEGRADED / BROKEN).

## Alternative: project-scoped MCP config (no plugin)

This repo carries a root `.mcp.json`; any project can use the same one-line
server entry:

```json
{ "mcpServers": { "grasp": { "command": "grasp-mcp" } } }
```

## Developing or auditing the plugin locally

```bash
claude --plugin-dir .      # load this checkout as a local plugin for testing
claude plugin validate     # check plugin.json and component syntax
```

`/reload-plugins` inside a session picks up changes without a restart.

Records land in `~/.grasp/` (`idr.jsonl`, `context.jsonl`) — or wherever
`GRASP_HOME` points — and re-verify offline with this package alone.
