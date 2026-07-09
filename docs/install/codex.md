# Install GRASP in OpenAI Codex CLI

Codex CLI configures MCP servers in TOML — `~/.codex/config.toml` globally, or
a project-scoped `.codex/config.toml` in trusted projects. The Codex CLI and
the Codex IDE extension share this config.

## 1. Put `grasp-mcp` on PATH

```bash
pipx install "git+https://github.com/CodeTonight-SA/grasp"
```

## 2. Add the server

In `~/.codex/config.toml`:

```toml
[mcp_servers.grasp]
command = "grasp-mcp"
```

Useful optional keys on the same table:

```toml
[mcp_servers.grasp]
command = "grasp-mcp"
env = { GRASP_HOME = "/absolute/path/for/the/ledger" }  # default: ~/.grasp
startup_timeout_sec = 20
tool_timeout_sec = 60
# enabled = false                        # park it without deleting the entry
# enabled_tools = ["grasp_verify"]       # allow list, applied before deny list
# default_tools_approval_mode = "prompt" # auto | prompt | approve
```

Per-tool approval overrides are supported
(`tools.grasp_record_decision.approval_mode = "auto"`), and `required = true`
makes Codex fail startup if the server is unavailable — a reasonable setting
when the whole point is that conduct is recorded.

## 3. Manage from the CLI

The `codex mcp` command manages servers, and any key can be overridden per
invocation with dot-notation config flags:

```bash
codex --config mcp_servers.grasp.enabled=false ...
```

Records land in `~/.grasp/` (`idr.jsonl`, `context.jsonl`) — or wherever
`GRASP_HOME` points — and re-verify offline with this package alone.
