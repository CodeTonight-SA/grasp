# GRASP with Claude for Work (claude.ai / Cowork)

**Honest status: remote-only, bridge required.** Claude for Work supports MCP
through **custom connectors to remote servers only** — there is no stdio/local
server support on claude.ai or in Cowork, and plugins with local MCP servers
work desktop-only. `grasp-mcp` is a local stdio server, so it cannot be added
to claude.ai directly, and we do not claim otherwise.

## What works today

- **Claude Desktop** (available on paid plans): use the local stdio path —
  see [claude-desktop.md](claude-desktop.md). Records stay on your machine.
- **Claude Code**: the plugin path — see [claude-code.md](claude-code.md).

## The stdio → remote bridge option (self-hosted)

To reach claude.ai/Cowork you must expose the server as a **remote MCP
endpoint over HTTPS, reachable on the public internet** (VPN- or
firewall-blocked servers cannot connect):

1. Host `grasp-mcp` behind a stdio→Streamable-HTTP MCP gateway of your choice
   on an HTTPS URL. GRASP does not bundle a gateway and there is no
   first-party hosted GRASP endpoint — you deploy and secure this yourself.
   The ledger (`~/.grasp/` or `GRASP_HOME`) then lives where the bridge runs.
2. In claude.ai: **Organization settings → Connectors → Add** (Owners, on
   Team/Enterprise), enter the remote server URL; OAuth Client ID/Secret go
   under **Advanced** if your gateway requires them. Individual users then
   enable the connector and authorise once. With enterprise-managed auth
   (beta), an Owner can authorise once for the whole org.

## Caveats worth knowing before you commit

- Cowork sessions run isolated on Anthropic's servers; org network egress
  settings do not apply to MCP calls from Cowork.
- Known issue (April 2026): custom remote MCP connectors prompt for
  permission on **every tool call** in Cowork, and "Allow all for this task"
  is greyed out — with no org-level per-tool permission control. GRASP's
  record-before-every-consequential-action contract multiplies those prompts;
  weigh that before rolling out to a team.
