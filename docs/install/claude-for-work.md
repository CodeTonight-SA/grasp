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

To reach claude.ai/Cowork specifically, you must expose the server as a
**remote MCP endpoint over HTTPS, reachable on the public internet** —
claude.ai's Connectors route (the one this page covers) has no tunnel option
of its own, so a VPN- or firewall-blocked server cannot connect through it:

1. Host `grasp-mcp` behind a stdio→Streamable-HTTP MCP gateway of your choice
   on an HTTPS URL. GRASP does not bundle a gateway and there is no
   first-party hosted GRASP endpoint — you deploy and secure this yourself.
   The ledger (`~/.grasp/` or `GRASP_HOME`) then lives where the bridge runs.
2. In claude.ai: **Organization settings → Connectors → Add** (Owners, on
   Team/Enterprise), enter the remote server URL; OAuth Client ID/Secret go
   under **Advanced** if your gateway requires them. Individual users then
   enable the connector and authorise once. With enterprise-managed auth
   (beta), an Owner can authorise once for the whole org.

If your organisation instead builds on **Claude Managed Agents** or the
**Messages API** — a separate product, configured in the Claude Console, not
claude.ai — **MCP tunnels** let a Managed Agent reach a private, firewalled
`grasp-mcp` bridge without a public endpoint at all (workspace settings,
research preview at the time of writing). That does not change anything
above: it is a different way to reach Claude, not a new way to reach
claude.ai itself.

## Securing the bridge

A `grasp-mcp` process behind a public or org-wide gateway is reachable by
anyone the gateway lets through, so decide these before you expose it:

- **`source_path`.** Off by default — `grasp_prove_claim` refuses a
  `source_path` argument unless `GRASP_SOURCE_ROOTS` names the directories
  the bridge may read from (an `os.pathsep`-separated list of absolute
  paths). Leave it unset so callers must pass `source_text` directly, or set
  it to the narrowest tree that actually holds the documents you want
  provable — never the bridge's own working directory, which often holds
  its own secrets.
- **Authentication.** `grasp-mcp` itself has none: the gateway in front of
  it is where OAuth, an API key, or mTLS belongs. Anyone who can reach the
  bridge unauthenticated can record decisions and claims under its ledger.
- **`GRASP_GENESIS_ANCHOR`.** A shared, long-lived bridge process can serve
  many callers over time, so the default placeholder genesis
  (`human:mcp-operator`) is not a real claim about who started it. Set
  `GRASP_GENESIS_ANCHOR` to the anchor this deployment actually roots at —
  `human:<operator-id>`, `ci:<pipeline-id>`, `council:<verdict-id>`, or
  `hypo:<hypothesis-id>` — so the ledger's genesis is honest rather than
  borrowed from a single-operator default.

## Caveats worth knowing before you commit

- Cowork sessions run isolated on Anthropic's servers; org network egress
  settings do not apply to MCP calls from Cowork.
- Known issue (April 2026): custom remote MCP connectors prompt for
  permission on **every tool call** in Cowork, and "Allow all for this task"
  is greyed out — with no org-level per-tool permission control. GRASP's
  record-before-every-consequential-action contract multiplies those prompts;
  weigh that before rolling out to a team.
