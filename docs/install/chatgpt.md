# GRASP with ChatGPT (Developer mode)

**Honest status: remote-only, bridge required.** ChatGPT's full MCP client
(read *and* write tools) is a beta for Pro / Plus / Business / Enterprise /
Education accounts via **Developer mode**, and it connects to **remote MCP
servers only** — SSE or Streamable HTTP, with OAuth / no-auth / mixed auth.
ChatGPT **cannot connect to localhost**; endpoints must be public HTTPS.
`grasp-mcp` is a local stdio server, so a bridge is mandatory.

## Enable Developer mode

1. Workspace accounts: an admin first enables it under **Admin workspace
   settings → Permissions & Roles → Connected Data → Developer mode**
   (Enterprise/Edu admins control who may authorise connectors via RBAC).
2. Then in ChatGPT: **Settings → Apps → Advanced settings → Developer mode**.
   (OpenAI renamed "connectors" to "apps" as of 17 Dec 2025.)

OpenAI describes the mode as "powerful but dangerous" — it is intended for
developers who understand safe configuration and testing.

## Bridge `grasp-mcp` to a public HTTPS endpoint

Two documented patterns:

- **`mcp-remote` / gateway**: run a stdio→Streamable-HTTP proxy in front of
  `grasp-mcp` on infrastructure you control, behind HTTPS.
- **Tunnel**: expose that local bridge with an `ngrok`-style HTTPS tunnel for
  development.

There is no first-party hosted GRASP endpoint; you deploy the bridge
yourself, and the ledger (`~/.grasp/` or `GRASP_HOME`) lives where the bridge
runs — not inside ChatGPT.

## Behaviour inside ChatGPT

- GRASP's recording tools (`grasp_record_decision`, `grasp_record_belief`,
  `grasp_prove_claim`) are write tools: they do not set `readOnlyHint`, so
  ChatGPT treats them as write actions and asks for explicit confirmation
  per call. `grasp_verify` / `grasp_status` are read-shaped but are treated
  as write unless the server annotates `readOnlyHint`, which the current
  server does not.
- Verdicts come back exactly as computed (`verified` / `degraded` /
  `broken`); re-verify any time, offline, with the package alone — no server
  and no network.
