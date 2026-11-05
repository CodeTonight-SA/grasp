# grasp-mcp-seal -- a signed tool-call seal for Streamable HTTP MCP

`grasp-mcp-seal` is a reverse proxy for Streamable HTTP MCP. It sits between
any client -- including Anthropic's `mcp-proxy` -- and ONE fixed upstream MCP
server, and writes a signed, tamper-evident record of every `tools/call` it
forwards, using the same signers and chain (`grasp.idr`, `grasp.idr_forest`)
as the rest of GRASP.

## What it proves, and what it does not

**A record proves what THIS HOST recorded.** It does not prove that a call
happened, or that the recorded set is complete, against a host that lies
about its own log. If that matters to your deployment, anchor the chain's
head externally -- e.g. `grasp anchor`, or publish the head to a party you do
not control.

Prior art exists for signed MCP tool calls (`elang2/mcp-audit-gateway`,
Prismer's `Signet`, `correctover-mcp-gateway`, ScopeBlind's `protect-mcp`,
`mcp-glp-audit-proxy` -- found via search, not independently verified). This
is table stakes, not a novel mechanism: the useful part is that it is GRASP's
own signer and chain, reused rather than reimplemented, so it inherits the
rest of the package's verification story.

## Commitments, not plaintext

The chain never holds a tool's arguments or result in the clear. Each of the
two leaves a call produces --

- `mcp.tool.intent`, written BEFORE the call is forwarded, and
- `mcp.tool.outcome`, written AFTER the matching response is observed

-- commits to its payload as `sha256(salt || canonical_json(payload))`. The
per-record salt (and the plaintext it commits to) lives in a SEPARATE file,
`openings.jsonl` (mode 0600, never in the chain file itself), so an operator
can open one record to an auditor -- `grasp-mcp-seal verify --open RECORD_ID`
-- without publishing anything else on the chain.

If the intent cannot be written, the call is refused (`--on-seal-failure
refuse`, the default) and never reaches the upstream server. If the outcome
cannot be written, the result still reaches the caller; the failure is only
logged (`failures.jsonl`), and the intent shows up in `verify` as
**unsettled** -- a call that was recorded but whose outcome was never sealed.

## Run it

```bash
grasp-mcp-seal serve --upstream http://127.0.0.1:8080 \
    --listen 127.0.0.1:8091 --home ~/.grasp/mcp-seal
```

Binds to loopback (`127.0.0.1`) by default; a non-loopback bind needs the
explicit `--allow-remote-bind`. The upstream is fixed at start from
`--upstream` -- no header or body field can ever redirect it.

Offline verification, no account needed:

```bash
grasp-mcp-seal verify --home ~/.grasp/mcp-seal
grasp-mcp-seal verify --home ~/.grasp/mcp-seal --open <record-id> --json
```

`verify` re-checks every signature via `grasp.idr_forest` (the same
tamper-detection the rest of GRASP uses), then reports which intents have no
paired outcome yet.

## Wiring behind mcp-proxy

One sidecar per upstream. A typical `mcp-proxy` config routes a named path to
the seal, which itself points at the real upstream:

```yaml
mcpProxy:
  baseURL: https://your-tunnel-domain
  addr: :9090
  name: mcp-proxy
mcpServers:
  docs:
    transportType: streamablehttp
    url: http://seal:8091   # grasp-mcp-seal, NOT the real upstream directly
```

```bash
grasp-mcp-seal serve --upstream http://real-upstream:8080 --listen 0.0.0.0:8091
```

**Whether `mcp-proxy` preserves the client's `Host` header through to the
seal is unverified until first contact** -- nothing in this deployment may
depend on it. `grasp-mcp-seal` itself never trusts an incoming `Host`: it
always connects to the fixed `--upstream` host and port, and always sets its
OWN `Host` header on the outbound leg.

## What is forwarded, and what is not

- **Forwarded as-is**: the request path and query string, `Authorization`,
  `Mcp-Session-Id`, `Accept`, and every other header the client sent --
  including every value of a header sent more than once (two `Cookie` lines,
  say) -- except the hop-by-hop set (`Connection`, `Keep-Alive`,
  `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailers`,
  `Transfer-Encoding`, `Upgrade`, `Host`, `Content-Length` -- the last two are
  recomputed for the fixed upstream, never carried through verbatim).
- **Streamed, never buffered**: an SSE (`text/event-stream`) response is
  relayed to the client chunk by chunk as it arrives from upstream -- the
  seal never waits for the stream to end before forwarding what it has
  already received.
- **Sealed**: only `tools/call` JSON-RPC messages (recognised by method name,
  including inside a batch). Every other method -- `initialize`,
  `tools/list`, `resources/read`, plain notifications -- passes through
  unsealed.

## Capability lock

The default and only route this sidecar exposes is a plain reverse proxy to
one upstream. There is no bundled "nonce probe" or demo tool here -- pair
this with whatever capability-locked surface your deployment actually wants
reachable, and never route a server carrying personal or client data through
a tunnel with no zero-data-retention cover (see
`rules/untrusted-content-capability-lock.md` in the operator's own
instructions, if this is deployed inside GRIP).

## Benchmark

`tools/bench_mcp_seal.py` measures the added latency over a local upstream
(direct vs. proxied p50/p95, loopback only, stdlib only):

```bash
PYTHONPATH=. python3 tools/bench_mcp_seal.py --n 200
```
