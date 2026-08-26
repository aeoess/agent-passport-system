# aps-mcp-1: pre-dispatch authorization for MCP `tools/call`

A signed, replay-claimed, delegation-referenced authorization object travels in
`params._meta` under `org.agent-passport/authorization`.
`createApsMcpToolCallMiddleware` is a pre-dispatch guard the wrapped handler
cannot bypass: transport authentication first, then signature, target,
arguments-hash and `action_ref` verification, a single-use replay claim, an
authority decision, and only then dispatch. The receipt is attached to the
result under `org.agent-passport/receipt`.

Issue and verify helpers: `issueApsMcpAuthorizationV1`,
`verifyApsMcpAuthorizationV1`, `computeMcpArgumentsHashV1`,
`canonicalMcpServerUri`.

## mcp-use

`createApsMcpUseMiddleware` adapts the profile to
[mcp-use](https://github.com/mcp-use/mcp-use) exact-method middleware. Register
it on `mcp:tools/call`.

```ts
import { MCPServer } from 'mcp-use'
import { createApsMcpUseMiddleware } from 'agent-passport-system'

const server = new MCPServer({ name: 'my-server', version: '1.0.0' })

server.use('mcp:tools/call', createApsMcpUseMiddleware({
  mcp_server: 'https://mcp.example',
  resolve_key: resolveHistoricalKey,
  consume_action_ref: (actionRef, expiresAt) => claims.consumeOnce(actionRef, expiresAt),
  evaluate_authority: (authorization, request) => authority.evaluate(authorization, request),
  emit_receipt: (authorization, authority, result) => receipts.sign(authorization, authority, result),
  // Only needed when the transport is not mcp-use OAuth. Default is fail closed.
  // transport_authenticated: (ctx) => myGateway.verified(ctx),
}))
```

`transport_authenticated` defaults to `Boolean(ctx.auth)`, which is set only
when mcp-use validated an OAuth bearer token. A host that terminates
authentication anywhere else MUST supply the function, or every call is refused
with `MCP_TRANSPORT_UNAUTHENTICATED`. Failing closed is deliberate.

A refusal reaches the client the way mcp-use reports any thrown middleware
error: HTTP 200 with a tool result carrying `isError: true` and the APS code as
its text content, not a JSON-RPC protocol error. A host matching on
`error.code` will not see it.

### What the adapter does NOT do

Copied from the profile, because the adapter changes none of it.

- It makes no allow or deny decision of its own. Every decision belongs to
  `evaluate_authority`, which the host supplies.
- It does not replace transport OAuth. It reads whether the transport already
  authenticated the caller and refuses when that is not established.
- It stores nothing. Replay defence is the host's `consume_action_ref`, and
  receipts are the host's `emit_receipt`.

mcp-use is a development dependency of this repository, used for the
conformance assertion and the integration test. It is not a runtime or peer
dependency, and no mcp-use type appears in the published declaration surface.
