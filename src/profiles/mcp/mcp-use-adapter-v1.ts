// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

/**
 * mcp-use adapter for the aps-mcp-1 pre-dispatch authorization profile.
 *
 * Registers as an exact-method middleware on `mcp:tools/call`:
 *
 *     server.use('mcp:tools/call', createApsMcpUseMiddleware({ ... }))
 *
 * The adapter is a shape translation and nothing else. It maps mcp-use's
 * middleware context onto the profile's `(request, context, dispatch)` call and
 * returns the profile's result unchanged. Every authorization decision stays in
 * `createApsMcpToolCallMiddleware`.
 *
 * TYPE SURFACE. The context and next types below are declared structurally so
 * that `mcp-use` never appears in this package's emitted declarations. mcp-use
 * is a devDependency used for compile-time conformance assertions and the
 * integration test, not a runtime or peer dependency. `ApsMcpUseContext` is
 * deliberately a subset of mcp-use's `MiddlewareContext<'tools/call'>`: it
 * requires only the members this adapter reads, which is what lets the returned
 * function satisfy `McpMiddlewareFnFor<'mcp:tools/call'>` by structural
 * assignability without importing anything.
 */

import {
  createApsMcpToolCallMiddleware,
  type ApsMcpAuthorityDecision,
  type ApsMcpAuthorizationV1,
  type McpToolCallRequest,
  type McpToolCallResult,
} from './authorization-v1.js'
import type { HistoricalKeyResolver } from '../../v2/identity-binding/types.js'

/**
 * The members of an mcp-use middleware context that this adapter reads.
 *
 * A subset, on purpose. mcp-use's own context carries a Hono context, a session
 * and a shared state map; none of them are needed to authorize a tool call, and
 * requiring them here would couple the APS declaration surface to mcp-use.
 */
export interface ApsMcpUseContext {
  /** Always `tools/call` for a middleware registered on `mcp:tools/call`. */
  readonly method: 'tools/call'
  /** SDK `CallToolRequest` params. */
  readonly params: {
    readonly name: string
    readonly arguments?: Record<string, unknown>
    readonly _meta?: Record<string, unknown>
  }
  /**
   * Present only when the transport validated an OAuth bearer token.
   *
   * The adapter treats presence as proof of transport authentication and
   * absence as failure. A host that authenticates by some other means must say
   * so through `transport_authenticated`.
   */
  readonly auth?: unknown
}

/**
 * Continue the mcp-use middleware chain and dispatch the tool call.
 *
 * Generic in the result so the adapter is result-type-preserving: whatever the
 * host's chain returns for `tools/call` is what the adapter returns, with the
 * APS receipt added under `_meta`. That is what lets the returned function
 * satisfy mcp-use's exact-method middleware type, whose `next` and return type
 * are both the SDK's `tools/call` result rather than `unknown`.
 */
export type ApsMcpUseNext<TResult = McpToolCallResult> = () => Promise<TResult>

/** Options accepted by {@link createApsMcpUseMiddleware}. */
export interface ApsMcpUseMiddlewareOptions {
  mcp_server: string
  resolve_key: HistoricalKeyResolver
  consume_action_ref: (actionRef: string, expiresAt: string) => boolean | Promise<boolean>
  evaluate_authority: (
    authorization: ApsMcpAuthorizationV1,
    request: McpToolCallRequest,
  ) => ApsMcpAuthorityDecision | Promise<ApsMcpAuthorityDecision>
  emit_receipt: (
    authorization: ApsMcpAuthorizationV1,
    authority: ApsMcpAuthorityDecision,
    result: McpToolCallResult,
  ) => unknown | Promise<unknown>
  /**
   * Decide whether the transport already authenticated this request.
   *
   * Omit it and the adapter uses `Boolean(ctx.auth)`, which is true only when
   * mcp-use validated an OAuth bearer token. A host that terminates
   * authentication elsewhere, mutual TLS or a trusted gateway for example, MUST
   * supply this function; otherwise every call is refused with
   * `MCP_TRANSPORT_UNAUTHENTICATED`. The default is fail closed on purpose.
   */
  transport_authenticated?: (ctx: ApsMcpUseContext) => boolean | Promise<boolean>
}

/**
 * Build an mcp-use exact-method middleware for `mcp:tools/call`.
 *
 * Throws {@link ApsMcpAuthorizationError} before calling `next()` when
 * authorization fails, so the tool never dispatches.
 */
export function createApsMcpUseMiddleware(options: ApsMcpUseMiddlewareOptions) {
  const { transport_authenticated, ...profileOptions } = options
  const middleware = createApsMcpToolCallMiddleware(profileOptions)

  return async function apsMcpUseToolCall<TResult extends McpToolCallResult>(
    ctx: ApsMcpUseContext,
    next: ApsMcpUseNext<TResult>,
  ): Promise<TResult> {
    const authenticated = transport_authenticated === undefined
      ? Boolean(ctx.auth)
      : await transport_authenticated(ctx)

    const request: McpToolCallRequest = {
      method: 'tools/call',
      params: {
        name: ctx.params.name,
        ...(ctx.params.arguments === undefined ? {} : { arguments: ctx.params.arguments }),
        ...(ctx.params._meta === undefined ? {} : { _meta: ctx.params._meta }),
      },
    }

    // The profile spreads the dispatched result and adds only `_meta`, so the
    // value that comes back is the host's own TResult with the receipt attached.
    // That is why this narrowing is sound rather than a widening to `any`.
    return await middleware(
      request,
      { transport_authenticated: authenticated },
      async () => await next(),
    ) as TResult
  }
}
