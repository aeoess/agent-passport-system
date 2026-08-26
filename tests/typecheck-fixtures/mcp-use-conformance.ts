// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

/**
 * Compile-time conformance fixture. Never executed.
 *
 * Asserts that the value returned by createApsMcpUseMiddleware satisfies
 * mcp-use's exact-method middleware type for the 'mcp:tools/call' pattern.
 * This is the only place mcp-use types are referenced, and it is outside the
 * package's emitted declaration surface: tsconfig.json excludes tests/.
 *
 * Checked by `npm run typecheck:mcp-use`, which the Node 22 test leg runs.
 */
import type { McpMiddlewareFnFor } from 'mcp-use'
import { createApsMcpUseMiddleware } from '../../src/profiles/mcp/mcp-use-adapter-v1.js'

const middleware = createApsMcpUseMiddleware({
  mcp_server: 'https://mcp.example',
  resolve_key: () => ({ state: 'resolved', public_key_hex: '00' }),
  consume_action_ref: () => true,
  evaluate_authority: () => ({ state: 'permit', code: 'OK' }),
  emit_receipt: () => ({}),
})

export const assertExactMiddlewareShape: McpMiddlewareFnFor<'mcp:tools/call'> = middleware
