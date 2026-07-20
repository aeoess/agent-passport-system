// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign, verify } from '../../crypto/keys.js'
import {
  computeActionRefV2,
  createActionReferenceInputV2,
} from '../../v2/action-reference/v2.js'
import type { HistoricalKeyResolver } from '../../v2/identity-binding/types.js'
import {
  assertExactKeys,
  assertHex,
  assertIJson,
  assertPlainRecord,
  assertSortedUnique,
  assertUtcMilliseconds,
  sortedUnique,
} from '../../v2/identity-binding/validation.js'

export const APS_MCP_AUTHORIZATION_META = 'org.agent-passport/authorization'
export const APS_MCP_RECEIPT_META = 'org.agent-passport/receipt'
const INTENT_DOMAIN = 'APS-MCP-INTENT-V1\0'
const ARGUMENTS_DOMAIN = 'APS-MCP-ARGUMENTS-V1\0'

export interface ApsMcpSpendV1 {
  unit: string
  amount: string
}

export interface ApsMcpAuthorizationV1 {
  profile: 'aps-mcp-1'
  agent_id: string
  verification_method: string
  delegation_ref: string
  mcp_server: string
  method: 'tools/call'
  tool_name: string
  arguments_hash: string
  scope_required: string[]
  spend?: ApsMcpSpendV1
  nonce: string
  issued_at: string
  expires_at: string
  action_ref: string
  signature: string
}

export interface McpToolCallRequest {
  method: 'tools/call'
  params: {
    name: string
    arguments?: Record<string, unknown>
    _meta?: Record<string, unknown>
  }
}

export interface McpToolCallResult extends Record<string, unknown> {
  _meta?: Record<string, unknown>
}

export interface ApsMcpAuthorityDecision {
  state: 'permit' | 'deny' | 'indeterminate'
  code: string
  decision_ref?: string
}

export interface ApsMcpMiddlewareContext {
  /** Set only after MCP transport OAuth/resource validation has succeeded. */
  transport_authenticated: boolean
}

export class ApsMcpAuthorizationError extends Error {
  constructor(readonly code: string) {
    super(code)
    this.name = 'ApsMcpAuthorizationError'
  }
}

export function computeMcpArgumentsHashV1(argumentsValue: Record<string, unknown>): string {
  assertIJson(argumentsValue)
  return createHash('sha256')
    .update(ARGUMENTS_DOMAIN + canonicalizeJCS(argumentsValue), 'utf8')
    .digest('hex')
}

export function issueApsMcpAuthorizationV1(input: {
  agent_id: string
  verification_method: string
  delegation_ref: string
  mcp_server: string
  tool_name: string
  arguments: Record<string, unknown>
  scope_required: readonly string[]
  spend?: ApsMcpSpendV1
  nonce: string
  issued_at: string
  expires_at: string
  private_key_hex: string
}): ApsMcpAuthorizationV1 {
  const server = canonicalMcpServerUri(input.mcp_server)
  const argumentsHash = computeMcpArgumentsHashV1(input.arguments)
  const scopes = sortedUnique(
    input.scope_required.map((scope) => scope.normalize('NFC')),
    'scope_required',
  )
  const actionRef = computeActionRefV2(createActionReferenceInputV2({
    agent_id: input.agent_id,
    action_type: 'mcp:tools/call',
    target: `${server}#tool=${encodeURIComponent(input.tool_name)}`,
    payload_ref: argumentsHash,
    scope_required: scopes,
    issued_at: input.issued_at,
    nonce: input.nonce,
  }))
  const unsigned: Omit<ApsMcpAuthorizationV1, 'signature'> = {
    profile: 'aps-mcp-1',
    agent_id: input.agent_id,
    verification_method: input.verification_method,
    delegation_ref: input.delegation_ref,
    mcp_server: server,
    method: 'tools/call',
    tool_name: input.tool_name,
    arguments_hash: argumentsHash,
    scope_required: scopes,
    ...(input.spend === undefined ? {} : { spend: input.spend }),
    nonce: input.nonce,
    issued_at: input.issued_at,
    expires_at: input.expires_at,
    action_ref: actionRef,
  }
  validateAuthorizationUnsigned(unsigned)
  return {
    ...unsigned,
    signature: sign(INTENT_DOMAIN + canonicalizeJCS(unsigned), input.private_key_hex),
  }
}

export async function verifyApsMcpAuthorizationV1(
  candidate: unknown,
  expected: {
    mcp_server: string
    tool_name: string
    arguments: Record<string, unknown>
    now?: string
    resolve_key: HistoricalKeyResolver
  },
): Promise<{ state: 'valid' | 'invalid' | 'indeterminate'; code: string; authorization?: ApsMcpAuthorizationV1 }> {
  let authorization: ApsMcpAuthorizationV1
  try {
    authorization = validateAuthorization(candidate)
  } catch {
    return { state: 'invalid', code: 'MCP_AUTHORIZATION_MALFORMED' }
  }
  const expectedServer = canonicalMcpServerUri(expected.mcp_server)
  if (authorization.mcp_server !== expectedServer || authorization.tool_name !== expected.tool_name) {
    return { state: 'invalid', code: 'MCP_TARGET_MISMATCH' }
  }
  const argumentsHash = computeMcpArgumentsHashV1(expected.arguments)
  if (argumentsHash !== authorization.arguments_hash) {
    return { state: 'invalid', code: 'MCP_ARGUMENTS_MISMATCH' }
  }
  const recomputedActionRef = computeActionRefV2(createActionReferenceInputV2({
    agent_id: authorization.agent_id,
    action_type: 'mcp:tools/call',
    target: `${authorization.mcp_server}#tool=${encodeURIComponent(authorization.tool_name)}`,
    payload_ref: authorization.arguments_hash,
    scope_required: authorization.scope_required,
    issued_at: authorization.issued_at,
    nonce: authorization.nonce,
  }))
  if (recomputedActionRef !== authorization.action_ref) {
    return { state: 'invalid', code: 'MCP_ACTION_REF_MISMATCH' }
  }
  const now = expected.now ?? new Date().toISOString()
  if (now < authorization.issued_at || now >= authorization.expires_at) {
    return { state: 'invalid', code: 'MCP_AUTHORIZATION_NOT_CURRENT' }
  }
  const resolution = await expected.resolve_key({
    controller: authorization.agent_id,
    verification_method: authorization.verification_method,
    at: authorization.issued_at,
  })
  if (resolution.state !== 'resolved' || !resolution.public_key_hex) {
    return {
      state: resolution.state === 'unreachable' ? 'indeterminate' : 'invalid',
      code: `MCP_SIGNING_KEY_${resolution.state.toUpperCase()}`,
    }
  }
  const unsigned = omit(authorization, ['signature'])
  if (!verify(INTENT_DOMAIN + canonicalizeJCS(unsigned), authorization.signature, resolution.public_key_hex)) {
    return { state: 'invalid', code: 'MCP_SIGNATURE_INVALID' }
  }
  return { state: 'valid', code: 'OK', authorization }
}

/**
 * Creates an unavoidable pre-dispatch guard for an MCP tools/call handler.
 * Transport OAuth is checked first. The APS intent, replay claim, authority
 * decision, and budget reservation all complete before dispatch is invoked.
 */
export function createApsMcpToolCallMiddleware(options: {
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
}) {
  return async function apsMcpToolCall(
    request: McpToolCallRequest,
    context: ApsMcpMiddlewareContext,
    dispatch: (request: McpToolCallRequest) => McpToolCallResult | Promise<McpToolCallResult>,
  ): Promise<McpToolCallResult> {
    if (!context.transport_authenticated) throw new ApsMcpAuthorizationError('MCP_TRANSPORT_UNAUTHENTICATED')
    if (request.method !== 'tools/call') throw new ApsMcpAuthorizationError('MCP_METHOD_UNSUPPORTED')
    const metadata = request.params._meta
    const candidate = metadata?.[APS_MCP_AUTHORIZATION_META]
    const verification = await verifyApsMcpAuthorizationV1(candidate, {
      mcp_server: options.mcp_server,
      tool_name: request.params.name,
      arguments: request.params.arguments ?? {},
      resolve_key: options.resolve_key,
    })
    if (verification.state !== 'valid' || !verification.authorization) {
      throw new ApsMcpAuthorizationError(verification.code)
    }
    if (!await options.consume_action_ref(
      verification.authorization.action_ref,
      verification.authorization.expires_at,
    )) throw new ApsMcpAuthorizationError('MCP_ACTION_REPLAY')

    const authority = await options.evaluate_authority(verification.authorization, request)
    if (authority.state !== 'permit') throw new ApsMcpAuthorizationError(authority.code)

    const dispatched = await dispatch(request)
    const receipt = await options.emit_receipt(verification.authorization, authority, dispatched)
    return {
      ...dispatched,
      _meta: {
        ...(dispatched._meta ?? {}),
        [APS_MCP_RECEIPT_META]: receipt,
      },
    }
  }
}

export function canonicalMcpServerUri(value: string): string {
  const parsed = new URL(value)
  if (!['https:', 'http:'].includes(parsed.protocol) || parsed.username || parsed.password || parsed.hash) {
    throw new Error('Invalid MCP server resource URI')
  }
  if (parsed.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(parsed.hostname)) {
    throw new Error('MCP server resource URI requires HTTPS outside localhost')
  }
  if (parsed.pathname === '/' && !parsed.search) parsed.pathname = ''
  return parsed.toString().replace(/\/$/, '')
}

function validateAuthorization(candidate: unknown): ApsMcpAuthorizationV1 {
  assertPlainRecord(candidate, 'MCP authorization')
  assertExactKeys(candidate, [
    'profile', 'agent_id', 'verification_method', 'delegation_ref', 'mcp_server',
    'method', 'tool_name', 'arguments_hash', 'scope_required', 'nonce',
    'issued_at', 'expires_at', 'action_ref', 'signature',
  ], ['spend'], 'MCP authorization')
  const unsigned = omit(candidate, ['signature']) as unknown as Omit<ApsMcpAuthorizationV1, 'signature'>
  validateAuthorizationUnsigned(unsigned)
  assertHex(String(candidate.signature), 128, 'signature')
  return candidate as unknown as ApsMcpAuthorizationV1
}

function validateAuthorizationUnsigned(value: Omit<ApsMcpAuthorizationV1, 'signature'>): void {
  assertIJson(value)
  if (value.profile !== 'aps-mcp-1' || value.method !== 'tools/call') throw new Error('MCP profile')
  if (!/^did:[a-z0-9]+:.+$/.test(value.agent_id)) throw new Error('agent_id')
  if (!value.verification_method.startsWith(`${value.agent_id}#`)) throw new Error('verification_method')
  if (typeof value.delegation_ref !== 'string' || value.delegation_ref.length === 0) throw new Error('delegation_ref')
  if (canonicalMcpServerUri(value.mcp_server) !== value.mcp_server) throw new Error('non-canonical mcp_server')
  if (!/^[A-Za-z0-9_.-]{1,128}$/.test(value.tool_name)) throw new Error('tool_name')
  assertHex(value.arguments_hash, 64, 'arguments_hash')
  if (!Array.isArray(value.scope_required)) throw new Error('scope_required')
  assertSortedUnique(value.scope_required, 'scope_required')
  for (const scope of value.scope_required) if (scope !== scope.normalize('NFC')) throw new Error('scope_required NFC')
  if (value.spend !== undefined) {
    assertPlainRecord(value.spend, 'spend')
    assertExactKeys(value.spend, ['unit', 'amount'], [], 'spend')
    if (!/^[A-Za-z0-9:._-]{1,64}$/.test(value.spend.unit)) throw new Error('spend unit')
    if (!/^(0|[1-9]\d{0,18})$/.test(value.spend.amount)) throw new Error('spend amount')
  }
  assertHex(value.nonce, 32, 'nonce')
  assertUtcMilliseconds(value.issued_at, 'issued_at')
  assertUtcMilliseconds(value.expires_at, 'expires_at')
  if (value.issued_at >= value.expires_at) throw new Error('authorization time window')
  assertHex(value.action_ref, 64, 'action_ref')
}

function omit(value: object, keys: readonly string[]): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) if (!keys.includes(key)) result[key] = entry
  return result
}
