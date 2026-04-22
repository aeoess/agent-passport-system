// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * MCP Mutual Authentication Adapter
 *
 * Layers APS mutual-auth on top of Anthropic's Model Context Protocol.
 * MCP deals in tool calls between a client (agent) and a server (IS).
 * This adapter binds both sides into a signed mutual-auth session so
 * that a tool call receipt can later reference which authenticated
 * session produced it.
 *
 * Composition boundary:
 *   MCP server/client handshake — capability discovery
 *   APS mutual-auth              — identity proof + session binding
 *   APS action receipts          — per-tool-call proof inside session
 *
 * This adapter works with any MCP server and any MCP client. It does
 * NOT depend on the MCP SDK. It is a pure mapping layer.
 */

import type {
  MutualAuthCertificate,
  MutualAuthPolicy,
  TrustAnchor,
  MutualAuthHello,
  MutualAuthAttest,
  MutualAuthResult,
  MutualAuthSession,
} from '../v2/mutual-auth/index.js'
import {
  buildHello,
  buildAttest,
  verifyAttest,
  deriveSession,
  chooseVersion,
  newNonce,
  isSessionActive,
} from '../v2/mutual-auth/index.js'

/** MCP-specific binding helper: convert an MCP server URL into the
 *  `binding` value for an IS certificate. */
export function mcpServerBinding(server_url: string): string {
  try {
    const u = new URL(server_url)
    return `mcp://${u.host}${u.pathname === '/' ? '' : u.pathname}`
  } catch {
    // Not a URL — treat as an opaque identifier
    return `mcp://${server_url}`
  }
}

/** Agent-side: start the handshake against an MCP server. */
export function mcpBeginHandshake(
  agent_cert: MutualAuthCertificate,
  now_ms: number,
  nonce_b64 = newNonce(),
): { hello: MutualAuthHello; agent_nonce: string } {
  return {
    hello: buildHello(
      'agent',
      agent_cert.supported_versions,
      now_ms,
      nonce_b64,
    ),
    agent_nonce: nonce_b64,
  }
}

/** Server-side: respond to an agent hello with the IS attest. */
export function mcpRespondHandshake(
  agent_hello: MutualAuthHello,
  is_cert: MutualAuthCertificate,
  is_sk_hex: string,
  accepted_versions: string[],
  now_ms: number,
  is_nonce_b64 = newNonce(),
): { attest: MutualAuthAttest; is_nonce: string } | { error: 'version_unsupported' } {
  const chosen = chooseVersion(agent_hello.supported_versions, accepted_versions)
  if (chosen === null) return { error: 'version_unsupported' }
  const attest = buildAttest(
    {
      role: 'information_system',
      chosen_version: chosen,
      own_nonce_b64: is_nonce_b64,
      peer_nonce_b64: agent_hello.nonce_b64,
      certificate: is_cert,
      now_ms,
    },
    is_sk_hex,
  )
  return { attest, is_nonce: is_nonce_b64 }
}

/** Agent-side: verify the IS attest, produce the agent attest back. */
export function mcpCounterAttest(
  is_attest: MutualAuthAttest,
  agent_cert: MutualAuthCertificate,
  agent_sk_hex: string,
  agent_nonce_b64: string,
  policy: MutualAuthPolicy,
  trust_anchors: TrustAnchor[],
  now_ms: number,
  revoked_anchor_ids?: string[],
):
  | { attest: MutualAuthAttest }
  | { error: string; detail?: string } {
  const res = verifyAttest({
    attest: is_attest,
    expected_peer_nonce_b64: agent_nonce_b64,
    expected_own_nonce_b64: is_attest.own_nonce_b64,
    policy,
    trust_anchors,
    revoked_anchor_ids,
    now_ms,
  })
  if (!res.ok) {
    return { error: res.reason ?? 'verification_failed', detail: res.detail }
  }
  const attest = buildAttest(
    {
      role: 'agent',
      chosen_version: is_attest.chosen_version,
      own_nonce_b64: agent_nonce_b64,
      peer_nonce_b64: is_attest.own_nonce_b64,
      certificate: agent_cert,
      now_ms,
    },
    agent_sk_hex,
  )
  return { attest }
}

/** Server-side: verify the agent attest, derive the shared session. */
export function mcpFinalizeSession(
  agent_attest: MutualAuthAttest,
  is_attest: MutualAuthAttest,
  policy: MutualAuthPolicy,
  trust_anchors: TrustAnchor[],
  now_ms: number,
  revoked_anchor_ids?: string[],
): MutualAuthResult {
  const res = verifyAttest({
    attest: agent_attest,
    expected_peer_nonce_b64: is_attest.own_nonce_b64,
    expected_own_nonce_b64: agent_attest.own_nonce_b64,
    policy,
    trust_anchors,
    revoked_anchor_ids,
    now_ms,
  })
  if (!res.ok) {
    return {
      ok: false,
      failure: { reason: res.reason ?? 'signature_invalid', detail: res.detail },
    }
  }
  return deriveSession(agent_attest, is_attest, policy, now_ms)
}

/** Helper: check whether an MCP tool call is permitted under the
 *  established session. Verifies (a) session is still active and
 *  (b) the session's IS cert binding matches the MCP server URL. */
export interface MCPToolCallAuthCheck {
  session: MutualAuthSession
  server_url: string
  now_ms: number
}

export function mcpIsToolCallPermitted(
  input: MCPToolCallAuthCheck,
): { ok: boolean; reason?: string } {
  if (!isSessionActive(input.session, input.now_ms)) {
    return { ok: false, reason: 'expired_session' }
  }
  const expected = mcpServerBinding(input.server_url)
  if (input.session.is_cert.binding !== expected) {
    return { ok: false, reason: 'binding_mismatch' }
  }
  return { ok: true }
}
