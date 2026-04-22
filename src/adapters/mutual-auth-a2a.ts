// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * A2A Mutual Authentication Adapter
 *
 * Layers APS mutual-auth on top of Google A2A Agent Cards. A2A v1.0
 * introduced Signed Agent Cards, which let an agent cryptographically
 * present itself. This adapter closes the asymmetry by also letting
 * an information system present a certificate the agent verifies.
 *
 * Composition boundary:
 *   A2A Agent Card  — identity discovery (agent → network)
 *   APS passport    — identity + delegation + attestation grade
 *   MutualAuthCert  — binding of either party into the handshake
 *
 * This adapter does NOT replace A2A's signed cards. It carries an
 * additional MutualAuthCertificate alongside the card, for scenarios
 * where the peer is an IS (not another agent) and downgrade-proof
 * mutual auth is required.
 */

import type { A2AAgentCard } from '../types/a2a.js'
import type {
  MutualAuthCertificate,
  MutualAuthPolicy,
  TrustAnchor,
  MutualAuthHello,
  MutualAuthAttest,
  MutualAuthResult,
} from '../v2/mutual-auth/index.js'
import {
  buildHello,
  buildAttest,
  verifyAttest,
  deriveSession,
  chooseVersion,
} from '../v2/mutual-auth/index.js'

/** Envelope carrying an A2A card + the mutual-auth certificate that
 *  binds its identity into handshake scope. */
export interface A2AMutualAuthEnvelope {
  card: A2AAgentCard
  certificate: MutualAuthCertificate
}

/** Initiate an A2A mutual-auth exchange from the agent side.
 *  Caller owns the nonce supply (or pass none to auto-generate). */
export function a2aBeginHandshake(
  envelope: A2AMutualAuthEnvelope,
  now_ms: number,
  nonce_b64?: string,
): { hello: MutualAuthHello; envelope: A2AMutualAuthEnvelope } {
  const hello = buildHello(
    'agent',
    envelope.certificate.supported_versions,
    now_ms,
    nonce_b64,
  )
  return { hello, envelope }
}

/** The IS side: given the agent's hello, build the IS's attest. */
export function a2aRespondHandshake(
  peer_hello: MutualAuthHello,
  own_envelope: A2AMutualAuthEnvelope,
  own_sk_hex: string,
  accepted_versions: string[],
  now_ms: number,
  own_nonce_b64?: string,
): MutualAuthAttest | { error: 'version_unsupported' } {
  const chosen = chooseVersion(peer_hello.supported_versions, accepted_versions)
  if (chosen === null) return { error: 'version_unsupported' }
  const { newNonce } = require('../v2/mutual-auth/handshake.js')
  const nonce = own_nonce_b64 ?? newNonce()
  return buildAttest(
    {
      role: 'information_system',
      chosen_version: chosen,
      own_nonce_b64: nonce,
      peer_nonce_b64: peer_hello.nonce_b64,
      certificate: own_envelope.certificate,
      now_ms,
    },
    own_sk_hex,
  )
}

/** Agent side: verify the IS's attest, then produce the agent's own
 *  attest. */
export function a2aCounterAttest(
  is_attest: MutualAuthAttest,
  agent_envelope: A2AMutualAuthEnvelope,
  agent_sk_hex: string,
  policy: MutualAuthPolicy,
  trust_anchors: TrustAnchor[],
  now_ms: number,
  agent_nonce_b64: string,
  is_nonce_b64: string,
  revoked_anchor_ids?: string[],
): MutualAuthAttest | { error: string } {
  const res = verifyAttest({
    attest: is_attest,
    expected_peer_nonce_b64: agent_nonce_b64,
    expected_own_nonce_b64: is_nonce_b64,
    policy,
    trust_anchors,
    revoked_anchor_ids,
    now_ms,
  })
  if (!res.ok) {
    return { error: res.reason ?? 'verification_failed' }
  }
  return buildAttest(
    {
      role: 'agent',
      chosen_version: is_attest.chosen_version,
      own_nonce_b64: agent_nonce_b64,
      peer_nonce_b64: is_attest.own_nonce_b64,
      certificate: agent_envelope.certificate,
      now_ms,
    },
    agent_sk_hex,
  )
}

/** Final step on the IS side: verify the agent's attest, then derive
 *  the shared session. */
export function a2aFinalizeSession(
  agent_attest: MutualAuthAttest,
  is_attest: MutualAuthAttest,
  policy: MutualAuthPolicy,
  trust_anchors: TrustAnchor[],
  now_ms: number,
  expected_is_nonce: string,
  expected_agent_nonce: string,
  revoked_anchor_ids?: string[],
): MutualAuthResult {
  const res = verifyAttest({
    attest: agent_attest,
    expected_peer_nonce_b64: expected_is_nonce,
    expected_own_nonce_b64: expected_agent_nonce,
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

/** Attach an APS mutual-auth certificate to an A2A Agent Card as an
 *  extension block. Does not modify core card fields. */
export function attachMutualAuthToA2ACard(
  card: A2AAgentCard,
  cert: MutualAuthCertificate,
): A2AAgentCard & { agentPassport: Record<string, unknown> } {
  const existing = card.agentPassport ?? { did: '', passportSignature: '' }
  return {
    ...card,
    agentPassport: {
      ...existing,
      mutualAuthCertificate: cert,
    },
  }
}

/** Extract an APS mutual-auth certificate from an A2A Agent Card
 *  extension, or null if absent. */
export function extractMutualAuthFromA2ACard(
  card: A2AAgentCard,
): MutualAuthCertificate | null {
  const ext = (card.agentPassport as Record<string, unknown> | undefined)
  const cert = ext?.mutualAuthCertificate
  if (!cert || typeof cert !== 'object') return null
  return cert as MutualAuthCertificate
}
