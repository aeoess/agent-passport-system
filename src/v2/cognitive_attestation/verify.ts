// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// cognitive_attestation signal_type (v0.1): verification
// ══════════════════════════════════════════════════════════════════
// Verifies the Ed25519 signature on a cognitive_attestation envelope
// against the agent_id embedded in the envelope. Does NOT verify the
// truth of class_payload claims; per PR #104 notes the signal_type
// attests to what was reasoned over, not whether a policy passed. The
// downstream consumer carries that policy check.
// ══════════════════════════════════════════════════════════════════

import { verify as edVerify } from '../../crypto/keys.js'

import { canonicalizeForSignature } from './envelope.js'
import {
  isCandidateSetPayload,
  isDecisionPathPayload,
  isPreconditionSetPayload,
} from './types.js'
import type {
  CognitiveAttestationEnvelope,
  CognitiveAttestationVerifyResult,
} from './types.js'

const HEX_AGENT_ID = /^[0-9a-f]{64}$/
const HEX_SIGNATURE = /^[0-9a-f]{128}$/

/**
 * Verify the Ed25519 signature on an envelope. Returns
 * `{ valid: true }` only when every shape check passes AND the signature
 * verifies against `envelope.agent_id`. A failure carries a `reason`
 * naming the specific shape or cryptographic failure.
 *
 * The function accepts `unknown` and narrows internally so a malformed
 * input does not throw; it returns a structured failure instead. Reason
 * codes are listed in `types.ts` on `CognitiveAttestationVerifyResult`.
 */
export function verifyCognitiveAttestation(
  envelope: unknown,
): CognitiveAttestationVerifyResult {
  if (typeof envelope !== 'object' || envelope === null) {
    return { valid: false, reason: 'INVALID_SIGNAL_TYPE' }
  }
  const e = envelope as Record<string, unknown>

  if (e.signal_type !== 'cognitive_attestation') {
    return { valid: false, reason: 'INVALID_SIGNAL_TYPE' }
  }
  if (typeof e.class !== 'string' ||
    (e.class !== 'precondition_set' &&
     e.class !== 'candidate_set' &&
     e.class !== 'decision_path')) {
    return { valid: false, reason: 'INVALID_CLASS' }
  }
  if (typeof e.agent_id !== 'string' || !HEX_AGENT_ID.test(e.agent_id)) {
    return { valid: false, reason: 'INVALID_AGENT_ID' }
  }
  if (typeof e.signature !== 'string' || !HEX_SIGNATURE.test(e.signature)) {
    return { valid: false, reason: 'INVALID_SIGNATURE_FORMAT' }
  }
  if (e.class === 'precondition_set' && !isPreconditionSetPayload(e.class_payload)) {
    return { valid: false, reason: 'INVALID_PAYLOAD' }
  }
  if (e.class === 'candidate_set' && !isCandidateSetPayload(e.class_payload)) {
    return { valid: false, reason: 'INVALID_PAYLOAD' }
  }
  if (e.class === 'decision_path' && !isDecisionPathPayload(e.class_payload)) {
    return { valid: false, reason: 'INVALID_PAYLOAD' }
  }

  const bytes = canonicalizeForSignature(envelope as CognitiveAttestationEnvelope)
  const ok = edVerify(bytes, e.signature, e.agent_id)
  if (!ok) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  return { valid: true }
}
