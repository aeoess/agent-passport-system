// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Primitive — projection verification + cross-projection
// consistency checks
// ══════════════════════════════════════════════════════════════════
// Spec §2.3 / §2.4 / §2.6. Verification is strictly local: the verifier
// needs only the projection and the issuer's public key. No other axes,
// no database lookups, no external services.
// ══════════════════════════════════════════════════════════════════

import { verify as ed25519Verify } from '../../crypto/keys.js'
import { envelopeBytes, hashAxisLeaf } from './canonical.js'
import { reconstructRoot } from './merkle.js'
import { projectAttribution } from './project.js'
import type {
  AttributionAxisTag,
  AttributionConsistencyResult,
  AttributionPrimitive,
  AttributionProjection,
  AttributionVerifyResult,
} from './types.js'

const VALID_TAGS: ReadonlySet<AttributionAxisTag> = new Set(['D', 'P', 'G', 'C'])
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/

function isProjectionStructurallyValid(p: AttributionProjection): boolean {
  if (!p || typeof p !== 'object') return false
  if (typeof p.action_ref !== 'string' || !HEX64.test(p.action_ref)) return false
  if (typeof p.merkle_root !== 'string' || !HEX64.test(p.merkle_root)) return false
  if (typeof p.signature !== 'string' || !HEX128.test(p.signature)) return false
  if (typeof p.issuer !== 'string' || p.issuer.length === 0) return false
  if (typeof p.timestamp !== 'string' || p.timestamp.length === 0) return false
  if (!Array.isArray(p.merkle_path) || p.merkle_path.length !== 2) return false
  if (!p.merkle_path.every((h) => typeof h === 'string' && HEX64.test(h))) return false
  return true
}

/** Verify a single-axis projection. §2.3. */
export function verifyAttributionProjection(
  projection: AttributionProjection,
  issuerPublicKeyHex: string,
): AttributionVerifyResult {
  if (!isProjectionStructurallyValid(projection)) {
    return { valid: false, reason: 'MALFORMED' }
  }
  if (!VALID_TAGS.has(projection.axis_tag)) {
    return { valid: false, reason: 'INVALID_AXIS_TAG' }
  }

  const axisLeaf = hashAxisLeaf(projection.axis_data)
  let computedRoot: Buffer
  try {
    computedRoot = reconstructRoot(axisLeaf, projection.merkle_path, projection.axis_tag)
  } catch {
    return { valid: false, reason: 'MALFORMED' }
  }
  const computedRootHex = computedRoot.toString('hex')
  if (computedRootHex !== projection.merkle_root.toLowerCase()) {
    return { valid: false, reason: 'MERKLE_MISMATCH' }
  }

  const envelope = envelopeBytes({
    action_ref: projection.action_ref,
    merkle_root: projection.merkle_root,
    issuer: projection.issuer,
    timestamp: projection.timestamp,
  })
  let sigOk = false
  try {
    sigOk = ed25519Verify(envelope, projection.signature, issuerPublicKeyHex)
  } catch {
    sigOk = false
  }
  if (!sigOk) return { valid: false, reason: 'SIGNATURE_INVALID' }

  return { valid: true }
}

/** Verify an AttributionPrimitive end-to-end by projecting and verifying
 *  each of the four axes under the same issuer key. Returns the first
 *  failing axis's reason, or valid if all four pass. Useful for the issuer
 *  itself as a post-construction sanity check. */
export function verifyAttributionPrimitive(
  primitive: AttributionPrimitive,
  issuerPublicKeyHex: string,
): AttributionVerifyResult {
  // We construct projections from the primitive's own axes, so this is
  // really a check that (merkle_root, signature, envelope) are internally
  // consistent with the carried axes. A separately-issued tampered-with
  // primitive will fail MERKLE_MISMATCH or SIGNATURE_INVALID.
  for (const tag of ['D', 'P', 'G', 'C'] as const) {
    const projection = projectAttribution(primitive, tag)
    const res = verifyAttributionProjection(projection, issuerPublicKeyHex)
    if (!res.valid) return res
  }
  return { valid: true }
}

/** §2.4 cross-projection consistency. Given two projections a verifier
 *  believes originate from the same receipt, check that the shared fields
 *  actually match. Does NOT re-verify the signature — call
 *  verifyAttributionProjection() on each projection first if you don't
 *  already trust their origin. */
export function checkProjectionConsistency(
  p1: AttributionProjection,
  p2: AttributionProjection,
): AttributionConsistencyResult {
  if (p1.action_ref !== p2.action_ref) {
    return { same_receipt: false, reason: 'DIFFERENT_ACTIONS' }
  }
  if (p1.merkle_root !== p2.merkle_root) {
    return { same_receipt: false, reason: 'DIFFERENT_RECEIPTS' }
  }
  if (p1.signature !== p2.signature) {
    return { same_receipt: false, reason: 'DIFFERENT_SIGNATURES' }
  }
  if (p1.issuer !== p2.issuer || p1.timestamp !== p2.timestamp) {
    return { same_receipt: false, reason: 'METADATA_MISMATCH' }
  }
  return { same_receipt: true }
}
