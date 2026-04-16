// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Primitive — construction
// ══════════════════════════════════════════════════════════════════
// Spec §2.7 composition pipeline. Given a set of axes, an issuer DID, and
// an action tuple, produce a signed primitive. Callers hand us already-
// computed axis entries; weight derivation and hash computation of the
// underlying per-axis artifacts (AccessReceipt hashes, evaluation receipt
// hashes, delegation scope hashes, attestation hashes) is deployment
// policy per §7.1.
// ══════════════════════════════════════════════════════════════════

import { sign } from '../../crypto/keys.js'
import {
  assertCanonicalTimestamp,
  canonicalHashHex,
  canonicalTimestamp,
  envelopeBytes,
} from './canonical.js'
import { buildMerkleFrame } from './merkle.js'
import type {
  AttributionAction,
  AttributionAxes,
  AttributionPrimitive,
} from './types.js'

/** Derive action_ref from the action tuple. §1.2 / §3.4.
 *
 *  The spec pseudocode in §2.7 uses string concatenation (`agentId || type
 *  || canonical(params) || nonce`), but Theorem 1's reduction relies on
 *  canonical(T) being injective (A1). Plain string concatenation is not
 *  self-delimiting, so two distinct tuples could produce the same byte
 *  string. We adopt canonical(T) on the full tuple, which is injective by
 *  construction and matches the security argument. */
export function computeAttributionActionRef(action: AttributionAction): string {
  if (!action.agentId) throw new Error('attribution-primitive: action.agentId required')
  if (!action.actionType) throw new Error('attribution-primitive: action.actionType required')
  if (!action.nonce) throw new Error('attribution-primitive: action.nonce required')
  if (typeof action.params !== 'object' || action.params === null) {
    throw new Error('attribution-primitive: action.params must be an object')
  }
  return canonicalHashHex({
    agentId: action.agentId,
    actionType: action.actionType,
    params: action.params,
    nonce: action.nonce,
  })
}

export interface ConstructAttributionParams {
  /** The action being attested. Used to derive action_ref. */
  action: AttributionAction
  /** The four axes with their entries. Unsorted is fine — canonicalization
   *  will order them. */
  axes: AttributionAxes
  /** Issuer DID of the gateway or agent producing the receipt. */
  issuer: string
  /** Ed25519 private key (hex) that signs the envelope. Must match the
   *  public key registered for `issuer` out-of-band. */
  issuerPrivateKey: string
  /** Override the timestamp (test fixtures, replayed audits). Must satisfy
   *  §2.5 — millisecond precision, trailing Z. Defaults to now(). */
  timestamp?: string
}

/** Build and sign a complete AttributionPrimitive. §2.7. */
export function constructAttributionPrimitive(
  params: ConstructAttributionParams,
): AttributionPrimitive {
  if (!params.issuer) throw new Error('attribution-primitive: issuer required')
  if (!params.issuerPrivateKey) throw new Error('attribution-primitive: issuerPrivateKey required')

  const action_ref = computeAttributionActionRef(params.action)
  const frame = buildMerkleFrame(params.axes)
  const merkle_root = frame.root.toString('hex')
  const timestamp = params.timestamp ?? canonicalTimestamp()
  assertCanonicalTimestamp(timestamp)

  const envelope = envelopeBytes({
    action_ref,
    merkle_root,
    issuer: params.issuer,
    timestamp,
  })
  const signature = sign(envelope, params.issuerPrivateKey)

  return {
    action_ref,
    axes: frame.axes,
    merkle_root,
    issuer: params.issuer,
    timestamp,
    signature,
  }
}

/** Re-sign a primitive whose axes or metadata have changed (e.g., after
 *  applying decay in axis P). Returns a fresh primitive; the input is not
 *  mutated. Caller is responsible for providing a new timestamp if the
 *  resigned receipt should be distinct under replay protection. */
export function resignAttributionPrimitive(
  primitive: AttributionPrimitive,
  issuerPrivateKey: string,
  opts?: { timestamp?: string; axes?: AttributionAxes; action?: AttributionAction },
): AttributionPrimitive {
  const axes = opts?.axes ?? primitive.axes
  const action_ref = opts?.action
    ? computeAttributionActionRef(opts.action)
    : primitive.action_ref
  const frame = buildMerkleFrame(axes)
  const merkle_root = frame.root.toString('hex')
  const timestamp = opts?.timestamp ?? canonicalTimestamp()
  assertCanonicalTimestamp(timestamp)
  const envelope = envelopeBytes({
    action_ref,
    merkle_root,
    issuer: primitive.issuer,
    timestamp,
  })
  const signature = sign(envelope, issuerPrivateKey)
  return { action_ref, axes: frame.axes, merkle_root, issuer: primitive.issuer, timestamp, signature }
}
