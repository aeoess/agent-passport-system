// Delegation Re-anchoring — Module 26 (Gap 0B)
// Delegations can reference DID identifiers instead of raw public keys.
// Gateway resolves both during transition (compatibility bridge).
// Existing delegations referencing raw keys continue to work.
// New delegations prefer DID references.

import { verify } from '../crypto/keys.js'
import type { IdentityDocument } from '../types/identity.js'

// ══════════════════════════════════════
// TYPES
// ══════════════════════════════════════

export type DelegationRef =
  | { type: 'raw_key'; publicKey: string }
  | { type: 'did'; did: string; identityDocument?: IdentityDocument }

export interface ReanchoredDelegation {
  delegationId: string
  delegatorRef: DelegationRef
  delegateRef: DelegationRef
  scope: string[]
  spendLimit?: number
  originalDelegatorKey?: string   // for backward compat
  originalDelegateKey?: string
  reanchoredAt: string
}

// ══════════════════════════════════════
// CREATE DELEGATION REF
// ══════════════════════════════════════

export function createDelegationRef(opts:
  { publicKey: string } | { did: string; identityDocument?: IdentityDocument }
): DelegationRef {
  if ('did' in opts) {
    return { type: 'did', did: opts.did, identityDocument: opts.identityDocument }
  }
  return { type: 'raw_key', publicKey: opts.publicKey }
}

// ══════════════════════════════════════
// RESOLVE TO PUBLIC KEY
// ══════════════════════════════════════
// The critical function: resolve any DelegationRef to a public key for verification.

export function resolvePublicKey(ref: DelegationRef): string | null {
  if (ref.type === 'raw_key') return ref.publicKey
  if (ref.type === 'did' && ref.identityDocument) {
    return ref.identityDocument.currentPublicKey
  }
  // DID without identity document — cannot resolve locally
  return null
}

// ══════════════════════════════════════
// RE-ANCHOR DELEGATION
// ══════════════════════════════════════
// Takes a delegation that uses raw keys and upgrades it to DID references.

export function reanchorDelegation(opts: {
  delegationId: string
  delegatorKey: string
  delegateKey: string
  scope: string[]
  spendLimit?: number
  delegatorDid: string
  delegateDid: string
  delegatorIdentity?: IdentityDocument
  delegateIdentity?: IdentityDocument
}): ReanchoredDelegation {
  const { delegationId, delegatorKey, delegateKey, scope, spendLimit,
    delegatorDid, delegateDid, delegatorIdentity, delegateIdentity } = opts

  return {
    delegationId,
    delegatorRef: { type: 'did', did: delegatorDid, identityDocument: delegatorIdentity },
    delegateRef: { type: 'did', did: delegateDid, identityDocument: delegateIdentity },
    scope,
    spendLimit,
    originalDelegatorKey: delegatorKey,
    originalDelegateKey: delegateKey,
    reanchoredAt: new Date().toISOString(),
  }
}

// ══════════════════════════════════════
// VERIFY RE-ANCHORED DELEGATION
// ══════════════════════════════════════
// Checks that DID references resolve to the original raw keys.

export function verifyReanchoredDelegation(delegation: ReanchoredDelegation): {
  valid: boolean; errors: string[]
} {
  const errors: string[] = []

  // Resolve delegator
  const delegatorKey = resolvePublicKey(delegation.delegatorRef)
  if (!delegatorKey) {
    errors.push('Cannot resolve delegator DID to public key')
  } else if (delegation.originalDelegatorKey && delegatorKey !== delegation.originalDelegatorKey) {
    errors.push('Delegator DID resolves to different key than original delegation')
  }

  // Resolve delegate
  const delegateKey = resolvePublicKey(delegation.delegateRef)
  if (!delegateKey) {
    errors.push('Cannot resolve delegate DID to public key')
  } else if (delegation.originalDelegateKey && delegateKey !== delegation.originalDelegateKey) {
    errors.push('Delegate DID resolves to different key than original delegation')
  }

  return { valid: errors.length === 0, errors }
}

// ══════════════════════════════════════
// RESOLVE COMPATIBLE (COMPATIBILITY BRIDGE)
// ══════════════════════════════════════
// Given a message + signature, verify against either a raw key or a DID reference.
// This is the gateway's compatibility bridge during transition.

export function verifyWithRef(
  message: string, signature: string, ref: DelegationRef
): { verified: boolean; resolvedKey: string | null } {
  const key = resolvePublicKey(ref)
  if (!key) return { verified: false, resolvedKey: null }
  try {
    const result = verify(message, signature, key)
    return { verified: result, resolvedKey: key }
  } catch {
    return { verified: false, resolvedKey: key }
  }
}

// Check if a key was ever associated with a DID (handles rotated keys)
export function didCoversKey(ref: DelegationRef, publicKey: string): boolean {
  if (ref.type === 'raw_key') return ref.publicKey === publicKey
  if (!ref.identityDocument) return false
  const doc = ref.identityDocument
  if (doc.currentPublicKey === publicKey) return true
  for (const entry of doc.rotationLog) {
    if (entry.oldPublicKey === publicKey || entry.newPublicKey === publicKey) return true
  }
  return false
}
