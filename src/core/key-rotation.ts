// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Key Rotation — DID Document + Identity Continuity + Delegation Invalidation
// ══════════════════════════════════════════════════════════════════
// Post-consilium design (5 models attacked this spec):
//   - Split planned (configurable overlap, default 24h) vs emergency (immediate)
//   - Old key stays in verificationMethod with explicit retiredAt metadata
//   - rotateAndInvalidate uses explicit state machine, partial failure visible
//   - SDK computes, Gateway MUST enforce (isKeyActive is convenience only)
// ══════════════════════════════════════════════════════════════════

import { canonicalize } from './canonical.js'
import { sign, verify, publicKeyFromPrivate } from '../crypto/keys.js'
import { createDID, hexToMultibase, multibaseToHex } from './did.js'
import type { AgentPassport, KeyPair, CascadeRevocationResult } from '../types/passport.js'
import type {
  RotatableDIDDocument, RotatableVerificationMethod,
  RotationMode, RotationState, DIDRotationEntry,
} from '../types/passport.js'

const DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1',
]

const DEFAULT_PLANNED_OVERLAP_MS = 24 * 60 * 60 * 1000 // 24 hours

// ══════════════════════════════════════
// createDIDDocument — initial document for a passport
// ══════════════════════════════════════

/**
 * Create a rotation-capable DID Document for a passport.
 * One verificationMethod, empty rotationLog, no pending rotation.
 */
export function createDIDDocument(passport: AgentPassport): RotatableDIDDocument {
  const did = createDID(passport.publicKey)
  const keyId = `${did}#key-1`
  const publicKeyMultibase = hexToMultibase(passport.publicKey)

  const vm: RotatableVerificationMethod = {
    id: keyId,
    type: 'Ed25519VerificationKey2020',
    controller: did,
    publicKeyMultibase,
  }

  return {
    '@context': DID_CONTEXT,
    id: did,
    controller: did,
    verificationMethod: [vm],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    rotationLog: [],
    created: passport.createdAt,
    updated: passport.createdAt,
  }
}

// ══════════════════════════════════════
// announceKeyRotation — start a rotation
// ══════════════════════════════════════

function keyIdForPublicKey(did: string, index: number): string {
  return `${did}#key-${index}`
}

function nextKeyIndex(doc: RotatableDIDDocument): number {
  return doc.verificationMethod.length + 1
}

function canonicalRotationPayload(previousKey: string, newKey: string, mode: RotationMode, activationTime: string): string {
  return canonicalize({ previousKey, newKey, mode, activationTime })
}

/**
 * Announce a key rotation. Old key signs the rotation entry.
 *
 * planned mode: configurable overlap (default 24h). Both keys valid until activationTime.
 * emergency mode: old key immediately retired. New key is sole authority.
 */
export function announceKeyRotation(
  doc: RotatableDIDDocument,
  oldPrivateKey: string,
  newKeyPair: KeyPair,
  options: { mode: RotationMode; activationDelayMs?: number },
): RotatableDIDDocument {
  if (doc.pendingRotation) {
    throw new Error('Rotation already pending. Complete or cancel the current rotation first.')
  }

  const mode = options.mode
  const now = new Date()
  const delayMs = mode === 'emergency'
    ? 0
    : (options.activationDelayMs ?? DEFAULT_PLANNED_OVERLAP_MS)
  const activationTime = new Date(now.getTime() + delayMs).toISOString()
  const announcedAt = now.toISOString()

  // Find the current active key to verify old key ownership
  const activeKeyId = doc.authentication[0]
  const activeVm = doc.verificationMethod.find(vm => vm.id === activeKeyId)
  if (!activeVm) {
    throw new Error('No active verification method found')
  }

  // Derive the old public key from the private key and verify it matches
  const oldPublicKey = publicKeyFromPrivate(oldPrivateKey)
  const activePublicKeyHex = multibaseToHexSafe(activeVm.publicKeyMultibase)
  if (oldPublicKey !== activePublicKeyHex) {
    throw new Error('Provided private key does not match the current active key')
  }

  // Sign rotation entry
  const rotationPayload = canonicalRotationPayload(oldPublicKey, newKeyPair.publicKey, mode, activationTime)
  const rotationSignature = sign(rotationPayload, oldPrivateKey)

  // Add new key to verificationMethod
  const newKeyIndex = nextKeyIndex(doc)
  const newKeyId = keyIdForPublicKey(doc.id, newKeyIndex)
  const newVm: RotatableVerificationMethod = {
    id: newKeyId,
    type: 'Ed25519VerificationKey2020',
    controller: doc.id,
    publicKeyMultibase: hexToMultibase(newKeyPair.publicKey),
  }

  const updatedDoc = structuredClone(doc)
  updatedDoc.verificationMethod.push(newVm)
  updatedDoc.updated = announcedAt

  if (mode === 'emergency') {
    // Emergency: immediately retire old key, activate new key
    const oldVmIdx = updatedDoc.verificationMethod.findIndex(vm => vm.id === activeKeyId)
    if (oldVmIdx >= 0) {
      updatedDoc.verificationMethod[oldVmIdx].retiredAt = announcedAt
    }
    updatedDoc.authentication = [newKeyId]
    updatedDoc.assertionMethod = [newKeyId]
    updatedDoc.capabilityDelegation = [newKeyId]

    // Straight to rotationLog (no pending)
    const entry: DIDRotationEntry = {
      previousKey: oldPublicKey,
      newKey: newKeyPair.publicKey,
      mode,
      announcedAt,
      activationTime,
      state: 'activated',
      rotationSignature,
      completedAt: announcedAt,
    }
    updatedDoc.rotationLog.push(entry)
  } else {
    // Planned: both keys valid during overlap
    updatedDoc.authentication.push(newKeyId)
    updatedDoc.assertionMethod.push(newKeyId)
    updatedDoc.capabilityDelegation.push(newKeyId)

    updatedDoc.pendingRotation = {
      newKeyId,
      mode,
      activationTime,
      state: 'announced',
      rotationSignature,
    }
  }

  return updatedDoc
}

// ══════════════════════════════════════
// activateKeyRotation — complete a planned rotation
// ══════════════════════════════════════

/**
 * Activate a pending planned rotation after activationTime.
 * Removes old key from auth/assertion/capabilityDelegation, sets retiredAt.
 */
export function activateKeyRotation(
  doc: RotatableDIDDocument,
  now?: Date,
): RotatableDIDDocument {
  if (!doc.pendingRotation) {
    throw new Error('No pending rotation to activate')
  }

  const currentTime = now ?? new Date()
  const activationTime = new Date(doc.pendingRotation.activationTime)
  if (currentTime < activationTime) {
    throw new Error(
      `Activation time not reached. Current: ${currentTime.toISOString()}, activation: ${activationTime.toISOString()}`
    )
  }

  const updatedDoc = structuredClone(doc)
  const pending = updatedDoc.pendingRotation!
  const newKeyId = pending.newKeyId

  // Find old key(s) — everything in auth that isn't the new key
  const oldKeyIds = updatedDoc.authentication.filter(id => id !== newKeyId)

  // Retire old keys
  for (const oldKeyId of oldKeyIds) {
    const vmIdx = updatedDoc.verificationMethod.findIndex(vm => vm.id === oldKeyId)
    if (vmIdx >= 0) {
      updatedDoc.verificationMethod[vmIdx].retiredAt = currentTime.toISOString()
    }
  }

  // Set auth lists to new key only
  updatedDoc.authentication = [newKeyId]
  updatedDoc.assertionMethod = [newKeyId]
  updatedDoc.capabilityDelegation = [newKeyId]

  // Find old public key for the log entry
  const oldVm = doc.verificationMethod.find(vm => oldKeyIds.includes(vm.id))
  const oldPublicKey = oldVm ? multibaseToHexSafe(oldVm.publicKeyMultibase) : ''
  const newVm = updatedDoc.verificationMethod.find(vm => vm.id === newKeyId)
  const newPublicKey = newVm ? multibaseToHexSafe(newVm.publicKeyMultibase) : ''

  // Move to rotationLog
  const entry: DIDRotationEntry = {
    previousKey: oldPublicKey,
    newKey: newPublicKey,
    mode: pending.mode,
    announcedAt: doc.updated, // best approximation
    activationTime: pending.activationTime,
    state: 'activated',
    rotationSignature: pending.rotationSignature,
    completedAt: currentTime.toISOString(),
  }
  updatedDoc.rotationLog.push(entry)
  delete updatedDoc.pendingRotation
  updatedDoc.updated = currentTime.toISOString()

  return updatedDoc
}

// ══════════════════════════════════════
// verifyRotationChain — verify all rotation signatures
// ══════════════════════════════════════

/**
 * Walk rotationLog and verify each entry's rotationSignature.
 * Returns true if ALL entries have valid signatures, false if any fail.
 */
export function verifyRotationChain(doc: RotatableDIDDocument): boolean {
  for (const entry of doc.rotationLog) {
    const payload = canonicalRotationPayload(
      entry.previousKey, entry.newKey, entry.mode, entry.activationTime,
    )
    if (!verify(payload, entry.rotationSignature, entry.previousKey)) {
      return false
    }
  }
  return true
}

// ══════════════════════════════════════
// isKeyActive — convenience check (Gateway is authoritative)
// ══════════════════════════════════════

/**
 * Check if a public key is currently authorized for active operations.
 * NOTE: This is SDK convenience. Gateway enforcement is authoritative.
 */
export function isKeyActive(
  doc: RotatableDIDDocument,
  publicKey: string,
  now?: Date,
): boolean {
  const currentTime = now ?? new Date()

  // Find the verificationMethod for this key
  const multibase = hexToMultibase(publicKey)
  const vm = doc.verificationMethod.find(v => v.publicKeyMultibase === multibase)
  if (!vm) return false

  // If explicitly retired, not active
  if (vm.retiredAt) return false

  // Must be in authentication list
  if (!doc.authentication.includes(vm.id)) return false

  // If there's a pending planned rotation and activation time has passed,
  // the old key should be considered inactive (Gateway enforces this server-side)
  if (doc.pendingRotation && doc.pendingRotation.newKeyId !== vm.id) {
    const activationTime = new Date(doc.pendingRotation.activationTime)
    if (currentTime >= activationTime) {
      return false
    }
  }

  return true
}

// ══════════════════════════════════════
// rotateAndInvalidate — full rotation + delegation invalidation
// ══════════════════════════════════════

export interface RotationResult {
  didDocument: RotatableDIDDocument
  rotationState: RotationState
  revocationResults: Array<{ delegationId: string; cascadeCount: number; error?: string }>
}

/** Gateway-side cascade revocation callback. `cascadeRevoke` lives on
 *  `DelegationStore` in @aeoess/gateway; callers pass the bound method in.
 *  When omitted, `rotateAndInvalidate` rotates the key but records every
 *  delegation ID as an error ("cascade revocation unavailable"), so
 *  partial-failure semantics are preserved. */
export type CascadeRevokeFn = (
  delegationId: string, revokedBy: string, reason: string, privateKey: string,
) => CascadeRevocationResult

/**
 * Full rotation with delegation invalidation. Explicit state machine:
 * announced → revocation_in_progress → revocation_complete → activated
 *
 * Partial failure is VISIBLE. If 3 of 5 delegations revoke but 2 fail,
 * state stays 'revocation_in_progress' and the caller sees which failed.
 */
export function rotateAndInvalidate(
  doc: RotatableDIDDocument,
  oldPrivateKey: string,
  newKeyPair: KeyPair,
  delegationIdsToRevoke: string[],
  options: { mode: RotationMode; activationDelayMs?: number; cascadeRevoke?: CascadeRevokeFn },
): RotationResult {
  // Step 1: announced
  let updatedDoc = announceKeyRotation(doc, oldPrivateKey, newKeyPair, options)

  // For emergency mode, announceKeyRotation already set state to activated
  // and moved to rotationLog. We still need to handle revocations.
  const isEmergency = options.mode === 'emergency'

  // Step 2: revocation_in_progress
  const revocationResults: Array<{ delegationId: string; cascadeCount: number; error?: string }> = []
  let allRevoked = true

  // Derive old public key for revokedBy
  const oldPublicKey = publicKeyFromPrivate(oldPrivateKey)
  const cascadeRevoke = options.cascadeRevoke

  for (const delegationId of delegationIdsToRevoke) {
    if (!cascadeRevoke) {
      revocationResults.push({
        delegationId, cascadeCount: 0,
        error: 'cascadeRevoke callback not provided — pass DelegationStore.cascadeRevoke from @aeoess/gateway',
      })
      allRevoked = false
      continue
    }
    try {
      const result = cascadeRevoke(delegationId, oldPublicKey, 'key_rotation', oldPrivateKey)
      revocationResults.push({ delegationId, cascadeCount: result.totalRevoked })
    } catch (err: any) {
      revocationResults.push({ delegationId, cascadeCount: 0, error: err.message })
      allRevoked = false
    }
  }

  // Update the rotation log entry with revoked delegation IDs
  const revokedIds = revocationResults
    .filter(r => !r.error)
    .map(r => r.delegationId)

  // Determine final state
  let rotationState: RotationState

  if (isEmergency) {
    // Emergency: already activated by announceKeyRotation
    // Update the last rotationLog entry with revocation data
    const lastEntry = updatedDoc.rotationLog[updatedDoc.rotationLog.length - 1]
    if (lastEntry) {
      lastEntry.revokedDelegations = revokedIds
      if (!allRevoked) {
        lastEntry.state = 'revocation_in_progress'
        rotationState = 'revocation_in_progress'
      } else {
        rotationState = 'activated'
      }
    } else {
      rotationState = 'activated'
    }
  } else {
    // Planned: still pending, record revocation state
    if (delegationIdsToRevoke.length === 0) {
      rotationState = 'announced'
    } else if (allRevoked) {
      rotationState = 'revocation_complete'
      if (updatedDoc.pendingRotation) {
        updatedDoc.pendingRotation.state = 'revocation_complete'
      }
    } else {
      rotationState = 'revocation_in_progress'
      if (updatedDoc.pendingRotation) {
        updatedDoc.pendingRotation.state = 'revocation_in_progress'
      }
    }
  }

  return {
    didDocument: updatedDoc,
    rotationState,
    revocationResults,
  }
}

// ══════════════════════════════════════
// Internal helpers
// ══════════════════════════════════════

function multibaseToHexSafe(mb: string): string {
  try {
    return multibaseToHex(mb)
  } catch {
    return mb
  }
}
