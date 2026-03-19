// Identity Continuity & Key Rotation — Module 22
// When a principal rotates their key, the OLD key signs the rotation event
// (proving the old key holder authorized it) and the NEW key also signs
// (proving possession). This creates a verifiable chain of identity continuity.
// Emergency rotation uses a pre-committed recovery key when the old key is compromised.

import { v4 as uuidv4 } from 'uuid'
import { sign, verify, publicKeyFromPrivate } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  IdentityDocument, KeyRotationEntry, RotationVerification,
} from '../types/identity.js'

// ══════════════════════════════════════
// CREATE IDENTITY DOCUMENT
// ══════════════════════════════════════

export function createIdentityDocument(opts: {
  publicKey: string
  recoveryKeys?: string[]
}): IdentityDocument {
  const now = new Date().toISOString()
  return {
    identityId: 'id_' + uuidv4().slice(0, 12),
    currentPublicKey: opts.publicKey,
    previousPublicKey: null,
    rotationLog: [],
    recoveryKeys: opts.recoveryKeys ?? [],
    createdAt: now,
    updatedAt: now,
  }
}

// ══════════════════════════════════════
// ROTATE KEY (normal — old key signs)
// ══════════════════════════════════════

export function rotateKey(opts: {
  identity: IdentityDocument
  oldPrivateKey: string
  newKeyPair: { publicKey: string; privateKey: string }
  reason: KeyRotationEntry['reason']
}): { identity: IdentityDocument; rotationEntry: KeyRotationEntry } {
  const { identity, oldPrivateKey, newKeyPair, reason } = opts
  const now = new Date().toISOString()
  const rotationId = 'rot_' + uuidv4().slice(0, 12)

  const continuityPayload = canonicalize({
    rotationId,
    oldPublicKey: identity.currentPublicKey,
    newPublicKey: newKeyPair.publicKey,
    reason,
    rotatedAt: now,
  })

  const possessionPayload = canonicalize({
    rotationId,
    newPublicKey: newKeyPair.publicKey,
  })

  const continuitySignature = sign(continuityPayload, oldPrivateKey)
  const possessionSignature = sign(possessionPayload, newKeyPair.privateKey)

  const entry: KeyRotationEntry = {
    rotationId,
    oldPublicKey: identity.currentPublicKey,
    newPublicKey: newKeyPair.publicKey,
    reason,
    rotatedAt: now,
    continuitySignature,
    possessionSignature,
  }

  const updatedIdentity: IdentityDocument = {
    ...identity,
    previousPublicKey: identity.currentPublicKey,
    currentPublicKey: newKeyPair.publicKey,
    rotationLog: [...identity.rotationLog, entry],
    updatedAt: now,
  }

  return { identity: updatedIdentity, rotationEntry: entry }
}

// ══════════════════════════════════════
// EMERGENCY ROTATION (recovery key signs)
// ══════════════════════════════════════

export function emergencyRotate(opts: {
  identity: IdentityDocument
  recoveryPrivateKey: string
  newKeyPair: { publicKey: string; privateKey: string }
}): { identity: IdentityDocument; rotationEntry: KeyRotationEntry } {
  const { identity, recoveryPrivateKey, newKeyPair } = opts
  const now = new Date().toISOString()
  const rotationId = 'rot_' + uuidv4().slice(0, 12)

  // V5-MED-3: Validate recovery key is in the pre-committed recovery key list
  const recoveryPublicKey = publicKeyFromPrivate(recoveryPrivateKey)
  if (!identity.recoveryKeys.includes(recoveryPublicKey)) {
    throw new Error('Recovery key is not in the identity\'s pre-committed recovery key list')
  }

  const continuityPayload = canonicalize({
    rotationId,
    oldPublicKey: identity.currentPublicKey,
    newPublicKey: newKeyPair.publicKey,
    reason: 'recovery' as const,
    rotatedAt: now,
  })

  const possessionPayload = canonicalize({
    rotationId,
    newPublicKey: newKeyPair.publicKey,
  })

  const continuitySignature = sign(continuityPayload, recoveryPrivateKey)
  const possessionSignature = sign(possessionPayload, newKeyPair.privateKey)

  const entry: KeyRotationEntry = {
    rotationId,
    oldPublicKey: identity.currentPublicKey,
    newPublicKey: newKeyPair.publicKey,
    reason: 'recovery',
    rotatedAt: now,
    continuitySignature,
    possessionSignature,
  }

  const updatedIdentity: IdentityDocument = {
    ...identity,
    previousPublicKey: identity.currentPublicKey,
    currentPublicKey: newKeyPair.publicKey,
    rotationLog: [...identity.rotationLog, entry],
    updatedAt: now,
  }

  return { identity: updatedIdentity, rotationEntry: entry }
}

// ══════════════════════════════════════
// VERIFY A SINGLE ROTATION ENTRY
// ══════════════════════════════════════

export function verifyRotation(entry: KeyRotationEntry): RotationVerification {
  const errors: string[] = []

  const continuityPayload = canonicalize({
    rotationId: entry.rotationId,
    oldPublicKey: entry.oldPublicKey,
    newPublicKey: entry.newPublicKey,
    reason: entry.reason,
    rotatedAt: entry.rotatedAt,
  })

  const possessionPayload = canonicalize({
    rotationId: entry.rotationId,
    newPublicKey: entry.newPublicKey,
  })

  let continuityValid = false
  try {
    continuityValid = verify(continuityPayload, entry.continuitySignature, entry.oldPublicKey)
  } catch { continuityValid = false }
  if (!continuityValid) errors.push('Continuity signature invalid — old key did not authorize rotation')

  let possessionValid = false
  try {
    possessionValid = verify(possessionPayload, entry.possessionSignature, entry.newPublicKey)
  } catch { possessionValid = false }
  if (!possessionValid) errors.push('Possession signature invalid — new key not proven')

  return {
    valid: continuityValid && possessionValid,
    errors,
    continuityValid,
    possessionValid,
    chainValid: true,
  }
}

// ══════════════════════════════════════
// VERIFY FULL ROTATION LOG
// ══════════════════════════════════════

export function verifyRotationLog(identity: IdentityDocument): RotationVerification {
  const errors: string[] = []
  let continuityValid = true
  let possessionValid = true
  let chainValid = true

  if (identity.rotationLog.length === 0) {
    return { valid: true, errors: [], continuityValid: true, possessionValid: true, chainValid: true }
  }

  for (let i = 0; i < identity.rotationLog.length; i++) {
    const entry = identity.rotationLog[i]

    if (i > 0) {
      const prevEntry = identity.rotationLog[i - 1]
      if (entry.oldPublicKey !== prevEntry.newPublicKey) {
        chainValid = false
        errors.push(`Rotation ${i}: oldPublicKey does not match previous newPublicKey`)
      }
    }

    const entryResult = verifyRotation(entry)
    if (!entryResult.continuityValid) {
      continuityValid = false
      errors.push(`Rotation ${i}: ${entryResult.errors.join(', ')}`)
    }
    if (!entryResult.possessionValid) {
      possessionValid = false
      if (entryResult.errors.length > 0 && !errors.includes(`Rotation ${i}: ${entryResult.errors.join(', ')}`)) {
        errors.push(`Rotation ${i}: ${entryResult.errors.join(', ')}`)
      }
    }
  }

  const lastEntry = identity.rotationLog[identity.rotationLog.length - 1]
  if (lastEntry.newPublicKey !== identity.currentPublicKey) {
    chainValid = false
    errors.push('Current public key does not match last rotation newPublicKey')
  }

  return { valid: continuityValid && possessionValid && chainValid, errors, continuityValid, possessionValid, chainValid }
}

// ══════════════════════════════════════
// RESOLVE CURRENT KEY
// ══════════════════════════════════════

export function resolveCurrentKey(identity: IdentityDocument): string {
  return identity.currentPublicKey
}

// ══════════════════════════════════════
// WAS KEY ACTIVE
// ══════════════════════════════════════

export function wasKeyActive(identity: IdentityDocument, publicKey: string): boolean {
  if (identity.currentPublicKey === publicKey) return true
  for (const entry of identity.rotationLog) {
    if (entry.oldPublicKey === publicKey) return true
    if (entry.newPublicKey === publicKey) return true
  }
  return false
}
