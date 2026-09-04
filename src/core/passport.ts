// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Core Passport Operations — create, sign, update, expire

import { generateKeyPair, sign, verify, publicKeyFromPrivate } from '../crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from './canonical.js'
import { parseRfc3339 } from './rfc3339.js'
import type {
  AgentPassport, SignedPassport, KeyPair,
  CreatePassportOptions, ReputationScore, IssuerSignature
} from '../types/passport.js'

const DEFAULT_EXPIRY_DAYS = 365

function defaultReputation(): ReputationScore {
  return {
    overall: 1,
    collaborationsCompleted: 0,
    proposalsSubmitted: 0,
    proposalsApproved: 0,
    tokensContributed: 0,
    tasksCompleted: 0,
    lastUpdated: new Date().toISOString()
  }
}

function calculateVoteWeight(capabilities: string[]): number {
  // Base weight 1, increases with capabilities
  const weights: Record<string, number> = {
    code_execution: 0.5,
    system_control: 0.5,
    web_search: 0.2,
    email_management: 0.3,
    file_management: 0.3,
    git_operations: 0.3,
    browser_automation: 0.2,
    voice_transcription: 0.1,
    social_media_posting: 0.1
  }
  const bonus = capabilities.reduce((sum, cap) => sum + (weights[cap] || 0.1), 0)
  return Math.max(1, Math.round(1 + bonus))
}

export function createPassport(options: CreatePassportOptions): {
  signedPassport: SignedPassport
  keyPair: KeyPair
} {
  const keyPair = generateKeyPair()
  const now = new Date()

  // Persistent passport mode: use explicit validity window if provided
  let createdAt: string
  let expiresAt: string
  let notBefore: string | undefined

  if (options.validityWindow) {
    createdAt = now.toISOString()
    expiresAt = options.validityWindow.notAfter
    notBefore = options.validityWindow.notBefore || createdAt
  } else {
    const expiry = new Date()
    expiry.setTime(now.getTime())
    expiry.setDate(expiry.getDate() + (options.expiresInDays || DEFAULT_EXPIRY_DAYS))
    createdAt = now.toISOString()
    expiresAt = expiry.toISOString()
  }

  const passport: AgentPassport = {
    version: '1.0.0',
    agentId: options.agentId,
    agentName: options.agentName,
    ownerAlias: options.ownerAlias,
    publicKey: keyPair.publicKey,
    mission: options.mission,
    capabilities: options.capabilities,
    runtime: options.runtime,
    createdAt,
    expiresAt,
    ...(notBefore ? { notBefore } : {}),
    voteWeight: calculateVoteWeight(options.capabilities),
    reputation: defaultReputation(),
    delegations: options.delegations || [],
    metadata: options.metadata || {}
  }

  const signedPassport = signPassport(passport, keyPair.privateKey)
  return { signedPassport, keyPair }
}

export function signPassport(passport: AgentPassport, privateKey: string): SignedPassport {
  const canonical = canonicalizeForWrite(passport)
  const signature = sign(canonical, privateKey)
  return {
    passport,
    signature,
    signedAt: new Date().toISOString()
  }
}

export function updatePassport(
  passport: AgentPassport,
  updates: Partial<AgentPassport>,
  privateKey: string
): SignedPassport {
  const updated: AgentPassport = { ...passport, ...updates }
  // Recalculate vote weight if capabilities changed
  if (updates.capabilities) {
    updated.voteWeight = calculateVoteWeight(updates.capabilities)
  }
  return signPassport(updated, privateKey)
}

export function isExpired(passport: AgentPassport): boolean {
  // An expiry this SDK cannot read is not an expiry it can honour: a passport
  // whose expiresAt is not an RFC 3339 instant counts as expired, never as
  // one that has no readable limit and is therefore still good.
  const expiry = parseRfc3339(passport.expiresAt)
  if (!expiry.ok) return true
  return expiry.ms < Date.now()
}

/**
 * Check full validity window for persistent passports.
 * Returns true if: notBefore <= now <= expiresAt
 * For session passports (no notBefore), checks only expiry.
 */
export function isPassportValid(passport: AgentPassport): { valid: boolean, reason?: string } {
  const now = Date.now()
  // A window edge that cannot be read cannot place `now` inside the window,
  // so an unreadable edge fails the check rather than being skipped over.
  if (passport.notBefore) {
    const notBefore = parseRfc3339(passport.notBefore)
    if (!notBefore.ok) {
      return { valid: false, reason: 'INVALID_NOT_BEFORE' }
    }
    if (now < notBefore.ms) {
      return { valid: false, reason: 'NOT_YET_VALID' }
    }
  }
  const expiresAt = parseRfc3339(passport.expiresAt)
  if (!expiresAt.ok) {
    return { valid: false, reason: 'INVALID_EXPIRES_AT' }
  }
  if (now > expiresAt.ms) {
    return { valid: false, reason: 'EXPIRED' }
  }
  return { valid: true }
}

/**
 * Countersign a passport with the issuer's private key.
 * This is the Certificate Authority operation — proves AEOESS issued this passport.
 * The issuer signature covers the entire SignedPassport (passport + agent signature + signedAt).
 */
export function countersignPassport(
  signedPassport: SignedPassport,
  issuerPrivateKey: string,
  issuerId: string = 'aeoess'
): SignedPassport {
  const payload = canonicalizeForWrite({
    passport: signedPassport.passport,
    signature: signedPassport.signature,
    signedAt: signedPassport.signedAt,
  })
  const issuerSig = sign(payload, issuerPrivateKey)
  return {
    ...signedPassport,
    issuerSignature: {
      issuerId,
      issuerPublicKey: publicKeyFromPrivate(issuerPrivateKey),
      signature: issuerSig,
      signedAt: new Date().toISOString(),
    },
  }
}

/**
 * Verify an issuer countersignature on a passport.
 * Returns true if the passport was issued by the authority holding issuerPublicKey.
 */
export function verifyIssuerSignature(
  signedPassport: SignedPassport,
  issuerPublicKey: string
): boolean {
  if (!signedPassport.issuerSignature) return false
  if (signedPassport.issuerSignature.issuerPublicKey !== issuerPublicKey) return false
  const payload = canonicalize({
    passport: signedPassport.passport,
    signature: signedPassport.signature,
    signedAt: signedPassport.signedAt,
  })
  return verify(payload, signedPassport.issuerSignature.signature, issuerPublicKey)
}

/**
 * Quick presence check: does this passport have an issuer countersignature attached?
 * NOTE: This does NOT verify the signature cryptographically.
 * Use verifyIssuerSignature(passport, issuerPublicKey) for real verification.
 * @deprecated Use verifyIssuerSignature() for security-critical checks.
 */
export function isIssuerVerified(signedPassport: SignedPassport): boolean {
  return !!signedPassport.issuerSignature && signedPassport.issuerSignature.signature.length === 128
}

/** Alias: presence check for issuer signature (not cryptographic verification) */
export const isIssuerSigned = isIssuerVerified
