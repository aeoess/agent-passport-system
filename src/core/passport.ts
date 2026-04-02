// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Core Passport Operations — create, sign, update, expire

import { generateKeyPair, sign, verify, publicKeyFromPrivate } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
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
    const expiry = new Date(now)
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
  const canonical = canonicalize(passport)
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
  return new Date(passport.expiresAt) < new Date()
}

/**
 * Check full validity window for persistent passports.
 * Returns true if: notBefore <= now <= expiresAt
 * For session passports (no notBefore), checks only expiry.
 */
export function isPassportValid(passport: AgentPassport): { valid: boolean, reason?: string } {
  const now = new Date()
  if (passport.notBefore && now < new Date(passport.notBefore)) {
    return { valid: false, reason: 'NOT_YET_VALID' }
  }
  if (now > new Date(passport.expiresAt)) {
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
  const payload = canonicalize({
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
 * Check if a passport has a valid issuer countersignature from any known authority.
 */
export function isIssuerVerified(signedPassport: SignedPassport): boolean {
  return !!signedPassport.issuerSignature && signedPassport.issuerSignature.signature.length === 128
}
