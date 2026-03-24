// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Core Passport Operations — create, sign, update, expire

import { generateKeyPair, sign } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import type {
  AgentPassport, SignedPassport, KeyPair,
  CreatePassportOptions, ReputationScore
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
  const expiry = new Date(now)
  expiry.setDate(expiry.getDate() + (options.expiresInDays || DEFAULT_EXPIRY_DAYS))

  const passport: AgentPassport = {
    version: '1.0.0',
    agentId: options.agentId,
    agentName: options.agentName,
    ownerAlias: options.ownerAlias,
    publicKey: keyPair.publicKey,
    mission: options.mission,
    capabilities: options.capabilities,
    runtime: options.runtime,
    createdAt: now.toISOString(),
    expiresAt: expiry.toISOString(),
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
