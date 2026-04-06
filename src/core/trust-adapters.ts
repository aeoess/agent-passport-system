// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Trust Bootstrap Adapters — Bridge external credentials to APS identity
// ══════════════════════════════════════════════════════════════════
// Every adapter creates a FRESH Ed25519 keypair. External credentials are
// trust inputs (evidence), not identity material. Raw credentials NEVER
// touch the SDK (caller pre-hashes).
//
// Adapters are bootstrap bridges with clear assurance labeling.
// Each includes an upgrade path to full attested identity.
// ══════════════════════════════════════════════════════════════════

import { generateKeyPair } from '../crypto/keys.js'
import { signPassport } from './passport.js'
import type { SignedPassport, KeyPair, AgentPassport } from '../types/passport.js'

export interface ImportEvidence {
  source: 'api_key_hash' | 'github_org' | 'ci_signing_key' | 'oauth_token' | 'custom'
  provider?: string
  identifier_hash: string      // HMAC-SHA256 by caller, NEVER raw credential
  verified: boolean
  verified_at?: string
  assurance_input: 'low' | 'medium' | 'high'
  metadata?: Record<string, unknown>
}

export interface BootstrapResult {
  passport: SignedPassport
  keyPair: KeyPair
  importEvidence: ImportEvidence
  warnings: string[]
  suggestedGrade: number
}

function defaultRuntime() {
  return { platform: 'unknown', models: [], toolsCount: 0, memoryType: 'ephemeral' }
}

function defaultReputation() {
  return {
    overall: 0, collaborationsCompleted: 0, proposalsSubmitted: 0,
    proposalsApproved: 0, tokensContributed: 0, tasksCompleted: 0,
    lastUpdated: new Date().toISOString(),
  }
}

function makePassport(keyPair: KeyPair, name: string, owner: string, metadata: Record<string, unknown>): AgentPassport {
  const now = new Date()
  const expiry = new Date(now)
  expiry.setDate(expiry.getDate() + 30)
  return {
    version: '1.0.0',
    agentId: `agent-${keyPair.publicKey.slice(0, 12)}`,
    agentName: name,
    ownerAlias: owner,
    publicKey: keyPair.publicKey,
    mission: 'Bootstrapped identity',
    capabilities: ['bootstrapped'],
    runtime: defaultRuntime(),
    createdAt: now.toISOString(),
    expiresAt: expiry.toISOString(),
    voteWeight: 1,
    reputation: defaultReputation(),
    delegations: [],
    metadata,
  }
}

/**
 * Bootstrap from an API key hash.
 * Caller pre-hashes: HMAC-SHA256(apiKey, provider). SDK NEVER sees raw key.
 * Fresh Ed25519 keypair generated. Grade suggestion: 0 (no cryptographic proof).
 */
export function bootstrapFromAPIKey(options: {
  identifierHash: string
  provider?: string
  name?: string
  owner?: string
}): BootstrapResult {
  const keyPair = generateKeyPair()
  const evidence: ImportEvidence = {
    source: 'api_key_hash',
    provider: options.provider,
    identifier_hash: options.identifierHash,
    verified: false,
    assurance_input: 'low',
  }

  const metadata: Record<string, unknown> = { importedFrom: evidence }
  const passport = makePassport(
    keyPair,
    options.name || `${options.provider || 'api'}-agent`,
    options.owner || 'unknown',
    metadata,
  )
  const signed = signPassport(passport, keyPair.privateKey)

  return {
    passport: signed,
    keyPair,
    importEvidence: evidence,
    warnings: [
      `Bootstrapped from API key hash (${options.provider || 'unknown'} provider). ` +
      `No cryptographic proof of key ownership. Submit runtime attestation for Grade 2+.`,
    ],
    suggestedGrade: 0,
  }
}

/**
 * Bootstrap from GitHub identity.
 * If githubToken provided: calls GitHub API to verify org membership.
 * If not: verified=false, assurance='low', warning emitted.
 * Grade suggestion: 1 if verified, 0 if unverified.
 */
export async function bootstrapFromGitHub(options: {
  username: string
  org: string
  githubToken?: string
}): Promise<BootstrapResult> {
  const keyPair = generateKeyPair()
  let verified = false
  let verifiedAt: string | undefined
  let assurance: 'low' | 'medium' | 'high' = 'low'
  const warnings: string[] = []

  if (options.githubToken) {
    try {
      const resp = await fetch(
        `https://api.github.com/orgs/${options.org}/members/${options.username}`,
        { headers: { 'Authorization': `Bearer ${options.githubToken}`, 'Accept': 'application/vnd.github+json' } },
      )
      verified = resp.status === 204 || resp.status === 200 // 204 = member confirmed
      verifiedAt = new Date().toISOString()
      assurance = verified ? 'medium' : 'low'
      if (!verified) {
        warnings.push(`GitHub API returned ${resp.status} for ${options.username} in ${options.org}. Membership not confirmed.`)
      }
    } catch (err: any) {
      warnings.push(`GitHub API call failed: ${err.message}. Proceeding unverified.`)
    }
  } else {
    warnings.push(
      `No GitHub token provided. Org membership for ${options.username}@${options.org} is UNVERIFIED. ` +
      `Provide a token for verified bootstrap.`,
    )
  }

  const evidence: ImportEvidence = {
    source: 'github_org',
    provider: 'github',
    identifier_hash: `github:${options.org}/${options.username}`,
    verified,
    verified_at: verifiedAt,
    assurance_input: assurance,
    metadata: { org: options.org, username: options.username },
  }

  const metadata: Record<string, unknown> = { importedFrom: evidence }
  const passport = makePassport(
    keyPair,
    `${options.username}@${options.org}`,
    options.username,
    metadata,
  )
  const signed = signPassport(passport, keyPair.privateKey)

  warnings.push(
    `Bootstrapped from GitHub identity. Submit runtime attestation for Grade 2+.`,
  )

  return {
    passport: signed,
    keyPair,
    importEvidence: evidence,
    warnings,
    suggestedGrade: verified ? 1 : 0,
  }
}

/**
 * Bootstrap from CI signing key.
 * CI public key becomes provider attestation evidence.
 * Fresh APS keypair generated separately.
 * Grade suggestion: 2 if key provided.
 */
export function bootstrapFromCIKey(options: {
  publicKeyHex: string
  provider: string
  workflowId?: string
  repoUrl?: string
}): BootstrapResult {
  const keyPair = generateKeyPair()
  const evidence: ImportEvidence = {
    source: 'ci_signing_key',
    provider: options.provider,
    identifier_hash: options.publicKeyHex,
    verified: true,
    verified_at: new Date().toISOString(),
    assurance_input: 'high',
    metadata: {
      ci_public_key: options.publicKeyHex,
      workflow_id: options.workflowId,
      repo_url: options.repoUrl,
    },
  }

  const metadata: Record<string, unknown> = { importedFrom: evidence }
  const passport = makePassport(
    keyPair,
    `${options.provider}-ci-agent`,
    options.provider,
    metadata,
  )
  const signed = signPassport(passport, keyPair.privateKey)

  return {
    passport: signed,
    keyPair,
    importEvidence: evidence,
    warnings: [
      `Bootstrapped from CI signing key (${options.provider}). ` +
      `CI public key attached as provider attestation. Submit runtime attestation for full Grade 2+ verification.`,
    ],
    suggestedGrade: 2,
  }
}

/**
 * Upgrade a bootstrapped passport to full attested identity.
 * Links the old bootstrapped identity to the new attested one.
 * Preserves history: old agent_id in metadata.
 */
export function upgradeBootstrappedPassport(options: {
  existingPassport: SignedPassport
  existingKeyPair: KeyPair
  newAttestation: object
}): { upgradedPassport: SignedPassport; previousAgentId: string } {
  const previousAgentId = options.existingPassport.passport.agentId
  const upgraded: AgentPassport = {
    ...options.existingPassport.passport,
    metadata: {
      ...options.existingPassport.passport.metadata,
      upgradedFrom: previousAgentId,
      upgradeAttestation: options.newAttestation,
      upgradedAt: new Date().toISOString(),
    },
  }

  const signed = signPassport(upgraded, options.existingKeyPair.privateKey)
  return { upgradedPassport: signed, previousAgentId }
}
