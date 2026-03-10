// Agent Passport System — Principal Identity
// Cryptographic chain from human principal to agent.
// The principal has their own Ed25519 keypair and endorses agents.

import { v4 as uuidv4 } from 'uuid'
import { createHash } from 'node:crypto'
import { generateKeyPair, sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { createDID } from './did.js'
import type { KeyPair, SignedPassport } from '../types/passport.js'
import type {
  PrincipalIdentity, PrincipalEndorsement, PrincipalDisclosure,
  FleetRecord, FleetAgent, EndorsementVerification, DisclosureLevel
} from '../types/principal.js'

// ── Principal Creation ──

/**
 * Create a new principal identity with its own Ed25519 keypair.
 * The principal is the human or org behind the agent.
 */
export function createPrincipalIdentity(options: {
  displayName: string
  domain?: string
  jurisdiction?: string
  contactChannel?: string
  disclosureLevel?: DisclosureLevel
  metadata?: Record<string, unknown>
}): { principal: PrincipalIdentity; keyPair: KeyPair } {
  const keyPair = generateKeyPair()
  const principal: PrincipalIdentity = {
    principalId: `principal-${uuidv4().slice(0, 8)}`,
    displayName: options.displayName,
    publicKey: keyPair.publicKey,
    domain: options.domain,
    jurisdiction: options.jurisdiction,
    contactChannel: options.contactChannel,
    disclosureLevel: options.disclosureLevel || 'public',
    createdAt: new Date().toISOString(),
    metadata: options.metadata || {}
  }
  return { principal, keyPair }
}

// ── Endorsement ──

/**
 * Endorse an agent. The principal signs a commitment:
 * "This agent acts under my authority within this scope."
 * Creates a two-layer trust chain: principal → agent.
 */
export function endorseAgent(options: {
  principal: PrincipalIdentity
  principalPrivateKey: string
  agentId: string
  agentPublicKey: string
  scope: string[]
  relationship: PrincipalEndorsement['relationship']
  expiresInDays?: number
}): PrincipalEndorsement {
  const now = new Date()
  const expiry = new Date(now)
  expiry.setDate(expiry.getDate() + (options.expiresInDays || 365))

  const endorsementId = `endorsement-${uuidv4().slice(0, 8)}`
  const payload = {
    endorsementId,
    principalId: options.principal.principalId,
    principalPublicKey: options.principal.publicKey,
    agentId: options.agentId,
    agentPublicKey: options.agentPublicKey,
    scope: options.scope,
    relationship: options.relationship,
    endorsedAt: now.toISOString(),
    expiresAt: expiry.toISOString()
  }

  const canonical = canonicalize(payload)
  const signature = sign(canonical, options.principalPrivateKey)

  return {
    ...payload,
    revoked: false,
    signature
  }
}

/**
 * Verify an endorsement's cryptographic signature.
 */
export function verifyEndorsement(endorsement: PrincipalEndorsement): EndorsementVerification {
  const errors: string[] = []
  const expired = new Date(endorsement.expiresAt) < new Date()

  if (expired) errors.push('Endorsement has expired')
  if (endorsement.revoked) errors.push('Endorsement has been revoked')

  // Reconstruct the signed payload (everything except revoked/revokedAt/revokedReason/signature)
  const payload = {
    endorsementId: endorsement.endorsementId,
    principalId: endorsement.principalId,
    principalPublicKey: endorsement.principalPublicKey,
    agentId: endorsement.agentId,
    agentPublicKey: endorsement.agentPublicKey,
    scope: endorsement.scope,
    relationship: endorsement.relationship,
    endorsedAt: endorsement.endorsedAt,
    expiresAt: endorsement.expiresAt
  }

  const canonical = canonicalize(payload)
  const sigValid = verify(canonical, endorsement.signature, endorsement.principalPublicKey)
  if (!sigValid) errors.push('Invalid signature')

  return {
    valid: sigValid && !expired && !endorsement.revoked,
    expired,
    revoked: endorsement.revoked,
    principalId: endorsement.principalId,
    agentId: endorsement.agentId,
    errors
  }
}

/**
 * Revoke a principal's endorsement of an agent.
 * "I no longer authorize this agent."
 */
export function revokeEndorsement(
  endorsement: PrincipalEndorsement,
  reason: string
): PrincipalEndorsement {
  return {
    ...endorsement,
    revoked: true,
    revokedAt: new Date().toISOString(),
    revokedReason: reason
  }
}

// ── Selective Disclosure ──

/**
 * Create a selective disclosure of principal identity.
 * Controls how much information is revealed.
 *
 * - minimal: just a hash of principalId + proof (verifiable but anonymous)
 * - verified-only: principalId + publicKey + domain
 * - public: everything
 */
export function createDisclosure(
  principal: PrincipalIdentity,
  principalPrivateKey: string,
  level?: DisclosureLevel
): PrincipalDisclosure {
  const effectiveLevel = level || principal.disclosureLevel

  let revealedFields: Record<string, unknown>

  switch (effectiveLevel) {
    case 'minimal': {
      // Hash the principalId with SHA-256 (non-reversible).
      // NOTE: DID is included for signature verification but reveals the public key.
      // Known limitation: minimal disclosure is anonymous to third parties who don't
      // have a public key directory, but not anonymous to parties who do.
      // Future: consider blind signatures or ZK proofs for true anonymity.
      const idHash = simpleHash(principal.principalId)
      revealedFields = { idHash, did: createDID(principal.publicKey) }
      break
    }
    case 'verified-only':
      revealedFields = {
        principalId: principal.principalId,
        publicKey: principal.publicKey,
        did: createDID(principal.publicKey),
        domain: principal.domain
      }
      break
    case 'public':
    default:
      revealedFields = {
        principalId: principal.principalId,
        displayName: principal.displayName,
        publicKey: principal.publicKey,
        did: createDID(principal.publicKey),
        domain: principal.domain,
        jurisdiction: principal.jurisdiction,
        contactChannel: principal.contactChannel
      }
      break
  }

  const canonical = canonicalize(revealedFields)
  const proof = sign(canonical, principalPrivateKey)

  return {
    disclosureId: `disclosure-${uuidv4().slice(0, 8)}`,
    principalId: principal.principalId,
    level: effectiveLevel,
    revealedFields,
    proof,
    createdAt: new Date().toISOString()
  }
}

/**
 * Verify a selective disclosure's proof.
 * For minimal disclosures, you can verify the proof without knowing the identity.
 */
export function verifyDisclosure(disclosure: PrincipalDisclosure): {
  valid: boolean
  level: DisclosureLevel
  error?: string
} {
  try {
    // For minimal, we need the DID to extract the public key
    const did = disclosure.revealedFields.did as string
    if (!did) return { valid: false, level: disclosure.level, error: 'No DID in disclosure' }

    const publicKey = did.split(':')[2]
    if (!publicKey) return { valid: false, level: disclosure.level, error: 'Invalid DID format' }

    const canonical = canonicalize(disclosure.revealedFields)
    const sigValid = verify(canonical, disclosure.proof, publicKey)

    return { valid: sigValid, level: disclosure.level, error: sigValid ? undefined : 'Invalid proof' }
  } catch (err) {
    return { valid: false, level: disclosure.level, error: String(err) }
  }
}

// ── Fleet Management ──

/**
 * Create a fleet record for a principal.
 * A fleet tracks all agents endorsed by one principal.
 */
export function createFleet(principal: PrincipalIdentity): FleetRecord {
  return {
    principalId: principal.principalId,
    principalPublicKey: principal.publicKey,
    agents: [],
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  }
}

/**
 * Add an endorsed agent to the fleet.
 */
export function addToFleet(fleet: FleetRecord, endorsement: PrincipalEndorsement): FleetRecord {
  const agent: FleetAgent = {
    agentId: endorsement.agentId,
    agentPublicKey: endorsement.agentPublicKey,
    endorsementId: endorsement.endorsementId,
    relationship: endorsement.relationship,
    status: endorsement.revoked ? 'revoked' :
            new Date(endorsement.expiresAt) < new Date() ? 'expired' : 'active',
    endorsedAt: endorsement.endorsedAt
  }
  return {
    ...fleet,
    agents: [...fleet.agents, agent],
    updatedAt: new Date().toISOString()
  }
}

/**
 * Get fleet status summary.
 */
export function getFleetStatus(fleet: FleetRecord): {
  principalId: string
  totalAgents: number
  activeAgents: number
  revokedAgents: number
  expiredAgents: number
  agents: FleetAgent[]
} {
  const active = fleet.agents.filter(a => a.status === 'active')
  const revoked = fleet.agents.filter(a => a.status === 'revoked')
  const expired = fleet.agents.filter(a => a.status === 'expired')
  return {
    principalId: fleet.principalId,
    totalAgents: fleet.agents.length,
    activeAgents: active.length,
    revokedAgents: revoked.length,
    expiredAgents: expired.length,
    agents: fleet.agents
  }
}

/**
 * Revoke an agent from the fleet (updates status).
 */
export function revokeFromFleet(fleet: FleetRecord, agentId: string): FleetRecord {
  return {
    ...fleet,
    agents: fleet.agents.map(a =>
      a.agentId === agentId ? { ...a, status: 'revoked' as const } : a
    ),
    updatedAt: new Date().toISOString()
  }
}

// ── Passport Endorsement ──

/**
 * Endorse a signed passport. The principal signs the agent's passport,
 * creating a verifiable chain: principal → agent.
 * Returns the endorsement + the passport with principal info in metadata.
 */
export function endorsePassport(options: {
  principal: PrincipalIdentity
  principalPrivateKey: string
  signedPassport: SignedPassport
  scope: string[]
  relationship: PrincipalEndorsement['relationship']
  expiresInDays?: number
}): {
  endorsement: PrincipalEndorsement
  endorsedPassport: SignedPassport
} {
  const { principal, signedPassport } = options
  const passport = signedPassport.passport

  // Create the endorsement
  const endorsement = endorseAgent({
    principal,
    principalPrivateKey: options.principalPrivateKey,
    agentId: passport.agentId,
    agentPublicKey: passport.publicKey,
    scope: options.scope,
    relationship: options.relationship,
    expiresInDays: options.expiresInDays
  })

  // Attach principal identity to passport metadata
  const endorsedPassport: SignedPassport = {
    ...signedPassport,
    passport: {
      ...passport,
      metadata: {
        ...passport.metadata,
        principalEndorsement: {
          endorsementId: endorsement.endorsementId,
          principalId: principal.principalId,
          principalDID: createDID(principal.publicKey),
          principalPublicKey: principal.publicKey,
          relationship: endorsement.relationship,
          scope: endorsement.scope,
          endorsedAt: endorsement.endorsedAt,
          expiresAt: endorsement.expiresAt,
          signature: endorsement.signature
        }
      }
    }
  }

  return { endorsement, endorsedPassport }
}

/**
 * Verify that a passport's principal endorsement is valid.
 * Checks the endorsement signature embedded in passport metadata.
 */
export function verifyPassportEndorsement(signedPassport: SignedPassport): EndorsementVerification {
  const meta = signedPassport.passport.metadata?.principalEndorsement as {
    endorsementId: string
    principalId: string
    principalDID: string
    principalPublicKey: string
    relationship: string
    scope: string[]
    endorsedAt: string
    expiresAt: string
    signature: string
  } | undefined

  if (!meta) {
    return {
      valid: false, expired: false, revoked: false,
      principalId: '', agentId: signedPassport.passport.agentId,
      errors: ['No principal endorsement found in passport metadata']
    }
  }

  // Reconstruct the endorsement and verify
  const endorsement: PrincipalEndorsement = {
    endorsementId: meta.endorsementId,
    principalId: meta.principalId,
    principalPublicKey: meta.principalPublicKey,
    agentId: signedPassport.passport.agentId,
    agentPublicKey: signedPassport.passport.publicKey,
    scope: meta.scope,
    relationship: meta.relationship as PrincipalEndorsement['relationship'],
    endorsedAt: meta.endorsedAt,
    expiresAt: meta.expiresAt,
    revoked: false,
    signature: meta.signature
  }

  return verifyEndorsement(endorsement)
}

/**
 * Check if a passport has a principal endorsement.
 */
export function hasPrincipalEndorsement(signedPassport: SignedPassport): boolean {
  return !!signedPassport.passport.metadata?.principalEndorsement
}

// ── Helpers ──

function simpleHash(input: string): string {
  // SHA-256 hash for creating non-reversible identifiers in minimal disclosure.
  // Replaces prior 32-bit shift-XOR that was brute-forceable against
  // the principal-XXXXXXXX format (~4B possibilities).
  return createHash('sha256').update(input).digest('hex')
}
