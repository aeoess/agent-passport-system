// ══════════════════════════════════════════════════════════════════
// Gateway Identity Layer — Wiring DID, Principal, Entity Verification
// ══════════════════════════════════════════════════════════════════
// Connects 4 previously orphaned modules into the gateway:
//   did.ts → DID resolution from public key
//   principal.ts → principal endorsement chain verification
//   entity-verification.ts → cross-implementation entity verification
//   vc.ts → verifiable credential checking (via DID)
//
// The gateway already verifies Ed25519 signatures against raw keys.
// This layer adds: WHO delegated this agent? Is the chain verified?
// Does the agent have a resolvable DID? Is it endorsed by a principal?
// ══════════════════════════════════════════════════════════════════

import { createDID, resolveDID, isValidDID, passportToDIDDocument } from './did.js'
import { verifyEndorsement, hasPrincipalEndorsement, verifyPassportEndorsement } from './principal.js'
import { verifyEntityChain } from './entity-verification.js'
import type { SignedPassport, Delegation } from '../types/passport.js'
import type { DIDDocument, DIDResolutionResult } from '../types/did.js'
import type { PrincipalEndorsement } from '../types/principal.js'
import type { ConstraintFailure } from '../types/gateway.js'

// ── Identity Verification Result ──
// Stored on RegisteredAgent after registration.
// Captures what the gateway knows about who this agent IS beyond just
// their Ed25519 key.

export interface GatewayIdentityVerification {
  /** Agent's DID (derived from public key) */
  did: string
  /** DID Document (if resolution succeeded) */
  didDocument?: DIDDocument
  /** Whether DID resolution succeeded */
  didResolved: boolean
  /** Whether the passport carries a principal endorsement */
  hasPrincipalEndorsement: boolean
  /** Principal verification result (if endorsement exists) */
  principalVerification?: {
    valid: boolean
    principalId?: string
    errors: string[]
  }
  /** Entity verification result (if DID + entity lookup available) */
  entityVerification?: {
    status: 'verified' | 'cached' | 'failed'
    entityId?: string
    resolvedAt?: string
  }
  /** Overall identity strength: how much do we know about this agent? */
  strength: 'key_only' | 'did_resolved' | 'principal_endorsed' | 'entity_verified'
  /** Verification timestamp */
  verifiedAt: string
}

// ── Identity Verification Config ──

export interface IdentityVerificationConfig {
  /** Enable DID resolution during registration. Default: true when identity verification enabled */
  resolveDID: boolean
  /** Verify principal endorsement chain. Default: true when identity verification enabled */
  verifyPrincipal: boolean
  /** Verify entity chain (requires entityLookup). Default: false */
  verifyEntity: boolean
  /** Entity lookup function for entity verification */
  entityLookup?: (entityId: string) => Promise<{ did: string; publicKey: string; verifiedAt: string } | null>
  /** Minimum identity strength required for registration. Default: 'key_only' */
  minimumStrength: GatewayIdentityVerification['strength']
}

export const DEFAULT_IDENTITY_CONFIG: IdentityVerificationConfig = {
  resolveDID: true,
  verifyPrincipal: true,
  verifyEntity: false,
  minimumStrength: 'key_only',
}

// ── Strength Ordering ──

const STRENGTH_ORDER: GatewayIdentityVerification['strength'][] = [
  'key_only', 'did_resolved', 'principal_endorsed', 'entity_verified',
]

export function strengthMeetsMinimum(
  actual: GatewayIdentityVerification['strength'],
  minimum: GatewayIdentityVerification['strength'],
): boolean {
  return STRENGTH_ORDER.indexOf(actual) >= STRENGTH_ORDER.indexOf(minimum)
}

// ── Main Verification Function ──

/** Verify an agent's identity beyond their Ed25519 key.
 *  Called during gateway registration. Returns identity verification
 *  result that gets stored on RegisteredAgent. */
export async function verifyAgentIdentity(
  passport: SignedPassport,
  config: IdentityVerificationConfig,
): Promise<GatewayIdentityVerification> {
  const publicKey = passport.passport.publicKey
  const now = new Date().toISOString()

  // Step 1: Derive DID from public key
  const did = createDID(publicKey)
  let didDocument: DIDDocument | undefined
  let didResolved = false

  // Step 2: Resolve DID (if enabled)
  if (config.resolveDID) {
    try {
      const resolution = resolveDID(did)
      if (resolution.didDocument) {
        didDocument = resolution.didDocument
        didResolved = true
      }
    } catch {
      // DID resolution failed — not fatal, we still have the raw key
    }

    // Also generate DID Document from passport for self-resolution
    if (!didDocument) {
      try {
        didDocument = passportToDIDDocument(passport.passport)
        didResolved = true
      } catch { /* passport-to-DID conversion failed */ }
    }
  }

  // Step 3: Verify principal endorsement (if enabled and present)
  let hasPrincipal = false
  let principalVerification: GatewayIdentityVerification['principalVerification']

  if (config.verifyPrincipal && hasPrincipalEndorsement(passport)) {
    hasPrincipal = true
    const endorsementResult = verifyPassportEndorsement(passport)
    principalVerification = {
      valid: endorsementResult.valid,
      principalId: endorsementResult.principalId,
      errors: endorsementResult.errors || [],
    }
  }

  // Step 4: Entity verification (if enabled and DID resolved)
  let entityVerification: GatewayIdentityVerification['entityVerification']

  if (config.verifyEntity && config.entityLookup && didResolved) {
    try {
      const entityResult = await verifyEntityChain(
        did,
        config.entityLookup as Parameters<typeof verifyEntityChain>[1],
        { entityId: passport.passport.agentId, allowCached: true },
      )
      entityVerification = {
        status: entityResult.verified ? 'verified' : 'failed',
        entityId: passport.passport.agentId,
        resolvedAt: now,
      }
    } catch {
      entityVerification = { status: 'failed' }
    }
  }

  // Step 5: Determine identity strength
  let strength: GatewayIdentityVerification['strength'] = 'key_only'
  if (entityVerification?.status === 'verified') {
    strength = 'entity_verified'
  } else if (hasPrincipal && principalVerification?.valid) {
    strength = 'principal_endorsed'
  } else if (didResolved) {
    strength = 'did_resolved'
  }

  return {
    did,
    didDocument,
    didResolved,
    hasPrincipalEndorsement: hasPrincipal,
    principalVerification,
    entityVerification,
    strength,
    verifiedAt: now,
  }
}

/** Build an identity constraint failure for the gateway */
export function identityStrengthFailure(
  actual: GatewayIdentityVerification['strength'],
  required: GatewayIdentityVerification['strength'],
): ConstraintFailure {
  return {
    facet: 'identity',
    status: 'fail',
    code: 'INSUFFICIENT_IDENTITY_STRENGTH',
    limit: required,
    actual,
    severity: 'hard',
    retryable: false,
    message: `Identity strength '${actual}' below required '${required}'`,
  }
}

/** Synchronous identity verification — DID + principal only, no entity lookup.
 *  This is the fast path used during registerAgent(). Entity verification
 *  can be performed separately via the async verifyAgentIdentity(). */
export function verifyAgentIdentitySync(
  passport: SignedPassport,
  config: IdentityVerificationConfig,
  endorsement?: PrincipalEndorsement,
): GatewayIdentityVerification {
  const publicKey = passport.passport.publicKey
  const now = new Date().toISOString()

  // Step 1: Derive DID
  const did = createDID(publicKey)
  let didDocument: DIDDocument | undefined
  let didResolved = false

  // Step 2: Resolve DID
  if (config.resolveDID) {
    try {
      const resolution = resolveDID(did)
      if (resolution.didDocument) {
        didDocument = resolution.didDocument
        didResolved = true
      }
    } catch { /* DID resolution failed */ }

    if (!didDocument) {
      try {
        didDocument = passportToDIDDocument(passport.passport)
        didResolved = true
      } catch { /* passport-to-DID conversion failed */ }
    }
  }

  // Step 3: Verify principal endorsement
  let hasPrincipal = false
  let principalVerification: GatewayIdentityVerification['principalVerification']

  if (config.verifyPrincipal) {
    // Check separately provided endorsement first (preferred — doesn't require passport re-sign)
    if (endorsement) {
      const endorsementResult = verifyEndorsement(endorsement)
      hasPrincipal = endorsementResult.valid
      principalVerification = {
        valid: endorsementResult.valid,
        principalId: endorsementResult.principalId,
        errors: endorsementResult.errors || [],
      }
    }
    // Fall back to checking passport metadata (if endorsement was embedded before signing)
    if (!hasPrincipal && hasPrincipalEndorsement(passport)) {
      const endorsementResult = verifyPassportEndorsement(passport)
      hasPrincipal = endorsementResult.valid
      principalVerification = {
        valid: endorsementResult.valid,
        principalId: endorsementResult.principalId,
        errors: endorsementResult.errors || [],
      }
    }
  }

  // Step 4: Determine strength (no entity verification in sync path)
  let strength: GatewayIdentityVerification['strength'] = 'key_only'
  if (hasPrincipal && principalVerification?.valid) {
    strength = 'principal_endorsed'
  } else if (didResolved) {
    strength = 'did_resolved'
  }

  return {
    did,
    didDocument,
    didResolved,
    hasPrincipalEndorsement: hasPrincipal,
    principalVerification,
    strength,
    verifiedAt: now,
  }
}
