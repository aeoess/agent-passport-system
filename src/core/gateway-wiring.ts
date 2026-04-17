// ══════════════════════════════════════════════════════════════════
// Gateway Wiring Layer — Connects remaining modules to enforcement
// ══════════════════════════════════════════════════════════════════
// Thin adapter + re-export layer. The gateway imports this single
// module to access hooks from 13 previously disconnected modules.
// Each hook translates gateway context into module-specific calls.
// ══════════════════════════════════════════════════════════════════

import { commercePreflight } from './commerce.js'
import type { SignedPassport, Delegation } from '../types/passport.js'
import type { ConstraintFailure } from '../types/gateway.js'

// ── Commerce Preflight Hook ──

export interface CommerceCheckResult {
  passed: boolean
  reason?: string
  failure?: ConstraintFailure
}

export function checkCommerceConstraint(
  passport: SignedPassport,
  delegation: Delegation,
  tool: string,
  spend?: { amount: number; currency: string },
): CommerceCheckResult {
  if (!spend || !delegation.scope?.some(s => s.startsWith('commerce'))) {
    return { passed: true }
  }
  const result = commercePreflight({
    signedPassport: passport,
    delegation: delegation as any,
    merchantName: tool,
    estimatedTotal: { amount: spend.amount, currency: spend.currency as any },
  })
  if (!result.permitted) {
    return {
      passed: false,
      reason: `Commerce preflight failed: ${result.checks.filter((c: any) => !c.passed).map((c: any) => c.detail).join('; ')}`,
      failure: {
        facet: 'spend', status: 'fail', code: 'COMMERCE_PREFLIGHT_FAILED',
        limit: delegation.spendLimit, actual: spend.amount,
        severity: 'hard', retryable: false,
        message: `Commerce preflight: ${result.checks.filter((c: any) => !c.passed).map((c: any) => c.check).join(', ')}`,
      },
    }
  }
  return { passed: true }
}

// ── Charter: institutional rule hydration ──
import { verifyCharter } from './charter.js'
import type { CharterCore } from '../types/charter.js'

export interface CharterPolicyExtract {
  charterId: string
  valid: boolean
  scopeRestrictions?: string[]
  requireWitness?: boolean
}

export function extractCharterPolicy(charter: CharterCore): CharterPolicyExtract {
  try {
    const verification = verifyCharter(charter)
    return {
      charterId: charter.charterId,
      valid: verification.valid,
      scopeRestrictions: charter.offices?.flatMap((o: any) => o.scopeRestrictions ?? []),
      requireWitness: charter.offices?.some((o: any) => o.requiresWitness),
    }
  } catch {
    return { charterId: charter.charterId, valid: false }
  }
}

// ── Re-exports: Precedent ──
export { createPrecedentLibrary, checkAlignment, addToLibrary, markAsNormative, analyzeDrift } from './precedent.js'
export type { PrecedentLibrary, PrecedentAlignment, NormativePrecedent } from './precedent.js'

// ── Re-exports: Routing ──
export { capabilityMatches, capabilityCoverage, checkDelegationScope } from './routing.js'

// ── Re-exports: EU AI Act ──
// generateComplianceReport moved to @aeoess/gateway. See MIGRATION.md.

// ── Re-exports: Federation ──
export { importReceipt, verifyReceiptEnvelope, vouchReputation, verifyVouchedReputation, applyReputationDowngrade } from './federation.js'

// ── Re-exports: Coordination ──
export {
  createTaskBrief, assignTask, acceptTask,
  submitEvidence, reviewEvidence, submitDeliverable, completeTask,
} from './coordination.js'

// ── Re-exports: Oracle/Witness ──
export {
  createWitnessPool, createAttestation, verifyWitnessAttestation,
  addAttestation, evaluateWitnessConsensus, computeDiversityScore,
} from './oracle-witness.js'

// ── Re-exports: Reserve ──
export { createReserveAttestation, verifyReserveAttestation, meetsAssuranceRequirement } from './reserve.js'

// ── Re-exports: Agent Context ──
// AgentContext and createAgentContext moved to @aeoess/gateway. See MIGRATION.md.

// ── Re-exports: Governance Consumer ──
export { checkHTMLGovernance, checkHeaderGovernance, governanceLoop360 } from './governance-consumer.js'

// ── Re-exports: Encrypted Messaging ──
export {
  generateEncryptionKeypair, deriveEncryptionKeypair,
  createKeyAnnouncement, verifyKeyAnnouncement,
  encryptPayload, decryptPayload,
  createEncryptedAgoraMessage, decryptAgoraMessage, verifyOuterSignature,
} from './encrypted-messaging.js'

// ── Re-exports: Messaging Audit ──
export {
  createMessageAuditLog, createAuditRecord, verifyAuditRecord,
  appendToAuditLog, queryBySender, queryCrossChainMessages,
} from './messaging-audit.js'
