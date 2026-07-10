// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Curated essential exports — import from 'agent-passport-system/core'
// Full API still available at 'agent-passport-system'

// Identity
export { generateKeyPair } from './crypto/keys.js'
export { createPassport } from './core/passport.js'
export { verifyPassport } from './verification/verify.js'

// Delegation
export {
  createDelegation,
  verifyDelegation,
  revokeDelegation,
  subDelegate,
  cascadeRevoke,
  scopeAuthorizes,
} from './core/delegation.js'

// Policy & Enforcement
export {
  createActionIntent,
  evaluateIntent,
} from './core/policy.js'

// createAgentContext moved to @aeoess/gateway. See MIGRATION.md.

// Values Floor
export {
  loadFloor,
  attestFloor,
} from './core/values.js'

// Commerce
export {
  commercePreflight,
  createCommerceDelegation,
  recordSpend,
  getSpendSummary,
  requestHumanApproval,
} from './core/commerce.js'

// Reputation
export {
  resolveAuthorityTier,
  checkTierForIntent,
} from './core/reputation-authority.js'

// Key Management
export { rotateKey } from './core/identity.js'

// Content-Addressed Identity
export { computeActionRef } from './core/action-ref.js'
// External cross-ecosystem correlation key, distinct from the native action_ref.
export { computeExternalActionRefV1 } from './core/external-action-ref.js'
export type { ExternalActionRefV1Input } from './core/external-action-ref.js'
export { computeIdempotencyKey } from './core/idempotency.js'

// Compliance: generateComplianceReport moved to @aeoess/gateway. See MIGRATION.md.

// Re-export essential types
export type {
  SignedPassport,
  AgentPassport,
} from './types/passport.js'

export type {
  PassportGrade,
} from './types/attestation.js'

export type {
  ActionIntent,
  PolicyReceipt,
} from './types/policy.js'

export type {
  CommercePreflightResult,
  CommerceDelegation,
  IdempotencyStore,
} from './types/commerce.js'
