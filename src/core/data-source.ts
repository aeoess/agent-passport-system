// Data Source Registration & Access Receipts — Module 36A
// Foundation layer for data contribution tracking.
// Access is not contribution, and contribution is not value.
// Prove use before trying to price it.
//
// Provides cryptographic accountability, not independent verification.
// Receipts are trustworthy to the degree that you trust the gateway operator.

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { buildMerkleRoot, generateMerkleProof, verifyMerkleProof } from './attribution.js'
import type { MerkleProof } from '../types/passport.js'
import type {
  SourceReceipt, SourceMode, DataContentType, DataTerms, DataPurpose,
  DataAccessReceipt, AccessMethod, CompensationModel,
  SourceReceiptVerification, AccessReceiptVerification, TermsComplianceResult,
  DerivativePolicy,
} from '../types/data-source.js'
import { addReceipt } from './receipt-ledger.js'
import type { ReceiptLedger } from './receipt-ledger.js'

import { createHash } from 'crypto'

function sha256(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex')
}

// ══════════════════════════════════════
// SOURCE REGISTRATION
// ══════════════════════════════════════

export function registerSelfAttestedSource(opts: {
  ownerPrincipalId: string
  ownerPublicKey: string
  ownerPrivateKey: string
  contentCommitment: string
  contentType: DataContentType
  contentDescriptor: string
  dataTerms: DataTerms
}): SourceReceipt {
  const now = new Date().toISOString()
  const receipt: Omit<SourceReceipt, 'signature'> = {
    sourceReceiptId: 'srcr_' + uuidv4().slice(0, 12),
    sourceMode: 'self_attested',
    sourcePrincipalId: opts.ownerPrincipalId,
    signerPublicKey: opts.ownerPublicKey,
    contentCommitment: opts.contentCommitment,
    contentType: opts.contentType,
    contentDescriptor: opts.contentDescriptor,
    dataTerms: opts.dataTerms,
    issuedAt: now,
    issuedBy: opts.ownerPublicKey,
  }
  const canonical = canonicalize(receipt)
  const signature = sign(canonical, opts.ownerPrivateKey)
  return { ...receipt, signature }
}

export function registerCustodianAttestedSource(opts: {
  ownerPrincipalId: string
  ownerPublicKey: string
  custodianPublicKey: string
  custodianPrivateKey: string
  contentCommitment: string
  contentType: DataContentType
  contentDescriptor: string
  dataTerms: DataTerms
}): SourceReceipt {
  const now = new Date().toISOString()
  const receipt: Omit<SourceReceipt, 'signature'> = {
    sourceReceiptId: 'srcr_' + uuidv4().slice(0, 12),
    sourceMode: 'custodian_attested',
    sourcePrincipalId: opts.ownerPrincipalId,
    signerPublicKey: opts.custodianPublicKey,
    contentCommitment: opts.contentCommitment,
    contentType: opts.contentType,
    contentDescriptor: opts.contentDescriptor,
    dataTerms: opts.dataTerms,
    issuedAt: now,
    issuedBy: opts.custodianPublicKey,
  }
  const canonical = canonicalize(receipt)
  const signature = sign(canonical, opts.custodianPrivateKey)
  return { ...receipt, signature }
}

export function registerGatewayObservedSource(opts: {
  gatewayPublicKey: string
  gatewayPrivateKey: string
  contentCommitment: string
  contentType: DataContentType
  contentDescriptor: string
  gatewayDefaultTerms: DataTerms
}): SourceReceipt {
  const now = new Date().toISOString()
  const receipt: Omit<SourceReceipt, 'signature'> = {
    sourceReceiptId: 'srcr_' + uuidv4().slice(0, 12),
    sourceMode: 'gateway_observed',
    sourcePrincipalId: null,             // owner unknown
    signerPublicKey: opts.gatewayPublicKey,
    contentCommitment: opts.contentCommitment,
    contentType: opts.contentType,
    contentDescriptor: opts.contentDescriptor,
    dataTerms: opts.gatewayDefaultTerms,
    issuedAt: now,
    issuedBy: opts.gatewayPublicKey,
  }
  const canonical = canonicalize(receipt)
  const signature = sign(canonical, opts.gatewayPrivateKey)
  return { ...receipt, signature }
}

// ══════════════════════════════════════
// VERIFY SOURCE RECEIPT
// ══════════════════════════════════════

export function verifySourceReceipt(receipt: SourceReceipt): SourceReceiptVerification {
  const errors: string[] = []

  // Signature check
  const { signature, revokedAt, revocationReason, expiresAt, ...signable } = receipt
  const canonical = canonicalize(signable)
  let signatureValid = false
  try {
    signatureValid = verify(canonical, signature, receipt.issuedBy)
  } catch { signatureValid = false }
  if (!signatureValid) errors.push('Invalid source receipt signature')

  // Terms validity (basic structural checks)
  const termsValid = receipt.dataTerms.allowedPurposes.length > 0
  if (!termsValid) errors.push('DataTerms must have at least one allowed purpose')

  // Expiry check
  const notExpired = !receipt.expiresAt || new Date(receipt.expiresAt) > new Date()
  if (!notExpired) errors.push('Source receipt expired')

  // Revocation check
  const notRevoked = !receipt.revokedAt
  if (!notRevoked) errors.push('Source receipt revoked')

  // Trust level from attestation mode
  const trustLevel: 'high' | 'medium' | 'low' =
    receipt.sourceMode === 'self_attested' ? 'high' :
    receipt.sourceMode === 'custodian_attested' ? 'medium' : 'low'

  return {
    valid: signatureValid && termsValid && notExpired && notRevoked,
    errors,
    signatureValid,
    termsValid,
    notExpired,
    notRevoked,
    trustLevel,
  }
}

// ══════════════════════════════════════
// REVOKE SOURCE RECEIPT
// ══════════════════════════════════════

export function revokeSourceReceipt(opts: {
  receipt: SourceReceipt
  reason?: string
  revokerPrivateKey: string
}): SourceReceipt {
  // Revocation is a state mutation, not a re-sign.
  // The original signature remains valid for the original registration.
  // revokedAt is set to mark the source as inactive for future access.
  return {
    ...opts.receipt,
    revokedAt: new Date().toISOString(),
    revocationReason: opts.reason,
  }
}

// ══════════════════════════════════════
// DATA ACCESS RECEIPTS
// ══════════════════════════════════════

export function recordDataAccess(opts: {
  sourceReceipt: SourceReceipt
  dataHash: string
  agentId: string
  agentPublicKey: string
  delegationId?: string
  principalId: string
  executionFrameId: string
  accessScope: string
  accessMethod: AccessMethod
  declaredPurpose: DataPurpose
  gatewayId: string
  gatewayPublicKey: string
  gatewayPrivateKey: string
}): DataAccessReceipt {
  const now = new Date().toISOString()
  const receipt: Omit<DataAccessReceipt, 'gatewaySignature'> = {
    accessReceiptId: 'dacr_' + uuidv4().slice(0, 12),
    sourceReceiptId: opts.sourceReceipt.sourceReceiptId,
    sourceMode: opts.sourceReceipt.sourceMode,
    dataHash: opts.dataHash,
    agentId: opts.agentId,
    agentPublicKey: opts.agentPublicKey,
    delegationId: opts.delegationId,
    principalId: opts.principalId,
    executionFrameId: opts.executionFrameId,
    accessScope: opts.accessScope,
    accessMethod: opts.accessMethod,
    declaredPurpose: opts.declaredPurpose,
    termsAtAccessTime: { ...opts.sourceReceipt.dataTerms },
    timestamp: now,
    gatewayId: opts.gatewayId,
    gatewayPublicKey: opts.gatewayPublicKey,
  }
  const canonical = canonicalize(receipt)
  const gatewaySignature = sign(canonical, opts.gatewayPrivateKey)
  return { ...receipt, gatewaySignature }
}

export function verifyDataAccessReceipt(receipt: DataAccessReceipt): AccessReceiptVerification {
  const errors: string[] = []

  // Gateway signature check
  const { gatewaySignature, ...signable } = receipt
  const canonical = canonicalize(signable)
  let gatewaySignatureValid = false
  try {
    gatewaySignatureValid = verify(canonical, gatewaySignature, receipt.gatewayPublicKey)
  } catch { gatewaySignatureValid = false }
  if (!gatewaySignatureValid) errors.push('Invalid gateway signature on access receipt')

  // Source receipt reference exists (basic structural check)
  const sourceReceiptExists = !!receipt.sourceReceiptId && receipt.sourceReceiptId.startsWith('srcr_')
  if (!sourceReceiptExists) errors.push('Missing or malformed sourceReceiptId')

  // Temporal validity
  const ts = new Date(receipt.timestamp)
  const temporalValid = !isNaN(ts.getTime()) && ts <= new Date()
  if (!temporalValid) errors.push('Invalid or future timestamp')

  return {
    valid: gatewaySignatureValid && sourceReceiptExists && temporalValid,
    errors,
    gatewaySignatureValid,
    sourceReceiptExists,
    temporalValid,
  }
}

// ══════════════════════════════════════
// TERMS COMPLIANCE — hard vs advisory
// ══════════════════════════════════════

export function checkTermsCompliance(opts: {
  sourceReceipt: SourceReceipt
  declaredPurpose: DataPurpose
  agentId: string
  principalId: string
  currentAccessCount?: number
}): TermsComplianceResult {
  const hardViolations: string[] = []
  const advisoryWarnings: string[] = []
  const terms = opts.sourceReceipt.dataTerms

  // ── Hard violations (deterministic, can block) ──

  // Revoked source
  if (opts.sourceReceipt.revokedAt) {
    hardViolations.push(`Source revoked at ${opts.sourceReceipt.revokedAt}`)
  }

  // Expired terms
  if (terms.expiresAt && new Date(terms.expiresAt) <= new Date()) {
    hardViolations.push(`Terms expired at ${terms.expiresAt}`)
  }

  // Excluded agent
  if (terms.excludedAgents?.includes(opts.agentId)) {
    hardViolations.push(`Agent ${opts.agentId} is in excludedAgents`)
  }

  // Excluded principal
  if (terms.excludedPrincipals?.includes(opts.principalId)) {
    hardViolations.push(`Principal ${opts.principalId} is in excludedPrincipals`)
  }

  // Max access count exceeded
  let accessesRemaining: number | undefined
  if (terms.maxAccessCount != null && opts.currentAccessCount != null) {
    accessesRemaining = terms.maxAccessCount - opts.currentAccessCount
    if (accessesRemaining <= 0) {
      hardViolations.push(`Max access count exceeded (${opts.currentAccessCount}/${terms.maxAccessCount})`)
    }
  }

  // ── Advisory warnings (declared-intent, audit trail only) ──

  // Purpose not in allowed
  if (!terms.allowedPurposes.includes(opts.declaredPurpose)) {
    advisoryWarnings.push(`Declared purpose '${opts.declaredPurpose}' not in allowedPurposes`)
  }

  // Purpose in excluded
  if (terms.excludedPurposes?.includes(opts.declaredPurpose)) {
    advisoryWarnings.push(`Declared purpose '${opts.declaredPurpose}' is in excludedPurposes`)
  }

  return {
    compliant: hardViolations.length === 0,
    hardViolations,
    advisoryWarnings,
    accessesRemaining,
  }
}

// ══════════════════════════════════════
// TERMS COMPOSITION (monotonic narrowing)
// ══════════════════════════════════════

const DERIVATIVE_STRICTNESS: Record<DerivativePolicy, number> = {
  'unrestricted': 0,
  'same_terms': 1,
  'attribution_required': 2,
  'no_derivatives': 3,
}

export function composeTerms(terms: DataTerms[]): DataTerms {
  if (terms.length === 0) throw new Error('Cannot compose empty terms array')
  if (terms.length === 1) return { ...terms[0] }

  // Intersection of allowed purposes (most restrictive)
  let allowedPurposes = [...terms[0].allowedPurposes]
  for (let i = 1; i < terms.length; i++) {
    allowedPurposes = allowedPurposes.filter(p => terms[i].allowedPurposes.includes(p))
  }

  // Union of excluded purposes
  const excludedSet = new Set<DataPurpose>()
  for (const t of terms) {
    if (t.excludedPurposes) t.excludedPurposes.forEach(p => excludedSet.add(p))
  }

  // Union of excluded agents
  const excludedAgentsSet = new Set<string>()
  for (const t of terms) {
    if (t.excludedAgents) t.excludedAgents.forEach(a => excludedAgentsSet.add(a))
  }

  // Union of excluded principals
  const excludedPrincipalsSet = new Set<string>()
  for (const t of terms) {
    if (t.excludedPrincipals) t.excludedPrincipals.forEach(p => excludedPrincipalsSet.add(p))
  }

  // OR of requireAttribution (if any requires, all must)
  const requireAttribution = terms.some(t => t.requireAttribution)
  const requireNotification = terms.some(t => t.requireNotification)

  // Most restrictive derivative policy
  let maxStrictness = 0
  let derivativePolicy: DerivativePolicy = 'unrestricted'
  for (const t of terms) {
    const s = DERIVATIVE_STRICTNESS[t.derivativePolicy]
    if (s > maxStrictness) { maxStrictness = s; derivativePolicy = t.derivativePolicy }
  }

  // Shortest retention limit
  const retentions = terms.map(t => t.retentionLimit).filter(Boolean) as string[]
  const retentionLimit = retentions.length > 0 ? retentions.sort()[0] : undefined

  // Earliest expiry
  const expiries = terms.map(t => t.expiresAt).filter(Boolean) as string[]
  const expiresAt = expiries.length > 0
    ? expiries.sort()[0]  // ISO strings sort correctly
    : undefined

  // Max trust level required
  const trustLevels = terms.map(t => t.requiredTrustLevel).filter(v => v != null) as number[]
  const requiredTrustLevel = trustLevels.length > 0 ? Math.max(...trustLevels) : undefined

  // Min access count (most restrictive)
  const counts = terms.map(t => t.maxAccessCount).filter(v => v != null) as number[]
  const maxAccessCount = counts.length > 0 ? Math.min(...counts) : undefined

  // Most restrictive audit visibility (source_only > source_and_principal > ... > public)
  const AUDIT_STRICTNESS: Record<string, number> = {
    'source_only': 3, 'source_and_principal': 2, 'source_principal_auditor': 1, 'public': 0,
  }
  let auditMax = 0
  let auditVisibility = terms[0].auditVisibility
  for (const t of terms) {
    const s = AUDIT_STRICTNESS[t.auditVisibility] ?? 0
    if (s > auditMax) { auditMax = s; auditVisibility = t.auditVisibility }
  }

  // Compensation: cannot be automatically composed — use first source's model
  // (In practice, composition requires a settlement policy, which is Brief 4)
  const compensation = terms[0].compensation

  // Revocable: if ANY source is revocable, composed terms are revocable
  const revocable = terms.some(t => t.revocable)

  return {
    allowedPurposes,
    excludedPurposes: excludedSet.size > 0 ? Array.from(excludedSet) : undefined,
    excludedAgents: excludedAgentsSet.size > 0 ? Array.from(excludedAgentsSet) : undefined,
    excludedPrincipals: excludedPrincipalsSet.size > 0 ? Array.from(excludedPrincipalsSet) : undefined,
    requiredTrustLevel,
    requireAttribution,
    requireNotification,
    compensation,
    maxAccessCount,
    retentionLimit,
    expiresAt,
    derivativePolicy,
    auditVisibility,
    revocable,
  }
}

// ══════════════════════════════════════
// MERKLE COMMITMENT & VERIFICATION
// ══════════════════════════════════════

function hashAccessReceipt(receipt: DataAccessReceipt): string {
  return sha256(canonicalize(receipt))
}

export function buildDataAccessMerkleRoot(receipts: DataAccessReceipt[]): string {
  const hashes = receipts.map(r => hashAccessReceipt(r))
  return buildMerkleRoot(hashes)
}

export function proveDataAccessInclusion(
  receipts: DataAccessReceipt[],
  targetReceiptId: string
): MerkleProof | null {
  const target = receipts.find(r => r.accessReceiptId === targetReceiptId)
  if (!target) return null
  const hashes = receipts.map(r => hashAccessReceipt(r))
  const targetHash = hashAccessReceipt(target)
  return generateMerkleProof(hashes, targetHash)
}

export function verifyDataAccessInclusionProof(proof: MerkleProof): boolean {
  return verifyMerkleProof(proof)
}

// ══════════════════════════════════════
// LEDGER INTEGRATION
// ══════════════════════════════════════

export function addDataAccessToLedger(
  ledger: ReceiptLedger,
  receipt: DataAccessReceipt
): void {
  const hash = hashAccessReceipt(receipt)
  addReceipt(ledger, hash)
}
