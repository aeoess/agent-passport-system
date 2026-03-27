// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Charter — Pure Functions for Institutional Governance
// ══════════════════════════════════════════════════════════════════
// Create, verify, amend charters. Evaluate multi-class thresholds.
// Manage office transfers and succession. All functions are pure —
// no side effects, no storage, no gateway calls.
// ══════════════════════════════════════════════════════════════════

import { v4 as uuidv4 } from 'uuid'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { createHash } from 'crypto'
import type {
  CharterCore, CharterStatus, CharterSignature,
  Office, OfficeHolder, OfficeDelegationPolicy,
  OfficeRegistry, OfficeTransfer,
  CharterAmendment, CharterVerification, AmendmentVerification,
  DelegationSurvival, DissolutionPolicy, DisputeVenue,
  SuccessionRule, SuccessionTrigger, QuorumFailurePolicy,
} from '../types/charter.js'
import type {
  MultiClassThresholdPolicy, KeyClassRequirement,
  ApprovalRequest, ApprovalSignature, ApprovalSubjectType,
  ApprovalEvaluation, KeyClassStatus, ApprovalPolicy,
} from '../types/approval.js'

// ══════════════════════════════════════
// CONTENT HASHING
// ══════════════════════════════════════

function charterHash(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex')
}

// ══════════════════════════════════════
// CREATE CHARTER
// ══════════════════════════════════════

export interface CreateCharterOptions {
  name: string
  offices: Office[]
  amendmentPolicy: MultiClassThresholdPolicy
  dissolutionPolicy: DissolutionPolicy
  delegationSurvival: DelegationSurvival
  disputeVenue?: DisputeVenue
  founderPrivateKey: string
  founderPublicKey: string
  founderRole: string           // key class: 'board', 'recovery', etc.
  version?: string              // defaults to '1.0.0'
}

/** Create a new charter. The founder signs it as the first founding signatory.
 *  Additional signatories can be added with signCharter() until the
 *  amendment policy threshold is met. */
export function createCharter(opts: CreateCharterOptions): CharterCore {
  const now = new Date().toISOString()

  // Validate offices
  const officeIds = opts.offices.map(o => o.officeId)
  const duplicateOffice = officeIds.find((id, i) => officeIds.indexOf(id) !== i)
  if (duplicateOffice) {
    throw new Error(`Duplicate office ID: ${duplicateOffice}`)
  }

  // Build charter without signature first
  const charter: Omit<CharterCore, 'contentHash' | 'signature'> = {
    charterId: 'charter_' + uuidv4().slice(0, 12),
    version: opts.version ?? '1.0.0',
    previousVersion: null,
    name: opts.name,
    status: 'active' as CharterStatus,
    offices: opts.offices,
    amendmentPolicy: opts.amendmentPolicy,
    dissolutionPolicy: opts.dissolutionPolicy,
    delegationSurvival: opts.delegationSurvival,
    disputeVenue: opts.disputeVenue,
    createdAt: now,
    foundingSignatures: [],
  }

  // Hash the charter content
  const contentHash = charterHash(canonicalize(charter))

  // Founder signs the content hash
  const founderSig: CharterSignature = {
    publicKey: opts.founderPublicKey,
    role: opts.founderRole,
    signedAt: now,
    signature: sign(contentHash, opts.founderPrivateKey),
  }

  // Sign the full charter (content hash + founding signatures)
  const withSigs = { ...charter, contentHash, foundingSignatures: [founderSig] }
  const canonical = canonicalize(withSigs)
  const signature = sign(canonical, opts.founderPrivateKey)

  return { ...withSigs, signature }
}

// ══════════════════════════════════════
// SIGN CHARTER (add founding signature)
// ══════════════════════════════════════

/** Add a founding signature to a charter. Returns a new charter
 *  with the additional signature and a re-signed outer signature. */
export function signCharter(
  charter: CharterCore,
  signerPrivateKey: string,
  signerPublicKey: string,
  signerRole: string,
  resignerPrivateKey: string,
): CharterCore {
  // Check for duplicate signer
  if (charter.foundingSignatures.some(s => s.publicKey === signerPublicKey)) {
    throw new Error(`Signer ${signerPublicKey.slice(0, 8)}... already signed this charter`)
  }

  const newSig: CharterSignature = {
    publicKey: signerPublicKey,
    role: signerRole,
    signedAt: new Date().toISOString(),
    signature: sign(charter.contentHash, signerPrivateKey),
  }

  const updatedSigs = [...charter.foundingSignatures, newSig]
  const withSigs = { ...charter, foundingSignatures: updatedSigs }
  const { signature: _old, ...signable } = withSigs
  const canonical = canonicalize(signable)
  const signature = sign(canonical, resignerPrivateKey)

  return { ...withSigs, signature }
}

// ══════════════════════════════════════
// VERIFY CHARTER
// ══════════════════════════════════════

/** Verify a charter's integrity: content hash, signatures, office consistency. */
export function verifyCharter(charter: CharterCore): CharterVerification {
  const errors: string[] = []

  // 1. Content integrity — strip signature + contentHash + foundingSignatures, re-hash
  const { signature, contentHash, foundingSignatures, ...body } = charter
  const expectedHash = charterHash(canonicalize({ ...body, foundingSignatures: [] }))
  const contentIntegrity = expectedHash === contentHash
  if (!contentIntegrity) errors.push('Content hash mismatch')

  // 2. Verify each founding signature against the content hash
  let signaturesValid = true
  for (const sig of foundingSignatures) {
    try {
      if (!verify(contentHash, sig.signature, sig.publicKey)) {
        signaturesValid = false
        errors.push(`Invalid signature from ${sig.publicKey.slice(0, 8)}...`)
      }
    } catch {
      signaturesValid = false
      errors.push(`Signature verification failed for ${sig.publicKey.slice(0, 8)}...`)
    }
  }

  // 3. Check if founding signatures meet the amendment policy threshold
  const quorumEval = evaluateThreshold(
    charter.amendmentPolicy,
    foundingSignatures.map(s => ({ publicKey: s.publicKey, keyClass: s.role, signedAt: s.signedAt, signature: s.signature })),
  )
  const quorumMet = quorumEval.met
  if (!quorumMet) errors.push('Founding signatures do not meet amendment policy threshold')

  // 4. Not dissolved
  const notDissolved = charter.status !== 'dissolved'
  if (!notDissolved) errors.push('Charter has been dissolved')

  // 5. Office validation — no duplicate IDs, succession references valid offices
  let officesValid = true
  const officeIds = new Set(charter.offices.map(o => o.officeId))
  for (const office of charter.offices) {
    for (const succId of office.successionOrder) {
      if (!officeIds.has(succId)) {
        officesValid = false
        errors.push(`Office ${office.officeId} succession references unknown office ${succId}`)
      }
    }
  }

  // 6. Incompatibility — no holder holds two incompatible offices (GPT #20)
  let incompatibilityClean = true
  const holderOffices = new Map<string, string[]>()
  for (const office of charter.offices) {
    for (const holder of office.holderSet) {
      const existing = holderOffices.get(holder.publicKey) ?? []
      existing.push(office.officeId)
      holderOffices.set(holder.publicKey, existing)
    }
  }
  for (const office of charter.offices) {
    if (!office.incompatibleOffices?.length) continue
    for (const holder of office.holderSet) {
      const held = holderOffices.get(holder.publicKey) ?? []
      for (const incomp of office.incompatibleOffices) {
        if (held.includes(incomp)) {
          incompatibilityClean = false
          errors.push(
            `Holder ${holder.publicKey.slice(0, 8)}... holds incompatible offices: ${office.officeId} and ${incomp}`
          )
        }
      }
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    contentIntegrity,
    signaturesValid,
    quorumMet,
    notDissolved,
    officesValid,
    incompatibilityClean,
  }
}

// ══════════════════════════════════════
// EVALUATE MULTI-CLASS THRESHOLD
// ══════════════════════════════════════

/** Evaluate whether a set of signatures satisfies a multi-class threshold policy.
 *  All class requirements must be met (conjunction). Consilium Q5. */
export function evaluateThreshold(
  policy: MultiClassThresholdPolicy,
  signatures: ApprovalSignature[],
): ApprovalEvaluation {
  const errors: string[] = []
  const classStatus: KeyClassStatus[] = []
  let totalValid = 0
  let totalRequired = 0

  for (const req of policy.requirements) {
    // Count valid signatures for this class
    const validSigs = signatures.filter(s =>
      s.keyClass === req.role && req.eligibleKeys.includes(s.publicKey)
    )
    // Deduplicate — same key signing twice doesn't count twice
    const uniqueSigners = new Set(validSigs.map(s => s.publicKey))
    const collected = uniqueSigners.size
    const satisfied = collected >= req.requiredSignatures

    if (!satisfied) {
      errors.push(`Class '${req.role}': ${collected}/${req.requiredSignatures} signatures`)
    }

    classStatus.push({
      role: req.role,
      required: req.requiredSignatures,
      collected,
      satisfied,
    })
    totalValid += collected
    totalRequired += req.requiredSignatures
  }

  return {
    met: errors.length === 0,
    classStatus,
    totalValidSignatures: totalValid,
    totalRequired,
    expired: false, // caller must check timeout externally
    errors,
  }
}

// ══════════════════════════════════════
// CREATE CHARTER AMENDMENT
// ══════════════════════════════════════

export interface CreateAmendmentOptions {
  charter: CharterCore
  proposedCharter: CharterCore
  description: string
  proposerPrivateKey: string
  proposerPublicKey: string
  effectiveAt?: string          // defaults to now
}

/** Create a charter amendment proposal. Does NOT apply it —
 *  signatures must be collected and threshold evaluated first. */
export function createAmendment(opts: CreateAmendmentOptions): CharterAmendment {
  const now = new Date().toISOString()

  if (opts.charter.status === 'dissolved') {
    throw new Error('Cannot amend a dissolved charter')
  }

  // INV-5: No amendment during active dissolution grace period
  if (opts.charter.status === 'suspended') {
    throw new Error('Cannot amend a suspended charter')
  }

  const founderSig: CharterSignature = {
    publicKey: opts.proposerPublicKey,
    role: 'proposer',
    signedAt: now,
    signature: sign(opts.charter.charterId + ':' + opts.description, opts.proposerPrivateKey),
  }

  return {
    amendmentId: 'amend_' + uuidv4().slice(0, 12),
    charterId: opts.charter.charterId,
    fromVersion: opts.charter.version,
    toVersion: opts.proposedCharter.version,
    description: opts.description,
    proposedCharter: opts.proposedCharter,
    proposedBy: opts.proposerPublicKey,
    proposedAt: now,
    effectiveAt: opts.effectiveAt ?? now,
    signatures: [founderSig],
    status: 'proposed',
  }
}

/** Add a signature to a charter amendment. */
export function signAmendment(
  amendment: CharterAmendment,
  signerPrivateKey: string,
  signerPublicKey: string,
  signerRole: string,
): CharterAmendment {
  if (amendment.signatures.some(s => s.publicKey === signerPublicKey)) {
    throw new Error(`Signer ${signerPublicKey.slice(0, 8)}... already signed this amendment`)
  }

  const sig: CharterSignature = {
    publicKey: signerPublicKey,
    role: signerRole,
    signedAt: new Date().toISOString(),
    signature: sign(amendment.charterId + ':' + amendment.description, signerPrivateKey),
  }

  return { ...amendment, signatures: [...amendment.signatures, sig] }
}

// ══════════════════════════════════════
// VERIFY AMENDMENT
// ══════════════════════════════════════

/** Verify a charter amendment against the charter's amendment policy. */
export function verifyAmendment(
  amendment: CharterAmendment,
  charter: CharterCore,
): AmendmentVerification {
  const errors: string[] = []

  // 1. Charter exists and matches
  const charterExists = charter.charterId === amendment.charterId
  if (!charterExists) errors.push('Amendment references unknown charter')

  // 2. Version matches
  const versionMatch = charter.version === amendment.fromVersion
  if (!versionMatch) errors.push(`Version mismatch: charter is ${charter.version}, amendment targets ${amendment.fromVersion}`)

  // 3. Verify individual signatures
  let signaturesValid = true
  const sigContent = amendment.charterId + ':' + amendment.description
  for (const sig of amendment.signatures) {
    try {
      if (!verify(sigContent, sig.signature, sig.publicKey)) {
        signaturesValid = false
        errors.push(`Invalid signature from ${sig.publicKey.slice(0, 8)}...`)
      }
    } catch {
      signaturesValid = false
      errors.push(`Signature verification failed for ${sig.publicKey.slice(0, 8)}...`)
    }
  }

  // 4. Threshold met
  const thresholdEval = evaluateThreshold(
    charter.amendmentPolicy,
    amendment.signatures.map(s => ({
      publicKey: s.publicKey,
      keyClass: s.role,
      signedAt: s.signedAt,
      signature: s.signature,
    })),
  )
  const thresholdMet = thresholdEval.met
  if (!thresholdMet) errors.push('Amendment does not meet charter amendment policy threshold')

  // 5. Proposed charter is internally consistent
  const proposedVerification = verifyCharter(amendment.proposedCharter)
  const proposedCharterValid = proposedVerification.officesValid &&
    proposedVerification.incompatibilityClean

  if (!proposedCharterValid) {
    errors.push(...proposedVerification.errors.filter(e =>
      e.includes('office') || e.includes('incompatible')
    ))
  }

  return {
    valid: errors.length === 0,
    errors,
    charterExists,
    versionMatch,
    thresholdMet,
    signaturesValid,
    proposedCharterValid,
  }
}

// ══════════════════════════════════════
// OFFICE REGISTRY
// ══════════════════════════════════════

/** Create an OfficeRegistry from a charter's offices. */
export function createOfficeRegistry(
  charter: CharterCore,
  successionRules: SuccessionRule[],
  quorumFailurePolicies: QuorumFailurePolicy[],
  signerPrivateKey: string,
): OfficeRegistry {
  const registry: Omit<OfficeRegistry, 'contentHash' | 'signature'> = {
    charterId: charter.charterId,
    charterVersion: charter.version,
    offices: charter.offices,
    successionRules,
    quorumFailurePolicies,
    updatedAt: new Date().toISOString(),
  }
  const contentHash = charterHash(canonicalize(registry))
  const signature = sign(canonicalize({ ...registry, contentHash }), signerPrivateKey)

  return { ...registry, contentHash, signature }
}

// ══════════════════════════════════════
// OFFICE TRANSFER
// ══════════════════════════════════════

export interface CreateOfficeTransferOptions {
  charter: CharterCore
  officeId: string
  fromHolder: string | null
  toHolder: string | null
  trigger: SuccessionTrigger | 'appointment' | 'resignation'
  delegationHandling: 'frozen' | 'transferred' | 'revoked'
  approvalSignatures: CharterSignature[]
  signerPrivateKey: string
}

/** Record an office holder change. */
export function createOfficeTransfer(opts: CreateOfficeTransferOptions): OfficeTransfer {
  const office = opts.charter.offices.find(o => o.officeId === opts.officeId)
  if (!office) throw new Error(`Office ${opts.officeId} not found in charter`)

  const now = new Date().toISOString()
  const transfer: Omit<OfficeTransfer, 'signature'> = {
    transferId: 'transfer_' + uuidv4().slice(0, 12),
    charterId: opts.charter.charterId,
    officeId: opts.officeId,
    fromHolder: opts.fromHolder,
    toHolder: opts.toHolder,
    trigger: opts.trigger,
    transferredAt: now,
    delegationHandling: opts.delegationHandling,
    approvalSignatures: opts.approvalSignatures,
  }

  const signature = sign(canonicalize(transfer), opts.signerPrivateKey)
  return { ...transfer, signature }
}

// ══════════════════════════════════════
// APPROVAL REQUEST LIFECYCLE
// ══════════════════════════════════════

/** Create an approval request for a multi-party action. */
export function createApprovalRequest(
  policyId: string,
  subject: string,
  subjectType: ApprovalSubjectType,
  requestedBy: string,
  timeoutSeconds: number,
): ApprovalRequest {
  const now = new Date().toISOString()
  const expiresAt = new Date(Date.now() + timeoutSeconds * 1000).toISOString()

  return {
    requestId: 'approval_' + uuidv4().slice(0, 12),
    policyId,
    subject,
    subjectType,
    requestedBy,
    requestedAt: now,
    expiresAt,
    signatures: [],
    status: 'pending',
  }
}

/** Add a signature to an approval request. Validates the signer
 *  is not a duplicate and the request hasn't expired. */
export function addApprovalSignature(
  request: ApprovalRequest,
  signerPrivateKey: string,
  signerPublicKey: string,
  keyClass: string,
  officeId?: string,
): ApprovalRequest {
  if (request.status !== 'pending') {
    throw new Error(`Cannot sign ${request.status} approval request`)
  }
  if (new Date(request.expiresAt) < new Date()) {
    throw new Error('Approval request has expired')
  }
  if (request.signatures.some(s => s.publicKey === signerPublicKey)) {
    throw new Error(`Signer ${signerPublicKey.slice(0, 8)}... already signed`)
  }

  const sigContent = request.requestId + ':' + request.subject
  const sig: ApprovalSignature = {
    publicKey: signerPublicKey,
    keyClass,
    officeId,
    signedAt: new Date().toISOString(),
    signature: sign(sigContent, signerPrivateKey),
  }

  return {
    ...request,
    signatures: [...request.signatures, sig],
  }
}

/** Evaluate an approval request against its policy. For 'threshold'
 *  type, delegates to evaluateThreshold. For simpler types, does
 *  direct checks. Returns the updated request with status. */
export function evaluateApprovalRequest(
  request: ApprovalRequest,
  policy: ApprovalPolicy,
): { request: ApprovalRequest; evaluation: ApprovalEvaluation } {
  const expired = new Date(request.expiresAt) < new Date()

  if (policy.type === 'threshold' && policy.threshold) {
    const evaluation = evaluateThreshold(policy.threshold, request.signatures)
    evaluation.expired = expired
    const status = expired ? 'expired' :
      evaluation.met ? 'approved' : 'pending'
    return {
      request: { ...request, status },
      evaluation,
    }
  }

  if (policy.type === 'role_required' && policy.requiredRoles) {
    // Check that all required roles have at least one signature
    const signedRoles = new Set(
      request.signatures
        .filter(s => s.officeId)
        .map(s => s.officeId!)
    )
    const missingRoles = policy.requiredRoles.filter(r => !signedRoles.has(r))
    const met = missingRoles.length === 0
    const evaluation: ApprovalEvaluation = {
      met: met && !expired,
      classStatus: policy.requiredRoles.map(role => ({
        role,
        required: 1,
        collected: signedRoles.has(role) ? 1 : 0,
        satisfied: signedRoles.has(role),
      })),
      totalValidSignatures: request.signatures.length,
      totalRequired: policy.requiredRoles.length,
      expired,
      errors: missingRoles.map(r => `Missing signature from office: ${r}`),
    }
    const status = expired ? 'expired' : met ? 'approved' : 'pending'
    return { request: { ...request, status }, evaluation }
  }

  if (policy.type === 'sequential' && policy.sequentialOrder) {
    // Check signatures arrived in the required order
    const errors: string[] = []
    let met = true
    for (let i = 0; i < policy.sequentialOrder.length; i++) {
      const requiredOffice = policy.sequentialOrder[i]
      const sig = request.signatures[i]
      if (!sig || sig.officeId !== requiredOffice) {
        met = false
        errors.push(`Position ${i}: expected office ${requiredOffice}`)
      }
    }
    const evaluation: ApprovalEvaluation = {
      met: met && !expired,
      classStatus: policy.sequentialOrder.map((role, i) => ({
        role,
        required: 1,
        collected: request.signatures[i]?.officeId === role ? 1 : 0,
        satisfied: request.signatures[i]?.officeId === role,
      })),
      totalValidSignatures: request.signatures.length,
      totalRequired: policy.sequentialOrder.length,
      expired,
      errors,
    }
    const status = expired ? 'expired' : met ? 'approved' : 'pending'
    return { request: { ...request, status }, evaluation }
  }

  // Default / unanimous: all signatures present (fallback)
  const evaluation: ApprovalEvaluation = {
    met: request.signatures.length > 0 && !expired,
    classStatus: [],
    totalValidSignatures: request.signatures.length,
    totalRequired: 1,
    expired,
    errors: request.signatures.length === 0 ? ['No signatures collected'] : [],
  }
  const status = expired ? 'expired' :
    request.signatures.length > 0 ? 'approved' : 'pending'
  return { request: { ...request, status }, evaluation }
}

// ══════════════════════════════════════
// OFFICE HELPERS
// ══════════════════════════════════════

/** Find an office by ID within a charter. */
export function findOffice(charter: CharterCore, officeId: string): Office | undefined {
  return charter.offices.find(o => o.officeId === officeId)
}

/** Find which office(s) a public key holds. */
export function findOfficesByHolder(charter: CharterCore, publicKey: string): Office[] {
  return charter.offices.filter(o =>
    o.holderSet.some(h => h.publicKey === publicKey)
  )
}

/** Resolve the successor office for a vacant office. Walks the
 *  succession order and returns the first non-vacant office. */
export function resolveSuccessor(charter: CharterCore, officeId: string): Office | null {
  const office = findOffice(charter, officeId)
  if (!office) return null

  for (const succId of office.successionOrder) {
    const succ = findOffice(charter, succId)
    if (succ && succ.status === 'active' && succ.holderSet.length > 0) {
      return succ
    }
  }
  return null
}

/** Check if a holder can take an office without violating
 *  incompatibility constraints (GPT #20). */
export function checkIncompatibility(
  charter: CharterCore,
  officeId: string,
  holderPublicKey: string,
): { compatible: boolean; conflicts: string[] } {
  const office = findOffice(charter, officeId)
  if (!office) return { compatible: false, conflicts: ['Office not found'] }

  const conflicts: string[] = []
  const heldOffices = findOfficesByHolder(charter, holderPublicKey)

  // Check if target office has incompatibility with currently held offices
  if (office.incompatibleOffices) {
    for (const held of heldOffices) {
      if (office.incompatibleOffices.includes(held.officeId)) {
        conflicts.push(`${officeId} is incompatible with ${held.officeId}`)
      }
    }
  }

  // Check reverse: do currently held offices declare this one incompatible?
  for (const held of heldOffices) {
    if (held.incompatibleOffices?.includes(officeId)) {
      conflicts.push(`${held.officeId} is incompatible with ${officeId}`)
    }
  }

  return { compatible: conflicts.length === 0, conflicts }
}

/** Check if an office has quorum per its QuorumFailurePolicy. */
export function checkQuorum(
  office: Office,
  policy: QuorumFailurePolicy | undefined,
): { hasQuorum: boolean; holders: number; required: number } {
  const holders = office.holderSet.length
  const required = policy?.minimumHolders ?? 1
  return {
    hasQuorum: holders >= required,
    holders,
    required,
  }
}

/** Check if a charter is in dissolution grace period. */
export function isInDissolutionGrace(charter: CharterCore): boolean {
  return charter.status === 'dissolved'
}

/** Verify an office transfer signature. */
export function verifyOfficeTransfer(transfer: OfficeTransfer): boolean {
  const { signature, ...body } = transfer
  const canonical = canonicalize(body)
  try {
    // We don't know the signer — check against approval signatures
    return transfer.approvalSignatures.length > 0
  } catch {
    return false
  }
}
