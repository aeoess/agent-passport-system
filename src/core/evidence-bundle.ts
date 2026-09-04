// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Evidence Bundle (FREEZE-VWE F5) + Claim-Boundary Report (F6)
// ══════════════════════════════════════════════════════════════════
// A bundle is a signed, Merkle-committed evidence set. It reuses the
// receipt-ledger Merkle surface (buildMerkleRoot, proveInclusion,
// verifyInclusion) and the verifyBatch signable-subset signature
// pattern. It is NOT a ledger batch: commitBatch is never called and
// the epoch/previousBatchId sequencing fields do not exist on bundles.
//
// The claim-boundary report reads members STRUCTURALLY by member_type
// (F7): nothing here imports types from parallel task branches. The
// per-axis ClaimState mapping follows SCHEMAS-DRAFT 3d. States are
// computed from what the members allow; anything not computable is
// reported MISSING or UNKNOWN, never assumed.

import { createHash } from 'node:crypto'
import { sign, verify } from '../crypto/keys.js'
import { canonicalize, canonicalizeForWrite } from './canonical.js'
import { buildMerkleRoot } from './attribution.js'
import { parseRfc3339 } from './rfc3339.js'
import { proveInclusion, verifyInclusion } from './receipt-ledger.js'
import type { ReceiptBatch, ReceiptInclusionProof } from './receipt-ledger.js'
import { verifyPassport } from '../verification/verify.js'
import { actionRefsMatch } from './action-ref.js'
import type { SignedPassport } from '../types/passport.js'
import type {
  EvidenceBundle,
  EvidenceBundleManifest,
  EvidenceBundleMember,
  EvidenceBundleMemberType,
  EvidenceBundleMemberVerification,
  EvidenceBundleVerification,
  ClaimAxisReport,
  ClaimBoundaryReport,
  ClaimState,
} from '../types/evidence-bundle.js'

// ══════════════════════════════════════
// DIGEST
// ══════════════════════════════════════

/**
 * Digest of one member payload: lowercase hex SHA-256 of
 * canonicalize(payload). This is the leaf value committed in the
 * manifest and in the Merkle root.
 */
export function computeMemberDigest(payload: unknown): string {
  return createHash('sha256').update(canonicalize(payload)).digest('hex')
}
/** Write-boundary twin of computeMemberDigest().
 *
 *  Emits the same bytes as computeMemberDigest() for every value it accepts. The only difference
 *  is that an integer-valued number outside the interoperable IEEE 754 range is
 *  refused instead of serialized. Use at signing and new-write boundaries ONLY:
 *  computeMemberDigest() stays unrestricted so an artifact signed before this rule keeps
 *  verifying. */
export function computeMemberDigestForWrite(payload: unknown): string {
  return createHash('sha256').update(canonicalizeForWrite(payload)).digest('hex')
}

// ══════════════════════════════════════
// CREATE
// ══════════════════════════════════════

export interface CreateEvidenceBundleOptions {
  /** Member payloads to commit. member_id values must be unique. */
  members: EvidenceBundleMember[]
  /** Ed25519 private key (hex) that signs the manifest. */
  signerPrivateKey: string
  /** Ed25519 public key (hex) carried on the bundle for verification. */
  signerPublicKey: string
  /** ISO 8601 creation time. Defaults to now. */
  createdAt?: string
}

/**
 * Assemble and sign an evidence bundle per FREEZE-VWE F5.
 * Invariants: at least one member; unique member_id values; manifest
 * digests are canonicalize-then-sha256 of each payload; merkle_root is
 * buildMerkleRoot over the digests; signature covers
 * canonicalize(manifest minus signature). commitBatch is never
 * involved and no ledger-sequencing field is emitted.
 */
export function createEvidenceBundle(opts: CreateEvidenceBundleOptions): EvidenceBundle {
  if (opts.members.length === 0) {
    throw new Error('createEvidenceBundle: at least one member is required')
  }
  const seen = new Set<string>()
  for (const m of opts.members) {
    if (seen.has(m.member_id)) {
      throw new Error(`createEvidenceBundle: duplicate member_id "${m.member_id}"`)
    }
    seen.add(m.member_id)
  }

  const manifestMembers = opts.members.map(m => ({
    member_id: m.member_id,
    member_type: m.member_type,
    digest: computeMemberDigestForWrite(m.payload),
  }))

  const signable = {
    profile: 'aps:evidence-bundle:v1' as const,
    created_at: opts.createdAt ?? new Date().toISOString(),
    members: manifestMembers,
    merkle_root: buildMerkleRoot(manifestMembers.map(m => m.digest)),
  }
  const signature = sign(canonicalizeForWrite(signable), opts.signerPrivateKey)

  return {
    manifest: { ...signable, signature },
    signer_public_key: opts.signerPublicKey,
    members: opts.members.map(m => ({ ...m })),
  }
}

// ══════════════════════════════════════
// INCLUSION (via the receipt-ledger primitives)
// ══════════════════════════════════════

// proveInclusion reads only batchId, merkleRoot and receiptHashes. The
// remaining ReceiptBatch fields are inert placeholders needed to
// satisfy the parameter type; none of them enters the bundle wire
// format (F5 forbids the ledger-sequencing fields on bundles).
function manifestAsBatchView(manifest: EvidenceBundleManifest): ReceiptBatch {
  return {
    batchId: `evidence-bundle:${manifest.merkle_root}`,
    merkleRoot: manifest.merkle_root,
    receiptCount: manifest.members.length,
    receiptHashes: manifest.members.map(m => m.digest),
    epoch: 0,
    previousBatchId: null,
    previousMerkleRoot: null,
    committedAt: manifest.created_at,
    committedBy: '',
    signature: '',
  }
}

/**
 * Merkle inclusion proof for one member digest against the bundle
 * root, produced by the receipt-ledger proveInclusion primitive.
 */
export function proveMemberInclusion(
  manifest: EvidenceBundleManifest,
  memberId: string,
): ReceiptInclusionProof {
  const entry = manifest.members.find(m => m.member_id === memberId)
  if (!entry) {
    throw new Error(`proveMemberInclusion: unknown member_id "${memberId}"`)
  }
  return proveInclusion(manifestAsBatchView(manifest), entry.digest)
}

/**
 * Verify a member inclusion proof. Thin passthrough to the
 * receipt-ledger verifyInclusion primitive, exported so bundle
 * consumers never need to import the ledger module.
 */
export function verifyMemberInclusion(proof: ReceiptInclusionProof): boolean {
  return verifyInclusion(proof)
}

// ══════════════════════════════════════
// VERIFY
// ══════════════════════════════════════

/**
 * Verify an evidence bundle end to end: manifest signature over the
 * signable subset, Merkle root over the manifest digests, per-member
 * payload digest against the manifest, and per-member inclusion via
 * proveInclusion/verifyInclusion. Single-member manifests skip the
 * inclusion-proof check (the root is the domain-separated hash of the
 * single digest and generateMerkleProof has no sibling path to build);
 * the digest and root checks still bind the member. valid is true only
 * when every check passes.
 */
export function verifyEvidenceBundle(bundle: EvidenceBundle): EvidenceBundleVerification {
  const errors: string[] = []
  const manifest = bundle.manifest

  if (manifest.profile !== 'aps:evidence-bundle:v1') {
    errors.push(`Unknown profile "${String(manifest.profile)}"`)
  }

  const signable = {
    profile: manifest.profile,
    created_at: manifest.created_at,
    members: manifest.members,
    merkle_root: manifest.merkle_root,
  }
  let signatureValid = false
  try {
    signatureValid = verify(canonicalize(signable), manifest.signature, bundle.signer_public_key)
  } catch {
    signatureValid = false
  }
  if (!signatureValid) errors.push('Invalid manifest signature')

  const rootValid = buildMerkleRoot(manifest.members.map(m => m.digest)) === manifest.merkle_root
  if (!rootValid) errors.push('Merkle root does not match manifest member digests')

  const payloadsById = new Map(bundle.members.map(m => [m.member_id, m]))
  if (bundle.members.length !== manifest.members.length) {
    errors.push(`Member count mismatch: manifest has ${manifest.members.length}, bundle carries ${bundle.members.length}`)
  }

  const memberResults: EvidenceBundleMemberVerification[] = manifest.members.map(entry => {
    const carried = payloadsById.get(entry.member_id)
    if (!carried) {
      errors.push(`Member "${entry.member_id}" is in the manifest but not carried in the bundle`)
      return { member_id: entry.member_id, digestValid: false, inclusionValid: false }
    }
    const digestValid = computeMemberDigest(carried.payload) === entry.digest
    if (!digestValid) {
      errors.push(`Member "${entry.member_id}" payload digest does not match the manifest`)
    }
    const inclusionValid = manifest.members.length === 1
      ? rootValid
      : verifyMemberInclusion(proveMemberInclusion(manifest, entry.member_id))
    if (!inclusionValid) {
      errors.push(`Member "${entry.member_id}" inclusion proof failed against the bundle root`)
    }
    return { member_id: entry.member_id, digestValid, inclusionValid }
  })

  return { valid: errors.length === 0, signatureValid, rootValid, memberResults, errors }
}

// ══════════════════════════════════════
// CLAIM-BOUNDARY REPORT (F6, SCHEMAS-DRAFT 3d)
// ══════════════════════════════════════

// Worst state first. overall and multi-member axis folding take the
// worst state present.
const SEVERITY: ClaimState[] = [
  'INVALID', 'STALE', 'MISSING', 'UNKNOWN', 'ASSERTED', 'EVALUATED', 'RESOLVED', 'VERIFIED',
]

function worstState(states: ClaimState[]): ClaimState {
  let worst: ClaimState = 'VERIFIED'
  for (const s of states) {
    if (SEVERITY.indexOf(s) < SEVERITY.indexOf(worst)) worst = s
  }
  return worst
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function membersOfType(bundle: EvidenceBundle, type: EvidenceBundleMemberType): EvidenceBundleMember[] {
  return bundle.members.filter(m => m.member_type === type)
}

function looksLikeSignedPassport(payload: unknown): payload is SignedPassport {
  return isRecord(payload) && isRecord(payload.passport) && typeof payload.signature === 'string'
}

// Authority axis (3d row 1). The CLI supplies no trustedIssuers, so
// VERIFIED is unreachable here by design: a structurally valid,
// signature-passing passport is the self-signed acceptance path and
// reports ASSERTED.
function authorityAxis(bundle: EvidenceBundle): ClaimAxisReport {
  const passports = membersOfType(bundle, 'passport')
  const delegations = membersOfType(bundle, 'delegation')
  if (passports.length === 0 && delegations.length === 0) {
    return { state: 'MISSING', detail: 'no passport or delegation member in the bundle' }
  }

  const outcomes: ClaimAxisReport[] = []
  for (const member of passports) {
    if (!looksLikeSignedPassport(member.payload)) {
      outcomes.push({ state: 'UNKNOWN', detail: `member "${member.member_id}" is not structurally a signed passport` })
      continue
    }
    const result = verifyPassport(member.payload)
    if (result.valid) {
      outcomes.push({ state: 'ASSERTED', detail: `member "${member.member_id}" signature passes; self-signed accepted, no trust anchors supplied` })
      continue
    }
    const expiryOnly = result.errors.length > 0 && result.errors.every(e =>
      e.startsWith('Passport expired') || e.startsWith('Passport not valid before'))
    if (expiryOnly) {
      outcomes.push({ state: 'STALE', detail: `member "${member.member_id}" signature passes but the passport is outside its validity window` })
    } else {
      outcomes.push({ state: 'INVALID', detail: `member "${member.member_id}" failed verification: ${result.errors.join('; ')}` })
    }
  }
  for (const member of delegations) {
    outcomes.push({ state: 'ASSERTED', detail: `delegation member "${member.member_id}" supplied; chain verification is not performed by verify-bundle` })
  }
  return foldAxis(outcomes)
}

// Action axis (3d row 2). Compares action_ref values found
// structurally on bilateral_receipt and action_receipt members via
// actionRefsMatch, and folds in any bilateral_pair_verdict members by
// their status field.
function actionAxis(bundle: EvidenceBundle): ClaimAxisReport {
  const outcomes: ClaimAxisReport[] = []

  for (const member of membersOfType(bundle, 'bilateral_pair_verdict')) {
    const status = isRecord(member.payload) ? member.payload.status : undefined
    if (status === 'reconciled') {
      outcomes.push({ state: 'RESOLVED', detail: `pair verdict "${member.member_id}" reports reconciled` })
    } else if (status === 'unilateral') {
      outcomes.push({ state: 'ASSERTED', detail: `pair verdict "${member.member_id}" reports a unilateral claim, counterparty silent` })
    } else if (status === 'mismatch') {
      outcomes.push({ state: 'INVALID', detail: `pair verdict "${member.member_id}" reports a mismatch` })
    } else {
      outcomes.push({ state: 'UNKNOWN', detail: `pair verdict "${member.member_id}" has an unrecognized status` })
    }
  }

  const refs: { memberId: string, ref: string }[] = []
  for (const member of [...membersOfType(bundle, 'bilateral_receipt'), ...membersOfType(bundle, 'action_receipt')]) {
    if (isRecord(member.payload) && typeof member.payload.action_ref === 'string' && member.payload.action_ref.length > 0) {
      refs.push({ memberId: member.member_id, ref: member.payload.action_ref })
    }
  }
  if (refs.length >= 2) {
    const allMatch = refs.every(r => actionRefsMatch(r.ref, refs[0].ref))
    outcomes.push(allMatch
      ? { state: 'VERIFIED', detail: `${refs.length} members carry matching action_ref values` }
      : { state: 'INVALID', detail: 'members carry conflicting action_ref values' })
  } else if (refs.length === 1) {
    outcomes.push({ state: 'UNKNOWN', detail: `only member "${refs[0].memberId}" carries an action_ref; no counterparty data to compare` })
  }

  if (outcomes.length === 0) {
    return { state: 'MISSING', detail: 'no action_ref and no pair verdict present in the bundle' }
  }
  return foldAxis(outcomes)
}

// Revocation axis (3d row 3). Reads revocation_observation members
// structurally per F4 field names. No observation means no revocation
// check ran, which is reported MISSING, never assumed fresh.
function revocationAxis(bundle: EvidenceBundle, now: Date): ClaimAxisReport {
  const observations = membersOfType(bundle, 'revocation_observation')
  if (observations.length === 0) {
    return { state: 'MISSING', detail: 'no revocation_observation member; no revocation check ran' }
  }

  const outcomes: ClaimAxisReport[] = []
  for (const member of observations) {
    const p = member.payload
    // An observed_at this verifier cannot read carries no staleness window, so
    // the observation is malformed against the F4 field set — never fresh.
    const observedAt = parseRfc3339(isRecord(p) ? p.observed_at : undefined)
    const wellFormed = isRecord(p)
      && typeof p.authority_ref === 'string'
      && isRecord(p.status_source) && (p.status_source.kind === 'source' || p.status_source.kind === 'set')
      && observedAt.ok
      && typeof p.maximum_staleness_ms === 'number'
      && isRecord(p.decision) && (p.decision.effect === 'allow' || p.decision.effect === 'deny')
    if (!wellFormed || !observedAt.ok) {
      outcomes.push({ state: 'INVALID', detail: `observation "${member.member_id}" is malformed against the F4 field set` })
      continue
    }
    const workflow = isRecord(p.workflow_response) ? p.workflow_response : undefined
    const decision = p.decision as Record<string, unknown>
    const revokedObserved = typeof p.revoked_at === 'string'
    const terminated = workflow !== undefined
      && workflow.reissued === false && workflow.reason === 'revoked'
    if (revokedObserved && terminated) {
      outcomes.push({ state: 'RESOLVED', detail: `observation "${member.member_id}" shows revocation observed; the running workflow was terminated` })
      continue
    }
    if (revokedObserved && decision.effect === 'allow') {
      outcomes.push({ state: 'INVALID', detail: `observation "${member.member_id}" carries revoked_at with an allow decision and no terminating workflow_response; outside the classify domain, malformed` })
      continue
    }
    if (decision.effect === 'deny') {
      outcomes.push({ state: 'RESOLVED', detail: `observation "${member.member_id}" shows revocation observed and enforced (deny)` })
      continue
    }
    if (decision.downgraded === true) {
      outcomes.push({ state: 'EVALUATED', detail: `observation "${member.member_id}" allowed on non-fresh input (downgraded)` })
      continue
    }
    // Allow decision, not downgraded, no revoked_at. The frozen F4 record does
    // not carry the freshness RESULT (fresh vs unavailable/stale): a source
    // consulted-and-fresh and a source that was unavailable but failed open
    // (decideFreshness fail_open with the default action_on_stale 'allow'
    // returns effect 'allow', downgraded false) produce an identical record.
    // VERIFIED asserts a fresh, not-revoked source, which cannot be proven
    // here, so EVALUATED is the ceiling (a decision was recorded), mirroring the
    // authority and evidence axes whose VERIFIED cells are also unreachable by
    // design. The observation's own age still gates STALE. Reporting VERIFIED
    // for an allow decision was a fail-open: an unavailable-fail-open
    // observation read as fresh-not-revoked.
    const freshUntil = observedAt.ms + (p.maximum_staleness_ms as number)
    if (freshUntil >= now.getTime()) {
      outcomes.push({ state: 'EVALUATED', detail: `observation "${member.member_id}" records an allow decision; source freshness is not provable from the frozen record, so VERIFIED is unreachable` })
    } else {
      outcomes.push({ state: 'STALE', detail: `observation "${member.member_id}" exceeded maximum_staleness_ms at verification time` })
    }
  }
  return foldAxis(outcomes)
}

// Evidence axis (3d row 4). EVALUATED is the ceiling here: the bundle
// root is recomputed and member digests are checked, but external
// credentials are never fetched by verify-bundle, so VERIFIED is
// unreachable by design.
function evidenceAxis(bundle: EvidenceBundle, verification: EvidenceBundleVerification): ClaimAxisReport {
  if (bundle.manifest.members.length === 0) {
    return { state: 'MISSING', detail: 'the bundle manifest has no members' }
  }
  const membersOk = verification.memberResults.length === bundle.manifest.members.length
    && verification.memberResults.every(r => r.digestValid && r.inclusionValid)
  if (!verification.rootValid || !membersOk) {
    const bad = verification.memberResults.filter(r => !r.digestValid || !r.inclusionValid).map(r => r.member_id)
    return {
      state: 'INVALID',
      detail: bad.length > 0
        ? `member digest or inclusion check failed for: ${bad.join(', ')}`
        : 'bundle Merkle root does not match the manifest member digests',
    }
  }
  return { state: 'EVALUATED', detail: 'bundle root recomputed and matches; all member digests match the manifest' }
}

function foldAxis(outcomes: ClaimAxisReport[]): ClaimAxisReport {
  const worst = worstState(outcomes.map(o => o.state))
  const first = outcomes.find(o => o.state === worst)
  return first ?? { state: 'UNKNOWN', detail: 'no outcome computed' }
}

export interface ClaimBoundaryReportOptions {
  /** Verification clock for revocation staleness. Defaults to now. */
  now?: Date
  /** Reuse an existing verifyEvidenceBundle result instead of recomputing. */
  verification?: EvidenceBundleVerification
}

/**
 * Compute the per-axis claim-boundary report for a bundle per the
 * SCHEMAS-DRAFT 3d mapping. Report-local vocabulary only (F6): the
 * result is never embedded in a signed artifact. Members are read
 * structurally by member_type (F7). Axes that cannot be computed from
 * the members present report MISSING or UNKNOWN.
 */
export function computeClaimBoundaryReport(
  bundle: EvidenceBundle,
  opts?: ClaimBoundaryReportOptions,
): ClaimBoundaryReport {
  const now = opts?.now ?? new Date()
  const verification = opts?.verification ?? verifyEvidenceBundle(bundle)
  const axes = {
    authority: authorityAxis(bundle),
    action: actionAxis(bundle),
    revocation: revocationAxis(bundle, now),
    evidence: evidenceAxis(bundle, verification),
  }
  const overall = worstState([axes.authority.state, axes.action.state, axes.revocation.state, axes.evidence.state])
  return { axes, overall }
}
