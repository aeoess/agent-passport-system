// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Claim Verifier (Module 2 of 4) — pure registry type-checker
// ══════════════════════════════════════════════════════════════════
// verifyEvidenceClaim is a pure function. It checks an evidence bundle against
// the EvidenceProfile for a stated claim and returns a discriminated
// result. No I/O, no signing, no key resolution, no clock reads, no
// network, no mutation.
//
// What this module DOES check:
//   - claim.type is a known ClaimType present in the registry
//   - the registry entry for claim.type is populated (not a stub)
//   - APSBundle records are not silently substituted for leaf evidence
//     (a bundle is a Merkle commitment over receipt_ids; satisfying a
//     leaf claim from it requires an inclusion proof, which is out of
//     scope here)
//   - no forbidden substitution is being attempted (e.g. ActionReceipt
//     for BINDING_COMMITMENT)
//   - every required RecordType is present in the evidence list
//
// What this module does NOT check:
//   - signatures, receipt_id integrity, JCS canonicality
//   - timestamp freshness, expiry, key rotation, revocation
//   - delegation/authority chains
//   - cross-receipt referential integrity (e.g. that the
//     AuthorityBoundaryReceipt.action_id matches an ActionReceipt
//     whose receipt_id appears in a sibling record)
//
// Module 4 adds an optional `openContestationResolver` hook. When the
// caller supplies it, the verifier consults the resolver per evidence
// entry that carries a receiptId, after the static registry passes,
// and short-circuits to a 'contested' result on a blocking status.
// The resolver is opt-in: the SDK does not ship a contestation index,
// only the cascade primitive in ./downstream-taint.ts. Signature,
// freshness, and cross-receipt referential integrity remain Module 3
// (gateway integration). Treat verifyEvidenceClaim as the static
// type-system of the protocol: it tells you whether a stated set of
// receipts could in principle satisfy a stated claim, given the
// claim → evidence schema and an optional view onto the contestation
// ledger.
// ══════════════════════════════════════════════════════════════════

import {
  ClaimType,
  RecordType,
  EvidenceProfiles,
} from './claim-evidence-types.js'
import type { APSBundle } from './accountability/types/bundle.js'
import type { ContestStatus } from './accountability/types/contestability.js'

/**
 * Statuses where the contestation is open or resolved against the
 * record. A record under one of these statuses cannot be relied on
 * to satisfy a claim. Module 4 hook.
 */
const BLOCKING_CONTEST_STATUSES: readonly ContestStatus[] = [
  'filed',
  'under_review',
  'upheld',
  'remedied',
]

export type OpenContestationLookup = {
  contestationId: string
  status: ContestStatus
} | null

export type OpenContestationResolver = (recordId: string) => OpenContestationLookup

export type ClaimVerificationResult =
  | { status: 'valid'; claimType: ClaimType; satisfiedBy: RecordType[] }
  | {
      status: 'missing_evidence'
      claimType: ClaimType
      missing: RecordType[]
      provided: RecordType[]
    }
  | {
      status: 'forbidden_substitution'
      claimType: ClaimType
      offendingRecord: RecordType
      reason: string
    }
  | { status: 'unsupported_claim_type'; claimType: ClaimType }
  | { status: 'profile_not_populated'; claimType: ClaimType }
  | {
      status: 'bundle_requires_inclusion_proof'
      claimType: ClaimType
      bundleRecord: APSBundle
    }
  | {
      status: 'contested'
      claimType: ClaimType
      contestedRecordId: string
      contestationId: string
      contestationStatus: ContestStatus
    }

export interface ClaimVerificationInput {
  claim: { type: ClaimType; subject: string }
  evidence: Array<{ recordType: RecordType; record: unknown; receiptId?: string }>
  /** Optional Module 4 hook. When provided, every evidence entry that
   *  carries a receiptId is checked against the resolver after the
   *  static registry passes but before the verifier returns 'valid'.
   *  Statuses 'filed', 'under_review', 'upheld', 'remedied' all
   *  block; 'rejected', 'abandoned', 'expired' do not. */
  openContestationResolver?: OpenContestationResolver
}

export function verifyEvidenceClaim(input: ClaimVerificationInput): ClaimVerificationResult {
  const { claim, evidence } = input

  // 1. unsupported_claim_type — claim.type is not a registry key.
  const profile = (EvidenceProfiles as Record<string, typeof EvidenceProfiles[ClaimType]>)[
    claim.type
  ]
  if (profile === undefined) {
    return { status: 'unsupported_claim_type', claimType: claim.type }
  }

  // 2. profile_not_populated — registry entry is a stub.
  const hasRequired = profile.required.length > 0
  const hasForbidden = Object.keys(profile.forbiddenSubstitutions).length > 0
  if (!hasRequired && !hasForbidden) {
    return { status: 'profile_not_populated', claimType: claim.type }
  }

  // 3. bundle_requires_inclusion_proof — APSBundle slipped in for a non-batch claim.
  if (claim.type !== ClaimType.BATCH_ATTESTED) {
    const bundleEntry = evidence.find((e) => e.recordType === RecordType.APSBundle)
    if (bundleEntry !== undefined) {
      return {
        status: 'bundle_requires_inclusion_proof',
        claimType: claim.type,
        bundleRecord: bundleEntry.record as APSBundle,
      }
    }
  }

  // 4. forbidden_substitution — first match wins, in evidence order.
  for (const entry of evidence) {
    const reason = profile.forbiddenSubstitutions[entry.recordType]
    if (reason !== undefined) {
      return {
        status: 'forbidden_substitution',
        claimType: claim.type,
        offendingRecord: entry.recordType,
        reason,
      }
    }
  }

  // 5. missing_evidence — required types not present in evidence.
  const providedTypes = evidence.map((e) => e.recordType)
  const providedSet = new Set(providedTypes)
  const missing = profile.required.filter((r) => !providedSet.has(r))
  if (missing.length > 0) {
    return {
      status: 'missing_evidence',
      claimType: claim.type,
      missing,
      provided: providedTypes,
    }
  }

  // 6. contested (Module 4) — only when caller wires a resolver and
  //    an evidence entry carries a receiptId. First blocking match wins.
  if (input.openContestationResolver !== undefined) {
    for (const entry of evidence) {
      if (entry.receiptId === undefined) continue
      const lookup = input.openContestationResolver(entry.receiptId)
      if (lookup !== null && BLOCKING_CONTEST_STATUSES.includes(lookup.status)) {
        return {
          status: 'contested',
          claimType: claim.type,
          contestedRecordId: entry.receiptId,
          contestationId: lookup.contestationId,
          contestationStatus: lookup.status,
        }
      }
    }
  }

  // 7. valid.
  return {
    status: 'valid',
    claimType: claim.type,
    satisfiedBy: [...profile.required],
  }
}
