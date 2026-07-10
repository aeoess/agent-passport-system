// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Evidence Bundle - Type Definitions (FREEZE-VWE F5, F6, F7)
// ══════════════════════════════════════════════════════════════════
// A signed, Merkle-committed collection of protocol artifacts assembled
// as verification evidence. The manifest commits to each member by
// content digest; the bundle carries the member payloads alongside.
//
// Bundles are NOT ledger batches: there is no epoch chain and no
// previousBatchId. A bundle is a standalone evidence set (F5).
// Members are read structurally by member_type; T8 imports no types
// from parallel branches (F7). T9 unifies to real types after merge.

/**
 * Structural member discriminator per FREEZE-VWE F7. Verification code
 * keys on this string, never on imported types from parallel branches.
 */
export type EvidenceBundleMemberType =
  | 'bilateral_receipt'
  | 'bilateral_pair_verdict'
  | 'revocation_observation'
  | 'passport'
  | 'delegation'
  | 'action_receipt'
  | 'other'

/**
 * One manifest entry. digest is the lowercase hex SHA-256 of
 * canonicalize(payload) of the corresponding bundle member.
 * Invariant: member_id is unique within a manifest.
 */
export interface EvidenceBundleManifestMember {
  member_id: string
  member_type: EvidenceBundleMemberType
  digest: string
}

/**
 * Signed bundle manifest per FREEZE-VWE F5. Field set is frozen:
 * profile, created_at, members, merkle_root, signature. merkle_root is
 * buildMerkleRoot over the member digests. signature is Ed25519 over
 * canonicalize(manifest minus signature), the verifyBatch
 * signable-subset pattern. No epoch, no previousBatchId (forbidden).
 */
export interface EvidenceBundleManifest {
  profile: 'aps:evidence-bundle:v1'
  created_at: string
  members: EvidenceBundleManifestMember[]
  merkle_root: string
  signature: string
}

/**
 * One carried member payload. payload is unknown by design: bundle
 * members are foreign artifacts read structurally (F7), so no member
 * type from another module is imported here.
 */
export interface EvidenceBundleMember {
  member_id: string
  member_type: EvidenceBundleMemberType
  payload: unknown
}

/**
 * The bundle file shape: manifest plus member payloads plus the
 * signer's public key. signer_public_key sits OUTSIDE the signed
 * subset (the F5 manifest field set is frozen), so the signature
 * proves integrity under the stated key, not who the signer is.
 * Binding the key to an expected signer is the caller's trust
 * decision, exactly as with ReceiptBatch.committedBy.
 */
export interface EvidenceBundle {
  manifest: EvidenceBundleManifest
  signer_public_key: string
  members: EvidenceBundleMember[]
}

/** Per-member outcome inside a bundle verification. */
export interface EvidenceBundleMemberVerification {
  member_id: string
  /** Recomputed payload digest equals the manifest digest. */
  digestValid: boolean
  /** Merkle inclusion proof for the manifest digest verifies against merkle_root. */
  inclusionValid: boolean
}

/** Result of verifyEvidenceBundle. valid is true only when every check passed. */
export interface EvidenceBundleVerification {
  valid: boolean
  signatureValid: boolean
  rootValid: boolean
  memberResults: EvidenceBundleMemberVerification[]
  errors: string[]
}

/**
 * Verifier-report vocabulary per FREEZE-VWE F6. Report-local only:
 * this enum never appears inside a signed artifact. The per-axis
 * mapping in SCHEMAS-DRAFT 3d is normative for how CLI verify-bundle
 * assigns these states.
 */
export type ClaimState =
  | 'VERIFIED'
  | 'EVALUATED'
  | 'RESOLVED'
  | 'ASSERTED'
  | 'STALE'
  | 'UNKNOWN'
  | 'MISSING'
  | 'INVALID'

/** The four report axes of the claim-boundary report. */
export type ClaimAxis = 'authority' | 'action' | 'revocation' | 'evidence'

/** One axis outcome: the state plus a one-line human-readable reason. */
export interface ClaimAxisReport {
  state: ClaimState
  detail: string
}

/**
 * Full claim-boundary report over a bundle. overall is the worst axis
 * state by severity (INVALID worst, VERIFIED best). Severity order:
 * INVALID, STALE, MISSING, UNKNOWN, ASSERTED, EVALUATED, RESOLVED,
 * VERIFIED.
 */
export interface ClaimBoundaryReport {
  axes: {
    authority: ClaimAxisReport
    action: ClaimAxisReport
    revocation: ClaimAxisReport
    evidence: ClaimAxisReport
  }
  overall: ClaimState
}
