// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import type { AuthorityDelegationV1 } from '../authority-delegation/types.js'

/** Draft-native direct revocation of an AuthorityDelegationV1, draft-03 section 3.5.1.
 *
 *  Distinct from the pre-draft `RevocationRecord` in src/types/passport.ts, which carries
 *  a raw public key in `revokedBy`, a free-text `reason`, no cascade transaction identity,
 *  no nonce, no record_type and no domain-separated preimage. That record cannot represent
 *  section 3.5.1 evidence and is not reused here. The two models stay distinguishable. */
export const AUTHORITY_REVOCATION_RECORD_TYPE = 'aps:authority-revocation:v1' as const
export const AUTHORITY_REVOCATION_VERSION = '1.0' as const

/** The content over which `revocation_id` is computed: the record with `revocation_id`
 *  and `signature` absent. `revoked_at` is inside it, as section 3.5.1 requires of the
 *  revocation time. */
export interface AuthorityRevocationBodyV1 {
  record_type: typeof AUTHORITY_REVOCATION_RECORD_TYPE
  version: typeof AUTHORITY_REVOCATION_VERSION
  /** Content address of the revoked delegation: `sha256:<64 lowercase hex>`. */
  delegation_id: string
  /** The revoking authority. Section 3.5 names exactly one party for a direct
   *  revocation, the target delegation's issuer, so a valid record has
   *  `revoker === delegation.issuer` for the delegation it names. */
  revoker: string
  /** Which key signed. A non-empty string, and nothing more is required of its shape: no
   *  local rule relates it to `revoker`. Whether the method belongs to the issuer is
   *  decided only by key resolution against the target delegation's `issuer` at
   *  `revoked_at`, which verifyAuthorityRevocation() performs. */
  verification_method: string
  /** Canonical UTC-millisecond revocation time, supplied by the caller, never read from
   *  a clock inside issuance. */
  revoked_at: string
  /** Machine-readable reason. A non-empty string; section 3.5.1 fixes no grammar for one
   *  and none is invented here. */
  reason_code: string
  /** OPTIONAL free-text detail. Absent means the key is not present at all: JCS has no
   *  canonical form for undefined, so an absent detail is never serialized as null. */
  detail?: string
  /** The transaction identity shared by every record one cascade produces. Deterministic
   *  and content-bound; see cascadeTransactionId() in canonical.ts. */
  cascade_transaction_id: string
  /** 16 random bytes as 32 lowercase hexadecimal characters. */
  nonce: string
}

export interface AuthorityRevocationV1 extends AuthorityRevocationBodyV1 {
  /** `sha256:<64 lowercase hex>` over the ID domain tag and JCS of the body. */
  revocation_id: string
  /** Raw 64-byte Ed25519 signature as 128 lowercase hexadecimal characters. */
  signature: string
}

export type AuthorityRevocationFailureCode =
  | 'SCHEMA_INVALID'
  | 'UNSUPPORTED_RECORD_TYPE'
  | 'UNSUPPORTED_VERSION'
  | 'NONCANONICAL_VALUE'
  /** revocation_id does not recompute from the record's own body. */
  | 'ID_MISMATCH'
  /** cascade_transaction_id does not recompute from the record's own body. */
  | 'CASCADE_TRANSACTION_MISMATCH'
  /** The delegation handed in is not the one this record names. */
  | 'TARGET_MISMATCH'
  /** The delegation handed in does not recompute its own delegation_id, so its `issuer`
   *  is not an authenticated field and the revoker check cannot be made against it. */
  | 'TARGET_ID_MISMATCH'
  /** `revoker` is not the target delegation's `issuer`. */
  | 'REVOKER_NOT_ISSUER'
  | 'KEY_RESOLUTION_FAILED'
  | 'KEY_SCHEME_UNSUPPORTED'
  | 'KEY_NOT_FOUND'
  | 'KEY_AMBIGUOUS'
  | 'KEY_UNREACHABLE'
  | 'KEY_MATERIAL_MALFORMED'
  | 'SIGNATURE_INVALID'

export interface AuthorityRevocationFailure {
  code: AuthorityRevocationFailureCode
  message: string
}

export interface AuthorityRevocationVerificationResult {
  state: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  valid: boolean
  failures: AuthorityRevocationFailure[]
}

/** What a store's first-write primitive reports: whether this call was the write that
 *  took the first-wins slot, and what the store holds for the target now.
 *
 *  `inserted` is the only way a caller learns which of the two happened. `stored` is the
 *  record passed in when `inserted` is true and the record already held when it is false,
 *  so a caller that must distinguish them reads `inserted` rather than comparing bytes. */
export interface AuthorityRevocationInsertion {
  inserted: boolean
  stored: AuthorityRevocationV1
}

/** The read and write boundary a revocation resolver needs.
 *
 *  Nothing in this interface promises durability. An implementation backed by process
 *  memory, a file, or a replicated database all satisfy it; only the implementation says
 *  which. Section 3.5.1 makes the cascade-completion record depend on the last
 *  descendant's revocation being PERSISTENT, and no method here establishes persistence,
 *  which is one reason no completion record is issued in this module.
 *
 *  This interface carries no method that takes an arbitrary, unverified record.
 *  `insertVerifiedRevocation` is a persistence primitive, not an entry point: the only
 *  supported way to move a candidate revocation into a store is
 *  recordAuthorityRevocation() in record.ts, which verifies first and calls the primitive
 *  only on a `valid` result. See that function for why the split exists. */
export interface AuthorityRevocationStore {
  /** Whether `delegationId` is inside this store's view at all.
   *
   *  This is what keeps absence from meaning "active". A store that has never heard of a
   *  delegation cannot say the delegation is unrevoked; it can only say it does not know.
   *  A store whose view covers the delegation and holds no revocation for it can. */
  tracks(delegationId: string): boolean
  /** The revocation recorded for `delegationId`, or undefined when none is recorded. */
  get(delegationId: string): AuthorityRevocationV1 | undefined
  /** Persistence primitive. Writes `revocation` only when this store holds no record for
   *  `revocation.delegation_id`, and reports what it holds for that target now.
   *
   *  ACCEPTS ONLY A RECORD ALREADY VERIFIED AGAINST ITS TARGET DELEGATION by
   *  recordAuthorityRevocation(). It performs no verification, and none is possible here:
   *  verification needs the target delegation and a key resolver, neither of which a store
   *  has. An implementation is a write path, not a trust boundary, and a caller that
   *  reaches past recordAuthorityRevocation() to this method is the one asserting the
   *  record was verified.
   *
   *  First verified revocation for a delegation wins. Revocation is irreversible (INV-5),
   *  so a later call naming a delegation that already has a record does not replace it:
   *  `inserted` is false and `stored` is the record already held, unchanged. The check for
   *  an existing record and the write MUST be one indivisible operation, so that two
   *  callers racing on the same delegation cannot both observe `inserted: true`.
   *
   *  For a DURABLE implementation that means the first write MUST be an atomic conditional
   *  insert keyed by `delegation_id` — an insert the storage engine itself makes succeed
   *  for exactly one of two concurrent callers, such as a unique-constrained primary key,
   *  a compare-and-set, or an insert-if-absent. Reading the existing record and then
   *  writing does NOT satisfy this contract: under concurrency two callers can both read
   *  an empty slot before either writes, both report `inserted: true`, and the second
   *  write displaces the first, which makes the recorded revocation time, reason and
   *  revoker mutable after the fact and breaks first-wins and INV-5. The in-memory
   *  reference meets the contract only because its read and write are one synchronous
   *  statement sequence on a single-threaded runtime; that is a property of that runtime,
   *  not a pattern a durable store may copy.
   *
   *  Brings its target into the tracked view: recording a revocation for a delegation is a
   *  statement that this store has an opinion about that delegation. */
  insertVerifiedRevocation(revocation: AuthorityRevocationV1): AuthorityRevocationInsertion
}

/** What a gateway eventually supplies to the chain verifier. Interface only; no gateway
 *  implementation lives in this repository. */
export type AuthorityRevocationLookup = (
  delegation: AuthorityDelegationV1,
) => AuthorityRevocationV1 | undefined
