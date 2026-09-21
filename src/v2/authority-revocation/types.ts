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
  /** Which of the revoker's keys signed. Must begin `${revoker}#`. */
  verification_method: string
  /** Canonical UTC-millisecond revocation time, supplied by the caller, never read from
   *  a clock inside issuance. */
  revoked_at: string
  /** Machine-readable reason: `^[a-z][a-z0-9_.-]{0,63}$`. */
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
  /** verification_method does not belong to the revoker. */
  | 'VERIFICATION_METHOD_MISMATCH'
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

/** The read and write boundary a revocation resolver needs.
 *
 *  Nothing in this interface promises durability. An implementation backed by process
 *  memory, a file, or a replicated database all satisfy it; only the implementation says
 *  which. Section 3.5.1 makes the cascade-completion record depend on the last
 *  descendant's revocation being PERSISTENT, and no method here establishes persistence,
 *  which is one reason no completion record is issued in this module. */
export interface AuthorityRevocationStore {
  /** Whether `delegationId` is inside this store's view at all.
   *
   *  This is what keeps absence from meaning "active". A store that has never heard of a
   *  delegation cannot say the delegation is unrevoked; it can only say it does not know.
   *  A store whose view covers the delegation and holds no revocation for it can. */
  tracks(delegationId: string): boolean
  /** The revocation recorded for `delegationId`, or undefined when none is recorded. */
  get(delegationId: string): AuthorityRevocationV1 | undefined
  /** Record `revocation` and return what this store now holds for its target.
   *
   *  First valid revocation for a delegation wins. Revocation is irreversible (INV-5), so
   *  a later call naming a delegation that already has a record does not replace it: it
   *  returns the record already held. The returned record is therefore not always the one
   *  passed in, and a caller that needs to know writes the comparison itself. */
  put(revocation: AuthorityRevocationV1): AuthorityRevocationV1
}

/** What a gateway eventually supplies to the chain verifier. Interface only; no gateway
 *  implementation lives in this repository. */
export type AuthorityRevocationLookup = (
  delegation: AuthorityDelegationV1,
) => AuthorityRevocationV1 | undefined
