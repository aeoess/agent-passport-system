// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import {
  authorityDelegationBody,
  computeAuthorityDelegationId,
} from '../authority-delegation/canonical.js'
import { snapshotPlainData } from '../authority-delegation/plain-data.js'
import {
  isCanonicalTimestamp,
  validateAuthorityDelegationShape,
} from '../authority-delegation/schema.js'
import type { AuthorityDelegationV1 } from '../authority-delegation/types.js'
import {
  computeAuthorityRevocationCascadeTransactionIdForWrite,
  computeAuthorityRevocationIdForWrite,
  signAuthorityRevocation,
} from './canonical.js'
import type { AuthorityRevocationCascadeOriginV1 } from './canonical.js'
import { validateAuthorityRevocationShape } from './schema.js'
import {
  AUTHORITY_REVOCATION_RECORD_TYPE,
  AUTHORITY_REVOCATION_VERSION,
} from './types.js'
import type { AuthorityRevocationBodyV1, AuthorityRevocationV1 } from './types.js'

/** Everything issuance takes besides the target delegation and the signing key. */
export interface AuthorityRevocationIssueInput {
  /** Canonical UTC-millisecond revocation time, supplied by the caller.
   *
   *  Issuance never reads a clock. The value lands in the record's signed `revoked_at`,
   *  so the same inputs produce the same bytes on every run, which is what makes the
   *  identifier and the signature reproducible in a test and in a conformance vector.
   *  Named `now` to match SubAuthorityIssueOptions. */
  now: string
  /** The revoking authority. Checked against the target delegation's `issuer`. */
  revoker: string
  /** Which of the revoker's keys signs. Must begin `${revoker}#`. */
  verification_method: string
  reason_code: string
  /** OPTIONAL. Omitted from the record entirely when not supplied; never written as null. */
  detail?: string
  nonce: string
}

/**
 * Mint a draft-03 section 3.5.1 direct revocation for one AuthorityDelegationV1.
 *
 * Section 3.5 line 634 states the only authorization rule this function applies: "Any
 * delegation MAY be revoked by its issuer." The exact comparison is
 * `input.revoker === delegation.issuer`, where `delegation` is the target record passed
 * in by the caller and `issuer` is its own member. The record being minted is never
 * consulted for its own authorization: a field a would-be revoker writes inside its own
 * record cannot make that revoker the issuer of somebody else's delegation.
 *
 * The target's `delegation_id` is recomputed from its body before that comparison. A
 * `delegation_id` sits outside the delegation's own identifier preimage, so a record
 * whose claimed identifier does not match its body has an unauthenticated `issuer` too,
 * and refusing there is what keeps the revoker check meaningful.
 *
 * What this function does NOT establish: that the holder of `privateKey` is in fact
 * `input.revoker`. An identifier-to-key binding is a resolver's answer, not a local one.
 * verifyAuthorityRevocation() makes that check, resolving the key under the TARGET
 * delegation's `issuer`. Issuance can only refuse to mint a record that is already
 * unverifiable; it cannot promise the record will verify.
 *
 * Nothing about a cascade over descendants is emitted here. This function produces one
 * record about one delegation. Enforcement against descendants comes from chain
 * verification, which rejects any chain containing a revoked ancestor.
 *
 * Throws on refusal; each message names its code in parentheses.
 */
export function issueAuthorityRevocation(
  delegation: AuthorityDelegationV1,
  input: AuthorityRevocationIssueInput,
  privateKey: string,
): AuthorityRevocationV1 {
  // Each member is read exactly once, so a getter or Proxy trap cannot answer one way
  // when a value is checked and another way when it is hashed and signed.
  const read = (key: keyof AuthorityRevocationIssueInput): unknown => {
    try { return input ? input[key] : undefined } catch { return undefined }
  }
  const now = read('now')
  const revoker = read('revoker')
  const verificationMethod = read('verification_method')
  const reasonCode = read('reason_code')
  const hasDetail = (() => {
    try { return !!input && Object.prototype.hasOwnProperty.call(input, 'detail') } catch { return false }
  })()
  const detail = hasDetail ? read('detail') : undefined
  const nonce = read('nonce')

  if (!isCanonicalTimestamp(now)) {
    throw new Error('authority revocation now must be a canonical UTC-millisecond timestamp (NONCANONICAL_VALUE)')
  }

  const target = snapshotPlainData(delegation) as AuthorityDelegationV1
  const targetFailures = validateAuthorityDelegationShape(target)
  if (targetFailures.length > 0) {
    throw new Error(`authority revocation target delegation invalid (${targetFailures[0].code})`)
  }
  if (computeAuthorityDelegationId(authorityDelegationBody(target)) !== target.delegation_id) {
    throw new Error('authority revocation target content address does not match its body (TARGET_ID_MISMATCH)')
  }

  // Draft section 3.5: a delegation may be revoked by its issuer. The compared fields are
  // the caller's claimed revoker and the TARGET delegation's own `issuer` member.
  if (typeof revoker !== 'string' || revoker !== target.issuer) {
    throw new Error('authority revocation revoker is not the target delegation issuer (REVOKER_NOT_ISSUER)')
  }
  if (typeof verificationMethod !== 'string' || !verificationMethod.startsWith(`${revoker}#`)) {
    throw new Error('authority revocation verification_method must begin with the revoker and "#" (VERIFICATION_METHOD_MISMATCH)')
  }

  const origin: AuthorityRevocationCascadeOriginV1 = {
    record_type: AUTHORITY_REVOCATION_RECORD_TYPE,
    version: AUTHORITY_REVOCATION_VERSION,
    delegation_id: target.delegation_id,
    revoker,
    verification_method: verificationMethod,
    revoked_at: now,
    reason_code: reasonCode as string,
    ...(hasDetail ? { detail: detail as string } : {}),
    nonce: nonce as string,
  }
  const body: AuthorityRevocationBodyV1 = {
    ...origin,
    cascade_transaction_id: computeAuthorityRevocationCascadeTransactionIdForWrite(origin),
  }

  // Shape is judged on the finished record, so the probe carries placeholder values in
  // exactly the two members that are not derivable yet. Both are replaced below.
  const probe = {
    ...body,
    revocation_id: `sha256:${'0'.repeat(64)}`,
    signature: '0'.repeat(128),
  } as AuthorityRevocationV1
  const failures = validateAuthorityRevocationShape(probe)
  if (failures.length > 0) {
    throw new Error(`authority revocation invalid: ${failures[0].message} (${failures[0].code})`)
  }

  const unsigned: Omit<AuthorityRevocationV1, 'signature'> = {
    ...body,
    revocation_id: computeAuthorityRevocationIdForWrite(body),
  }
  return { ...unsigned, signature: signAuthorityRevocation(unsigned, privateKey) }
}
