// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import {
  authorityDelegationBody,
  computeAuthorityDelegationId,
  computeAuthorityDelegationIdForWrite,
  signAuthorityDelegation,
  verifyAuthorityDelegationSignature,
} from './canonical.js'
import { compareAuthority } from './compare.js'
import { isCanonicalTimestamp, validateAuthorityDelegationShape } from './schema.js'
import type {
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
  RevocationResolution,
  VerificationKeyResolver,
} from './types.js'

function assertBody(body: AuthorityDelegationBodyV1): void {
  const probe: AuthorityDelegationV1 = {
    ...body,
    delegation_id: `sha256:${'0'.repeat(64)}`,
    signature: '0'.repeat(128),
  }
  const failures = validateAuthorityDelegationShape(probe)
  if (failures.length > 0) {
    throw new Error(`authority delegation body invalid: ${failures.map(item => `${item.code}: ${item.message}`).join('; ')}`)
  }
}

/** Create a deterministic v1 record from explicit body fields and an Ed25519 key. */
export function issueAuthorityDelegation(
  body: AuthorityDelegationBodyV1,
  privateKey: string,
): AuthorityDelegationV1 {
  assertBody(body)
  const delegation_id = computeAuthorityDelegationIdForWrite(body)
  const unsigned: Omit<AuthorityDelegationV1, 'signature'> = { ...body, delegation_id }
  return { ...unsigned, signature: signAuthorityDelegation(unsigned, privateKey) }
}

/**
 * Options required to issue a delegated child. `resolveVerificationKey` and
 * `resolveRevocation` let issueSubAuthorityDelegation verify the immediate
 * parent's signature and live status before minting the child, per draft
 * section 3.6.
 */
export interface SubAuthorityIssueOptions {
  /** Canonical UTC-millisecond timestamp at which the parent's validity is checked. */
  now: string
  resolveVerificationKey: VerificationKeyResolver
  resolveRevocation: (delegation: AuthorityDelegationV1) => RevocationResolution
}

/**
 * Issue a child after verifying the immediate parent and the attenuation checks.
 *
 * Draft section 3.6 (lines 695-704) requires an issuer minting a child to verify the
 * parent delegation's signature and temporal validity before signing the child, and to
 * refuse to issue under an expired, not-yet-valid, or revoked parent; lines 589-592
 * treat an unknown revocation state as indeterminate, never as valid.
 *
 * Checks run in this order, throwing at the first one that fails; each thrown Error
 * message names the SDK code in parentheses: `now` is a canonical UTC-millisecond
 * timestamp (NONCANONICAL_VALUE); the parent's shape (its first failure's code); the
 * parent's delegation_id against its own body (ID_MISMATCH); the parent's signing key
 * resolves (KEY_RESOLUTION_FAILED) and its signature verifies (SIGNATURE_INVALID); the
 * parent is valid at `now` (NOT_YET_VALID, EXPIRED); the parent's revocation resolves
 * to exactly "active" (REVOKED, REVOCATION_UNKNOWN); then the existing checks, in
 * their existing order: the child body's shape, its parent_delegation_id, chain
 * continuity, issued_at inside the parent's validity window, and the seven-facet
 * attenuation of the child under the parent.
 *
 * Not checked here: a body that already carries a delegation_id or signature member
 * is hashed and signed with that member included.
 */
export function issueSubAuthorityDelegation(
  parent: AuthorityDelegationV1,
  body: AuthorityDelegationBodyV1,
  privateKey: string,
  options: SubAuthorityIssueOptions,
): AuthorityDelegationV1 {
  const { now, resolveVerificationKey, resolveRevocation } = options

  if (!isCanonicalTimestamp(now)) {
    throw new Error('authority delegation now must be a canonical UTC-millisecond timestamp (NONCANONICAL_VALUE)')
  }

  const parentFailures = validateAuthorityDelegationShape(parent)
  if (parentFailures.length > 0) {
    throw new Error(`authority delegation parent invalid (${parentFailures[0].code})`)
  }

  const expectedParentId = computeAuthorityDelegationId(authorityDelegationBody(parent))
  if (expectedParentId !== parent.delegation_id) {
    throw new Error('authority delegation parent content address does not match its body (ID_MISMATCH)')
  }

  let parentKey: string | null | undefined
  try {
    parentKey = resolveVerificationKey(parent.issuer, parent.verification_method, parent.issued_at)
  } catch {
    parentKey = null
  }
  if (parentKey === null || parentKey === undefined) {
    throw new Error('authority delegation parent issuer verification key could not be resolved (KEY_RESOLUTION_FAILED)')
  }
  if (!verifyAuthorityDelegationSignature(parent, parentKey)) {
    throw new Error('authority delegation parent Ed25519 signature is invalid (SIGNATURE_INVALID)')
  }

  const parentTime = parent.authority.time
  if (now < parentTime.not_before) {
    throw new Error('authority delegation parent is not yet valid at now (NOT_YET_VALID)')
  }
  if (now >= parentTime.not_after) {
    throw new Error('authority delegation parent has expired at now (EXPIRED)')
  }

  let parentRevocation: unknown
  try {
    parentRevocation = resolveRevocation(parent)
  } catch {
    parentRevocation = null
  }
  if (parentRevocation === 'revoked') {
    throw new Error('authority delegation parent is revoked (REVOKED)')
  }
  if (parentRevocation !== 'active') {
    throw new Error('authority delegation parent revocation status is unknown (REVOCATION_UNKNOWN)')
  }

  assertBody(body)
  if (body.parent_delegation_id !== parent.delegation_id) {
    throw new Error('authority delegation parent mismatch (PARENT_MISMATCH)')
  }
  if (body.issuer !== parent.subject) {
    throw new Error('authority delegation chain continuity failure (CHAIN_CONTINUITY)')
  }
  const issued = body.issued_at
  if (issued < parent.authority.time.not_before ||
      issued >= parent.authority.time.not_after) {
    throw new Error('authority delegation issued_at is outside parent validity (ISSUED_AT_OUTSIDE_PARENT)')
  }
  const failures = compareAuthority(parent.authority, body.authority)
  if (failures.length > 0) {
    throw new Error(`authority delegation does not narrow (${failures[0].code})`)
  }
  return issueAuthorityDelegation(body, privateKey)
}
