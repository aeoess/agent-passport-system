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
import { snapshotPlainData } from './plain-data.js'
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
    throw new Error(`authority delegation body invalid: ${failures[0].message} (${failures[0].code})`)
  }
}

/**
 * True when `body` is a non-null object carrying an own `delegation_id` or `signature`
 * member, whatever its value, including `undefined` and `null`.
 */
function carriesOwnIdentityMember(body: unknown): boolean {
  return (
    typeof body === 'object' &&
    body !== null &&
    (Object.prototype.hasOwnProperty.call(body, 'delegation_id') ||
      Object.prototype.hasOwnProperty.call(body, 'signature'))
  )
}

/**
 * Compute the delegation_id and Ed25519 signature and assemble the signed record.
 *
 * Module-private write-boundary finishing step shared by issueAuthorityDelegation and
 * issueSubAuthorityDelegation: both call this only after their own checks have already
 * passed, so it never re-validates `body`.
 */
function finalizeAuthorityDelegation(
  body: AuthorityDelegationBodyV1,
  privateKey: string,
): AuthorityDelegationV1 {
  const delegation_id = computeAuthorityDelegationIdForWrite(body)
  const unsigned: Omit<AuthorityDelegationV1, 'signature'> = { ...body, delegation_id }
  return { ...unsigned, signature: signAuthorityDelegation(unsigned, privateKey) }
}

/**
 * Create a deterministic v1 root record from explicit body fields and an Ed25519 key.
 *
 * Issues roots only. Refuses a body already carrying an own delegation_id or signature
 * member (SCHEMA_INVALID), so the returned record's delegation_id always recomputes
 * from its own body: draft section 3.1 (lines 484-490) and section 3.6 (lines
 * 700-704). Refuses a body whose parent_delegation_id is not null (PARENT_MISMATCH):
 * section 3.1, line 428, states that parent_delegation_id is null only for a root
 * selected by verifier trust policy. A child is minted only through
 * issueSubAuthorityDelegation, which performs the section 3.6 (lines 695-704) parent
 * checks before signing.
 *
 * The body is snapshotted to plain JSON data (see plain-data.ts) first; every check
 * below, and the signing itself, reads only that snapshot, never the caller's original
 * body, so a getter or a Proxy trap in `body` cannot answer differently the second
 * time it would otherwise have been read.
 */
export function issueAuthorityDelegation(
  body: AuthorityDelegationBodyV1,
  privateKey: string,
): AuthorityDelegationV1 {
  const snapshot = snapshotPlainData(body) as AuthorityDelegationBodyV1
  if (carriesOwnIdentityMember(snapshot)) {
    throw new Error('authority delegation body must carry neither delegation_id nor signature (SCHEMA_INVALID)')
  }
  assertBody(snapshot)
  if (snapshot.parent_delegation_id !== null) {
    throw new Error('authority delegation root body must have a null parent_delegation_id (PARENT_MISMATCH)')
  }
  return finalizeAuthorityDelegation(snapshot, privateKey)
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
 * to exactly "active" (REVOKED, REVOCATION_UNKNOWN); the body carries neither an own
 * delegation_id nor an own signature member (SCHEMA_INVALID); then the existing
 * checks, in their existing order: the child body's shape, its parent_delegation_id,
 * chain continuity, issued_at inside the parent's validity window, and the
 * seven-facet attenuation of the child under the parent.
 *
 * The delegation_id-or-signature check runs immediately after the revocation check
 * and immediately before the child body's shape check, per draft section 3.1
 * (lines 484-490) and section 3.6 (lines 700-704): a body hashed and signed while
 * already carrying one of those members would not recompute its delegation_id from
 * its own body, leaving an invalidity for a later verifier to discover instead of
 * refusing it at issuance.
 *
 * `parent` is snapshotted to plain JSON data (see plain-data.ts) before its shape
 * check; a parent that is not plain fails that check with the shape check's existing
 * message form. `body` is snapshotted at the position of the existing bare-body
 * check; a body that is not plain gives SCHEMA_INVALID there. Every check after each
 * snapshot, and the signing itself, reads only that snapshot, never the caller's
 * original parent or body, so a getter or a Proxy trap cannot answer differently the
 * second time it would otherwise have been read.
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

  const parentSnapshot = snapshotPlainData(parent) as AuthorityDelegationV1
  const parentFailures = validateAuthorityDelegationShape(parentSnapshot)
  if (parentFailures.length > 0) {
    throw new Error(`authority delegation parent invalid (${parentFailures[0].code})`)
  }

  const expectedParentId = computeAuthorityDelegationId(authorityDelegationBody(parentSnapshot))
  if (expectedParentId !== parentSnapshot.delegation_id) {
    throw new Error('authority delegation parent content address does not match its body (ID_MISMATCH)')
  }

  let parentKey: string | null | undefined
  try {
    parentKey = resolveVerificationKey(parentSnapshot.issuer, parentSnapshot.verification_method, parentSnapshot.issued_at)
  } catch {
    parentKey = null
  }
  if (parentKey === null || parentKey === undefined) {
    throw new Error('authority delegation parent issuer verification key could not be resolved (KEY_RESOLUTION_FAILED)')
  }
  if (!verifyAuthorityDelegationSignature(parentSnapshot, parentKey)) {
    throw new Error('authority delegation parent Ed25519 signature is invalid (SIGNATURE_INVALID)')
  }

  const parentTime = parentSnapshot.authority.time
  if (now < parentTime.not_before) {
    throw new Error('authority delegation parent is not yet valid at now (NOT_YET_VALID)')
  }
  if (now >= parentTime.not_after) {
    throw new Error('authority delegation parent has expired at now (EXPIRED)')
  }

  let parentRevocation: unknown
  try {
    parentRevocation = resolveRevocation(parentSnapshot)
  } catch {
    parentRevocation = null
  }
  if (parentRevocation === 'revoked') {
    throw new Error('authority delegation parent is revoked (REVOKED)')
  }
  if (parentRevocation !== 'active') {
    throw new Error('authority delegation parent revocation status is unknown (REVOCATION_UNKNOWN)')
  }

  const bodySnapshot = snapshotPlainData(body) as AuthorityDelegationBodyV1
  if (carriesOwnIdentityMember(bodySnapshot)) {
    throw new Error('authority delegation body must carry neither delegation_id nor signature (SCHEMA_INVALID)')
  }

  assertBody(bodySnapshot)
  if (bodySnapshot.parent_delegation_id !== parentSnapshot.delegation_id) {
    throw new Error('authority delegation parent mismatch (PARENT_MISMATCH)')
  }
  if (bodySnapshot.issuer !== parentSnapshot.subject) {
    throw new Error('authority delegation chain continuity failure (CHAIN_CONTINUITY)')
  }
  const issued = bodySnapshot.issued_at
  if (issued < parentSnapshot.authority.time.not_before ||
      issued >= parentSnapshot.authority.time.not_after) {
    throw new Error('authority delegation issued_at is outside parent validity (ISSUED_AT_OUTSIDE_PARENT)')
  }
  const failures = compareAuthority(parentSnapshot.authority, bodySnapshot.authority)
  if (failures.length > 0) {
    throw new Error(`authority delegation does not narrow (${failures[0].code})`)
  }
  return finalizeAuthorityDelegation(bodySnapshot, privateKey)
}
