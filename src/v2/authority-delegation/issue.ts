// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import {
  computeAuthorityDelegationIdForWrite,
  signAuthorityDelegation,
} from './canonical.js'
import { compareAuthority } from './compare.js'
import { validateAuthorityDelegationShape } from './schema.js'
import type { AuthorityDelegationBodyV1, AuthorityDelegationV1 } from './types.js'

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
 * Issue a child after immediate-parent attenuation checks. The caller must first
 * validate the complete parent chain and revocation state; this pure primitive
 * cannot establish live ancestor status by itself.
 */
export function issueSubAuthorityDelegation(
  parent: AuthorityDelegationV1,
  body: AuthorityDelegationBodyV1,
  privateKey: string,
): AuthorityDelegationV1 {
  const parentFailures = validateAuthorityDelegationShape(parent)
  if (parentFailures.length > 0) {
    throw new Error(`authority delegation parent invalid: ${parentFailures.map(item => item.code).join(', ')}`)
  }
  assertBody(body)
  if (body.parent_delegation_id !== parent.delegation_id) {
    throw new Error('authority delegation parent mismatch')
  }
  if (body.issuer !== parent.subject) {
    throw new Error('authority delegation chain continuity failure')
  }
  const issued = Date.parse(body.issued_at)
  if (issued < Date.parse(parent.authority.time.not_before) ||
      issued >= Date.parse(parent.authority.time.not_after)) {
    throw new Error('authority delegation issued_at is outside parent validity')
  }
  const failures = compareAuthority(parent.authority, body.authority)
  if (failures.length > 0) {
    throw new Error(`authority delegation does not narrow: ${failures.map(item => item.code).join(', ')}`)
  }
  return issueAuthorityDelegation(body, privateKey)
}
