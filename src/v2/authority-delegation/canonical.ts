// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { canonicalizeJCS, canonicalizeJCSForWrite } from '../../core/canonical-jcs.js'
import { sign, verify } from '../../crypto/keys.js'
import type { AuthorityDelegationBodyV1, AuthorityDelegationV1 } from './types.js'

export const AUTHORITY_DELEGATION_ID_DOMAIN = 'APS-AUTHORITY-DELEGATION-ID-V1\0'
export const AUTHORITY_DELEGATION_SIGNATURE_DOMAIN = 'APS-AUTHORITY-DELEGATION-SIGNATURE-V1\0'

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

/** Exact RFC 8785 input used to derive delegation_id. */
export function authorityDelegationIdInput(body: AuthorityDelegationBodyV1): string {
  return AUTHORITY_DELEGATION_ID_DOMAIN + canonicalizeJCS(body)
}
/** Write-boundary twin of authorityDelegationIdInput().
 *
 *  Emits the same bytes as authorityDelegationIdInput() for every value it accepts. The only difference
 *  is that an integer-valued number outside the interoperable IEEE 754 range is
 *  refused instead of serialized. Use at signing and new-write boundaries ONLY:
 *  authorityDelegationIdInput() stays unrestricted so an artifact signed before this rule keeps
 *  verifying. */
export function authorityDelegationIdInputForWrite(body: AuthorityDelegationBodyV1): string {
  return AUTHORITY_DELEGATION_ID_DOMAIN + canonicalizeJCSForWrite(body)
}

export function computeAuthorityDelegationId(body: AuthorityDelegationBodyV1): string {
  return `sha256:${sha256Hex(authorityDelegationIdInput(body))}`
}

/** Write-boundary twin of computeAuthorityDelegationId().
 *
 *  Reaches a canonicalizer only indirectly, through authorityDelegationIdInput. Use when
 *  ISSUING a delegation; verify.ts and the budget ledger keep calling the unrestricted
 *  form so a delegation issued before this rule still re-derives its id. */
export function computeAuthorityDelegationIdForWrite(body: AuthorityDelegationBodyV1): string {
  return `sha256:${sha256Hex(authorityDelegationIdInputForWrite(body))}`
}

/** Exact Ed25519 input: domain plus JCS(record without signature). */
export function authorityDelegationSignatureInput(
  delegation: Omit<AuthorityDelegationV1, 'signature'>,
): string {
  return AUTHORITY_DELEGATION_SIGNATURE_DOMAIN + canonicalizeJCS(delegation)
}

/** Write-boundary twin of authorityDelegationSignatureInput().
 *
 *  signAuthorityDelegation() mints a signature over this string while
 *  verifyAuthorityDelegationSignature() rebuilds the identical string to check an
 *  existing one, so the helper is shared and cannot be guarded in place. */
function authorityDelegationSignatureInputForWrite(
  delegation: Omit<AuthorityDelegationV1, 'signature'>,
): string {
  return AUTHORITY_DELEGATION_SIGNATURE_DOMAIN + canonicalizeJCSForWrite(delegation)
}

export function signAuthorityDelegation(
  delegation: Omit<AuthorityDelegationV1, 'signature'>,
  privateKey: string,
): string {
  return sign(authorityDelegationSignatureInputForWrite(delegation), privateKey)
}

export function verifyAuthorityDelegationSignature(
  delegation: AuthorityDelegationV1,
  publicKey: string,
): boolean {
  const { signature, ...unsigned } = delegation
  return verify(authorityDelegationSignatureInput(unsigned), signature, publicKey)
}

export function authorityDelegationBody(
  delegation: AuthorityDelegationV1,
): AuthorityDelegationBodyV1 {
  const { delegation_id: _delegationId, signature: _signature, ...body } = delegation
  return body
}
