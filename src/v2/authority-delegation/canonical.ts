// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
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

export function computeAuthorityDelegationId(body: AuthorityDelegationBodyV1): string {
  return `sha256:${sha256Hex(authorityDelegationIdInput(body))}`
}

/** Exact Ed25519 input: domain plus JCS(record without signature). */
export function authorityDelegationSignatureInput(
  delegation: Omit<AuthorityDelegationV1, 'signature'>,
): string {
  return AUTHORITY_DELEGATION_SIGNATURE_DOMAIN + canonicalizeJCS(delegation)
}

export function signAuthorityDelegation(
  delegation: Omit<AuthorityDelegationV1, 'signature'>,
  privateKey: string,
): string {
  return sign(authorityDelegationSignatureInput(delegation), privateKey)
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
