// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { canonicalizeJCS, canonicalizeJCSForWrite } from '../../core/canonical-jcs.js'
import { sign, verify } from '../../crypto/keys.js'
import type { AuthorityRevocationBodyV1, AuthorityRevocationV1 } from './types.js'

/** Domain tags for the three preimages this record uses. Each is a distinct APS tag
 *  followed by one zero byte, the same discipline AuthorityDelegationV1 and
 *  PrincipalBindingRevocationV1 follow, so bytes minted for one construction can never
 *  be read as bytes minted for another. */
export const AUTHORITY_REVOCATION_ID_DOMAIN = 'APS-AUTHORITY-REVOCATION-ID-V1\0'
export const AUTHORITY_REVOCATION_SIGNATURE_DOMAIN = 'APS-AUTHORITY-REVOCATION-SIGNATURE-V1\0'
export const AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN =
  'APS-AUTHORITY-REVOCATION-CASCADE-TRANSACTION-ID-V1\0'

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

/** The origin content a cascade transaction identity is derived from: the revocation body
 *  with `cascade_transaction_id` absent, alongside `revocation_id` and `signature`.
 *
 *  Section 3.5.1 says a cascade carries a transaction identity shared by every record it
 *  produces, and says nothing about how it is constructed. A content-bound derivation is
 *  chosen over a random value so that issuance stays byte-deterministic for fixed inputs
 *  and so a verifier can recompute the field instead of accepting whatever the issuer
 *  wrote there. Independent cascades do not collide because the origin's 16-byte `nonce`
 *  is inside this preimage. */
export type AuthorityRevocationCascadeOriginV1 = Omit<
  AuthorityRevocationBodyV1,
  'cascade_transaction_id'
>

/** Exact RFC 8785 input used to derive cascade_transaction_id. */
export function authorityRevocationCascadeTransactionInput(
  origin: AuthorityRevocationCascadeOriginV1,
): string {
  return AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN + canonicalizeJCS(origin)
}

export function computeAuthorityRevocationCascadeTransactionId(
  origin: AuthorityRevocationCascadeOriginV1,
): string {
  return `sha256:${sha256Hex(authorityRevocationCascadeTransactionInput(origin))}`
}

/** Write-boundary twin of computeAuthorityRevocationCascadeTransactionId(). */
export function computeAuthorityRevocationCascadeTransactionIdForWrite(
  origin: AuthorityRevocationCascadeOriginV1,
): string {
  return `sha256:${sha256Hex(
    AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN + canonicalizeJCSForWrite(origin),
  )}`
}

/** Exact RFC 8785 input used to derive revocation_id. */
export function authorityRevocationIdInput(body: AuthorityRevocationBodyV1): string {
  return AUTHORITY_REVOCATION_ID_DOMAIN + canonicalizeJCS(body)
}

export function computeAuthorityRevocationId(body: AuthorityRevocationBodyV1): string {
  return `sha256:${sha256Hex(authorityRevocationIdInput(body))}`
}

/** Write-boundary twin of computeAuthorityRevocationId().
 *
 *  Emits the same bytes as computeAuthorityRevocationId() for every value it accepts; it
 *  only refuses an integer-valued number outside the interoperable IEEE 754 range rather
 *  than serializing it. Use when ISSUING. verify.ts keeps calling the unrestricted form,
 *  so a record minted before this rule still re-derives its identifier. */
export function computeAuthorityRevocationIdForWrite(body: AuthorityRevocationBodyV1): string {
  return `sha256:${sha256Hex(AUTHORITY_REVOCATION_ID_DOMAIN + canonicalizeJCSForWrite(body))}`
}

/** Exact Ed25519 input: the signature domain tag plus JCS of the record with `signature`
 *  absent. `revocation_id` IS inside this preimage, so the identifier is signed rather
 *  than being an unauthenticated label beside the signature. */
export function authorityRevocationSignatureInput(
  revocation: Omit<AuthorityRevocationV1, 'signature'>,
): string {
  return AUTHORITY_REVOCATION_SIGNATURE_DOMAIN + canonicalizeJCS(revocation)
}

export function signAuthorityRevocation(
  revocation: Omit<AuthorityRevocationV1, 'signature'>,
  privateKey: string,
): string {
  return sign(
    AUTHORITY_REVOCATION_SIGNATURE_DOMAIN + canonicalizeJCSForWrite(revocation),
    privateKey,
  )
}

export function verifyAuthorityRevocationSignature(
  revocation: AuthorityRevocationV1,
  publicKey: string,
): boolean {
  const { signature, ...unsigned } = revocation
  return verify(authorityRevocationSignatureInput(unsigned), signature, publicKey)
}

/** The body a revocation_id is computed over: the record with `revocation_id` and
 *  `signature` removed. */
export function authorityRevocationBody(
  revocation: AuthorityRevocationV1,
): AuthorityRevocationBodyV1 {
  const { revocation_id: _revocationId, signature: _signature, ...body } = revocation
  return body
}

/** The cascade origin a cascade_transaction_id is computed over: the body with
 *  `cascade_transaction_id` removed. */
export function authorityRevocationCascadeOrigin(
  body: AuthorityRevocationBodyV1,
): AuthorityRevocationCascadeOriginV1 {
  const { cascade_transaction_id: _cascadeTransactionId, ...origin } = body
  return origin
}
