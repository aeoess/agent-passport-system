// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Content addressing and Ed25519 signing for the two records this module
// declares. Nothing here reimplements JCS, SHA-256 or Ed25519: each comes from the helper
// the rest of this package already uses.
//
// Not required by draft-pidlisnyi-aps-03. See ./types.ts for the specification position.

import { createHash } from 'node:crypto'
import { canonicalizeJCS, canonicalizeJCSForWrite } from '../../core/canonical-jcs.js'
import { sign, verify } from '../../crypto/keys.js'
import type {
  AuthorityBoundFulfilment,
  AuthorityBoundFulfilmentBody,
  AuthorityExhaustion,
  AuthorityExhaustionBody,
} from './types.js'

/** Domain tags. Each is a distinct tag followed by one zero byte, the same discipline
 *  `AuthorityDelegationV1` and `AuthorityRevocationV1` follow, so bytes minted for one
 *  construction can never be read as bytes minted for another. The `PROPOSED-` prefix is
 *  part of the tag: if any of this is ever specified, the specified construction will use a
 *  different tag and records minted under this one will not verify under it. That is the
 *  intended behaviour, not a migration problem to solve later. */
export const AUTHORITY_BOUND_FULFILMENT_SIGNATURE_DOMAIN =
  'PROPOSED-APS-AUTHORITY-BOUND-FULFILMENT-SIGNATURE-V0\0'
export const AUTHORITY_EXHAUSTION_ID_DOMAIN = 'PROPOSED-APS-AUTHORITY-EXHAUSTION-ID-V0\0'
export const AUTHORITY_EXHAUSTION_SIGNATURE_DOMAIN =
  'PROPOSED-APS-AUTHORITY-EXHAUSTION-SIGNATURE-V0\0'

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function withoutSignature<T extends { signature: string }>(record: T): Omit<T, 'signature'> {
  const { signature: _signature, ...body } = record
  return body
}

/** Exact Ed25519 preimage for a fulfilment attestation: the domain tag plus RFC 8785 JCS of
 *  the record with `signature` absent. */
export function authorityBoundFulfilmentSignatureInput(
  body: AuthorityBoundFulfilmentBody,
): string {
  return AUTHORITY_BOUND_FULFILMENT_SIGNATURE_DOMAIN + canonicalizeJCS(body)
}

/** Write-boundary twin. Use when ISSUING. The verification path keeps calling the
 *  unrestricted form, so a record minted before the write rule still verifies. */
export function authorityBoundFulfilmentSignatureInputForWrite(
  body: AuthorityBoundFulfilmentBody,
): string {
  return AUTHORITY_BOUND_FULFILMENT_SIGNATURE_DOMAIN + canonicalizeJCSForWrite(body)
}

export function signAuthorityBoundFulfilment(
  body: AuthorityBoundFulfilmentBody,
  privateKeyHex: string,
): string {
  return sign(authorityBoundFulfilmentSignatureInputForWrite(body), privateKeyHex)
}

export function verifyAuthorityBoundFulfilmentSignature(
  record: AuthorityBoundFulfilment,
  publicKeyHex: string,
): boolean {
  return verify(
    authorityBoundFulfilmentSignatureInput(
      withoutSignature(record) as AuthorityBoundFulfilmentBody,
    ),
    record.signature,
    publicKeyHex,
  )
}

/** Exact preimage for `exhaustion_id`: the ID domain tag plus JCS of the body. */
export function authorityExhaustionIdInput(body: AuthorityExhaustionBody): string {
  return AUTHORITY_EXHAUSTION_ID_DOMAIN + canonicalizeJCS(body)
}

export function computeAuthorityExhaustionId(body: AuthorityExhaustionBody): string {
  return `sha256:${sha256Hex(authorityExhaustionIdInput(body))}`
}

export function computeAuthorityExhaustionIdForWrite(body: AuthorityExhaustionBody): string {
  return `sha256:${sha256Hex(
    AUTHORITY_EXHAUSTION_ID_DOMAIN + canonicalizeJCSForWrite(body),
  )}`
}

/** Exact Ed25519 preimage for the exhaustion record: the signature domain tag plus JCS of
 *  the record with `signature` absent. `exhaustion_id` IS inside this preimage, so the
 *  identifier is signed rather than being an unauthenticated label beside the signature. */
export function authorityExhaustionSignatureInput(
  record: Omit<AuthorityExhaustion, 'signature'>,
): string {
  return AUTHORITY_EXHAUSTION_SIGNATURE_DOMAIN + canonicalizeJCS(record)
}

export function authorityExhaustionSignatureInputForWrite(
  record: Omit<AuthorityExhaustion, 'signature'>,
): string {
  return AUTHORITY_EXHAUSTION_SIGNATURE_DOMAIN + canonicalizeJCSForWrite(record)
}

export function signAuthorityExhaustion(
  record: Omit<AuthorityExhaustion, 'signature'>,
  privateKeyHex: string,
): string {
  return sign(authorityExhaustionSignatureInputForWrite(record), privateKeyHex)
}

export function verifyAuthorityExhaustionSignature(
  record: AuthorityExhaustion,
  publicKeyHex: string,
): boolean {
  return verify(
    authorityExhaustionSignatureInput(
      withoutSignature(record) as Omit<AuthorityExhaustion, 'signature'>,
    ),
    record.signature,
    publicKeyHex,
  )
}
