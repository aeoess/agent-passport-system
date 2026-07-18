// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign, verify } from '../../crypto/keys.js'
import type {
  HistoricalKeyResolver,
  IdentityVerificationResult,
  PrincipalBindingRevocationV1,
} from './types.js'
import {
  assertExactKeys,
  assertHex,
  assertIJson,
  assertPlainRecord,
  assertUtcMilliseconds,
} from './validation.js'

const ID_DOMAIN = 'APS-PRINCIPAL-BINDING-REVOCATION-ID-V1\0'
const SIGNATURE_DOMAIN = 'APS-PRINCIPAL-BINDING-REVOCATION-SIG-V1\0'

export function issuePrincipalBindingRevocationV1(input: {
  binding_id: string
  principal_id: string
  verification_method: string
  revoked_at: string
  reason_code: string
  nonce: string
  principal_private_key_hex: string
}): PrincipalBindingRevocationV1 {
  const draft: Omit<PrincipalBindingRevocationV1, 'revocation_id' | 'signature'> = {
    record_type: 'aps.principal-binding-revocation',
    version: '1.0',
    binding_id: input.binding_id,
    principal_id: input.principal_id,
    verification_method: input.verification_method,
    revoked_at: input.revoked_at,
    reason_code: input.reason_code,
    nonce: input.nonce,
  }
  validateRevocationDraft(draft)
  const revocationId = digest(ID_DOMAIN + canonicalizeJCS(draft))
  const withId: Omit<PrincipalBindingRevocationV1, 'signature'> = {
    ...draft,
    revocation_id: revocationId,
  }
  return {
    ...withId,
    signature: sign(SIGNATURE_DOMAIN + canonicalizeJCS(withId), input.principal_private_key_hex),
  }
}

export async function verifyPrincipalBindingRevocationV1(
  candidate: unknown,
  resolveKey: HistoricalKeyResolver,
): Promise<IdentityVerificationResult> {
  let revocation: PrincipalBindingRevocationV1
  try {
    revocation = validateRevocation(candidate)
  } catch {
    return invalid('PRINCIPAL_BINDING_REVOCATION_MALFORMED')
  }
  const idForm = omit(revocation, ['revocation_id', 'signature'])
  if (digest(ID_DOMAIN + canonicalizeJCS(idForm)) !== revocation.revocation_id) {
    return invalid('PRINCIPAL_BINDING_REVOCATION_ID_MISMATCH')
  }
  const resolution = await resolveKey({
    controller: revocation.principal_id,
    verification_method: revocation.verification_method,
    at: revocation.revoked_at,
  })
  if (resolution.state !== 'resolved' || !resolution.public_key_hex) {
    return {
      state: resolution.state === 'unreachable' ? 'indeterminate' : 'invalid',
      code: `PRINCIPAL_BINDING_REVOCATION_KEY_${resolution.state.toUpperCase()}`,
      proof_of_possession: false,
      key_authority: resolution.state === 'unreachable' ? 'unresolved' : 'rejected',
    }
  }
  const signatureForm = omit(revocation, ['signature'])
  if (!verify(
    SIGNATURE_DOMAIN + canonicalizeJCS(signatureForm),
    revocation.signature,
    resolution.public_key_hex,
  )) return invalid('PRINCIPAL_BINDING_REVOCATION_SIGNATURE_INVALID')

  return { state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified' }
}

function validateRevocation(value: unknown): PrincipalBindingRevocationV1 {
  assertPlainRecord(value, 'binding revocation')
  assertExactKeys(value, [
    'record_type', 'version', 'revocation_id', 'binding_id', 'principal_id',
    'verification_method', 'revoked_at', 'reason_code', 'nonce', 'signature',
  ], [], 'binding revocation')
  validateRevocationDraft(value as unknown as Omit<PrincipalBindingRevocationV1, 'revocation_id' | 'signature'>)
  assertHex(String(value.revocation_id), 64, 'revocation_id')
  assertHex(String(value.signature), 128, 'signature')
  return value as unknown as PrincipalBindingRevocationV1
}

function validateRevocationDraft(value: Omit<PrincipalBindingRevocationV1, 'revocation_id' | 'signature'>): void {
  assertIJson(value)
  if (value.record_type !== 'aps.principal-binding-revocation' || value.version !== '1.0') throw new Error('profile')
  assertHex(value.binding_id, 64, 'binding_id')
  if (!value.verification_method.startsWith(`${value.principal_id}#`)) throw new Error('verification_method')
  assertUtcMilliseconds(value.revoked_at, 'revoked_at')
  if (!/^[a-z][a-z0-9_.-]{0,63}$/.test(value.reason_code)) throw new Error('reason_code')
  assertHex(value.nonce, 32, 'nonce')
}

function digest(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function omit(value: object, keys: readonly string[]): Record<string, unknown> {
  const result: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(value)) if (!keys.includes(key)) result[key] = entry
  return result
}

function invalid(code: string): IdentityVerificationResult {
  return { state: 'invalid', code, proof_of_possession: false, key_authority: 'rejected' }
}
