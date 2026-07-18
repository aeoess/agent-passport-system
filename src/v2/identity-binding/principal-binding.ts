// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign, verify } from '../../crypto/keys.js'
import type {
  HistoricalKeyResolver,
  IdentityVerificationResult,
  PrincipalBindingV1,
  PrincipalClaimLevel,
} from './types.js'
import {
  assertExactKeys,
  assertHex,
  assertIJson,
  assertPlainRecord,
  assertSortedUnique,
  assertUtcMilliseconds,
  sortedUnique,
} from './validation.js'

const ID_DOMAIN = 'APS-PRINCIPAL-BINDING-ID-V1\0'
const SIGNATURE_DOMAIN = 'APS-PRINCIPAL-BINDING-SIG-V1\0'

export interface IssuePrincipalBindingV1Input {
  agent_id: string
  principal_id: string
  verification_method: string
  audiences: readonly string[]
  authority_profiles: readonly string[]
  status_uri: string
  issued_at: string
  expires_at: string
  nonce: string
  principal_private_key_hex: string
}

export function issuePrincipalBindingV1(input: IssuePrincipalBindingV1Input): PrincipalBindingV1 {
  const draft: Omit<PrincipalBindingV1, 'binding_id' | 'signature'> = {
    record_type: 'aps.principal-binding',
    version: '1.0',
    agent_id: input.agent_id,
    principal_id: input.principal_id,
    verification_method: input.verification_method,
    audiences: sortedUnique(input.audiences, 'audiences'),
    authority_profiles: sortedUnique(input.authority_profiles, 'authority_profiles'),
    status_uri: input.status_uri,
    issued_at: input.issued_at,
    expires_at: input.expires_at,
    nonce: input.nonce,
  }
  validateBindingDraft(draft)
  const bindingId = digest(ID_DOMAIN + canonicalizeJCS(draft))
  const withId: Omit<PrincipalBindingV1, 'signature'> = { ...draft, binding_id: bindingId }
  return {
    ...withId,
    signature: sign(SIGNATURE_DOMAIN + canonicalizeJCS(withId), input.principal_private_key_hex),
  }
}

export async function verifyPrincipalBindingV1(
  candidate: unknown,
  options: {
    now?: string
    resolve_key: HistoricalKeyResolver
    principal_is_externally_verified?: (principalId: string, at: string) => boolean | Promise<boolean>
  },
): Promise<IdentityVerificationResult> {
  let binding: PrincipalBindingV1
  try {
    binding = validateBinding(candidate)
  } catch {
    return invalid('PRINCIPAL_BINDING_MALFORMED')
  }
  const idForm = omit(binding, ['binding_id', 'signature'])
  if (digest(ID_DOMAIN + canonicalizeJCS(idForm)) !== binding.binding_id) {
    return invalid('PRINCIPAL_BINDING_ID_MISMATCH')
  }
  const now = options.now ?? new Date().toISOString()
  if (now < binding.issued_at || now >= binding.expires_at) {
    return invalid('PRINCIPAL_BINDING_NOT_CURRENT')
  }
  const resolution = await options.resolve_key({
    controller: binding.principal_id,
    verification_method: binding.verification_method,
    at: binding.issued_at,
  })
  if (resolution.state !== 'resolved' || !resolution.public_key_hex) {
    const indeterminate = resolution.state === 'unreachable'
    return {
      state: indeterminate ? 'indeterminate' : 'invalid',
      code: `PRINCIPAL_BINDING_KEY_${resolution.state.toUpperCase()}`,
      proof_of_possession: false,
      key_authority: indeterminate ? 'unresolved' : 'rejected',
    }
  }
  const signatureForm = omit(binding, ['signature'])
  if (!verify(
    SIGNATURE_DOMAIN + canonicalizeJCS(signatureForm),
    binding.signature,
    resolution.public_key_hex,
  )) {
    return invalid('PRINCIPAL_BINDING_SIGNATURE_INVALID')
  }
  let claimLevel: PrincipalClaimLevel = 'principal_attested'
  if (options.principal_is_externally_verified &&
      await options.principal_is_externally_verified(binding.principal_id, binding.issued_at)) {
    claimLevel = 'externally_verified_principal'
  }
  return {
    state: 'valid',
    code: 'OK',
    proof_of_possession: true,
    key_authority: 'verified',
    principal_claim_level: claimLevel,
  }
}

function validateBinding(value: unknown): PrincipalBindingV1 {
  assertPlainRecord(value, 'principal binding')
  assertExactKeys(value, [
    'record_type', 'version', 'binding_id', 'agent_id', 'principal_id',
    'verification_method', 'audiences', 'authority_profiles', 'status_uri',
    'issued_at', 'expires_at', 'nonce', 'signature',
  ], [], 'principal binding')
  validateBindingDraft(value as unknown as Omit<PrincipalBindingV1, 'binding_id' | 'signature'>)
  assertHex(String(value.binding_id), 64, 'binding_id')
  assertHex(String(value.signature), 128, 'signature')
  return value as unknown as PrincipalBindingV1
}

function validateBindingDraft(value: Omit<PrincipalBindingV1, 'binding_id' | 'signature'>): void {
  assertIJson(value)
  if (value.record_type !== 'aps.principal-binding' || value.version !== '1.0') throw new Error('profile')
  if (!/^did:[a-z0-9]+:.+$/.test(value.agent_id)) throw new Error('agent_id')
  if (!/^did:[a-z0-9]+:.+$/.test(value.principal_id) && !/^https:\/\//.test(value.principal_id)) {
    throw new Error('principal_id')
  }
  if (!value.verification_method.startsWith(`${value.principal_id}#`)) throw new Error('verification_method')
  if (!Array.isArray(value.audiences) || value.audiences.length === 0) throw new Error('audiences')
  if (!Array.isArray(value.authority_profiles) || value.authority_profiles.length === 0) throw new Error('authority_profiles')
  assertSortedUnique(value.audiences, 'audiences')
  assertSortedUnique(value.authority_profiles, 'authority_profiles')
  if (!/^https:\/\//.test(value.status_uri)) throw new Error('status_uri')
  assertUtcMilliseconds(value.issued_at, 'issued_at')
  assertUtcMilliseconds(value.expires_at, 'expires_at')
  if (value.issued_at >= value.expires_at) throw new Error('binding time window')
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
