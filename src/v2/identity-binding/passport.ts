// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign, verify } from '../../crypto/keys.js'
import { hexToMultibase, multibaseToHex } from '../../core/did.js'
import {
  defaultVerificationMethod,
  didKeyFromPublicKey,
  selfCertifyingPublicKey,
} from './did-aps.js'
import type {
  HistoricalKeyResolver,
  IdentityVerificationResult,
  PassportV2,
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

const ID_DOMAIN = 'APS-PASSPORT-ID-V2\0'
const SIGNATURE_DOMAIN = 'APS-PASSPORT-SIG-V2\0'

export interface IssuePassportV2Input {
  public_key_hex: string
  private_key_hex: string
  agent_id?: string
  verification_method?: string
  issued_at: string
  expires_at: string
  nonce: string
  display_name?: string
  capabilities?: readonly string[]
}

export function issuePassportV2(input: IssuePassportV2Input): PassportV2 {
  assertHex(input.public_key_hex, 64, 'public_key_hex')
  const agentId = input.agent_id ?? didKeyFromPublicKey(input.public_key_hex)
  const draft: Omit<PassportV2, 'passport_id' | 'signature'> = {
    record_type: 'aps.agent-passport',
    version: '2.0',
    agent_id: agentId,
    verification_method: input.verification_method ?? defaultVerificationMethod(agentId),
    public_key_multibase: hexToMultibase(input.public_key_hex),
    issued_at: input.issued_at,
    expires_at: input.expires_at,
    nonce: input.nonce,
    self_asserted: {
      ...(input.display_name === undefined ? {} : { display_name: input.display_name }),
      capabilities: sortedUnique(input.capabilities ?? [], 'self_asserted.capabilities'),
    },
  }
  validatePassportDraft(draft)
  const passportId = digest(ID_DOMAIN + canonicalizeJCS(draft))
  const withId: Omit<PassportV2, 'signature'> = { ...draft, passport_id: passportId }
  const signature = sign(SIGNATURE_DOMAIN + canonicalizeJCS(withId), input.private_key_hex)
  return { ...withId, signature }
}

export async function verifyPassportV2(
  candidate: unknown,
  options: { now?: string; resolve_key?: HistoricalKeyResolver } = {},
): Promise<IdentityVerificationResult> {
  let passport: PassportV2
  try {
    passport = validatePassport(candidate)
  } catch {
    return invalid('PASSPORT_MALFORMED')
  }

  const idForm = omit(passport, ['passport_id', 'signature'])
  if (digest(ID_DOMAIN + canonicalizeJCS(idForm)) !== passport.passport_id) {
    return invalid('PASSPORT_ID_MISMATCH')
  }
  const publicKey = multibaseToHex(passport.public_key_multibase)
  const signatureForm = omit(passport, ['signature'])
  if (!verify(SIGNATURE_DOMAIN + canonicalizeJCS(signatureForm), passport.signature, publicKey)) {
    return invalid('PASSPORT_SIGNATURE_INVALID')
  }

  const now = options.now ?? new Date().toISOString()
  if (now < passport.issued_at || now >= passport.expires_at) {
    return { ...invalid('PASSPORT_NOT_CURRENT'), proof_of_possession: true }
  }

  const derived = selfCertifyingPublicKey(passport.agent_id)
  if (derived !== null) {
    if (derived !== publicKey) {
      return {
        ...invalid('PASSPORT_KEY_AUTHORITY_REJECTED'),
        proof_of_possession: true,
        key_authority: 'rejected',
      }
    }
    return { state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified' }
  }

  if (!options.resolve_key) {
    return {
      state: 'indeterminate',
      code: 'PASSPORT_KEY_AUTHORITY_UNRESOLVED',
      proof_of_possession: true,
      key_authority: 'unresolved',
    }
  }
  const resolution = await options.resolve_key({
    controller: passport.agent_id,
    verification_method: passport.verification_method,
    at: passport.issued_at,
  })
  if (resolution.state !== 'resolved' || !resolution.public_key_hex) {
    return {
      state: resolution.state === 'unreachable' ? 'indeterminate' : 'invalid',
      code: `PASSPORT_KEY_${resolution.state.toUpperCase()}`,
      proof_of_possession: true,
      key_authority: resolution.state === 'unreachable' ? 'unresolved' : 'rejected',
    }
  }
  if (resolution.public_key_hex !== publicKey) {
    return {
      ...invalid('PASSPORT_KEY_AUTHORITY_REJECTED'),
      proof_of_possession: true,
      key_authority: 'rejected',
    }
  }
  return { state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified' }
}

function validatePassport(value: unknown): PassportV2 {
  assertPlainRecord(value, 'passport')
  assertExactKeys(value, [
    'record_type', 'version', 'passport_id', 'agent_id', 'verification_method',
    'public_key_multibase', 'issued_at', 'expires_at', 'nonce', 'self_asserted', 'signature',
  ], [], 'passport')
  validatePassportDraft(value as unknown as Omit<PassportV2, 'passport_id' | 'signature'>)
  assertHex(String(value.passport_id), 64, 'passport_id')
  assertHex(String(value.signature), 128, 'signature')
  return value as unknown as PassportV2
}

function validatePassportDraft(value: Omit<PassportV2, 'passport_id' | 'signature'>): void {
  assertIJson(value)
  if (value.record_type !== 'aps.agent-passport' || value.version !== '2.0') throw new Error('passport profile')
  if (!/^did:[a-z0-9]+:.+$/.test(value.agent_id)) throw new Error('agent_id')
  if (!value.verification_method.startsWith(`${value.agent_id}#`)) throw new Error('verification_method')
  const key = multibaseToHex(value.public_key_multibase)
  assertHex(key, 64, 'public_key_multibase')
  assertUtcMilliseconds(value.issued_at, 'issued_at')
  assertUtcMilliseconds(value.expires_at, 'expires_at')
  if (value.issued_at >= value.expires_at) throw new Error('passport time window')
  assertHex(value.nonce, 32, 'nonce')
  assertPlainRecord(value.self_asserted, 'self_asserted')
  assertExactKeys(value.self_asserted, ['capabilities'], ['display_name'], 'self_asserted')
  if (!Array.isArray(value.self_asserted.capabilities)) throw new Error('capabilities')
  assertSortedUnique(value.self_asserted.capabilities, 'capabilities')
  if (value.self_asserted.display_name !== undefined && typeof value.self_asserted.display_name !== 'string') {
    throw new Error('display_name')
  }
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
