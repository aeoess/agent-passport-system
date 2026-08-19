// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { canonicalizeJCS, canonicalizeJCSForWrite } from '../../core/canonical-jcs.js'
import { sign, verify } from '../../crypto/keys.js'
import type { HistoricalKeyResolver } from '../../v2/identity-binding/types.js'
import {
  assertExactKeys,
  assertHex,
  assertIJson,
  assertPlainRecord,
  assertSortedUnique,
  assertUtcMilliseconds,
  sortedUnique,
} from '../../v2/identity-binding/validation.js'
import type { IdJagClaims } from './types.js'
import { IDJAG_DRAFT } from './types.js'

const GRANT_DOMAIN = 'APS-IDJAG-GRANT-V1\0'
const ACTOR_BINDING_DOMAIN = 'APS-IDJAG-ACTOR-BINDING-V1\0'
const DECISION_DOMAIN = 'APS-IDJAG-GRANT-DECISION-V1\0'
const IMPORT_SIGNATURE_DOMAIN = 'APS-IDJAG-IMPORT-SIG-V1\0'

export type IdJagActorBindingV1 =
  | {
      method: 'cnf.jkt'
      agent_id: string
      verification_method: string
      jwk_thumbprint: string
    }
  | {
      method: 'dual_signature'
      agent_id: string
      verification_method: string
      signature: string
    }

export interface IdJagImportV1 {
  profile: 'aps-id-jag-import-v1'
  draft: string
  grant_ref: string
  grant_decision_ref: string
  delegation_chain_root: string
  issuer: string
  subject: string
  client_id: string
  audience: string[]
  agent_id: string
  actor_binding: IdJagActorBindingV1
  verified_by: string
  verification_method: string
  grant_key_id: string
  verified_at: string
  issued_at: string
  signature: string
}

export interface VerifiedCompactIdJagGrantV1 {
  compact_jws: string
  claims: IdJagClaims & { cnf?: { jkt?: string } }
  verification: {
    status: 'verified'
    verified_by: string
    verification_method: string
    grant_key_id: string
    verified_at: string
  }
}

export interface IdJagImportVerificationV1 {
  state: 'valid' | 'invalid' | 'indeterminate'
  code: string
  grant_bytes: 'matched' | 'mismatch'
  importer_signature: 'verified' | 'rejected' | 'unresolved'
  actor_binding: 'verified' | 'rejected' | 'unresolved'
}

export function computeIdJagGrantRefV1(compactJws: string): string {
  validateCompactJws(compactJws)
  return digest(GRANT_DOMAIN + compactJws)
}

export function createIdJagActorBindingSignatureV1(
  grantRef: string,
  agentId: string,
  verificationMethod: string,
  agentPrivateKeyHex: string,
): string {
  assertHex(grantRef, 64, 'grant_ref')
  const body = { agent_id: agentId, grant_ref: grantRef, verification_method: verificationMethod }
  return sign(ACTOR_BINDING_DOMAIN + canonicalizeJCSForWrite(body), agentPrivateKeyHex)
}

export async function createIdJagImportV1(input: {
  grant: VerifiedCompactIdJagGrantV1
  delegation_chain_root: string
  agent_binding: IdJagActorBindingV1
  importer_private_key_hex: string
  issued_at: string
  resolve_agent_key?: HistoricalKeyResolver
  resolve_agent_jwk_thumbprint?: (
    agentId: string,
    verificationMethod: string,
    at: string,
  ) => string | undefined | Promise<string | undefined>
}): Promise<IdJagImportV1> {
  validateVerifiedGrant(input.grant)
  assertHex(input.delegation_chain_root, 64, 'delegation_chain_root')
  assertUtcMilliseconds(input.issued_at, 'issued_at')
  const grantRef = computeIdJagGrantRefV1(input.grant.compact_jws)
  await verifyActorBindingOrThrow(
    input.grant,
    grantRef,
    input.agent_binding,
    input.resolve_agent_key,
    input.resolve_agent_jwk_thumbprint,
  )
  const audiences = normalizeAudience(input.grant.claims.aud, input.grant.claims.resource)
  const decisionInput = grantDecisionInput(
    grantRef,
    input.grant,
    input.agent_binding,
    input.delegation_chain_root,
    audiences,
  )
  const grantDecisionRef = digest(DECISION_DOMAIN + canonicalizeJCSForWrite(decisionInput))
  const unsigned: Omit<IdJagImportV1, 'signature'> = {
    profile: 'aps-id-jag-import-v1',
    draft: IDJAG_DRAFT,
    grant_ref: grantRef,
    grant_decision_ref: grantDecisionRef,
    delegation_chain_root: input.delegation_chain_root,
    issuer: input.grant.claims.iss,
    subject: input.grant.claims.sub,
    client_id: input.grant.claims.client_id,
    audience: audiences,
    agent_id: input.agent_binding.agent_id,
    actor_binding: input.agent_binding,
    verified_by: input.grant.verification.verified_by,
    verification_method: input.grant.verification.verification_method,
    grant_key_id: input.grant.verification.grant_key_id,
    verified_at: input.grant.verification.verified_at,
    issued_at: input.issued_at,
  }
  validateImportUnsigned(unsigned)
  return {
    ...unsigned,
    signature: sign(IMPORT_SIGNATURE_DOMAIN + canonicalizeJCSForWrite(unsigned), input.importer_private_key_hex),
  }
}

export async function verifyIdJagImportV1(
  candidate: unknown,
  source: { compact_jws: string; claims: VerifiedCompactIdJagGrantV1['claims'] },
  options: {
    resolve_importer_key: HistoricalKeyResolver
    resolve_agent_key?: HistoricalKeyResolver
    resolve_agent_jwk_thumbprint?: (
      agentId: string,
      verificationMethod: string,
      at: string,
    ) => string | undefined | Promise<string | undefined>
  },
): Promise<IdJagImportVerificationV1> {
  let record: IdJagImportV1
  try {
    record = validateImport(candidate)
    validateClaimsMatchCompactJws(source.compact_jws, source.claims)
  } catch {
    return outcome('invalid', 'IDJAG_IMPORT_MALFORMED', 'mismatch', 'rejected', 'rejected')
  }
  const grantRef = computeIdJagGrantRefV1(source.compact_jws)
  if (grantRef !== record.grant_ref || !claimsMatchRecord(source.claims, record)) {
    return outcome('invalid', 'IDJAG_GRANT_BYTES_MISMATCH', 'mismatch', 'rejected', 'rejected')
  }
  const syntheticGrant: VerifiedCompactIdJagGrantV1 = {
    compact_jws: source.compact_jws,
    claims: source.claims,
    verification: {
      status: 'verified',
      verified_by: record.verified_by,
      verification_method: record.verification_method,
      grant_key_id: record.grant_key_id,
      verified_at: record.verified_at,
    },
  }
  const decisionRef = digest(DECISION_DOMAIN + canonicalizeJCS(grantDecisionInput(
    grantRef,
    syntheticGrant,
    record.actor_binding,
    record.delegation_chain_root,
    record.audience,
  )))
  if (decisionRef !== record.grant_decision_ref) {
    return outcome('invalid', 'IDJAG_GRANT_DECISION_MISMATCH', 'matched', 'rejected', 'rejected')
  }
  const importerResolution = await options.resolve_importer_key({
    controller: record.verified_by,
    verification_method: record.verification_method,
    at: record.issued_at,
  })
  if (importerResolution.state !== 'resolved' || !importerResolution.public_key_hex) {
    const unresolved = importerResolution.state === 'unreachable'
    return outcome(
      unresolved ? 'indeterminate' : 'invalid',
      `IDJAG_IMPORTER_KEY_${importerResolution.state.toUpperCase()}`,
      'matched', unresolved ? 'unresolved' : 'rejected', 'unresolved',
    )
  }
  const unsigned = omit(record, ['signature'])
  if (!verify(
    IMPORT_SIGNATURE_DOMAIN + canonicalizeJCS(unsigned),
    record.signature,
    importerResolution.public_key_hex,
  )) return outcome('invalid', 'IDJAG_IMPORTER_SIGNATURE_INVALID', 'matched', 'rejected', 'unresolved')

  try {
    await verifyActorBindingOrThrow(
      syntheticGrant,
      grantRef,
      record.actor_binding,
      options.resolve_agent_key,
      options.resolve_agent_jwk_thumbprint,
    )
  } catch (error) {
    const unresolved = error instanceof Error && error.message.includes('unresolved')
    return outcome(
      unresolved ? 'indeterminate' : 'invalid',
      unresolved ? 'IDJAG_ACTOR_BINDING_UNRESOLVED' : 'IDJAG_ACTOR_BINDING_INVALID',
      'matched', 'verified', unresolved ? 'unresolved' : 'rejected',
    )
  }
  return outcome('valid', 'OK', 'matched', 'verified', 'verified')
}

function validateVerifiedGrant(grant: VerifiedCompactIdJagGrantV1): void {
  validateClaimsMatchCompactJws(grant.compact_jws, grant.claims)
  if (grant.verification.status !== 'verified') throw new Error('grant not verified')
  if (!grant.verification.verified_by || !grant.verification.verification_method || !grant.verification.grant_key_id) {
    throw new Error('grant verification metadata incomplete')
  }
  if (!grant.verification.verification_method.startsWith(`${grant.verification.verified_by}#`)) {
    throw new Error('grant verifier key/controller mismatch')
  }
  assertUtcMilliseconds(grant.verification.verified_at, 'verified_at')
}

function validateClaimsMatchCompactJws(compactJws: string, claims: IdJagClaims): void {
  validateCompactJws(compactJws)
  assertIJson(claims)
  const payload = JSON.parse(Buffer.from(compactJws.split('.')[1], 'base64url').toString('utf8')) as unknown
  assertIJson(payload)
  if (canonicalizeJCS(payload) !== canonicalizeJCS(claims)) throw new Error('decoded claims do not match compact JWS')
}

async function verifyActorBindingOrThrow(
  grant: VerifiedCompactIdJagGrantV1,
  grantRef: string,
  binding: IdJagActorBindingV1,
  resolveAgentKey?: HistoricalKeyResolver,
  resolveThumbprint?: (agentId: string, verificationMethod: string, at: string) => string | undefined | Promise<string | undefined>,
): Promise<void> {
  validateActorBinding(binding)
  if (binding.method === 'cnf.jkt') {
    if (grant.claims.cnf?.jkt !== binding.jwk_thumbprint) throw new Error('cnf.jkt mismatch')
    if (!resolveThumbprint) throw new Error('actor binding unresolved')
    const resolved = await resolveThumbprint(binding.agent_id, binding.verification_method, grant.verification.verified_at)
    if (!resolved) throw new Error('actor binding unresolved')
    if (resolved !== binding.jwk_thumbprint) throw new Error('agent key thumbprint mismatch')
    return
  }
  if (!resolveAgentKey) throw new Error('actor binding unresolved')
  const resolution = await resolveAgentKey({
    controller: binding.agent_id,
    verification_method: binding.verification_method,
    at: grant.verification.verified_at,
  })
  if (resolution.state !== 'resolved' || !resolution.public_key_hex) throw new Error('actor binding unresolved')
  const body = {
    agent_id: binding.agent_id,
    grant_ref: grantRef,
    verification_method: binding.verification_method,
  }
  if (!verify(
    ACTOR_BINDING_DOMAIN + canonicalizeJCS(body),
    binding.signature,
    resolution.public_key_hex,
  )) throw new Error('actor signature invalid')
}

function validateActorBinding(binding: IdJagActorBindingV1): void {
  assertPlainRecord(binding, 'actor binding')
  if (!/^did:[a-z0-9]+:.+$/.test(binding.agent_id)) throw new Error('actor agent_id')
  if (!binding.verification_method.startsWith(`${binding.agent_id}#`)) throw new Error('actor verification_method')
  if (binding.method === 'cnf.jkt') {
    assertExactKeys(binding, ['method', 'agent_id', 'verification_method', 'jwk_thumbprint'], [], 'actor binding')
    if (!/^[A-Za-z0-9_-]{43}$/.test(binding.jwk_thumbprint)) throw new Error('actor jwk thumbprint')
  } else if (binding.method === 'dual_signature') {
    assertExactKeys(binding, ['method', 'agent_id', 'verification_method', 'signature'], [], 'actor binding')
    assertHex(binding.signature, 128, 'actor signature')
  } else throw new Error('actor binding method')
}

function grantDecisionInput(
  grantRef: string,
  grant: VerifiedCompactIdJagGrantV1,
  binding: IdJagActorBindingV1,
  chainRoot: string,
  audience: string[],
): Record<string, unknown> {
  return {
    profile: 'aps-id-jag-grant-decision-v1',
    grant_ref: grantRef,
    delegation_chain_root: chainRoot,
    audience,
    actor_binding: binding,
    verified_by: grant.verification.verified_by,
    verification_method: grant.verification.verification_method,
    grant_key_id: grant.verification.grant_key_id,
    verified_at: grant.verification.verified_at,
  }
}

function validateImport(value: unknown): IdJagImportV1 {
  assertPlainRecord(value, 'ID-JAG import')
  assertExactKeys(value, [
    'profile', 'draft', 'grant_ref', 'grant_decision_ref', 'delegation_chain_root',
    'issuer', 'subject', 'client_id', 'audience', 'agent_id', 'actor_binding',
    'verified_by', 'verification_method', 'grant_key_id', 'verified_at', 'issued_at', 'signature',
  ], [], 'ID-JAG import')
  validateImportUnsigned(omit(value, ['signature']) as unknown as Omit<IdJagImportV1, 'signature'>)
  assertHex(String(value.signature), 128, 'signature')
  return value as unknown as IdJagImportV1
}

function validateImportUnsigned(value: Omit<IdJagImportV1, 'signature'>): void {
  assertIJson(value)
  if (value.profile !== 'aps-id-jag-import-v1' || value.draft !== IDJAG_DRAFT) throw new Error('ID-JAG profile')
  assertHex(value.grant_ref, 64, 'grant_ref')
  assertHex(value.grant_decision_ref, 64, 'grant_decision_ref')
  assertHex(value.delegation_chain_root, 64, 'delegation_chain_root')
  if (!value.issuer || !value.subject || !value.client_id || !value.grant_key_id) throw new Error('ID-JAG identifiers')
  if (!Array.isArray(value.audience) || value.audience.length === 0) throw new Error('audience')
  assertSortedUnique(value.audience, 'audience')
  validateActorBinding(value.actor_binding)
  if (value.agent_id !== value.actor_binding.agent_id) throw new Error('agent_id mismatch')
  if (!value.verification_method.startsWith(`${value.verified_by}#`)) throw new Error('importer verification method')
  assertUtcMilliseconds(value.verified_at, 'verified_at')
  assertUtcMilliseconds(value.issued_at, 'issued_at')
}

function normalizeAudience(aud: string, resource?: string): string[] {
  return sortedUnique([aud, ...(resource === undefined ? [] : [resource])], 'audience')
}

function claimsMatchRecord(claims: IdJagClaims, record: IdJagImportV1): boolean {
  return claims.iss === record.issuer && claims.sub === record.subject &&
    claims.client_id === record.client_id &&
    canonicalizeJCS(normalizeAudience(claims.aud, claims.resource)) === canonicalizeJCS(record.audience)
}

function validateCompactJws(value: string): void {
  if (typeof value !== 'string' || value.length > 131072 ||
      !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('invalid compact JWS')
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

function outcome(
  state: IdJagImportVerificationV1['state'],
  code: string,
  grant: IdJagImportVerificationV1['grant_bytes'],
  importer: IdJagImportVerificationV1['importer_signature'],
  actor: IdJagImportVerificationV1['actor_binding'],
): IdJagImportVerificationV1 {
  return { state, code, grant_bytes: grant, importer_signature: importer, actor_binding: actor }
}
