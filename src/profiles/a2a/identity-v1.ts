// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign, verify } from '../../crypto/keys.js'
import type { HistoricalKeyResolver } from '../../v2/identity-binding/types.js'
import {
  assertExactKeys,
  assertHex,
  assertIJson,
  assertPlainRecord,
  assertUtcMilliseconds,
} from '../../v2/identity-binding/validation.js'

export const APS_A2A_IDENTITY_EXTENSION = 'https://agent-passport.org/a2a/extensions/identity/v1'

export interface A2AApsIdentityParamsV1 {
  agent_id: string
  passport_uri: string
  passport_sha256: string
  principal_binding_uri?: string
  principal_binding_sha256?: string
  issued_at: string
  expires_at: string
}

export interface A2AAgentCardSignature {
  protected: string
  signature: string
  header?: Record<string, unknown>
}

export type A2AAgentCardObject = Record<string, unknown> & {
  capabilities: Record<string, unknown> & { extensions?: unknown[] }
  signatures?: A2AAgentCardSignature[]
}

export interface A2AApsIdentityVerification {
  state: 'valid' | 'invalid' | 'indeterminate' | 'unsupported'
  code: string
  agent_id?: string
  card_signature: 'verified' | 'rejected' | 'unresolved'
  passport: 'resolved' | 'mismatch' | 'unresolved'
  principal_binding: 'resolved' | 'mismatch' | 'unresolved' | 'absent'
}

export function attachApsIdentityExtensionV1(
  card: A2AAgentCardObject,
  params: A2AApsIdentityParamsV1,
  required = false,
): A2AAgentCardObject {
  validateParams(params)
  const existing = Array.isArray(card.capabilities.extensions)
    ? card.capabilities.extensions.filter((entry) =>
      !isExtensionWithUri(entry, APS_A2A_IDENTITY_EXTENSION))
    : []
  const result: A2AAgentCardObject = {
    ...card,
    capabilities: {
      ...card.capabilities,
      extensions: [...existing, {
        uri: APS_A2A_IDENTITY_EXTENSION,
        description: 'APS verifiable agent identity and principal-binding references',
        required,
        params,
      }],
    },
  }
  delete result.signatures
  assertIJson(result)
  return result
}

export function signA2AAgentCardV1(
  card: A2AAgentCardObject,
  privateKeyHex: string,
  kid: string,
): A2AAgentCardObject {
  const unsigned = withoutSignatures(card)
  assertIJson(unsigned)
  const extension = getApsIdentityParamsV1(unsigned)
  if (!kid.startsWith(`${extension.agent_id}#`)) throw new Error('A2A signature kid is not controlled by agent_id')
  const protectedHeader = canonicalizeJCS({ alg: 'EdDSA', kid, typ: 'JOSE' })
  const protectedB64 = base64url(Buffer.from(protectedHeader, 'utf8'))
  const payloadB64 = base64url(Buffer.from(canonicalizeJCS(unsigned), 'utf8'))
  const signatureHex = sign(`${protectedB64}.${payloadB64}`, privateKeyHex)
  const signature: A2AAgentCardSignature = {
    protected: protectedB64,
    signature: base64url(Buffer.from(signatureHex, 'hex')),
  }
  return { ...unsigned, signatures: [signature] }
}

export async function verifyApsA2AAgentCardV1(
  candidate: unknown,
  options: {
    resolve_key: HistoricalKeyResolver
    resolve_artifact?: (uri: string) => Uint8Array | Promise<Uint8Array>
    now?: string
  },
): Promise<A2AApsIdentityVerification> {
  let card: A2AAgentCardObject
  let params: A2AApsIdentityParamsV1
  try {
    assertPlainRecord(candidate, 'Agent Card')
    card = candidate as A2AAgentCardObject
    assertIJson(card)
    params = getApsIdentityParamsV1(card)
    if (!Array.isArray(card.signatures) || card.signatures.length === 0) throw new Error('missing signatures')
  } catch {
    return result('invalid', 'A2A_CARD_MALFORMED', 'rejected')
  }

  const now = options.now ?? new Date().toISOString()
  if (now < params.issued_at || now >= params.expires_at) {
    return result('invalid', 'A2A_IDENTITY_EXTENSION_NOT_CURRENT', 'rejected', params.agent_id)
  }

  const unsigned = withoutSignatures(card)
  const payloadB64 = base64url(Buffer.from(canonicalizeJCS(unsigned), 'utf8'))
  let unresolvedKey = false
  let verifiedSignature = false
  for (const signature of card.signatures ?? []) {
    let header: Record<string, unknown>
    try {
      const raw = Buffer.from(signature.protected, 'base64url').toString('utf8')
      header = JSON.parse(raw) as Record<string, unknown>
      assertExactKeys(header, ['alg', 'kid', 'typ'], [], 'JWS protected header')
      if (header.alg !== 'EdDSA' || header.typ !== 'JOSE' || typeof header.kid !== 'string') continue
      if (!header.kid.startsWith(`${params.agent_id}#`)) continue
    } catch {
      continue
    }
    const resolution = await options.resolve_key({
      controller: params.agent_id,
      verification_method: String(header.kid),
      at: params.issued_at,
    })
    if (resolution.state === 'unreachable') unresolvedKey = true
    if (resolution.state !== 'resolved' || !resolution.public_key_hex) continue
    let signatureHex: string
    try {
      signatureHex = Buffer.from(signature.signature, 'base64url').toString('hex')
    } catch {
      continue
    }
    if (verify(`${signature.protected}.${payloadB64}`, signatureHex, resolution.public_key_hex)) {
      verifiedSignature = true
      break
    }
  }
  if (!verifiedSignature) {
    return result(
      unresolvedKey ? 'indeterminate' : 'invalid',
      unresolvedKey ? 'A2A_SIGNING_KEY_UNREACHABLE' : 'A2A_SIGNATURE_INVALID',
      unresolvedKey ? 'unresolved' : 'rejected',
      params.agent_id,
    )
  }

  if (!options.resolve_artifact) {
    return {
      ...result('indeterminate', 'A2A_IDENTITY_ARTIFACTS_UNRESOLVED', 'verified', params.agent_id),
      passport: 'unresolved',
      principal_binding: params.principal_binding_uri ? 'unresolved' : 'absent',
    }
  }
  const passport = await resolveDigest(options.resolve_artifact, params.passport_uri, params.passport_sha256)
  const principal = params.principal_binding_uri && params.principal_binding_sha256
    ? await resolveDigest(options.resolve_artifact, params.principal_binding_uri, params.principal_binding_sha256)
    : 'absent'
  if (passport === 'mismatch' || principal === 'mismatch') {
    return {
      ...result('invalid', 'A2A_IDENTITY_ARTIFACT_DIGEST_MISMATCH', 'verified', params.agent_id),
      passport,
      principal_binding: principal,
    }
  }
  if (passport === 'unresolved' || principal === 'unresolved') {
    return {
      ...result('indeterminate', 'A2A_IDENTITY_ARTIFACT_UNREACHABLE', 'verified', params.agent_id),
      passport,
      principal_binding: principal,
    }
  }
  return {
    state: 'valid',
    code: 'OK',
    agent_id: params.agent_id,
    card_signature: 'verified',
    passport,
    principal_binding: principal,
  }
}

/** Legacy custom fields do not carry the A2A JWS payload and cannot verify. */
export function assessLegacyAgentPassportExtension(_candidate: unknown): {
  state: 'legacy_unverifiable'
  code: 'A2A_LEGACY_EXTENSION_UNSIGNED_PROJECTION'
} {
  return { state: 'legacy_unverifiable', code: 'A2A_LEGACY_EXTENSION_UNSIGNED_PROJECTION' }
}

export function getApsIdentityParamsV1(card: A2AAgentCardObject): A2AApsIdentityParamsV1 {
  const extensions = card.capabilities?.extensions
  if (!Array.isArray(extensions)) throw new Error('A2A Agent Card has no extensions')
  const matches = extensions.filter((entry) => isExtensionWithUri(entry, APS_A2A_IDENTITY_EXTENSION))
  if (matches.length !== 1) throw new Error('A2A Agent Card must carry exactly one APS identity extension')
  const extension = matches[0] as Record<string, unknown>
  validateParams(extension.params)
  return extension.params as unknown as A2AApsIdentityParamsV1
}

function validateParams(value: unknown): asserts value is A2AApsIdentityParamsV1 {
  assertPlainRecord(value, 'APS A2A identity params')
  assertExactKeys(value, [
    'agent_id', 'passport_uri', 'passport_sha256', 'issued_at', 'expires_at',
  ], ['principal_binding_uri', 'principal_binding_sha256'], 'APS A2A identity params')
  if (typeof value.agent_id !== 'string' || !value.agent_id.startsWith('did:')) throw new Error('agent_id')
  if (typeof value.passport_uri !== 'string' || !/^https:\/\//.test(value.passport_uri)) throw new Error('passport_uri')
  assertHex(String(value.passport_sha256), 64, 'passport_sha256')
  const hasBindingUri = typeof value.principal_binding_uri === 'string'
  const hasBindingHash = typeof value.principal_binding_sha256 === 'string'
  if (hasBindingUri !== hasBindingHash) throw new Error('principal binding URI and digest must appear together')
  if (hasBindingUri && !/^https:\/\//.test(String(value.principal_binding_uri))) throw new Error('principal_binding_uri')
  if (hasBindingHash) assertHex(String(value.principal_binding_sha256), 64, 'principal_binding_sha256')
  assertUtcMilliseconds(String(value.issued_at), 'issued_at')
  assertUtcMilliseconds(String(value.expires_at), 'expires_at')
  if (String(value.issued_at) >= String(value.expires_at)) throw new Error('A2A extension time window')
}

function withoutSignatures(card: A2AAgentCardObject): A2AAgentCardObject {
  const { signatures: _signatures, ...unsigned } = card
  return structuredClone(unsigned) as A2AAgentCardObject
}

function isExtensionWithUri(value: unknown, uri: string): boolean {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    (value as Record<string, unknown>).uri === uri
}

async function resolveDigest(
  resolve: (uri: string) => Uint8Array | Promise<Uint8Array>,
  uri: string,
  expected: string,
): Promise<'resolved' | 'mismatch' | 'unresolved'> {
  try {
    const bytes = await resolve(uri)
    const actual = createHash('sha256').update(bytes).digest('hex')
    return actual === expected ? 'resolved' : 'mismatch'
  } catch {
    return 'unresolved'
  }
}

function base64url(value: Uint8Array): string {
  return Buffer.from(value).toString('base64url')
}

function result(
  state: A2AApsIdentityVerification['state'],
  code: string,
  signature: A2AApsIdentityVerification['card_signature'],
  agentId?: string,
): A2AApsIdentityVerification {
  return {
    state,
    code,
    ...(agentId === undefined ? {} : { agent_id: agentId }),
    card_signature: signature,
    passport: 'unresolved',
    principal_binding: 'unresolved',
  }
}
