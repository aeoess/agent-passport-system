// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { grantsAreCanonical } from './scope.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
} from './types.js'
import type { AuthorityDelegationV1, AuthorityFailure } from './types.js'

const ID = /^sha256:[0-9a-f]{64}$/
const HEX_32 = /^[0-9a-f]{32}$/
const HEX_128 = /^[0-9a-f]{128}$/
const DECIMAL = /^(0|[1-9][0-9]*)$/
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/
const MAX_QUANTITY = 9223372036854775807n
const MILLIS_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  return actual.length === wanted.length && actual.every((key, i) => key === wanted[i])
}

function wellFormedUnicode(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i)
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false
    }
  }
  return true
}

export function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !MILLIS_UTC.test(value) || value.startsWith('0000-')) return false
  const parsed = new Date(value)
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value
}

export function isCanonicalQuantity(value: unknown): value is string {
  if (typeof value !== 'string' || !DECIMAL.test(value)) return false
  try { return BigInt(value) <= MAX_QUANTITY } catch { return false }
}

function failure(code: AuthorityFailure['code'], message: string): AuthorityFailure {
  return { code, message }
}

/** Closed-schema and canonical-value validation for an in-memory decoded record. */
export function validateAuthorityDelegationShape(value: unknown): AuthorityFailure[] {
  const failures: AuthorityFailure[] = []
  const top = record(value)
  if (!top || !exactKeys(top, [
    'record_type', 'version', 'delegation_id', 'parent_delegation_id', 'issuer',
    'subject', 'verification_method', 'issued_at', 'nonce', 'authority', 'signature',
  ])) return [failure('SCHEMA_INVALID', 'delegation must be an exact closed v1 object')]

  if (top.record_type !== AUTHORITY_DELEGATION_RECORD_TYPE || top.version !== AUTHORITY_DELEGATION_VERSION) {
    failures.push(failure('UNSUPPORTED_VERSION', 'unsupported authority-delegation record_type or version'))
  }
  if (typeof top.delegation_id !== 'string' || !ID.test(top.delegation_id)) {
    failures.push(failure('SCHEMA_INVALID', 'delegation_id must be sha256:<64 lowercase hex>'))
  }
  if (top.parent_delegation_id !== null &&
      (typeof top.parent_delegation_id !== 'string' || !ID.test(top.parent_delegation_id))) {
    failures.push(failure('SCHEMA_INVALID', 'parent_delegation_id must be null or a delegation digest'))
  }
  for (const key of ['issuer', 'subject', 'verification_method'] as const) {
    const item = top[key]
    if (typeof item !== 'string' || item.length === 0 || Buffer.byteLength(item, 'utf8') > 1024 || !wellFormedUnicode(item)) {
      failures.push(failure('SCHEMA_INVALID', `${key} must be a non-empty well-formed Unicode string`))
    }
  }
  if (!isCanonicalTimestamp(top.issued_at)) failures.push(failure('NONCANONICAL_VALUE', 'issued_at must be canonical UTC milliseconds'))
  if (typeof top.nonce !== 'string' || !HEX_32.test(top.nonce)) failures.push(failure('NONCANONICAL_VALUE', 'nonce must be 32 lowercase hex characters'))
  if (typeof top.signature !== 'string' || !HEX_128.test(top.signature)) failures.push(failure('SCHEMA_INVALID', 'signature must be 128 lowercase hex characters'))

  const authority = record(top.authority)
  if (!authority || !exactKeys(authority, ['scope', 'spend', 'depth', 'time', 'reputation', 'values', 'reversibility'])) {
    failures.push(failure('SCHEMA_INVALID', 'authority must carry exactly all seven facets'))
    return failures
  }

  const scope = record(authority.scope)
  if (!scope || !exactKeys(scope, ['profile', 'grants']) || typeof scope.profile !== 'string' ||
      !IDENTIFIER.test(scope.profile) || !Array.isArray(scope.grants) ||
      !scope.grants.every(item => typeof item === 'string')) {
    failures.push(failure('SCHEMA_INVALID', 'scope must contain profile and grants'))
  } else {
    if (scope.profile !== SCOPE_PROFILE_V1) failures.push(failure('UNSUPPORTED_PROFILE', 'unsupported scope profile'))
    if (!grantsAreCanonical(scope.grants as string[])) failures.push(failure('NONCANONICAL_VALUE', 'scope grants must be valid, sorted, unique, and irredundant'))
  }

  const spend = record(authority.spend)
  if (!spend || typeof spend.mode !== 'string') {
    failures.push(failure('SCHEMA_INVALID', 'spend must be a tagged object'))
  } else if (spend.mode === 'unbounded') {
    if (!exactKeys(spend, ['mode'])) failures.push(failure('SCHEMA_INVALID', 'unbounded spend has no other fields'))
  } else if (spend.mode === 'bounded') {
    if (!exactKeys(spend, ['mode', 'unit', 'per_action', 'cumulative']) ||
        typeof spend.unit !== 'string' || !IDENTIFIER.test(spend.unit) ||
        !isCanonicalQuantity(spend.per_action) || !isCanonicalQuantity(spend.cumulative)) {
      failures.push(failure('NONCANONICAL_VALUE', 'bounded spend fields are malformed'))
    } else if (BigInt(spend.per_action) > BigInt(spend.cumulative)) {
      failures.push(failure('SCHEMA_INVALID', 'spend per_action cannot exceed cumulative'))
    }
  } else failures.push(failure('SCHEMA_INVALID', 'unknown spend mode'))

  const depth = record(authority.depth)
  if (!depth || !exactKeys(depth, ['remaining']) || !Number.isInteger(depth.remaining) ||
      (depth.remaining as number) < 0 || (depth.remaining as number) > 255) {
    failures.push(failure('SCHEMA_INVALID', 'depth.remaining must be an integer from 0 through 255'))
  }

  const time = record(authority.time)
  if (!time || !exactKeys(time, ['not_before', 'not_after']) ||
      !isCanonicalTimestamp(time.not_before) || !isCanonicalTimestamp(time.not_after)) {
    failures.push(failure('NONCANONICAL_VALUE', 'time bounds must be canonical UTC milliseconds'))
  } else if (Date.parse(time.not_before) >= Date.parse(time.not_after)) {
    failures.push(failure('SCHEMA_INVALID', 'time window must be non-empty'))
  } else if (isCanonicalTimestamp(top.issued_at) && Date.parse(time.not_before) < Date.parse(top.issued_at)) {
    failures.push(failure('SCHEMA_INVALID', 'time.not_before cannot predate issued_at'))
  }

  const reputation = record(authority.reputation)
  if (!reputation || !exactKeys(reputation, ['profile', 'ceiling']) ||
      typeof reputation.profile !== 'string' || !IDENTIFIER.test(reputation.profile) ||
      !Number.isInteger(reputation.ceiling) || (reputation.ceiling as number) < 0 ||
      (reputation.ceiling as number) > 100) {
    failures.push(failure('SCHEMA_INVALID', 'reputation ceiling must be an integer from 0 through 100'))
  } else if (reputation.profile !== REPUTATION_PROFILE_V1) {
    failures.push(failure('UNSUPPORTED_PROFILE', 'unsupported reputation profile'))
  }

  const values = record(authority.values)
  if (!values || !exactKeys(values, ['profile', 'required']) || typeof values.profile !== 'string' ||
      !IDENTIFIER.test(values.profile) || !Array.isArray(values.required) ||
      !values.required.every(item => typeof item === 'string' && IDENTIFIER.test(item))) {
    failures.push(failure('SCHEMA_INVALID', 'values.required must contain valid identifiers'))
  } else {
    if (values.profile !== VALUES_PROFILE_V1) failures.push(failure('UNSUPPORTED_PROFILE', 'unsupported values profile'))
    const required = values.required as string[]
    if (required.some((item, i) => i > 0 && required[i - 1] >= item)) {
      failures.push(failure('NONCANONICAL_VALUE', 'values.required must be sorted and unique'))
    }
  }

  const reversibility = record(authority.reversibility)
  if (!reversibility || !exactKeys(reversibility, ['profile', 'ceiling']) ||
      typeof reversibility.profile !== 'string' || !IDENTIFIER.test(reversibility.profile) ||
      !['tentative', 'compensable', 'irreversible'].includes(String(reversibility.ceiling))) {
    failures.push(failure('SCHEMA_INVALID', 'reversibility facet is malformed'))
  } else if (reversibility.profile !== REVERSIBILITY_PROFILE_V1) {
    failures.push(failure('UNSUPPORTED_PROFILE', 'unsupported reversibility profile'))
  }

  return failures
}

export function isAuthorityDelegationV1(value: unknown): value is AuthorityDelegationV1 {
  return validateAuthorityDelegationShape(value).length === 0
}
