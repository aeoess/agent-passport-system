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
// RFC 3339 exact UTC-millisecond form. Group 1 = year, 2 = month, 3 = day,
// 4 = hour, 5 = minute, 6 = second. Second 60 is valid only at 23:59 on the
// last day of its month in the proleptic Gregorian calendar (RFC 3339
// section 5.7; Appendix D writes the leap second as "YYYY-MM-DDT23:59:60Z"),
// checked below; the pattern alone only bounds hour, minute and second to
// their lexical ranges.
const CANONICAL_TIMESTAMP =
  /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)\.[0-9]{3}Z$/
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

/** Proleptic Gregorian leap year, so year 0000 is a leap year. */
function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0
}

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

/**
 * RFC 7493 section 2.1 I-JSON string check: false for any unpaired UTF-16
 * surrogate (including a trailing lone high surrogate) and for any
 * noncharacter code point (U+FDD0..U+FDEF, or any code point whose low 16
 * bits are FFFE or FFFF). A valid surrogate pair is decoded to its code
 * point before the noncharacter test.
 */
function isIJSONString(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i)
    let codePoint = unit
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i)
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false
      codePoint = (unit - 0xd800) * 0x400 + (next - 0xdc00) + 0x10000
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false
    }
    if (codePoint >= 0xfdd0 && codePoint <= 0xfdef) return false
    if ((codePoint & 0xffff) >= 0xfffe) return false
  }
  return true
}

/**
 * Record-wide I-JSON check over an already-decoded value: every object member
 * name and every string value, at any depth, must pass isIJSONString().
 * Iterative with an explicit stack (no recursion, so pathological nesting
 * depth cannot overflow the call stack) and tracks visited containers by
 * reference so a cyclic in-memory value terminates instead of looping
 * forever. Never throws.
 */
function recordStringsAreIJSON(root: Record<string, unknown>): boolean {
  const visited = new Set<unknown>()
  const stack: unknown[] = [root]
  while (stack.length > 0) {
    const current = stack.pop()
    if (current === null || typeof current !== 'object') continue
    if (visited.has(current)) continue
    visited.add(current)
    if (Array.isArray(current)) {
      for (const item of current) {
        if (typeof item === 'string') {
          if (!isIJSONString(item)) return false
        } else if (item !== null && typeof item === 'object') {
          stack.push(item)
        }
      }
    } else {
      for (const key of Object.keys(current as Record<string, unknown>)) {
        if (!isIJSONString(key)) return false
        const member = (current as Record<string, unknown>)[key]
        if (typeof member === 'string') {
          if (!isIJSONString(member)) return false
        } else if (member !== null && typeof member === 'object') {
          stack.push(member)
        }
      }
    }
  }
  return true
}

export function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string') return false
  const match = CANONICAL_TIMESTAMP.exec(value)
  if (!match) return false
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const hour = Number(match[4])
  const minute = Number(match[5])
  const second = Number(match[6])
  const maxDay = month === 2 && isLeapYear(year) ? 29 : DAYS_IN_MONTH[month - 1]
  if (day > maxDay) return false
  if (second === 60 && !(hour === 23 && minute === 59 && day === maxDay)) return false
  return true
}

/**
 * String-order comparison of two canonical timestamps.
 *
 * RFC 3339 section 5.1: timestamps in the same format (all UTC "Z", same
 * number of fractional digits) sort as strings into time order, so this
 * compares the strings directly rather than going through Date.parse (which
 * returns NaN for a leap-second ":60" value). Defined only for values that
 * have already passed isCanonicalTimestamp.
 */
export function compareCanonicalTimestamps(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
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

  if (!recordStringsAreIJSON(top)) {
    failures.push(failure('SCHEMA_INVALID', 'record strings must be I-JSON: no unpaired surrogates or noncharacters'))
  }

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
    if (typeof item !== 'string' || item.length === 0 || Buffer.byteLength(item, 'utf8') > 1024) {
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
  if (!scope || typeof scope.profile !== 'string') {
    failures.push(failure('SCHEMA_INVALID', 'scope must contain profile and grants'))
  } else if (scope.profile !== SCOPE_PROFILE_V1) {
    failures.push(failure('UNSUPPORTED_PROFILE', 'unsupported scope profile'))
  } else if (!exactKeys(scope, ['profile', 'grants']) || !Array.isArray(scope.grants) ||
      !scope.grants.every(item => typeof item === 'string')) {
    failures.push(failure('SCHEMA_INVALID', 'scope must contain profile and grants'))
  } else if (!grantsAreCanonical(scope.grants as string[])) {
    failures.push(failure('NONCANONICAL_VALUE', 'scope grants must be valid, sorted, unique, and irredundant'))
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
  } else if (time.not_before >= time.not_after) {
    failures.push(failure('SCHEMA_INVALID', 'time window must be non-empty'))
  } else if (isCanonicalTimestamp(top.issued_at) && time.not_before < top.issued_at) {
    failures.push(failure('SCHEMA_INVALID', 'time.not_before cannot predate issued_at'))
  }

  const reputation = record(authority.reputation)
  if (!reputation || typeof reputation.profile !== 'string') {
    failures.push(failure('SCHEMA_INVALID', 'reputation ceiling must be an integer from 0 through 100'))
  } else if (reputation.profile !== REPUTATION_PROFILE_V1) {
    failures.push(failure('UNSUPPORTED_PROFILE', 'unsupported reputation profile'))
  } else if (!exactKeys(reputation, ['profile', 'ceiling']) ||
      !Number.isInteger(reputation.ceiling) || (reputation.ceiling as number) < 0 ||
      (reputation.ceiling as number) > 100) {
    failures.push(failure('SCHEMA_INVALID', 'reputation ceiling must be an integer from 0 through 100'))
  }

  const values = record(authority.values)
  if (!values || typeof values.profile !== 'string') {
    failures.push(failure('SCHEMA_INVALID', 'values.required must contain valid identifiers'))
  } else if (values.profile !== VALUES_PROFILE_V1) {
    failures.push(failure('UNSUPPORTED_PROFILE', 'unsupported values profile'))
  } else if (!exactKeys(values, ['profile', 'required']) || !Array.isArray(values.required) ||
      !values.required.every(item => typeof item === 'string' && IDENTIFIER.test(item))) {
    failures.push(failure('SCHEMA_INVALID', 'values.required must contain valid identifiers'))
  } else {
    const required = values.required as string[]
    if (required.some((item, i) => i > 0 && required[i - 1] >= item)) {
      failures.push(failure('NONCANONICAL_VALUE', 'values.required must be sorted and unique'))
    }
  }

  const reversibility = record(authority.reversibility)
  if (!reversibility || typeof reversibility.profile !== 'string') {
    failures.push(failure('SCHEMA_INVALID', 'reversibility facet is malformed'))
  } else if (reversibility.profile !== REVERSIBILITY_PROFILE_V1) {
    failures.push(failure('UNSUPPORTED_PROFILE', 'unsupported reversibility profile'))
  } else if (!exactKeys(reversibility, ['profile', 'ceiling']) ||
      typeof reversibility.ceiling !== 'string' ||
      !['tentative', 'compensable', 'irreversible'].includes(reversibility.ceiling)) {
    failures.push(failure('SCHEMA_INVALID', 'reversibility facet is malformed'))
  }

  return failures
}

export function isAuthorityDelegationV1(value: unknown): value is AuthorityDelegationV1 {
  return validateAuthorityDelegationShape(value).length === 0
}
