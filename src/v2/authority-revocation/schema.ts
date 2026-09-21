// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { snapshotPlainData } from '../authority-delegation/plain-data.js'
import { isCanonicalTimestamp } from '../authority-delegation/schema.js'
import {
  AUTHORITY_REVOCATION_RECORD_TYPE,
  AUTHORITY_REVOCATION_VERSION,
} from './types.js'
import type {
  AuthorityRevocationFailure,
  AuthorityRevocationFailureCode,
  AuthorityRevocationV1,
} from './types.js'

const CONTENT_ADDRESS = /^sha256:[0-9a-f]{64}$/
const HEX_32 = /^[0-9a-f]{32}$/
const HEX_128 = /^[0-9a-f]{128}$/
const REASON_CODE = /^[a-z][a-z0-9_.-]{0,63}$/

/** Every member a valid record may carry. A member outside this list is SCHEMA_INVALID:
 *  the schema is closed, so an unknown field cannot ride inside a signed preimage
 *  unnoticed. `detail` is the only OPTIONAL one. */
const REQUIRED_KEYS = [
  'record_type',
  'version',
  'revocation_id',
  'delegation_id',
  'revoker',
  'verification_method',
  'revoked_at',
  'reason_code',
  'cascade_transaction_id',
  'nonce',
  'signature',
] as const
const OPTIONAL_KEYS = ['detail'] as const

function failure(
  code: AuthorityRevocationFailureCode,
  message: string,
): AuthorityRevocationFailure {
  return { code, message }
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null
}

/**
 * Closed-schema and canonical-value validation for an in-memory decoded revocation.
 *
 * Snapshots `value` to plain JSON data first (see authority-delegation/plain-data.ts) and
 * judges only that snapshot, so a getter or Proxy trap in the caller's argument is read
 * at most once and cannot answer this function's checks differently from the value a
 * caller goes on to hash.
 *
 * Returns every failure it finds rather than the first, matching
 * validateAuthorityDelegationShape(). The caller decides which one it reports.
 */
export function validateAuthorityRevocationShape(value: unknown): AuthorityRevocationFailure[] {
  const failures: AuthorityRevocationFailure[] = []
  const top = record(snapshotPlainData(value))
  if (!top) return [failure('SCHEMA_INVALID', 'revocation must be a JSON object')]

  if (top.record_type !== AUTHORITY_REVOCATION_RECORD_TYPE) {
    return [failure('UNSUPPORTED_RECORD_TYPE', `record_type must be ${AUTHORITY_REVOCATION_RECORD_TYPE}`)]
  }
  if (top.version !== AUTHORITY_REVOCATION_VERSION) {
    return [failure('UNSUPPORTED_VERSION', `version must be ${AUTHORITY_REVOCATION_VERSION}`)]
  }

  for (const key of REQUIRED_KEYS) {
    if (!Object.prototype.hasOwnProperty.call(top, key)) {
      failures.push(failure('SCHEMA_INVALID', `${key} is required`))
    }
  }
  const allowed = new Set<string>([...REQUIRED_KEYS, ...OPTIONAL_KEYS])
  for (const key of Object.keys(top)) {
    if (!allowed.has(key)) failures.push(failure('SCHEMA_INVALID', `unknown member ${key}`))
  }

  if (typeof top.revocation_id !== 'string' || !CONTENT_ADDRESS.test(top.revocation_id)) {
    failures.push(failure('SCHEMA_INVALID', 'revocation_id must be sha256:<64 lowercase hex>'))
  }
  if (typeof top.delegation_id !== 'string' || !CONTENT_ADDRESS.test(top.delegation_id)) {
    failures.push(failure('SCHEMA_INVALID', 'delegation_id must be sha256:<64 lowercase hex>'))
  }
  if (typeof top.cascade_transaction_id !== 'string' || !CONTENT_ADDRESS.test(top.cascade_transaction_id)) {
    failures.push(failure('SCHEMA_INVALID', 'cascade_transaction_id must be sha256:<64 lowercase hex>'))
  }
  if (typeof top.revoker !== 'string' || top.revoker.length === 0) {
    failures.push(failure('SCHEMA_INVALID', 'revoker must be a non-empty string'))
  }
  if (typeof top.verification_method !== 'string' || top.verification_method.length === 0) {
    failures.push(failure('SCHEMA_INVALID', 'verification_method must be a non-empty string'))
  } else if (typeof top.revoker === 'string' && !top.verification_method.startsWith(`${top.revoker}#`)) {
    failures.push(failure('VERIFICATION_METHOD_MISMATCH', 'verification_method must begin with the revoker and "#"'))
  }
  if (!isCanonicalTimestamp(top.revoked_at)) {
    failures.push(failure('NONCANONICAL_VALUE', 'revoked_at must be a canonical UTC-millisecond timestamp'))
  }
  if (typeof top.reason_code !== 'string' || !REASON_CODE.test(top.reason_code)) {
    failures.push(failure('NONCANONICAL_VALUE', 'reason_code must match ^[a-z][a-z0-9_.-]{0,63}$'))
  }
  if (Object.prototype.hasOwnProperty.call(top, 'detail') && typeof top.detail !== 'string') {
    failures.push(failure('SCHEMA_INVALID', 'detail, when present, must be a string'))
  }
  if (typeof top.nonce !== 'string' || !HEX_32.test(top.nonce)) {
    failures.push(failure('NONCANONICAL_VALUE', 'nonce must be 32 lowercase hex characters'))
  }
  if (typeof top.signature !== 'string' || !HEX_128.test(top.signature)) {
    failures.push(failure('SCHEMA_INVALID', 'signature must be 128 lowercase hex characters'))
  }
  return failures
}

export function isAuthorityRevocationV1(value: unknown): value is AuthorityRevocationV1 {
  return validateAuthorityRevocationShape(value).length === 0
}
