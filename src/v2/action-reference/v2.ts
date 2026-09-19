// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { parseStrictIJson } from '../receipt-core/jcs.js'
import {
  assertExactKeys,
  assertHex,
  assertIJson,
  assertPlainRecord,
  assertSortedUnique,
  sortedUnique,
} from '../identity-binding/validation.js'

const DOMAIN = 'APS-ACTION-REF-V2\0'

const ACTION_REF_ISSUED_AT =
  /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:([0-5][0-9]|60)\.[0-9]{3}Z$/

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0
}

/** issued_at check local to the action reference surface.
 *
 *  draft-pidlisnyi-aps-03 section 4.1 names RFC 3339 for issued_at, and RFC
 *  3339's grammar admits time-second 60 for a leap second. A validator has
 *  no leap-second table to consult, so second 60 is accepted lexically at
 *  any hour and minute the grammar allows. The shared assertUtcMilliseconds
 *  helper (identity-binding/validation.ts) rejects second 60 and also
 *  serves passport and principal-binding validation, so this check stays
 *  local here instead of changing that helper and the surfaces it serves.
 *
 *  Calendar validity is checked with integer arithmetic, never Date, since
 *  Date cannot represent a leap second.
 */
function assertActionRefIssuedAt(value: string): void {
  const match = ACTION_REF_ISSUED_AT.exec(value)
  if (!match) throw new Error('issued_at: expected canonical UTC milliseconds')
  const year = Number(match[1])
  const month = Number(match[2])
  const day = Number(match[3])
  const maxDay = month === 2 && isLeapYear(year) ? 29 : DAYS_IN_MONTH[month - 1]
  if (day > maxDay) throw new Error('issued_at: invalid calendar timestamp')
}

export interface ActionReferenceInputV2 {
  profile: 'aps-action-ref-v2'
  agent_id: string
  action_type: string
  target: string
  payload_ref: string
  scope_required: string[]
  issued_at: string
  nonce: string
}

export function createActionReferenceInputV2(input: {
  agent_id: string
  action_type: string
  target: string
  payload_ref: string
  scope_required: readonly string[]
  issued_at: string
  nonce: string
}): ActionReferenceInputV2 {
  const value: ActionReferenceInputV2 = {
    profile: 'aps-action-ref-v2',
    agent_id: input.agent_id,
    action_type: input.action_type,
    target: input.target,
    payload_ref: input.payload_ref,
    scope_required: sortedUnique(
      input.scope_required.map((scope) => scope.normalize('NFC')),
      'scope_required',
    ),
    issued_at: input.issued_at,
    nonce: input.nonce,
  }
  validateActionReferenceInputV2(value)
  return value
}

export function computeActionRefV2(input: ActionReferenceInputV2): string {
  validateActionReferenceInputV2(input)
  return createHash('sha256').update(DOMAIN + canonicalizeJCS(input), 'utf8').digest('hex')
}

export function computePayloadRefV1(payload: unknown): string {
  assertIJson(payload)
  return createHash('sha256')
    .update('APS-ACTION-PAYLOAD-V1\0' + canonicalizeJCS(payload), 'utf8')
    .digest('hex')
}

export function validateActionReferenceInputV2(candidate: unknown): asserts candidate is ActionReferenceInputV2 {
  assertPlainRecord(candidate, 'action reference')
  assertExactKeys(candidate, [
    'profile', 'agent_id', 'action_type', 'target', 'payload_ref',
    'scope_required', 'issued_at', 'nonce',
  ], [], 'action reference')
  assertIJson(candidate)
  if (candidate.profile !== 'aps-action-ref-v2') throw new Error('action reference profile')
  if (typeof candidate.agent_id !== 'string' || candidate.agent_id.length === 0) throw new Error('agent_id')
  if (typeof candidate.action_type !== 'string' || candidate.action_type.length === 0) throw new Error('action_type')
  if (typeof candidate.target !== 'string' || candidate.target.length === 0) throw new Error('target')
  if (typeof candidate.payload_ref !== 'string') throw new Error('payload_ref: expected 64 lowercase hexadecimal characters')
  assertHex(candidate.payload_ref, 64, 'payload_ref')
  if (!Array.isArray(candidate.scope_required)) throw new Error('scope_required')
  assertSortedUnique(candidate.scope_required as string[], 'scope_required')
  for (const scope of candidate.scope_required as string[]) {
    if (scope !== scope.normalize('NFC')) throw new Error('scope_required: non-NFC value')
  }
  if (typeof candidate.issued_at !== 'string') throw new Error('issued_at: expected canonical UTC milliseconds')
  assertActionRefIssuedAt(candidate.issued_at)
  if (typeof candidate.nonce !== 'string') throw new Error('nonce: expected 32 lowercase hexadecimal characters')
  assertHex(candidate.nonce, 32, 'nonce')
}

/** Serialized-input entry path for an action reference document.
 *
 *  WHY THIS EXISTS, and why validation could never have covered it. Rejecting a
 *  duplicate object member is a property of PARSING, not of validation. By the
 *  time raw JSON has become a JavaScript object the second `agent_id` has already
 *  overwritten the first and the evidence is gone, so no check added to
 *  computeActionRefV2 or validateActionReferenceInputV2, both of which receive an
 *  already-parsed value, can ever satisfy the duplicate-member requirement. The
 *  only place the fact still exists is the byte stream.
 *
 *  So this entry point takes the raw document and parses it with the strict
 *  parser that already lives in receipt-core, which rejects a duplicate member
 *  name after JSON string decoding, meaning "a" and "\u0061" collide as the same
 *  name. The result is then handed to the EXISTING validator unchanged: nothing
 *  here weakens or bypasses validateActionReferenceInputV2, it runs in full.
 */
export function parseActionReferenceInputV2(raw: string): ActionReferenceInputV2 {
  const parsed: unknown = parseStrictIJson(raw)
  validateActionReferenceInputV2(parsed)
  return parsed
}

/** Compute an action_ref straight from the serialized document.
 *
 *  The composed form of parseActionReferenceInputV2 and computeActionRefV2, for
 *  callers holding wire bytes rather than a constructed input. Identical digest
 *  to the parsed path for any document that parses, because it IS the parsed
 *  path once the bytes have been read.
 */
export function computeActionRefV2FromJson(raw: string): string {
  return computeActionRefV2(parseActionReferenceInputV2(raw))
}
