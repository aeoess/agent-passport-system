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
  /^([0-9]{4})-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)\.[0-9]{3}Z$/

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0
}

/** issued_at check local to the action reference surface.
 *
 *  draft-pidlisnyi-aps-03 section 4.1 names RFC 3339 for issued_at. RFC 3339
 *  section 5.7 admits time-second 60 only for a leap second, and Appendix D
 *  writes it as "YYYY-MM-DDT23:59:60Z": second 60 is valid only at 23:59 on
 *  the last day of its month in the proleptic Gregorian calendar, and every
 *  other second-60 value is invalid. There is no leap-second table to
 *  consult and none is needed, since the hour, minute and day settle it.
 *  The shared assertUtcMilliseconds helper (identity-binding/validation.ts)
 *  rejects second 60 outright and also serves passport and
 *  principal-binding validation, so this check stays local here instead of
 *  changing that helper and the surfaces it serves.
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
  const hour = Number(match[4])
  const minute = Number(match[5])
  const second = Number(match[6])
  const maxDay = month === 2 && isLeapYear(year) ? 29 : DAYS_IN_MONTH[month - 1]
  if (day > maxDay) throw new Error('issued_at: invalid calendar timestamp')
  if (second === 60 && !(hour === 23 && minute === 59 && day === maxDay)) {
    throw new Error('issued_at: invalid calendar timestamp')
  }
}

function isNoncharacterCodePoint(codePoint: number): boolean {
  if (codePoint >= 0xfdd0 && codePoint <= 0xfdef) return true
  return (codePoint & 0xffff) === 0xfffe || (codePoint & 0xffff) === 0xffff
}

function assertNoNoncharacters(value: string, path: string): void {
  for (let index = 0; index < value.length; index++) {
    const codePoint = value.codePointAt(index)
    if (codePoint === undefined) continue
    if (codePoint > 0xffff) index++ // consumed a surrogate pair; skip its low half
    if (isNoncharacterCodePoint(codePoint)) throw new Error(`${path}: noncharacter`)
  }
}

type NoncharacterFrame =
  | { kind: 'value'; value: unknown; path: string }
  | { kind: 'exit'; owner: object }

/** Module-local noncharacter walk for the section 4.1 I-JSON requirement.
 *
 *  draft-pidlisnyi-aps-03 lines 813-815 ("A verifier MUST reject an object
 *  with ... a non-I-JSON value"), read with line 204 (JCS over validated
 *  I-JSON) and RFC 7493 section 2.1: every member name and string value, at
 *  any depth, must contain no noncharacter (U+FDD0 to U+FDEF, and any code
 *  point whose low 16 bits are FFFE or FFFF). Surrogate pairs are decoded to
 *  their code point before the test; unpaired surrogates are already
 *  rejected by the existing I-JSON check this runs after.
 *
 *  Iterative and non-recursive: an explicit stack stands in for the call
 *  stack, and an object's membership in the current ancestor chain is
 *  tracked with matching push ('value') and pop ('exit') frames rather than
 *  recursive entry and return, so a cyclic structure fails instead of
 *  overflowing. This is independent of, and runs after, the recursive
 *  ancestor tracking assertIJson already performs.
 *
 *  Kept local to this module rather than folded into the shared assertIJson
 *  (identity-binding/validation.ts, also used by passports and principal
 *  bindings) or receipt-core/jcs.ts.
 */
function assertNoNoncharactersDeep(root: unknown, rootPath: string): void {
  const stack: NoncharacterFrame[] = [{ kind: 'value', value: root, path: rootPath }]
  const onPath = new Set<object>()
  while (stack.length > 0) {
    const frame = stack.pop() as NoncharacterFrame
    if (frame.kind === 'exit') {
      onPath.delete(frame.owner)
      continue
    }
    const { value, path } = frame
    if (typeof value === 'string') {
      assertNoNoncharacters(value, path)
      continue
    }
    if (value === null || typeof value !== 'object') continue
    if (onPath.has(value)) throw new Error(`${path}: cyclic value`)
    onPath.add(value)
    stack.push({ kind: 'exit', owner: value })
    if (Array.isArray(value)) {
      for (let index = value.length - 1; index >= 0; index--) {
        stack.push({ kind: 'value', value: value[index], path: `${path}[${index}]` })
      }
    } else {
      const entries = Object.entries(value as Record<string, unknown>)
      for (let index = entries.length - 1; index >= 0; index--) {
        const [key, entry] = entries[index]
        assertNoNoncharacters(key, `${path} key`)
        stack.push({ kind: 'value', value: entry, path: `${path}.${key}` })
      }
    }
  }
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

export function computeActionRefV2(
  input: ActionReferenceInputV2,
  profileContext: ActionReferenceProfileContextV2 = {},
): string {
  validateActionReferenceInputV2(input, profileContext)
  return createHash('sha256').update(DOMAIN + canonicalizeJCS(input), 'utf8').digest('hex')
}

export function computePayloadRefV1(payload: unknown): string {
  assertIJson(payload)
  assertNoNoncharactersDeep(payload, '$')
  return createHash('sha256')
    .update('APS-ACTION-PAYLOAD-V1\0' + canonicalizeJCS(payload), 'utf8')
    .digest('hex')
}

/** Profile context a caller supplies alongside a generic action reference.
 *
 *  Draft line 799 reads: "All string fields MUST be non-empty except that a profile MAY
 *  permit an empty scope_required array." The permission belongs to a profile, so the
 *  generic computation cannot grant it to itself, and a caller who holds the applicable
 *  profile says so here. Without it, an empty array is refused.
 */
export interface ActionReferenceProfileContextV2 {
  /** True only when the applicable profile explicitly permits an empty scope_required. */
  emptyScopeRequiredPermitted?: boolean
}

export function validateActionReferenceInputV2(
  candidate: unknown,
  profileContext: ActionReferenceProfileContextV2 = {},
): asserts candidate is ActionReferenceInputV2 {
  assertPlainRecord(candidate, 'action reference')
  assertExactKeys(candidate, [
    'profile', 'agent_id', 'action_type', 'target', 'payload_ref',
    'scope_required', 'issued_at', 'nonce',
  ], [], 'action reference')
  assertIJson(candidate)
  assertNoNoncharactersDeep(candidate, '$')
  if (candidate.profile !== 'aps-action-ref-v2') throw new Error('action reference profile')
  if (typeof candidate.agent_id !== 'string' || candidate.agent_id.length === 0) throw new Error('agent_id')
  if (typeof candidate.action_type !== 'string' || candidate.action_type.length === 0) throw new Error('action_type')
  if (typeof candidate.target !== 'string' || candidate.target.length === 0) throw new Error('target')
  if (typeof candidate.payload_ref !== 'string') throw new Error('payload_ref: expected 64 lowercase hexadecimal characters')
  assertHex(candidate.payload_ref, 64, 'payload_ref')
  if (!Array.isArray(candidate.scope_required)) throw new Error('scope_required')
  // An empty scope_required is not permitted by default. Line 799 puts the permission in
  // a profile, and this computation is the generic one, so it cannot grant it to itself;
  // a caller holding the applicable profile passes the context that does. This SDK used
  // to accept an empty array outright, which read the MAY as a standing permission.
  if ((candidate.scope_required as string[]).length === 0 && profileContext.emptyScopeRequiredPermitted !== true) {
    throw new Error('scope_required: empty is permitted only by an applicable profile')
  }
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
export function parseActionReferenceInputV2(
  raw: string,
  profileContext: ActionReferenceProfileContextV2 = {},
): ActionReferenceInputV2 {
  const parsed: unknown = parseStrictIJson(raw)
  validateActionReferenceInputV2(parsed, profileContext)
  return parsed
}

/** Compute an action_ref straight from the serialized document.
 *
 *  The composed form of parseActionReferenceInputV2 and computeActionRefV2, for
 *  callers holding wire bytes rather than a constructed input. Identical digest
 *  to the parsed path for any document that parses, because it IS the parsed
 *  path once the bytes have been read.
 */
export function computeActionRefV2FromJson(
  raw: string,
  profileContext: ActionReferenceProfileContextV2 = {},
): string {
  return computeActionRefV2(parseActionReferenceInputV2(raw, profileContext), profileContext)
}
