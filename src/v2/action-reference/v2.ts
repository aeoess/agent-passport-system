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
  assertUtcMilliseconds,
  sortedUnique,
} from '../identity-binding/validation.js'

const DOMAIN = 'APS-ACTION-REF-V2\0'

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
  assertHex(String(candidate.payload_ref), 64, 'payload_ref')
  if (!Array.isArray(candidate.scope_required)) throw new Error('scope_required')
  assertSortedUnique(candidate.scope_required as string[], 'scope_required')
  for (const scope of candidate.scope_required as string[]) {
    if (scope !== scope.normalize('NFC')) throw new Error('scope_required: non-NFC value')
  }
  assertUtcMilliseconds(String(candidate.issued_at), 'issued_at')
  assertHex(String(candidate.nonce), 32, 'nonce')
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
