// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { strictJCS, assertExactKeys } from './jcs.js'
import { isExactUtcMilliseconds } from './receipt.js'
import type { CoreDecisionOutputV1, DecisionRefInputV1, JsonValue } from './types.js'

export const DECISION_REF_TAG = 'APS-DECISION-REF-V1' as const
export const DECISION_COMPONENT_TAGS = {
  authority: 'APS-DECISION-AUTHORITY-V1',
  policy: 'APS-DECISION-POLICY-V1',
  context: 'APS-DECISION-CONTEXT-V1',
  output: 'APS-DECISION-OUTPUT-V1',
} as const

const HEX64 = /^[0-9a-f]{64}$/
const tagged = (tag: string, canonical: string): string => `${tag}\0${canonical}`
const sha256Hex = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex')

export function computeDecisionComponentRefV1(tag: keyof typeof DECISION_COMPONENT_TAGS, value: JsonValue): string {
  return sha256Hex(tagged(DECISION_COMPONENT_TAGS[tag], strictJCS(value)))
}

export function validateDecisionRefInputV1(input: DecisionRefInputV1): void {
  assertExactKeys(input as unknown as Record<string, unknown>,
    ['profile', 'action_ref', 'authority_state_ref', 'policy_ref', 'context_ref', 'decision_output_ref'],
    ['profile', 'action_ref', 'authority_state_ref', 'policy_ref', 'context_ref', 'decision_output_ref'],
    'DecisionRefInputV1')
  if (input.profile !== 'aps-decision-ref-v1') throw new TypeError('DecisionRefInputV1: profile')
  for (const [key, value] of Object.entries(input)) {
    if (key !== 'profile' && (typeof value !== 'string' || !HEX64.test(value))) {
      throw new TypeError(`DecisionRefInputV1: ${key} must be lowercase sha256 hex`)
    }
  }
}

export function computeDecisionRefV1(input: DecisionRefInputV1): string {
  validateDecisionRefInputV1(input)
  return sha256Hex(tagged(DECISION_REF_TAG, strictJCS(input)))
}

export function normalizeCoreDecisionOutputV1(input: CoreDecisionOutputV1): CoreDecisionOutputV1 {
  assertExactKeys(input as unknown as Record<string, unknown>,
    ['profile', 'verdict', 'effective_authority_ref', 'constraints', 'valid_until'],
    ['profile', 'verdict', 'effective_authority_ref', 'constraints', 'valid_until'], 'CoreDecisionOutputV1')
  strictJCS(input)
  if (input.profile !== 'aps-core-decision-output-v1') throw new TypeError('CoreDecisionOutputV1: profile')
  if (!['permit', 'deny', 'narrow'].includes(input.verdict)) throw new TypeError('CoreDecisionOutputV1: verdict')
  if (input.effective_authority_ref !== null && !HEX64.test(input.effective_authority_ref)) {
    throw new TypeError('CoreDecisionOutputV1: effective_authority_ref')
  }
  if (input.verdict === 'deny' && input.effective_authority_ref !== null) {
    throw new TypeError('CoreDecisionOutputV1: deny requires null effective_authority_ref')
  }
  if (input.verdict !== 'deny' && input.effective_authority_ref === null) {
    throw new TypeError('CoreDecisionOutputV1: permit/narrow require effective_authority_ref')
  }
  if (!Array.isArray(input.constraints) || !input.constraints.every(v => typeof v === 'string')) {
    throw new TypeError('CoreDecisionOutputV1: constraints')
  }
  if (input.verdict === 'deny') {
    if (input.valid_until !== null) throw new TypeError('CoreDecisionOutputV1: deny requires null valid_until')
  } else if (typeof input.valid_until !== 'string' || !isExactUtcMilliseconds(input.valid_until)) {
    throw new TypeError('CoreDecisionOutputV1: permit/narrow require valid_until as exact UTC milliseconds')
  }
  const constraints = [...new Set(input.constraints.map(v => v.normalize('NFC')))]
    .sort((a, b) => {
      const aa = Array.from(a, c => c.codePointAt(0) as number)
      const bb = Array.from(b, c => c.codePointAt(0) as number)
      for (let i = 0; i < Math.min(aa.length, bb.length); i++) if (aa[i] !== bb[i]) return aa[i] - bb[i]
      return aa.length - bb.length
    })
  return { ...input, constraints }
}

export function buildDecisionRefV1(input: {
  action_ref: string
  authority_state: JsonValue
  policy_input: JsonValue
  decision_context: JsonValue
  decision_output: JsonValue
}): { input: DecisionRefInputV1; decision_ref: string } {
  if (!HEX64.test(input.action_ref)) throw new TypeError('action_ref must be lowercase sha256 hex')
  const refInput: DecisionRefInputV1 = {
    profile: 'aps-decision-ref-v1',
    action_ref: input.action_ref,
    authority_state_ref: computeDecisionComponentRefV1('authority', input.authority_state),
    policy_ref: computeDecisionComponentRefV1('policy', input.policy_input),
    context_ref: computeDecisionComponentRefV1('context', input.decision_context),
    decision_output_ref: computeDecisionComponentRefV1('output', input.decision_output),
  }
  return { input: refInput, decision_ref: computeDecisionRefV1(refInput) }
}
