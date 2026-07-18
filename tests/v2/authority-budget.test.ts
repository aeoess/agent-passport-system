// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../../src/crypto/keys.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  InMemoryAuthorityBudgetLedger,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
} from '../../src/v2/authority-delegation/index.js'
import type { AuthorityDelegationBodyV1, AuthorityDelegationV1 } from '../../src/v2/authority-delegation/index.js'

function root(): { delegation: AuthorityDelegationV1; subjectKey: ReturnType<typeof generateKeyPair> } {
  const rootKey = generateKeyPair()
  const subjectKey = generateKeyPair()
  const body: AuthorityDelegationBodyV1 = {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: null,
    issuer: 'did:example:root', subject: 'did:example:a',
    verification_method: 'did:example:root#key',
    issued_at: '2026-07-18T22:00:00.000Z', nonce: '11111111111111111111111111111111',
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100', cumulative: '100' },
      depth: { remaining: 2 },
      time: { not_before: '2026-07-18T22:00:00.000Z', not_after: '2026-07-18T23:00:00.000Z' },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 100 },
      values: { profile: VALUES_PROFILE_V1, required: [] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'irreversible' },
    },
  }
  return { delegation: issueAuthorityDelegation(body, rootKey.privateKey), subjectKey }
}

function child(parent: AuthorityDelegationV1, subjectKey: ReturnType<typeof generateKeyPair>, subject: string, nonce: string): AuthorityDelegationV1 {
  const body: AuthorityDelegationBodyV1 = {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: parent.delegation_id,
    issuer: parent.subject, subject,
    verification_method: `${parent.subject}#key`,
    issued_at: '2026-07-18T22:00:01.000Z', nonce,
    authority: {
      ...structuredClone(parent.authority),
      depth: { remaining: 1 },
      time: { not_before: '2026-07-18T22:00:01.000Z', not_after: '2026-07-18T22:59:00.000Z' },
    },
  }
  return issueSubAuthorityDelegation(parent, body, subjectKey.privateKey)
}

test('sibling actions debit their shared ancestor atomically', () => {
  const { delegation: parent, subjectKey } = root()
  const left = child(parent, subjectKey, 'did:example:left', '22222222222222222222222222222222')
  const right = child(parent, subjectKey, 'did:example:right', '33333333333333333333333333333333')
  const ledger = new InMemoryAuthorityBudgetLedger()

  const first = ledger.reserve([parent, left], 'a'.repeat(64), 'iso4217:USD:minor', '60')
  const second = ledger.reserve([parent, right], 'b'.repeat(64), 'iso4217:USD:minor', '60')
  assert.equal(first.ok, true)
  assert.deepEqual(second, { ok: false, code: 'CUMULATIVE_EXCEEDED' })
  assert.deepEqual(ledger.counter(parent.delegation_id), { reserved: '60', committed: '0' })

  assert.equal(ledger.commit('a'.repeat(64)).ok, true)
  assert.deepEqual(ledger.counter(parent.delegation_id), { reserved: '0', committed: '60' })
  assert.equal(ledger.commit('a'.repeat(64)).code, 'IDEMPOTENT')
})

test('action_ref retries are idempotent, conflicts fail, and dispatched reservations cannot cancel', () => {
  const { delegation: parent, subjectKey } = root()
  const leaf = child(parent, subjectKey, 'did:example:leaf', '44444444444444444444444444444444')
  const ledger = new InMemoryAuthorityBudgetLedger()
  const actionRef = 'c'.repeat(64)

  assert.equal(ledger.reserve([parent, leaf], actionRef, 'iso4217:USD:minor', '25').code, 'RESERVED')
  assert.equal(ledger.reserve([parent, leaf], actionRef, 'iso4217:USD:minor', '25').code, 'IDEMPOTENT')
  assert.equal(ledger.reserve([parent, leaf], actionRef, 'iso4217:USD:minor', '26').code, 'CONFLICT')
  assert.equal(ledger.markDispatched(actionRef).ok, true)
  assert.deepEqual(ledger.cancel(actionRef), { ok: false, code: 'INVALID_STATE', state: 'dispatched' })
  assert.equal(ledger.commit(actionRef).ok, true)
})

test('budget ledger rejects truncated, malformed, and duplicate chains', () => {
  const { delegation: parent, subjectKey } = root()
  const leaf = child(parent, subjectKey, 'did:example:leaf', '55555555555555555555555555555555')
  const ledger = new InMemoryAuthorityBudgetLedger()
  assert.equal(ledger.reserve([], 'd'.repeat(64), 'iso4217:USD:minor', '1').code, 'CONFLICT')
  assert.equal(ledger.reserve([leaf], 'e'.repeat(64), 'iso4217:USD:minor', '1').code, 'CONFLICT')
  assert.equal(ledger.reserve([parent, parent], 'f'.repeat(64), 'iso4217:USD:minor', '1').code, 'CONFLICT')
})
