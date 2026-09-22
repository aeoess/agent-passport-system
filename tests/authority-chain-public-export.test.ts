import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as api from '../src/index.js'

test('the draft-03 release surface is exported from the package root', () => {
  // Release check, not a unit test. A symbol implemented under src but absent
  // here is not reachable through the package root consumers install.
  const functions = [
    // Section 3
    'verifyAuthorityDelegationChain',
    'verifyAuthorityDelegation',
    'issueAuthorityDelegation',
    'issueSubAuthorityDelegation',
    'compareAuthority',
    'isValidScopeGrant',
    'scopeGrantCovers',
    'grantsAreCanonical',
    'scopeNarrows',
    'InMemoryAuthorityBudgetLedger',
    'isAuthorityDelegationV1',
    'validateAuthorityDelegationShape',

    // Section 4.1
    'createActionReferenceInputV2',
    'computeActionRefV2',
    'computePayloadRefV1',
    'validateActionReferenceInputV2',
    'parseActionReferenceInputV2',
    'computeActionRefV2FromJson',

    // Section 4.2
    'computeExternalActionRefV1',

    // Section 5
    'validateReceiptStageV1',
    'verifyReceiptV1',
    'verifyReceiptV1Serialized',
    'verifyReceiptWithDecisionV1',
    'buildDecisionRefV1',
  ] as const

  for (const name of functions) {
    assert.equal(typeof api[name], 'function', `${name} is not exported from the package root`)
  }

  assert.equal(typeof api.RECEIPT_STAGE_TYPES_V1, 'object')
  // ActionReferenceInputV2 and ActionReferenceProfileContextV2 are types and do not exist at
  // runtime. Their export is checked by compilation and by the generated index.d.ts.
  // SubAuthorityIssueOptions, BudgetReservationState and BudgetOperationResult are also
  // types-only and checked the same way.
})

test('verifyAuthorityDelegationChain rejects a non-canonical now with NONCANONICAL_VALUE', () => {
  // A nonempty chain is required: the empty-chain guard runs first and would mask a
  // deleted timestamp check. `now` is checked before any record is inspected, so [{}]
  // reaches it.
  const r = api.verifyAuthorityDelegationChain([{}], { now: 'not-a-timestamp' } as any)
  assert.equal(r.valid, false)
  assert.equal(r.state, 'invalid')
  assert.equal(r.failures[0]?.code, 'NONCANONICAL_VALUE')
})

test('verifyAuthorityDelegationChain rejects an empty chain with SCHEMA_INVALID, not NONCANONICAL_VALUE', () => {
  const r = api.verifyAuthorityDelegationChain([], { now: 'not-a-timestamp' } as any)
  assert.equal(r.state, 'invalid')
  assert.equal(r.failures[0]?.code, 'SCHEMA_INVALID')
})
