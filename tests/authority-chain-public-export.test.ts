import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as api from '../src/index.js'

test('verifyAuthorityDelegationChain is a public export', () => {
  assert.equal(typeof api.verifyAuthorityDelegationChain, 'function')
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
