import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as api from '../src/index.js'

test('verifyAuthorityDelegationChain and compareAuthority are public exports', () => {
  assert.equal(typeof api.verifyAuthorityDelegationChain, 'function')
  assert.equal(typeof api.compareAuthority, 'function')
})

test('verifyAuthorityDelegationChain rejects a non-canonical now before reading the chain', () => {
  const r = api.verifyAuthorityDelegationChain([], { now: 'not-a-timestamp' } as any)
  assert.equal(r.valid, false)
  assert.equal(r.state === 'valid', false)
})
