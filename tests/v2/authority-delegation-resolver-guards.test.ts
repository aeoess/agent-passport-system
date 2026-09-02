// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Mutation survivors MA1/MA2: the resolver callbacks are attacker- and
// integrator-supplied, and their return values must be normalized.
// ══════════════════════════════════════════════════════════════════
// verifyAuthorityDelegationChain is the SDK's model fail-closed verifier and
// a Phase 2 recheck confirmed it is correct on the merits. That recheck left
// no test behind, so two mutations survived the full suite:
//
//   MA1  revocation = resolved            (drop the value normalization)
//   MA2  trustDecision used as truthy     (drop the boolean check)
//
// Under MA1 a resolveRevocation that returns undefined, null, a Promise (the
// shape you get from an async resolver passed by mistake) or any unexpected
// string is neither 'revoked' nor 'unknown', so both guards fall through and
// the chain reports valid. That turns a resolver bug or a mis-wired async
// callback into a silent admit. This file is that missing coverage.
//
// It is a SEPARATE file from authority-delegation.test.ts on purpose: this
// area is held by another worktree and a new file cannot conflict textually
// with edits to the existing one. Nothing in src/v2/authority-delegation was
// changed to make these pass; they pass against the shipped implementation.

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../../src/crypto/keys.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  issueAuthorityDelegation,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityChainVerificationOptions,
  AuthorityDelegationBodyV1,
} from '../../src/v2/authority-delegation/index.js'

const NOW = '2026-07-18T22:10:00.000Z'
const keys = generateKeyPair()

function rootBody(): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: null,
    issuer: 'did:example:root',
    subject: 'did:example:agent-a',
    verification_method: 'did:example:root#key-1',
    issued_at: '2026-07-18T22:00:00.000Z',
    nonce: '00112233445566778899aabbccddeeff',
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100', cumulative: '100' },
      depth: { remaining: 3 },
      time: { not_before: '2026-07-18T22:00:00.000Z', not_after: '2026-07-18T23:00:00.000Z' },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 80 },
      values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003'] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'compensable' },
    },
  }
}

const root = issueAuthorityDelegation(rootBody(), keys.privateKey)

function options(over: Partial<AuthorityChainVerificationOptions> = {}): AuthorityChainVerificationOptions {
  return {
    now: NOW,
    resolveVerificationKey: () => keys.publicKey,
    trustRoot: () => true,
    resolveRevocation: () => 'active',
    ...over,
  }
}

test('control: a well-formed chain with sound resolvers is valid', () => {
  const r = verifyAuthorityDelegationChain([root], options())
  assert.equal(r.state, 'valid')
  assert.equal(r.valid, true)
})

// ── MA1: resolveRevocation return-value normalization ──

test('MA1: a resolveRevocation returning undefined is REVOCATION_UNKNOWN, not valid', () => {
  const r = verifyAuthorityDelegationChain([root], options({
    resolveRevocation: (() => undefined) as never,
  }))
  assert.equal(r.valid, false)
  assert.equal(r.state, 'indeterminate')
  assert.equal(r.failures[0]?.code, 'REVOCATION_UNKNOWN')
})

test('MA1: a resolveRevocation returning null is REVOCATION_UNKNOWN, not valid', () => {
  const r = verifyAuthorityDelegationChain([root], options({
    resolveRevocation: (() => null) as never,
  }))
  assert.equal(r.valid, false)
  assert.equal(r.failures[0]?.code, 'REVOCATION_UNKNOWN')
})

test('MA1: an ASYNC resolveRevocation returns a Promise, which is not an answer', () => {
  // The likeliest real form of this bug: an integrator writes an async
  // resolver against a synchronous interface. A truthy Promise must never be
  // read as "not revoked".
  const r = verifyAuthorityDelegationChain([root], options({
    resolveRevocation: (async () => 'active') as never,
  }))
  assert.equal(r.valid, false)
  assert.equal(r.failures[0]?.code, 'REVOCATION_UNKNOWN')
})

test('MA1: an unrecognised revocation string is not an answer', () => {
  for (const bogus of ['ACTIVE', 'ok', 'true', '', 'valid', 'not_revoked']) {
    const r = verifyAuthorityDelegationChain([root], options({
      resolveRevocation: (() => bogus) as never,
    }))
    assert.equal(r.valid, false, `resolver returned ${JSON.stringify(bogus)} and the chain verified`)
    assert.equal(r.failures[0]?.code, 'REVOCATION_UNKNOWN')
  }
})

test('MA1: a truthy non-string revocation answer is not an answer', () => {
  for (const bogus of [1, true, {}, [], () => 'active']) {
    const r = verifyAuthorityDelegationChain([root], options({
      resolveRevocation: (() => bogus) as never,
    }))
    assert.equal(r.valid, false, `resolver returned ${typeof bogus} and the chain verified`)
  }
})

test('MA1: a throwing resolveRevocation is REVOCATION_UNKNOWN, not valid', () => {
  const r = verifyAuthorityDelegationChain([root], options({
    resolveRevocation: () => { throw new Error('registry unreachable') },
  }))
  assert.equal(r.valid, false)
  assert.equal(r.failures[0]?.code, 'REVOCATION_UNKNOWN')
})

test('MA1: an explicit revoked answer is REVOKED, distinct from unknown', () => {
  const r = verifyAuthorityDelegationChain([root], options({
    resolveRevocation: () => 'revoked',
  }))
  assert.equal(r.valid, false)
  assert.equal(r.state, 'invalid')
  assert.equal(r.failures[0]?.code, 'REVOKED')
})

// ── MA2: trustRoot return-value normalization ──

test('MA2: a trustRoot returning a truthy non-boolean is ROOT_UNTRUSTED, not valid', () => {
  for (const bogus of ['yes', 1, {}, [], 'true']) {
    const r = verifyAuthorityDelegationChain([root], options({
      trustRoot: (() => bogus) as never,
    }))
    assert.equal(r.valid, false, `trustRoot returned ${JSON.stringify(bogus)} and the chain verified`)
    assert.equal(r.state, 'indeterminate')
    assert.equal(r.failures[0]?.code, 'ROOT_UNTRUSTED')
  }
})

test('MA2: an ASYNC trustRoot returns a Promise, which is not a decision', () => {
  const r = verifyAuthorityDelegationChain([root], options({
    trustRoot: (async () => true) as never,
  }))
  assert.equal(r.valid, false)
  assert.equal(r.failures[0]?.code, 'ROOT_UNTRUSTED')
})

test('MA2: a throwing trustRoot is ROOT_UNTRUSTED, not valid', () => {
  const r = verifyAuthorityDelegationChain([root], options({
    trustRoot: () => { throw new Error('policy service down') },
  }))
  assert.equal(r.valid, false)
  assert.equal(r.failures[0]?.code, 'ROOT_UNTRUSTED')
})

test('MA2: a missing trustRoot is ROOT_UNTRUSTED, not an implicit yes', () => {
  const r = verifyAuthorityDelegationChain([root], options({
    trustRoot: undefined as never,
  }))
  assert.equal(r.valid, false)
  assert.equal(r.failures[0]?.code, 'ROOT_UNTRUSTED')
})

test('MA2: an explicit false from trustRoot is invalid, not indeterminate', () => {
  const r = verifyAuthorityDelegationChain([root], options({ trustRoot: () => false }))
  assert.equal(r.valid, false)
  assert.equal(r.state, 'invalid')
  assert.equal(r.failures[0]?.code, 'ROOT_UNTRUSTED')
})

// ── key resolution, same class ──

test('a key resolver returning null is KEY_RESOLUTION_FAILED, not valid', () => {
  const r = verifyAuthorityDelegationChain([root], options({
    resolveVerificationKey: () => null,
  }))
  assert.equal(r.valid, false)
  assert.equal(r.state, 'indeterminate')
  assert.equal(r.failures[0]?.code, 'KEY_RESOLUTION_FAILED')
})

test('a throwing key resolver is KEY_RESOLUTION_FAILED, not valid', () => {
  const r = verifyAuthorityDelegationChain([root], options({
    resolveVerificationKey: () => { throw new Error('jwks unreachable') },
  }))
  assert.equal(r.valid, false)
  assert.equal(r.failures[0]?.code, 'KEY_RESOLUTION_FAILED')
})
