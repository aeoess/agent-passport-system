// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Coverage for the plain-JSON-data rule: a record handed to any authority-delegation
// entry point must be built, at every depth, from null, a boolean, a finite number, a
// string, an exact plain array, or an exact plain object. A cycle, an accessor
// property, a non-enumerable own member, a value with no JSON form (a Map, a Date, a
// typed array, a class instance, an Array subclass), and anything a Proxy reports
// through its "get" trap rather than through its property descriptors are all
// malformed input: each gives SCHEMA_INVALID through the same combined-failure paths a
// noncharacter already used, and none of them is ever read more than once.
// See src/v2/authority-delegation/plain-data.ts.

import test from 'node:test'
import assert from 'node:assert/strict'
import vm from 'node:vm'
import { generateKeyPair } from '../../src/crypto/keys.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  InMemoryAuthorityBudgetLedger,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  computeAuthorityDelegationIdForWrite,
  isAuthorityDelegationV1,
  issueAuthorityDelegation,
  issueSubAuthorityDelegation,
  signAuthorityDelegation,
  validateAuthorityDelegationShape,
  verifyAuthorityDelegationChain,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityChainVerificationOptions,
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
} from '../../src/v2/authority-delegation/index.js'

/** Parses a JSON-serialised copy of `value` with JSON.parse running in a fresh
 *  node:vm context, so every array and object the result contains, at every depth,
 *  carries that context's Array.prototype and Object.prototype rather than this
 *  realm's. */
function decodeInNewRealm<T>(value: T): T {
  const text = JSON.stringify(value)
  return vm.runInNewContext('JSON.parse(t)', { t: text }) as T
}

const ROOT_ISSUER = 'did:example:root'
const ROOT_SUBJECT = 'did:example:agent-a'
const CHILD_SUBJECT = 'did:example:agent-b'
const ROOT_VM = `${ROOT_ISSUER}#key-1`
const CHILD_VM = `${ROOT_SUBJECT}#key-1`
const ROOT_NOT_BEFORE = '2026-07-18T22:00:00.000Z'
const ROOT_NOT_AFTER = '2026-07-18T23:00:00.000Z'
const NOW = '2026-07-18T22:10:00.000Z'

function rootBody(): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: null,
    issuer: ROOT_ISSUER,
    subject: ROOT_SUBJECT,
    verification_method: ROOT_VM,
    issued_at: ROOT_NOT_BEFORE,
    nonce: '00112233445566778899aabbccddeeff',
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '100', cumulative: '100' },
      depth: { remaining: 3 },
      time: { not_before: ROOT_NOT_BEFORE, not_after: ROOT_NOT_AFTER },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 80 },
      values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003'] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'compensable' },
    },
  }
}

function childBody(parent: AuthorityDelegationV1): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: parent.delegation_id,
    issuer: parent.subject,
    subject: CHILD_SUBJECT,
    verification_method: CHILD_VM,
    issued_at: '2026-07-18T22:00:01.000Z',
    nonce: '102132435465768798a9bacbdcedfe0f',
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '80', cumulative: '80' },
      depth: { remaining: 2 },
      time: { not_before: '2026-07-18T22:00:01.000Z', not_after: '2026-07-18T22:50:00.000Z' },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 70 },
      values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003', 'F-004'] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'tentative' },
    },
  }
}

function mutableRootBody(): Record<string, unknown> {
  return structuredClone(rootBody()) as unknown as Record<string, unknown>
}

/** Placeholder id and signature for a record this file never asks JCS to canonicalize. */
function unsignable(body: Record<string, unknown>): AuthorityDelegationV1 {
  return {
    ...body,
    delegation_id: `sha256:${'0'.repeat(64)}`,
    signature: '0'.repeat(128),
  } as unknown as AuthorityDelegationV1
}

/** Sign a body with the same write-boundary helpers issueAuthorityDelegation and
 *  issueSubAuthorityDelegation call internally, bypassing their own shape checks. */
function signDirectly(body: AuthorityDelegationBodyV1, privateKey: string): AuthorityDelegationV1 {
  const delegation_id = computeAuthorityDelegationIdForWrite(body)
  const signature = signAuthorityDelegation({ ...body, delegation_id }, privateKey)
  return { ...body, delegation_id, signature }
}

const rootKeys = generateKeyPair()
const childKeys = generateKeyPair()
const root = issueAuthorityDelegation(rootBody(), rootKeys.privateKey)

function resolveKeys(_issuer: string, method: string): string | null {
  if (method === root.verification_method) return rootKeys.publicKey
  if (method === CHILD_VM) return childKeys.publicKey
  return null
}

function chainOptions(trustedId: string): AuthorityChainVerificationOptions {
  return {
    now: NOW,
    resolveVerificationKey: resolveKeys,
    trustRoot: candidate => candidate.delegation_id === trustedId,
    resolveRevocation: () => 'active',
  }
}

function codesOf(checked: { failures: { code: string }[] }): string[] {
  return checked.failures.map(item => item.code)
}

test('scope grants held in an Array subclass whose every() always returns true: a widened child is invalid, never valid', () => {
  class LyingArray extends Array<string> {
    every(): boolean { return true }
  }
  const body = childBody(root)
  body.authority.scope.grants = LyingArray.from(['admin:root'])
  const child = signDirectly(body, childKeys.privateKey)
  const checked = verifyAuthorityDelegationChain([root, child], chainOptions(root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.notEqual(checked.state, 'valid')
})

class OpaqueHandle {
  held = true
}

function exoticValues(): Array<[string, unknown]> {
  return [
    ['a Map', new Map([['k', 'v']])],
    ['a Date', new Date('2026-01-01T00:00:00.000Z')],
    ['a Uint8Array', new Uint8Array([1, 2, 3])],
    ['a class instance', new OpaqueHandle()],
  ]
}

function recordWithScopeGrants(grants: unknown, profile: string, version = AUTHORITY_DELEGATION_VERSION): AuthorityDelegationV1 {
  const body = mutableRootBody()
  body.version = version
  ;(body.authority as Record<string, unknown>).scope = { profile, grants }
  return unsignable(body)
}

test('a value with no JSON form inside a v1 facet is SCHEMA_INVALID, the same combined list a noncharacter gives there', () => {
  const reference = recordWithScopeGrants('\uFDD0', SCOPE_PROFILE_V1)
  const referenceCodes = codesOf(verifyAuthorityDelegationChain([reference], chainOptions(reference.delegation_id)))
  for (const [label, value] of exoticValues()) {
    const record = recordWithScopeGrants(value, SCOPE_PROFILE_V1)
    const checked = verifyAuthorityDelegationChain([record], chainOptions(record.delegation_id))
    assert.equal(checked.state, 'invalid', label)
    assert.deepEqual(codesOf(checked), referenceCodes, label)
  }
})

test('a value with no JSON form inside a facet with an unsupported profile is SCHEMA_INVALID first, the same combined list a noncharacter gives there', () => {
  const reference = recordWithScopeGrants('\uFDD0', 'aps-hierarchical-v2')
  const referenceCodes = codesOf(verifyAuthorityDelegationChain([reference], chainOptions(reference.delegation_id)))
  assert.deepEqual(referenceCodes, ['SCHEMA_INVALID', 'UNSUPPORTED_PROFILE'])
  for (const [label, value] of exoticValues()) {
    const record = recordWithScopeGrants(value, 'aps-hierarchical-v2')
    const checked = verifyAuthorityDelegationChain([record], chainOptions(record.delegation_id))
    assert.equal(checked.state, 'invalid', label)
    assert.deepEqual(codesOf(checked), referenceCodes, label)
  }
})

test('a value with no JSON form inside a record whose version is "2.0" is SCHEMA_INVALID first, the same combined list a noncharacter gives there', () => {
  const reference = recordWithScopeGrants('\uFDD0', SCOPE_PROFILE_V1, '2.0')
  const referenceCodes = codesOf(verifyAuthorityDelegationChain([reference], chainOptions(reference.delegation_id)))
  assert.deepEqual(referenceCodes, ['SCHEMA_INVALID', 'UNSUPPORTED_VERSION'])
  for (const [label, value] of exoticValues()) {
    const record = recordWithScopeGrants(value, SCOPE_PROFILE_V1, '2.0')
    const checked = verifyAuthorityDelegationChain([record], chainOptions(record.delegation_id))
    assert.equal(checked.state, 'invalid', label)
    assert.deepEqual(codesOf(checked), referenceCodes, label)
  }
})

test('an accessor property whose getter throws and counts its calls is never called: verify, the ledger, and both issuers all refuse first', () => {
  let callCount = 0
  const body = childBody(root)
  Object.defineProperty(body.authority.scope, 'grants', {
    get() { callCount++; throw new Error('must not be called') },
    enumerable: true,
    configurable: true,
  })
  const badChild = unsignable(body as unknown as Record<string, unknown>)

  const checked = verifyAuthorityDelegationChain([root, badChild], chainOptions(root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.equal(checked.failures[0]?.code, 'SCHEMA_INVALID')
  assert.equal(callCount, 0)

  const ledger = new InMemoryAuthorityBudgetLedger()
  const reserved = ledger.reserve([root, badChild], 'a'.repeat(64), 'iso4217:USD:minor', '10')
  assert.deepEqual(reserved, { ok: false, code: 'CONFLICT' })
  assert.deepEqual(ledger.counter(root.delegation_id), { reserved: '0', committed: '0' })
  assert.equal(callCount, 0)

  assert.throws(
    () => issueSubAuthorityDelegation(root, body, childKeys.privateKey, {
      now: ROOT_NOT_BEFORE,
      resolveVerificationKey: resolveKeys,
      resolveRevocation: () => 'active',
    }),
    /\(SCHEMA_INVALID\)$/,
  )
  assert.equal(callCount, 0)

  const rootWithBadAccessor = rootBody()
  Object.defineProperty(rootWithBadAccessor.authority.scope, 'grants', {
    get() { callCount++; throw new Error('must not be called') },
    enumerable: true,
    configurable: true,
  })
  assert.throws(
    () => issueAuthorityDelegation(rootWithBadAccessor, rootKeys.privateKey),
    /\(SCHEMA_INVALID\)$/,
  )
  assert.equal(callCount, 0)
})

test('a non-enumerable own member is SCHEMA_INVALID', () => {
  const body = childBody(root)
  Object.defineProperty(body.authority.scope, 'grants', {
    value: ['commerce:checkout'],
    enumerable: false,
    writable: true,
    configurable: true,
  })
  const badChild = unsignable(body as unknown as Record<string, unknown>)
  const checked = verifyAuthorityDelegationChain([root, badChild], chainOptions(root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.ok(codesOf(checked).includes('SCHEMA_INVALID'))
})

test('a cycle inside a facet with an unsupported profile is SCHEMA_INVALID, never unsupported', () => {
  const body = childBody(root)
  const cyclic: unknown[] = []
  cyclic.push(cyclic)
  body.authority.scope = {
    profile: 'aps-hierarchical-v2' as typeof SCOPE_PROFILE_V1,
    grants: cyclic as unknown as string[],
  }
  const badChild = unsignable(body as unknown as Record<string, unknown>)
  const checked = verifyAuthorityDelegationChain([root, badChild], chainOptions(root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID', 'UNSUPPORTED_PROFILE'])
})

test('any Proxy member is SCHEMA_INVALID, whatever its get trap or its descriptors show, and the ledger gives CONFLICT', () => {
  // The descriptor truth is an unsupported profile; the get() trap lies that it is the
  // supported one. A Proxy member is rejected outright, before any of its descriptors
  // are read, so it is invalid rather than judged unsupported by the descriptor value.
  const descriptorSaysUnsupported = { profile: 'aps-hierarchical-v2', grants: ['commerce:checkout'] }
  const lyingToLookSupported = new Proxy(descriptorSaysUnsupported, {
    get(target, prop, receiver) {
      if (prop === 'profile') return SCOPE_PROFILE_V1
      return Reflect.get(target, prop, receiver)
    },
  })
  const invalidBody = childBody(root)
  invalidBody.authority.scope = lyingToLookSupported as unknown as typeof invalidBody.authority.scope
  const invalidChild = unsignable(invalidBody as unknown as Record<string, unknown>)
  const invalidChecked = verifyAuthorityDelegationChain([root, invalidChild], chainOptions(root.delegation_id))
  assert.equal(invalidChecked.state, 'invalid', 'a Proxy member is invalid, never unsupported by its descriptor value')
  assert.ok(codesOf(invalidChecked).includes('SCHEMA_INVALID'))
  const ledgerForUnsupportedView = new InMemoryAuthorityBudgetLedger()
  assert.deepEqual(
    ledgerForUnsupportedView.reserve([root, invalidChild], 'a'.repeat(64), 'iso4217:USD:minor', '1'),
    { ok: false, code: 'CONFLICT' },
  )

  // The descriptor truth is the supported profile, signed as such; the get() trap lies
  // that it is unsupported. A Proxy member is still rejected outright: it must never be
  // judged valid because its descriptors alone would pass.
  const descriptorSaysSupported = { profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] }
  const validBody = childBody(root)
  validBody.authority.scope = descriptorSaysSupported
  const signedChild = signDirectly(validBody, childKeys.privateKey)
  const lyingToLookUnsupported = new Proxy(descriptorSaysSupported, {
    get(target, prop, receiver) {
      if (prop === 'profile') return 'aps-hierarchical-v2'
      return Reflect.get(target, prop, receiver)
    },
  })
  const presentedChild: AuthorityDelegationV1 = {
    ...signedChild,
    authority: { ...signedChild.authority, scope: lyingToLookUnsupported as unknown as typeof signedChild.authority.scope },
  }
  const presentedChecked = verifyAuthorityDelegationChain([root, presentedChild], chainOptions(root.delegation_id))
  assert.equal(presentedChecked.state, 'invalid', 'a Proxy member must never be judged valid by its descriptors')
  assert.ok(codesOf(presentedChecked).includes('SCHEMA_INVALID'))
  const ledgerForSupportedView = new InMemoryAuthorityBudgetLedger()
  assert.deepEqual(
    ledgerForSupportedView.reserve([root, presentedChild], 'a'.repeat(64), 'iso4217:USD:minor', '1'),
    { ok: false, code: 'CONFLICT' },
  )
})

test('a valid chain decoded with JSON.parse in another realm verifies exactly like the same text decoded in this realm, as the whole chain and as individual members', () => {
  const child = issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, {
    now: ROOT_NOT_BEFORE,
    resolveVerificationKey: resolveKeys,
    resolveRevocation: () => 'active',
  })
  const chain = [root, child]
  const inRealmChecked = verifyAuthorityDelegationChain(chain, chainOptions(root.delegation_id))
  assert.equal(inRealmChecked.state, 'valid')

  // The whole chain array, and every member it holds, decoded together in another realm.
  const wholeChainCrossRealm = decodeInNewRealm(chain)
  assert.deepEqual(verifyAuthorityDelegationChain(wholeChainCrossRealm, chainOptions(root.delegation_id)), inRealmChecked)
  const wholeChainLedger = new InMemoryAuthorityBudgetLedger()
  assert.equal(
    wholeChainLedger.reserve(wholeChainCrossRealm, 'a'.repeat(64), 'iso4217:USD:minor', '1').ok,
    true,
  )
  for (const member of wholeChainCrossRealm) {
    assert.deepEqual(validateAuthorityDelegationShape(member), [])
  }

  // Each member decoded individually, in another realm, held in an ordinary array of
  // this realm.
  const perMemberCrossRealm = chain.map(member => decodeInNewRealm(member))
  assert.deepEqual(verifyAuthorityDelegationChain(perMemberCrossRealm, chainOptions(root.delegation_id)), inRealmChecked)
  const perMemberLedger = new InMemoryAuthorityBudgetLedger()
  assert.equal(
    perMemberLedger.reserve(perMemberCrossRealm, 'b'.repeat(64), 'iso4217:USD:minor', '1').ok,
    true,
  )
  for (const member of perMemberCrossRealm) {
    assert.deepEqual(validateAuthorityDelegationShape(member), [])
  }
})

test('both issuers issue byte-identical records for a body or a parent decoded in another realm', () => {
  const body = rootBody()
  const inRealm = issueAuthorityDelegation(body, rootKeys.privateKey)
  const crossRealmIssued = issueAuthorityDelegation(decodeInNewRealm(body), rootKeys.privateKey)
  assert.deepEqual(crossRealmIssued, inRealm)

  const childBodyValue = childBody(root)
  const childOptions = {
    now: ROOT_NOT_BEFORE,
    resolveVerificationKey: resolveKeys,
    resolveRevocation: () => 'active' as const,
  }
  const inRealmChild = issueSubAuthorityDelegation(root, childBodyValue, childKeys.privateKey, childOptions)
  const crossRealmChild = issueSubAuthorityDelegation(
    decodeInNewRealm(root),
    decodeInNewRealm(childBodyValue),
    childKeys.privateKey,
    childOptions,
  )
  assert.deepEqual(crossRealmChild, inRealmChild)
})

test('a Proxy member whose get view widens scope, and a Proxy root whose get view extends not_after, are SCHEMA_INVALID, never valid', () => {
  const trueScope = { profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] }
  const widenedScopeView = new Proxy(trueScope, {
    get(target, prop, receiver) {
      if (prop === 'grants') return ['commerce:*']
      return Reflect.get(target, prop, receiver)
    },
  })
  const bodyWithTrueScope = childBody(root)
  bodyWithTrueScope.authority.scope = trueScope
  const childWithTrueScope = signDirectly(bodyWithTrueScope, childKeys.privateKey)
  const presentedChild: AuthorityDelegationV1 = {
    ...childWithTrueScope,
    authority: { ...childWithTrueScope.authority, scope: widenedScopeView as unknown as typeof childWithTrueScope.authority.scope },
  }
  const checkedScope = verifyAuthorityDelegationChain([root, presentedChild], chainOptions(root.delegation_id))
  assert.equal(checkedScope.state, 'invalid')
  assert.ok(codesOf(checkedScope).includes('SCHEMA_INVALID'))
  assert.equal(isAuthorityDelegationV1(presentedChild), false)

  const trueRootTime = { not_before: ROOT_NOT_BEFORE, not_after: ROOT_NOT_AFTER }
  const widenedTimeView = new Proxy(trueRootTime, {
    get(target, prop, receiver) {
      if (prop === 'not_after') return '2099-01-01T00:00:00.000Z'
      return Reflect.get(target, prop, receiver)
    },
  })
  const rootBodyWithTrueTime = rootBody()
  rootBodyWithTrueTime.authority.time = trueRootTime
  const rootWithTrueTime = signDirectly(rootBodyWithTrueTime, rootKeys.privateKey)
  const presentedRoot: AuthorityDelegationV1 = {
    ...rootWithTrueTime,
    authority: { ...rootWithTrueTime.authority, time: widenedTimeView as unknown as typeof rootWithTrueTime.authority.time },
  }
  const checkedRootTime = verifyAuthorityDelegationChain([presentedRoot], chainOptions(presentedRoot.delegation_id))
  assert.equal(checkedRootTime.state, 'invalid')
  assert.ok(codesOf(checkedRootTime).includes('SCHEMA_INVALID'))
  assert.equal(isAuthorityDelegationV1(presentedRoot), false)
})

/**
 * Exercises one hostile value (a revoked Proxy, or a Proxy whose ownKeys, getPrototypeOf
 * or getOwnPropertyDescriptor trap throws) in every place it could reach an
 * authority-delegation entry point: a chain member, a nested facet, the chain container
 * itself, a ledger chain member, a root-issuer body, and a child-issuer parent. Every
 * placement must give a defined result and never let an exception out of the entry
 * point it reached.
 */
function assertHostileProxyIsAlwaysContained(label: string, memberShaped: unknown, containerShaped: unknown): void {
  assert.doesNotThrow(() => {
    const checked = verifyAuthorityDelegationChain([root, memberShaped], chainOptions(root.delegation_id))
    assert.equal(checked.state, 'invalid', `${label}: chain member`)
    assert.ok(codesOf(checked).includes('SCHEMA_INVALID'), `${label}: chain member`)
  }, `${label}: chain member must not throw`)

  assert.doesNotThrow(() => {
    const body = childBody(root)
    body.authority.scope = memberShaped as unknown as typeof body.authority.scope
    const child = unsignable(body as unknown as Record<string, unknown>)
    const checked = verifyAuthorityDelegationChain([root, child], chainOptions(root.delegation_id))
    assert.equal(checked.state, 'invalid', `${label}: nested facet`)
    assert.ok(codesOf(checked).includes('SCHEMA_INVALID'), `${label}: nested facet`)
  }, `${label}: nested facet must not throw`)

  assert.doesNotThrow(() => {
    const checked = verifyAuthorityDelegationChain(containerShaped as unknown as unknown[], chainOptions(root.delegation_id))
    assert.equal(checked.state, 'invalid', `${label}: chain container`)
    assert.ok(codesOf(checked).includes('SCHEMA_INVALID'), `${label}: chain container`)
  }, `${label}: chain container must not throw`)

  assert.doesNotThrow(() => {
    const ledger = new InMemoryAuthorityBudgetLedger()
    const reserved = ledger.reserve([root, memberShaped] as unknown as AuthorityDelegationV1[], 'a'.repeat(64), 'iso4217:USD:minor', '1')
    assert.deepEqual(reserved, { ok: false, code: 'CONFLICT' }, `${label}: ledger chain member`)
  }, `${label}: ledger chain member must not throw`)

  assert.throws(
    () => issueAuthorityDelegation(memberShaped as unknown as AuthorityDelegationBodyV1, rootKeys.privateKey),
    /\([A-Z_]+\)$/,
    `${label}: root-issuer body`,
  )

  assert.throws(
    () => issueSubAuthorityDelegation(memberShaped as unknown as AuthorityDelegationV1, childBody(root), childKeys.privateKey, {
      now: ROOT_NOT_BEFORE,
      resolveVerificationKey: resolveKeys,
      resolveRevocation: () => 'active',
    }),
    /\([A-Z_]+\)$/,
    `${label}: child-issuer parent`,
  )
}

test('a revoked Proxy, and a Proxy whose ownKeys, getPrototypeOf or getOwnPropertyDescriptor trap throws, each give a defined result everywhere they can appear, never an exception', () => {
  const revokedObject = Proxy.revocable({ profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] }, {})
  revokedObject.revoke()
  const revokedArray = Proxy.revocable([root], {})
  revokedArray.revoke()
  assertHostileProxyIsAlwaysContained('a revoked Proxy', revokedObject.proxy, revokedArray.proxy)

  const throwingHandlers: Array<[string, ProxyHandler<object>]> = [
    ['ownKeys throws', { ownKeys() { throw new Error('ownKeys must not be called') } }],
    ['getPrototypeOf throws', { getPrototypeOf() { throw new Error('getPrototypeOf must not be called') } }],
    ['getOwnPropertyDescriptor throws', { getOwnPropertyDescriptor() { throw new Error('getOwnPropertyDescriptor must not be called') } }],
  ]
  for (const [label, handler] of throwingHandlers) {
    const objectTarget = { profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] }
    const arrayTarget = [root]
    assertHostileProxyIsAlwaysContained(
      `a Proxy whose ${label}`,
      new Proxy(objectTarget, handler),
      new Proxy(arrayTarget, handler),
    )
  }
})

test('a Proxy chain container is invalid even when its own descriptors show a fully valid chain and its get trap disagrees', () => {
  const trueChain = [root]
  const widenedLengthView = new Proxy(trueChain, {
    get(target, prop, receiver) {
      if (prop === 'length') return 999999
      return Reflect.get(target, prop, receiver)
    },
  })
  const checked = verifyAuthorityDelegationChain(widenedLengthView as unknown as unknown[], chainOptions(root.delegation_id))
  assert.notEqual(checked.state, 'valid')
  assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID'])

  const ledger = new InMemoryAuthorityBudgetLedger()
  const reserved = ledger.reserve(widenedLengthView as unknown as AuthorityDelegationV1[], 'a'.repeat(64), 'iso4217:USD:minor', '1')
  assert.deepEqual(reserved, { ok: false, code: 'CONFLICT' })
})

test('a symbol-keyed extra property on a valid record leaves the result unchanged: valid', () => {
  const body = childBody(root)
  ;(body as unknown as Record<symbol, unknown>)[Symbol('extra')] = 'ignored'
  const child = signDirectly(body, childKeys.privateKey)
  const checked = verifyAuthorityDelegationChain([root, child], chainOptions(root.delegation_id))
  assert.equal(checked.state, 'valid')
})

test('the same valid chain built from ordinary plain objects is still valid, with the same records', () => {
  const expectedBody = childBody(root)
  const child = issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, {
    now: ROOT_NOT_BEFORE,
    resolveVerificationKey: resolveKeys,
    resolveRevocation: () => 'active',
  })
  const checked = verifyAuthorityDelegationChain([root, child], chainOptions(root.delegation_id))
  assert.equal(checked.state, 'valid')
  const { delegation_id: _delegationId, signature: _signature, ...childBodyOnly } = child
  assert.deepEqual(childBodyOnly, expectedBody)
})

test('a member named "__proto__" stays a member of the snapshot, so a signed record carrying one is still rejected by the closed schema', () => {
  // JSON.parse creates "__proto__" as an ordinary own member. Copying it by assignment
  // would set the copy's prototype instead and drop the member; the snapshot must keep it.
  const text = JSON.stringify(root)
  for (const [label, record] of [
    ['top level, value null', JSON.parse(`${text.slice(0, -1)},"__proto__":null}`)],
    ['top level, value an object', JSON.parse(`${text.slice(0, -1)},"__proto__":{"x":1}}`)],
    ['inside authority, value 1', JSON.parse(text.replace('"authority":{', '"authority":{"__proto__":1,'))],
    ['inside a facet, value "x"', JSON.parse(text.replace('"depth":{', '"depth":{"__proto__":"x",'))],
  ] as [string, AuthorityDelegationV1][]) {
    const checked = verifyAuthorityDelegationChain([record], chainOptions(root.delegation_id))
    assert.equal(checked.state, 'invalid', label)
    assert.equal(checked.failures[0]?.code, 'SCHEMA_INVALID', label)
    const ledger = new InMemoryAuthorityBudgetLedger()
    assert.equal(ledger.reserve([record], 'a'.repeat(64), 'iso4217:USD:minor', '1').code, 'CONFLICT', label)
  }
  const bodyWithProto = JSON.parse(`${JSON.stringify(rootBody()).slice(0, -1)},"__proto__":null}`)
  assert.throws(() => issueAuthorityDelegation(bodyWithProto, rootKeys.privateKey), /\(SCHEMA_INVALID\)$/)
})

test('an issued record keeps the body member order, followed by delegation_id and signature', () => {
  const body = rootBody()
  const issued = issueAuthorityDelegation(body, rootKeys.privateKey)
  assert.deepEqual(Object.keys(issued), [...Object.keys(body), 'delegation_id', 'signature'])
  assert.deepEqual(Object.keys(issued.authority), Object.keys(body.authority))
})
