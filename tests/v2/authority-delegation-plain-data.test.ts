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

/** JSON.rawJSON where the runtime has it; a runtime without it cannot make a raw JSON
 *  object at all. */
const rawJSON = (JSON as unknown as { rawJSON?: (text: string) => object }).rawJSON

function exoticValues(): Array<[string, unknown]> {
  const values: Array<[string, unknown]> = [
    ['a Map', new Map([['k', 'v']])],
    ['a Date', new Date('2026-01-01T00:00:00.000Z')],
    ['a Uint8Array', new Uint8Array([1, 2, 3])],
    ['a class instance', new OpaqueHandle()],
    ['a Boolean wrapper whose prototype is Object.prototype', Object.setPrototypeOf(new Boolean(false), Object.prototype)],
    ['a Number wrapper whose prototype is null', Object.setPrototypeOf(new Number(7), null)],
  ]
  if (rawJSON) values.push(['a raw JSON object', rawJSON('"commerce:*"')])
  return values
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

/** A null-prototype object whose own "constructor" data property names `constructorFn`:
 *  structurally a look-alike for an intrinsic Object.prototype under the old grandparent
 *  test, since its own prototype is null, but never one under the realm-intrinsic
 *  identity test, since `constructorFn`'s own "prototype" property is not this object. */
function objectPrototypeLookAlike(constructorFn: Function): any {
  const lookAlike = Object.create(null)
  Object.defineProperty(lookAlike, 'constructor', { value: constructorFn })
  return lookAlike
}

/** A record shaped like a valid child of `root`, but with wider scope grants, used only
 *  as the value a forged toJSON hands back; nothing in this file's fixed code ever calls
 *  toJSON, so this never actually reaches a verifier through it. */
function wideningChildRecord(): AuthorityDelegationV1 {
  const body = childBody(root)
  body.authority.scope = { profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] }
  return unsignable(body as unknown as Record<string, unknown>)
}

/** `wrapper`, re-prototyped to `prototype`, carrying every own member of `source` as an
 *  own enumerable data property: its own members read exactly like `source`, while
 *  JSON.stringify serializes a Boolean, Number, String or BigInt wrapper by the
 *  primitive it holds, or throws. A Symbol wrapper has no such case in JSON.stringify
 *  and serializes by its own members; it is refused because a JSON parser cannot
 *  produce it, not because the two views disagree. */
function wrapperWithMembers(wrapper: object, prototype: object | null, source: object): any {
  Object.setPrototypeOf(wrapper, prototype)
  for (const key of Object.keys(source)) {
    Object.defineProperty(wrapper, key, {
      value: (source as Record<string, unknown>)[key],
      writable: true,
      enumerable: true,
      configurable: true,
    })
  }
  return wrapper
}

/**
 * Exercises one hostile construction, never a Proxy, at every place an
 * authority-delegation entry point can receive it. `corrupt` applies the construction
 * to a fresh copy of a record or body, mutating it or wrapping it, and returns the
 * hostile value. Each placement starts from a value that entry point accepts, checked
 * first as a control, so each assertion that follows fails whenever the construction
 * itself is accepted:
 * - a signed child of `root`, as a chain member, as the argument to
 *   isAuthorityDelegationV1, and as a ledger chain member, where the uncorrupted child
 *   is valid, a v1 record, and reserved against;
 * - a bare root body carrying no delegation_id or signature, as the root-issuer body,
 *   where the uncorrupted body is issued;
 * - the signed root, as the child-issuer parent at a `now` inside its window, where the
 *   uncorrupted parent has the child issued.
 * Every hostile placement must give invalid with SCHEMA_INVALID, false, CONFLICT, or a
 * SCHEMA_INVALID refusal from the issuer.
 */
function assertPlainDataAttackIsRejected(label: string, corrupt: (target: any) => unknown): void {
  const signedChild = signDirectly(childBody(root), childKeys.privateKey)
  const childIssuerOptions = {
    now: NOW,
    resolveVerificationKey: resolveKeys,
    resolveRevocation: () => 'active' as const,
  }

  const controlChecked = verifyAuthorityDelegationChain([root, structuredClone(signedChild)], chainOptions(root.delegation_id))
  assert.equal(controlChecked.state, 'valid', `${label}: control verify`)
  assert.equal(isAuthorityDelegationV1(structuredClone(signedChild)), true, `${label}: control isAuthorityDelegationV1`)
  assert.equal(
    new InMemoryAuthorityBudgetLedger().reserve([root, structuredClone(signedChild)], 'a'.repeat(64), 'iso4217:USD:minor', '1').code,
    'RESERVED',
    `${label}: control ledger`,
  )
  assert.doesNotThrow(() => issueAuthorityDelegation(rootBody(), rootKeys.privateKey), `${label}: control root issuer`)
  assert.doesNotThrow(
    () => issueSubAuthorityDelegation(structuredClone(root), childBody(root), childKeys.privateKey, childIssuerOptions),
    `${label}: control child issuer`,
  )

  const hostileChild = corrupt(structuredClone(signedChild))
  const checked = verifyAuthorityDelegationChain([root, hostileChild], chainOptions(root.delegation_id))
  assert.equal(checked.state, 'invalid', `${label}: verify`)
  assert.ok(codesOf(checked).includes('SCHEMA_INVALID'), `${label}: verify`)

  assert.equal(isAuthorityDelegationV1(corrupt(structuredClone(signedChild))), false, `${label}: isAuthorityDelegationV1`)

  assert.deepEqual(
    new InMemoryAuthorityBudgetLedger().reserve(
      [root, corrupt(structuredClone(signedChild))] as unknown as AuthorityDelegationV1[],
      'a'.repeat(64),
      'iso4217:USD:minor',
      '1',
    ),
    { ok: false, code: 'CONFLICT' },
    `${label}: ledger`,
  )

  assert.throws(
    () => issueAuthorityDelegation(corrupt(rootBody()) as AuthorityDelegationBodyV1, rootKeys.privateKey),
    /\(SCHEMA_INVALID\)$/,
    `${label}: root-issuer body`,
  )
  assert.throws(
    () => issueSubAuthorityDelegation(
      corrupt(structuredClone(root)) as AuthorityDelegationV1,
      childBody(root),
      childKeys.privateKey,
      childIssuerOptions,
    ),
    /\(SCHEMA_INVALID\)$/,
    `${label}: child-issuer parent`,
  )
}

test('an own symbol-keyed property on a record, on a nested object, or on an array is SCHEMA_INVALID everywhere', () => {
  assertPlainDataAttackIsRejected('own symbol on the record', target => {
    target[Symbol('extra')] = 'ignored'
    return target
  })
  assertPlainDataAttackIsRejected('own symbol on a nested object', target => {
    target.authority.scope[Symbol('extra')] = 'ignored'
    return target
  })
  assertPlainDataAttackIsRejected('own symbol on an array', target => {
    target.authority.scope.grants[Symbol('extra')] = 'ignored'
    return target
  })
})

test('a record whose prototype is Object.create(null) carrying a toJSON that returns a wider record is SCHEMA_INVALID everywhere', () => {
  assertPlainDataAttackIsRejected('null-prototype fake Object.prototype carrying toJSON', target => {
    const fakeProto = Object.create(null)
    fakeProto.toJSON = () => wideningChildRecord()
    return Object.setPrototypeOf({ ...target }, fakeProto)
  })
})

test('grants held in an array whose prototype is an array whose own prototype has a null prototype and carries toJSON is SCHEMA_INVALID everywhere', () => {
  assertPlainDataAttackIsRejected('forged Array.prototype whose own prototype has a null prototype, carrying toJSON', target => {
    const fakeArrayProto: any = []
    Object.setPrototypeOf(fakeArrayProto, Object.create(null))
    Object.defineProperty(fakeArrayProto, 'toJSON', { value: () => ['*'] })
    Object.setPrototypeOf(target.authority.scope.grants, fakeArrayProto)
    return target
  })
})

test("an object whose prototype is a look-alike with constructor set to this realm's Object is SCHEMA_INVALID everywhere", () => {
  assertPlainDataAttackIsRejected("look-alike prototype naming this realm's Object", target => {
    const fakeProto = objectPrototypeLookAlike(Object)
    fakeProto.toJSON = () => wideningChildRecord()
    return Object.setPrototypeOf({ ...target }, fakeProto)
  })
})

test("an object whose prototype is a look-alike with constructor set to another realm's real Object is SCHEMA_INVALID everywhere", () => {
  const vmObjectConstructor = vm.runInNewContext('Object')
  assertPlainDataAttackIsRejected("look-alike prototype naming another realm's real Object", target => {
    const fakeProto = objectPrototypeLookAlike(vmObjectConstructor)
    fakeProto.toJSON = () => wideningChildRecord()
    return Object.setPrototypeOf({ ...target }, fakeProto)
  })
})

test('a class instance whose class prototype has a null prototype is SCHEMA_INVALID everywhere', () => {
  class NullProtoFacet {
    constructor(source: Record<string, unknown>) { Object.assign(this, source) }
  }
  Object.setPrototypeOf(NullProtoFacet.prototype, null)
  ;(NullProtoFacet.prototype as any).toJSON = () => ({ profile: SCOPE_PROFILE_V1, grants: ['commerce:*'] })
  assertPlainDataAttackIsRejected('class instance whose class prototype has a null prototype', target => {
    target.authority.scope = new NullProtoFacet(target.authority.scope)
    return target
  })
})

test('grants with an own Symbol.iterator yielding "*" is SCHEMA_INVALID everywhere', () => {
  assertPlainDataAttackIsRejected('grants array carrying an own Symbol.iterator', target => {
    Object.defineProperty(target.authority.scope.grants, Symbol.iterator, {
      value: function* () { yield '*' },
      enumerable: false,
      configurable: true,
    })
    return target
  })
})

test('an array carrying an own callable toJSON, or an own toJSON accessor, is SCHEMA_INVALID everywhere', () => {
  assertPlainDataAttackIsRejected('grants array carrying an own callable toJSON', target => {
    Object.defineProperty(target.authority.scope.grants, 'toJSON', {
      value: () => ['*'],
      enumerable: false,
      configurable: true,
    })
    return target
  })
  assertPlainDataAttackIsRejected('grants array carrying an own toJSON accessor', target => {
    Object.defineProperty(target.authority.scope.grants, 'toJSON', {
      get: () => () => ['*'],
      configurable: true,
    })
    return target
  })
})

test('an own toJSON that is not callable is data: dropped from an array, kept in an object, exactly as JSON.stringify treats it', () => {
  const child = signDirectly(childBody(root), childKeys.privateKey)

  // On an array: JSON.stringify serializes the array by its indices and ignores the
  // member, and so does the snapshot.
  const arrayCase = structuredClone(child)
  Object.defineProperty(arrayCase.authority.scope.grants, 'toJSON', {
    value: 'not callable',
    writable: true,
    enumerable: true,
    configurable: true,
  })
  assert.equal(
    JSON.stringify(arrayCase.authority.scope.grants),
    JSON.stringify(child.authority.scope.grants),
  )
  let seen: AuthorityDelegationV1 | undefined
  const checked = verifyAuthorityDelegationChain([root, arrayCase], {
    ...chainOptions(root.delegation_id),
    resolveRevocation: candidate => { if (candidate.parent_delegation_id !== null) seen = candidate; return 'active' },
  })
  assert.equal(checked.state, 'valid')
  assert.deepEqual(Object.getOwnPropertyNames(seen!.authority.scope.grants), ['0', 'length'])

  // On an object: JSON.stringify serializes the member, and so does the snapshot, so a
  // record carrying one is judged by the closed schema like any other extra member.
  const objectCase = mutableRootBody()
  ;(objectCase.authority as Record<string, unknown>).toJSON = 'not callable'
  const objectRecord = unsignable(objectCase)
  assert.ok(JSON.stringify(objectRecord).includes('"toJSON":"not callable"'))
  const objectChecked = verifyAuthorityDelegationChain([objectRecord], chainOptions(objectRecord.delegation_id))
  assert.equal(objectChecked.state, 'invalid')
  assert.ok(codesOf(objectChecked).includes('SCHEMA_INVALID'))
})

test('a chain container carrying an own property that is neither an index nor "length" is read like any other plain array', () => {
  const properChild = issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, {
    now: ROOT_NOT_BEFORE,
    resolveVerificationKey: resolveKeys,
    resolveRevocation: () => 'active',
  })
  const container: unknown[] = [root, properChild]
  Object.defineProperty(container, 'extra', { value: 'ignored', writable: true, enumerable: true, configurable: true })

  assert.equal(verifyAuthorityDelegationChain(container, chainOptions(root.delegation_id)).state, 'valid')
  assert.equal(
    new InMemoryAuthorityBudgetLedger().reserve(container as AuthorityDelegationV1[], 'a'.repeat(64), 'iso4217:USD:minor', '1').code,
    'RESERVED',
  )

  const hostileContainer: unknown[] = [root, properChild]
  Object.defineProperty(hostileContainer, 'toJSON', { value: () => [root], configurable: true })
  assert.equal(verifyAuthorityDelegationChain(hostileContainer, chainOptions(root.delegation_id)).state, 'invalid')
})

test('an array member that is a hole, an accessor or non-enumerable is SCHEMA_INVALID everywhere', () => {
  assertPlainDataAttackIsRejected('grants array with a hole', target => {
    const sparse: string[] = []
    sparse[1] = 'commerce:checkout'
    target.authority.scope.grants = sparse
    return target
  })
  assertPlainDataAttackIsRejected('grants array whose index 0 is an accessor', target => {
    const grants: string[] = []
    Object.defineProperty(grants, '0', { get: () => 'commerce:checkout', enumerable: true, configurable: true })
    Object.defineProperty(grants, 'length', { value: 1, writable: true })
    target.authority.scope.grants = grants
    return target
  })
  assertPlainDataAttackIsRejected('grants array whose index 0 is non-enumerable', target => {
    const grants = ['commerce:checkout']
    Object.defineProperty(grants, '0', { enumerable: false })
    target.authority.scope.grants = grants
    return target
  })
})

test('an own property of an array that is neither an index nor "length" is left out of the snapshot, exactly as JSON.stringify leaves it out', () => {
  const body = childBody(root)
  const child = signDirectly(body, childKeys.privateKey)
  const withExtra = structuredClone(child)
  Object.defineProperty(withExtra.authority.scope.grants, 'extra', {
    value: 'not an index',
    writable: true,
    enumerable: true,
    configurable: true,
  })
  assert.deepEqual(Object.getOwnPropertyNames(withExtra.authority.scope.grants), ['0', 'length', 'extra'])
  assert.equal(
    JSON.stringify(withExtra.authority.scope.grants),
    JSON.stringify(child.authority.scope.grants),
  )

  let seen: AuthorityDelegationV1 | undefined
  const checked = verifyAuthorityDelegationChain([root, withExtra], {
    ...chainOptions(root.delegation_id),
    resolveRevocation: candidate => { if (candidate.parent_delegation_id !== null) seen = candidate; return 'active' },
  })
  assert.equal(checked.state, 'valid')
  assert.deepEqual(Object.getOwnPropertyNames(seen!.authority.scope.grants), ['0', 'length'])
})

test('a record, a facet or a facet member held in a wrapper object with an Object.prototype or null prototype is SCHEMA_INVALID everywhere', () => {
  assertPlainDataAttackIsRejected('record held in a Boolean wrapper whose prototype is Object.prototype', target =>
    wrapperWithMembers(new Boolean(false), Object.prototype, target))
  assertPlainDataAttackIsRejected('authority held in a Number wrapper whose prototype is null', target => {
    target.authority = wrapperWithMembers(new Number(7), null, target.authority)
    return target
  })
  assertPlainDataAttackIsRejected('spend held in a BigInt wrapper whose prototype is Object.prototype', target => {
    target.authority.spend = wrapperWithMembers(Object(BigInt(1)), Object.prototype, target.authority.spend)
    return target
  })
  assertPlainDataAttackIsRejected('scope held in a Symbol wrapper whose prototype is null', target => {
    target.authority.scope = wrapperWithMembers(Object(Symbol('held')), null, target.authority.scope)
    return target
  })
  assertPlainDataAttackIsRejected('scope held in a Boolean wrapper from another realm', target => {
    target.authority.scope = wrapperWithMembers(vm.runInNewContext('new Boolean(true)'), Object.prototype, target.authority.scope)
    return target
  })
})

test('a callback that writes to the record it is given cannot change what the checks after it read', () => {
  const wideningBody = childBody(root)
  wideningBody.authority.scope = { profile: SCOPE_PROFILE_V1, grants: ['payments:*'] }
  const wideningChild = signDirectly(wideningBody, childKeys.privateKey)

  // Control: the same child under a parent that really does allow it is valid, so the
  // assertions below fail if a callback's writes reach the attenuation check.
  const openRootBody = rootBody()
  openRootBody.authority.scope = { profile: SCOPE_PROFILE_V1, grants: ['*'] }
  const openRoot = issueAuthorityDelegation(openRootBody, rootKeys.privateKey)
  const openChildBody = childBody(openRoot)
  openChildBody.authority.scope = { profile: SCOPE_PROFILE_V1, grants: ['payments:*'] }
  const openChild = signDirectly(openChildBody, childKeys.privateKey)
  assert.equal(
    verifyAuthorityDelegationChain([openRoot, openChild], chainOptions(openRoot.delegation_id)).state,
    'valid',
  )

  const honest = verifyAuthorityDelegationChain([root, wideningChild], chainOptions(root.delegation_id))
  assert.equal(honest.state, 'invalid')
  assert.deepEqual(codesOf(honest), ['SCOPE_WIDENING'])

  let given: AuthorityDelegationV1 | undefined
  const mutating = verifyAuthorityDelegationChain([root, wideningChild], {
    ...chainOptions(root.delegation_id),
    trustRoot: candidate => {
      given = candidate
      ;(candidate as AuthorityDelegationV1).authority.scope.grants = ['*']
      return true
    },
  })
  assert.equal(mutating.state, 'invalid')
  assert.deepEqual(codesOf(mutating), ['SCOPE_WIDENING'])
  assert.notEqual(given, root)
  assert.deepEqual(root.authority.scope.grants, ['commerce:*'])

  // The verifier's revocation callback runs after every other check of that member, so
  // a write there cannot change this function's own reads; it is handed a copy anyway.
  // The child issuer is where a revocation callback's write does reach later checks.
  const issuerOptions = { now: NOW, resolveVerificationKey: resolveKeys, resolveRevocation: () => 'active' as const }
  assert.doesNotThrow(() => issueSubAuthorityDelegation(openRoot, openChildBody, childKeys.privateKey, {
    ...issuerOptions,
    resolveVerificationKey: (_issuer: string, method: string) =>
      method === openRoot.verification_method ? rootKeys.publicKey : resolveKeys(_issuer, method),
  }))
  assert.throws(
    () => issueSubAuthorityDelegation(root, wideningBody, childKeys.privateKey, {
      ...issuerOptions,
      resolveRevocation: parent => {
        ;(parent as AuthorityDelegationV1).authority.scope.grants = ['*']
        return 'active'
      },
    }),
    /\(SCOPE_WIDENING\)$/,
  )
})

test('the child issuer refuses with a coded error when its options object cannot be read', () => {
  const body = childBody(root)
  const good = { now: NOW, resolveVerificationKey: resolveKeys, resolveRevocation: () => 'active' as const }
  assert.doesNotThrow(() => issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, good))

  for (const [label, options] of [
    ['a throwing now getter', { get now(): string { throw new Error('trap') }, resolveVerificationKey: resolveKeys, resolveRevocation: () => 'active' as const }],
    ['a throwing resolver getter', { now: NOW, get resolveVerificationKey(): never { throw new Error('trap') }, resolveRevocation: () => 'active' as const }],
    ['a Proxy whose get trap throws', new Proxy({}, { get() { throw new Error('trap') } })],
    ['no options at all', undefined],
  ] as const) {
    assert.throws(
      () => issueSubAuthorityDelegation(root, body, childKeys.privateKey, options as never),
      /\([A-Z_]+\)$/,
      label,
    )
  }
})

test('the verifier reads each member of its options object exactly once, and a throwing options getter is a defined result', () => {
  let reads = 0
  const twoFaced = {
    get now() {
      reads += 1
      return reads === 1 ? '2026-07-19T00:00:00.000Z' : NOW
    },
    resolveVerificationKey: resolveKeys,
    trustRoot: (candidate: AuthorityDelegationV1) => candidate.delegation_id === root.delegation_id,
    resolveRevocation: () => 'active' as const,
  }
  const checked = verifyAuthorityDelegationChain([root], twoFaced as unknown as AuthorityChainVerificationOptions)
  assert.equal(reads, 1)
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['EXPIRED'])

  const throwing = new Proxy({}, { get() { throw new Error('boom') } }) as AuthorityChainVerificationOptions
  const contained = verifyAuthorityDelegationChain([root], throwing)
  assert.equal(contained.state, 'invalid')
  assert.deepEqual(codesOf(contained), ['NONCANONICAL_VALUE'])
})

test('a chain container with an own Symbol.iterator is SCHEMA_INVALID, and the ledger gives CONFLICT', () => {
  const properChild = issueSubAuthorityDelegation(root, childBody(root), childKeys.privateKey, {
    now: ROOT_NOT_BEFORE,
    resolveVerificationKey: resolveKeys,
    resolveRevocation: () => 'active',
  })
  // The control: the same two records in a plain container are a valid chain, and the
  // ledger reserves against them. Only verify and the ledger take a chain container, so
  // only they can tell the hostile container from this one; isAuthorityDelegationV1 and
  // the two issuers take a record, and refuse any array whatever its own symbols.
  const plainContainer: unknown[] = [root, properChild]
  assert.equal(verifyAuthorityDelegationChain(plainContainer, chainOptions(root.delegation_id)).state, 'valid')
  assert.equal(
    new InMemoryAuthorityBudgetLedger().reserve(plainContainer as AuthorityDelegationV1[], 'a'.repeat(64), 'iso4217:USD:minor', '1').code,
    'RESERVED',
  )

  const hostileContainer: unknown[] = [root, properChild]
  Object.defineProperty(hostileContainer, Symbol.iterator, {
    value: function* () { yield hostileContainer[0] },
  })

  const checked = verifyAuthorityDelegationChain(hostileContainer, chainOptions(root.delegation_id))
  assert.equal(checked.state, 'invalid')
  assert.ok(codesOf(checked).includes('SCHEMA_INVALID'))

  assert.deepEqual(
    new InMemoryAuthorityBudgetLedger().reserve(hostileContainer as unknown as AuthorityDelegationV1[], 'a'.repeat(64), 'iso4217:USD:minor', '1'),
    { ok: false, code: 'CONFLICT' },
  )
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

/** Builds node_0 = [] and node_i = [node_(i-1), node_(i-1)]: d+1 distinct arrays sharing
 *  references so that there are 2^d root-to-leaf paths through them, without a cycle. */
function sharedReferenceStructure(depth: number): unknown {
  let node: unknown = []
  for (let i = 0; i < depth; i++) node = [node, node]
  return node
}

test('a depth-40 shared-reference structure inside an extra top-level member is rejected within 1 second, the same result any extra member gives', () => {
  const withDeepExtra = {
    ...unsignable(childBody(root) as unknown as Record<string, unknown>),
    extra_member: sharedReferenceStructure(40),
  } as unknown as AuthorityDelegationV1
  const start = process.hrtime.bigint()
  const checked = verifyAuthorityDelegationChain([root, withDeepExtra], chainOptions(root.delegation_id))
  const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6
  assert.ok(elapsedMs < 1000, `expected under 1000 ms, took ${elapsedMs.toFixed(1)} ms`)
  assert.equal(checked.state, 'invalid')

  const withShallowExtra = {
    ...unsignable(childBody(root) as unknown as Record<string, unknown>),
    extra_member: 'x',
  } as unknown as AuthorityDelegationV1
  const reference = verifyAuthorityDelegationChain([root, withShallowExtra], chainOptions(root.delegation_id))
  assert.deepEqual(codesOf(checked), codesOf(reference))
})

test('a 5,000,000-element array as the chain container is rejected within 100 ms, the same result any over-length chain gives', () => {
  const hugeChain = new Array(5_000_000).fill(root) as unknown as AuthorityDelegationV1[]
  const start = process.hrtime.bigint()
  const checked = verifyAuthorityDelegationChain(hugeChain, chainOptions(root.delegation_id))
  const elapsedMs = Number(process.hrtime.bigint() - start) / 1e6
  assert.ok(elapsedMs < 100, `expected under 100 ms, took ${elapsedMs.toFixed(1)} ms`)
  assert.equal(checked.state, 'invalid')
  assert.deepEqual(codesOf(checked), ['SCHEMA_INVALID'])

  const smallOverLength = new Array(257).fill(root) as unknown as AuthorityDelegationV1[]
  const reference = verifyAuthorityDelegationChain(smallOverLength, chainOptions(root.delegation_id))
  assert.deepEqual(codesOf(checked), codesOf(reference))
})
