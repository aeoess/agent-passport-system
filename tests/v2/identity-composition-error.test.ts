// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// IdentityCompositionError — A2A composition-contract §5 / §6.3 conformance.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  IdentityCompositionError,
  assertKeyPurpose,
} from '../../src/index.js'
import type {
  IdentityCompositionErrorReason,
  IdentityCompositionErrorContext,
} from '../../src/index.js'
import type { DIDDocument } from '../../src/types/did.js'

const KEY_ASSERT = 'did:aps:abc#key-assert'
const KEY_DELEGATE = 'did:aps:abc#key-delegate'
const KEY_INVOKE = 'did:aps:abc#key-invoke'
const KEY_AUTH = 'did:aps:abc#key-auth'
const KEY_AGREE = 'did:aps:abc#key-agree'
const KEY_UNKNOWN = 'did:aps:abc#key-not-published'

function fullDoc() {
  return {
    assertionMethod: [KEY_ASSERT],
    authentication: [KEY_AUTH],
    capabilityDelegation: [KEY_DELEGATE],
    keyAgreement: [KEY_AGREE],
    capabilityInvocation: [KEY_INVOKE],
  }
}

describe('IdentityCompositionError — A2A §5 error shape', () => {
  it('all four reason enum values are constructable and preserve .reason', () => {
    const reasons: IdentityCompositionErrorReason[] = [
      'rotation_window_closed',
      'emergency_revoked',
      'key_purpose_violation',
      'tampered',
    ]
    for (const reason of reasons) {
      const err = new IdentityCompositionError(reason, `test ${reason}`)
      assert.equal(err.reason, reason)
      assert.equal(err.message, `test ${reason}`)
      assert.equal(err.name, 'IdentityCompositionError')
      assert.ok(err instanceof IdentityCompositionError)
      assert.ok(err instanceof Error)
    }
  })

  it('preserves context payload on the error instance', () => {
    const ctx: IdentityCompositionErrorContext = {
      keyId: KEY_ASSERT,
      expectedPurpose: 'assertionMethod',
      foundIn: ['capabilityDelegation'],
      extraField: 'extra',
    }
    const err = new IdentityCompositionError('key_purpose_violation', 'msg', ctx)
    assert.deepEqual(err.context, ctx)
    assert.equal(err.context?.extraField, 'extra')
  })

  it('error is a real Error subclass (instanceof + prototype chain)', () => {
    const err = new IdentityCompositionError('tampered', 'bad sig')
    assert.ok(err instanceof Error)
    assert.ok(err instanceof IdentityCompositionError)
    assert.equal(err.name, 'IdentityCompositionError')
    // Prototype chain explicit per the constructor's setPrototypeOf call.
    assert.equal(Object.getPrototypeOf(err), IdentityCompositionError.prototype)
  })
})

describe('assertKeyPurpose — §6.3 verification relationship enforcement', () => {
  it('does not throw when keyId is in the expected purpose list', () => {
    assert.doesNotThrow(() => assertKeyPurpose(KEY_ASSERT, fullDoc(), 'assertionMethod'))
    assert.doesNotThrow(() => assertKeyPurpose(KEY_DELEGATE, fullDoc(), 'capabilityDelegation'))
    assert.doesNotThrow(() => assertKeyPurpose(KEY_INVOKE, fullDoc(), 'capabilityInvocation'))
    assert.doesNotThrow(() => assertKeyPurpose(KEY_AUTH, fullDoc(), 'authentication'))
    assert.doesNotThrow(() => assertKeyPurpose(KEY_AGREE, fullDoc(), 'keyAgreement'))
  })

  it('throws IdentityCompositionError with reason=key_purpose_violation when keyId not in expected purpose', () => {
    let caught: unknown
    try {
      assertKeyPurpose(KEY_DELEGATE, fullDoc(), 'assertionMethod')
    } catch (e) {
      caught = e
    }
    assert.ok(caught instanceof IdentityCompositionError, 'expected IdentityCompositionError')
    assert.equal((caught as IdentityCompositionError).reason, 'key_purpose_violation')
    assert.equal((caught as IdentityCompositionError).name, 'IdentityCompositionError')
  })

  it('context.foundIn enumerates other purposes the keyId is in (cross-purpose detection)', () => {
    let caught: IdentityCompositionError | undefined
    try {
      assertKeyPurpose(KEY_DELEGATE, fullDoc(), 'assertionMethod')
    } catch (e) {
      caught = e as IdentityCompositionError
    }
    assert.ok(caught)
    assert.equal(caught.context?.keyId, KEY_DELEGATE)
    assert.equal(caught.context?.expectedPurpose, 'assertionMethod')
    assert.deepEqual(caught.context?.foundIn, ['capabilityDelegation'])
    assert.match(caught.message, /not authorized for assertionMethod/)
    assert.match(caught.message, /found in: capabilityDelegation/)
  })

  it('context.foundIn is empty array and message says "not present" when keyId is unknown to the document', () => {
    let caught: IdentityCompositionError | undefined
    try {
      assertKeyPurpose(KEY_UNKNOWN, fullDoc(), 'assertionMethod')
    } catch (e) {
      caught = e as IdentityCompositionError
    }
    assert.ok(caught)
    assert.deepEqual(caught.context?.foundIn, [])
    assert.match(caught.message, /not present in DID document/)
  })

  it('handles a DIDDocument-shaped object with optional fields absent', () => {
    // Minimal doc — no keyAgreement, capabilityInvocation, capabilityDelegation.
    const minimal = {
      assertionMethod: [KEY_ASSERT],
      authentication: [KEY_AUTH],
    }
    assert.doesNotThrow(() => assertKeyPurpose(KEY_ASSERT, minimal, 'assertionMethod'))
    let caught: IdentityCompositionError | undefined
    try {
      assertKeyPurpose(KEY_ASSERT, minimal, 'capabilityDelegation')
    } catch (e) {
      caught = e as IdentityCompositionError
    }
    assert.ok(caught)
    assert.equal(caught.reason, 'key_purpose_violation')
    assert.deepEqual(caught.context?.foundIn, ['assertionMethod'])
  })
})

describe('DIDDocument type — five W3C verification relationships compile', () => {
  it('accepts a fully-populated DIDDocument with all five verification relationships', () => {
    const doc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: 'did:aps:abc',
      controller: 'did:aps:abc',
      verificationMethod: [
        {
          id: KEY_ASSERT,
          type: 'Ed25519VerificationKey2020',
          controller: 'did:aps:abc',
          publicKeyMultibase: 'z6Mkabcdef',
        },
      ],
      authentication: [KEY_AUTH],
      assertionMethod: [KEY_ASSERT],
      capabilityDelegation: [KEY_DELEGATE],
      keyAgreement: [KEY_AGREE],
      capabilityInvocation: [KEY_INVOKE],
      created: '2026-05-01T00:00:00.000Z',
      updated: '2026-05-01T00:00:00.000Z',
    }
    // Compile-time success implies the type accepts all five relationships.
    // Runtime spot-check that the assertion path picks the right list.
    assert.equal(doc.assertionMethod.length, 1)
    assert.equal(doc.keyAgreement?.length, 1)
    assert.equal(doc.capabilityInvocation?.length, 1)
    assert.doesNotThrow(() => assertKeyPurpose(KEY_AGREE, doc, 'keyAgreement'))
    assert.doesNotThrow(() => assertKeyPurpose(KEY_INVOKE, doc, 'capabilityInvocation'))
  })
})
