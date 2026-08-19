// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Phase 2B: shared canonicalization helpers split into read/write twins
// ══════════════════════════════════════════════════════════════════
// Each helper below canonicalized on behalf of BOTH a signing path and a
// verification path. Guarding one in place would have refused to rebuild the
// preimage of an artifact signed before the APS unsafe-integer rule existed, so
// each gained a *ForWrite twin that only the constructing callers use.
//
// Four properties per twin:
//   1. safe input: twin output byte-identical to the original
//   2. top-level unsafe integer refused, at the exact path
//   3. nested unsafe integer refused, at the exact nested path
//   4. the original stays UNRESTRICTED, which is what keeps history verifiable
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import { canonicalize, canonicalizeForWrite } from '../src/core/canonical.js'
import { canonicalizeJCS, canonicalizeJCSForWrite } from '../src/core/canonical-jcs.js'
import { UnsafeIntegerError } from '../src/core/write-policy.js'

import { computeAttestationBundleHash, computeAttestationBundleHashForWrite } from '../src/core/attestation.js'
import { computeMemberDigest, computeMemberDigestForWrite } from '../src/core/evidence-bundle.js'
import { hashExecutionReceipt, hashExecutionReceiptForWrite } from '../src/core/reversibility-fold.js'
import { hashObject, hashObjectForWrite } from '../src/v2/bridge.js'
import { leafHash, leafHashForWrite } from '../src/v2/attribution-settlement/merkle.js'
import { residualLeafHashHex, residualLeafHashHexForWrite } from '../src/v2/attribution-settlement/aggregate.js'
import { settlementSigningPayload, settlementSigningPayloadForWrite } from '../src/v2/attribution-settlement/sign.js'
import { hashAxisLeaf, hashAxisLeafForWrite } from '../src/v2/attribution-primitive/canonical.js'
import { receiptCore, receiptCoreForWrite } from '../src/v2/attribution-consent/create.js'
import { canonicalCoSignBody, canonicalCoSignBodyForWrite } from '../src/v2/human-oversight/index.js'
import { canonicalNoSig, canonicalNoSigForWrite } from '../src/v2/read_fidelity_receipt/receipt.js'
import {
  canonicalizeReceiptForId, canonicalizeReceiptForIdForWrite,
  canonicalizeReceiptForSig, canonicalizeReceiptForSigForWrite,
  canonicalizeDenialForId, canonicalizeDenialForIdForWrite,
  canonicalizeDenialForSig, canonicalizeDenialForSigForWrite,
} from '../src/v2/payment-rails/canonicalize.js'
import { authorityDelegationIdInput, authorityDelegationIdInputForWrite } from '../src/v2/authority-delegation/canonical.js'
import { computeCpaRef, computeCpaRefForWrite } from '../src/v2/context-provenance/cpa.js'

const SAFE = 9007199254740991
const UNSAFE = 9007199254740992

type Fn = (v: never) => unknown
const call = (f: Fn, v: unknown): unknown => (f as unknown as (x: unknown) => unknown)(v)

interface Split {
  label: string
  orig: Fn
  twin: Fn
  safe: unknown
  unsafe: unknown
  path: string
}

const SPLITS: Split[] = [
  { label: 'hashObject', orig: hashObject as Fn, twin: hashObjectForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'computeAttestationBundleHash', orig: computeAttestationBundleHash as Fn, twin: computeAttestationBundleHashForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'computeMemberDigest', orig: computeMemberDigest as Fn, twin: computeMemberDigestForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'settlement leafHash', orig: leafHash as Fn, twin: leafHashForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'residualLeafHashHex', orig: residualLeafHashHex as Fn, twin: residualLeafHashHexForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'hashAxisLeaf', orig: hashAxisLeaf as Fn, twin: hashAxisLeafForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'canonicalCoSignBody', orig: canonicalCoSignBody as Fn, twin: canonicalCoSignBodyForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'settlementSigningPayload', orig: settlementSigningPayload as Fn, twin: settlementSigningPayloadForWrite as Fn,
    safe: { a: SAFE, signature: 'x' }, unsafe: { a: UNSAFE, signature: 'x' }, path: '$.a' },
  { label: 'canonicalNoSig', orig: canonicalNoSig as Fn, twin: canonicalNoSigForWrite as Fn,
    safe: { a: SAFE, sig: 'x' }, unsafe: { a: UNSAFE, sig: 'x' }, path: '$.a' },
  { label: 'hashExecutionReceipt', orig: hashExecutionReceipt as Fn, twin: hashExecutionReceiptForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'computeCpaRef', orig: computeCpaRef as Fn, twin: computeCpaRefForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'authorityDelegationIdInput', orig: authorityDelegationIdInput as Fn, twin: authorityDelegationIdInputForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'canonicalizeReceiptForId', orig: canonicalizeReceiptForId as Fn, twin: canonicalizeReceiptForIdForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'canonicalizeReceiptForSig', orig: canonicalizeReceiptForSig as Fn, twin: canonicalizeReceiptForSigForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'canonicalizeDenialForId', orig: canonicalizeDenialForId as Fn, twin: canonicalizeDenialForIdForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'canonicalizeDenialForSig', orig: canonicalizeDenialForSig as Fn, twin: canonicalizeDenialForSigForWrite as Fn,
    safe: { a: SAFE }, unsafe: { a: UNSAFE }, path: '$.a' },
  { label: 'receiptCore', orig: receiptCore as Fn, twin: receiptCoreForWrite as Fn,
    safe: { version: '1.0', citer: 'did:aps:c', citer_public_key: 'aa', cited_principal: 'did:aps:p',
            cited_principal_public_key: 'bb', citation_content: { weight: SAFE }, binding_context: 'ctx',
            created_at: { wall_clock: 't', logical: 1 }, expires_at: { wall_clock: 't', logical: 2 } },
    unsafe: { version: '1.0', citer: 'did:aps:c', citer_public_key: 'aa', cited_principal: 'did:aps:p',
              cited_principal_public_key: 'bb', citation_content: { weight: UNSAFE }, binding_context: 'ctx',
              created_at: { wall_clock: 't', logical: 1 }, expires_at: { wall_clock: 't', logical: 2 } },
    path: '$.citation_content.weight' },
]

function serialize(v: unknown): string {
  return Buffer.isBuffer(v) ? v.toString('hex')
    : v instanceof Uint8Array ? Buffer.from(v).toString('hex')
    : String(v)
}

describe('Phase 2B: C-helper read/write twins', () => {
  for (const s of SPLITS) {
    it(`${s.label}: twin matches the original on safe input`, () => {
      assert.strictEqual(serialize(call(s.twin, s.safe)), serialize(call(s.orig, s.safe)))
    })

    it(`${s.label}: twin refuses an unsafe integer at the exact path`, () => {
      assert.throws(() => call(s.twin, s.unsafe), (err: unknown) => {
        assert.ok(err instanceof UnsafeIntegerError, `expected UnsafeIntegerError, got ${String(err)}`)
        assert.ok((err as Error).message.startsWith(`${s.path}:`), (err as Error).message)
        assert.strictEqual((err as UnsafeIntegerError).category, 'invalid_number')
        assert.strictEqual((err as UnsafeIntegerError).reason, 'integer_exceeds_interoperable_range')
        return true
      })
    })

    it(`${s.label}: the original stays unrestricted so history keeps verifying`, () => {
      assert.doesNotThrow(() => call(s.orig, s.unsafe))
    })
  }

  const NESTED_SAFE = { a: { b: [{ c: SAFE }] } }
  const NESTED_UNSAFE = { a: { b: [{ c: UNSAFE }] } }
  const NESTABLE = new Set([
    'hashObject', 'computeAttestationBundleHash', 'computeMemberDigest', 'settlement leafHash',
    'residualLeafHashHex', 'hashAxisLeaf', 'canonicalCoSignBody', 'hashExecutionReceipt',
    'computeCpaRef', 'authorityDelegationIdInput',
  ])

  for (const s of SPLITS.filter(x => NESTABLE.has(x.label))) {
    it(`${s.label}: nested unsafe integer refused at $.a.b[0].c`, () => {
      assert.strictEqual(serialize(call(s.twin, NESTED_SAFE)), serialize(call(s.orig, NESTED_SAFE)))
      assert.throws(() => call(s.twin, NESTED_UNSAFE), (err: unknown) => {
        assert.ok((err as Error).message.startsWith('$.a.b[0].c:'), (err as Error).message)
        return true
      })
    })
  }
})

describe('Phase 2B gate: the generic canonicalizers are untouched', () => {
  it('canonicalize and canonicalizeJCS still emit an out-of-range integer', () => {
    assert.strictEqual(canonicalize({ v: UNSAFE }), '{"v":9007199254740992}')
    assert.strictEqual(canonicalizeJCS({ v: UNSAFE }), '{"v":9007199254740992}')
  })

  it('the write canonicalizers refuse it', () => {
    assert.throws(() => canonicalizeForWrite({ v: UNSAFE }), UnsafeIntegerError)
    assert.throws(() => canonicalizeJCSForWrite({ v: UNSAFE }), UnsafeIntegerError)
  })

  it('write canonicalizers are byte-identical to the generic ones on safe input', () => {
    const probe = { agentId: 'did:aps:a1', amount: SAFE, nested: { z: 1, a: [1, 2, { k: 'v' }] }, note: null }
    assert.strictEqual(canonicalizeForWrite(probe), canonicalize(probe))
    assert.strictEqual(canonicalizeJCSForWrite(probe), canonicalizeJCS(probe))
  })
})

describe('Phase 2B gate: single observation on the write path', () => {
  function counting(first: number, later: number): { obj: Record<string, unknown>; reads: () => number } {
    let n = 0
    const obj = {}
    Object.defineProperty(obj, 'a', {
      enumerable: true,
      get() { n += 1; return n === 1 ? first : later },
    })
    return { obj, reads: () => n }
  }

  it('legacy write canonicalizer reads each property exactly once', () => {
    const c = counting(SAFE, UNSAFE)
    assert.strictEqual(canonicalizeForWrite(c.obj), `{"a":${SAFE}}`)
    assert.strictEqual(c.reads(), 1, `observed ${c.reads()} times`)
  })

  it('JCS write canonicalizer reads each property exactly once', () => {
    const c = counting(SAFE, UNSAFE)
    assert.strictEqual(canonicalizeJCSForWrite(c.obj), `{"a":${SAFE}}`)
    assert.strictEqual(c.reads(), 1, `observed ${c.reads()} times`)
  })

  it('an unsafe first observation is refused on both write canonicalizers', () => {
    const a = counting(UNSAFE, SAFE)
    assert.throws(() => canonicalizeForWrite(a.obj), UnsafeIntegerError)
    assert.strictEqual(a.reads(), 1)
    const b = counting(UNSAFE, SAFE)
    assert.throws(() => canonicalizeJCSForWrite(b.obj), UnsafeIntegerError)
    assert.strictEqual(b.reads(), 1)
  })
})
