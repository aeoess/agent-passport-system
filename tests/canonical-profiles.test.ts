// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Differential tests for the two canonicalization profiles this repository
// ships, added for #101.
//
//   canonicalize()     legacy. Sorts keys, REMOVES null and undefined members.
//                      The signing preimage of the core BilateralReceipt v1.0.
//   canonicalizeJCS()  RFC 8785. Sorts keys, PRESERVES null, REJECTS undefined.
//                      The signing preimage of the v2 primitives and of the
//                      in-toto/DecisionReceipt envelopes.
//
// The point of the file is that the two are not interchangeable, and that the
// bytes each one emits for a fixed input are pinned so a future change cannot
// move them quietly.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { canonicalize } from '../src/core/canonical.js'
import { canonicalizeJCS } from '../src/core/canonical-jcs.js'

describe('#101 (1): canonicalizeJCS rejects undefined at any depth', () => {
  it('rejects a top-level undefined and names the root', () => {
    assert.throws(
      () => canonicalizeJCS(undefined),
      (e: unknown) =>
        e instanceof TypeError && e.message === 'canonicalizeJCS: undefined at $',
    )
  })

  it('rejects an undefined object member and names the member', () => {
    assert.throws(
      () => canonicalizeJCS({ a: 1, b: undefined }),
      (e: unknown) =>
        e instanceof TypeError && e.message === 'canonicalizeJCS: undefined at $.b',
    )
  })

  it('rejects an undefined nested inside an array element and names the path', () => {
    assert.throws(
      () => canonicalizeJCS({ xs: [{ ok: 1 }, { bad: undefined }] }),
      (e: unknown) =>
        e instanceof TypeError && e.message === 'canonicalizeJCS: undefined at $.xs[1].bad',
    )
  })
})

describe('#101 (2): explicit null is preserved, and is what carries the wire bytes', () => {
  it('preserves an explicit null where undefined is refused', () => {
    assert.strictEqual(canonicalizeJCS({ a: 1, b: null }), '{"a":1,"b":null}')
  })

  it('preserves explicit null at depth and inside arrays', () => {
    assert.strictEqual(
      canonicalizeJCS({ outer: { inner: null }, xs: [null, 1] }),
      '{"outer":{"inner":null},"xs":[null,1]}',
    )
  })

  it('legacy removes null where JCS keeps it, which is the whole difference', () => {
    const body = { a: 1, b: null, c: 3 }
    assert.strictEqual(canonicalize(body), '{"a":1,"c":3}')
    assert.strictEqual(canonicalizeJCS(body), '{"a":1,"b":null,"c":3}')
  })

  it('an explicit null survives a JSON round trip where undefined does not', () => {
    // This is why the builders in #101 write an explicit null rather than
    // omitting the member: the signing preimage and the bytes that actually
    // travel have to agree, or the signature cannot be verified by a peer.
    const withNull = { k: null }
    const withUndefined = { k: undefined }
    assert.strictEqual('k' in JSON.parse(JSON.stringify(withNull)), true)
    assert.strictEqual('k' in JSON.parse(JSON.stringify(withUndefined)), false)
  })
})

describe('#101 (3): the three fixture vectors where the profiles disagree', () => {
  const corpus = JSON.parse(
    readFileSync('fixtures/bilateral-delegation/canonicalize-fixture-v1.json', 'utf8'),
  ) as { vectors: Array<{ name: string; input: unknown; canonical_bytes_hex: string }> }

  // Named by the issue as the vectors on which the two serializers differ.
  const DIVERGENT = [
    'nested-null-preservation',
    'bilateral-receipt-shape',
    'migration-attestation-shape',
  ]

  const byName = new Map(corpus.vectors.map(v => [v.name, v]))
  const pinned = (v: { canonical_bytes_hex: string }) =>
    Buffer.from(v.canonical_bytes_hex, 'hex').toString('utf8')

  for (const name of DIVERGENT) {
    it(`${name}: legacy and JCS differ, and the pin is the JCS form`, () => {
      const v = byName.get(name)
      assert.ok(v, `vector ${name} must exist in the corpus`)
      const jcs = canonicalizeJCS(v.input)
      const legacy = canonicalize(v.input)
      assert.notStrictEqual(legacy, jcs, 'the profiles must disagree on this vector')
      assert.strictEqual(pinned(v), jcs, 'the committed pin must be the JCS bytes')
      assert.notStrictEqual(pinned(v), legacy)
    })
  }

  it('exactly three of the ten vectors are divergent, and they are those three', () => {
    const divergent = corpus.vectors
      .filter(v => canonicalize(v.input) !== canonicalizeJCS(v.input))
      .map(v => v.name)
    assert.deepStrictEqual(divergent.sort(), [...DIVERGENT].sort())
  })

  it('every vector pin equals the JCS bytes, and no vector carries undefined', () => {
    for (const v of corpus.vectors) {
      // canonicalizeJCS is strict, so this call also proves the input is clean.
      assert.strictEqual(pinned(v), canonicalizeJCS(v.input), `vector ${v.name}`)
    }
  })
})

describe('#101 (4): the core BilateralReceipt preimage is the legacy profile', () => {
  // A fixed, fully deterministic body matching the literal built by
  // createBilateralReceipt (src/core/bilateral-receipt.ts), with the generated
  // receiptId and agreedAt frozen so the bytes can be pinned.
  const FIXED = {
    receiptId: '00000000-0000-4000-8000-000000000001',
    version: '1.0' as const,
    requestingAgentId: 'did:aps:requester01',
    servingAgentId: 'did:aps:server01',
    outcome: 'success',
    requestedAt: '2026-08-17T12:00:00Z',
    completedAt: '2026-08-17T12:00:01Z',
    agreedAt: '2026-08-17T12:00:02Z',
  }

  // The shape the builder produced BEFORE #101: the same receipt, but with each
  // absent optional present and holding undefined.
  const OLD_SHAPE = {
    ...FIXED,
    delegationId: undefined,
    evidenceCommitments: undefined,
    aud: undefined,
    action_ref: undefined,
    fieldDisclosureProfile: undefined,
  }

  // Captured from the code as it stood before any #101 edit landed.
  const PINNED_PREIMAGE =
    '{"agreedAt":"2026-08-17T12:00:02Z","completedAt":"2026-08-17T12:00:01Z",' +
    '"outcome":"success","receiptId":"00000000-0000-4000-8000-000000000001",' +
    '"requestedAt":"2026-08-17T12:00:00Z","requestingAgentId":"did:aps:requester01",' +
    '"servingAgentId":"did:aps:server01","version":"1.0"}'

  it('legacy bytes for the post-change body equal the pre-change pin', () => {
    assert.strictEqual(canonicalize(FIXED), PINNED_PREIMAGE)
  })

  it('the conditional-spread change moved no signed byte', () => {
    // The builder now omits absent optionals instead of materializing them as
    // undefined. Legacy canonicalize removed undefined members anyway, so the
    // preimage is identical for the two shapes. This is the assertion that
    // makes the #101 builder change safe.
    assert.strictEqual(canonicalize(OLD_SHAPE), canonicalize(FIXED))
    assert.strictEqual(canonicalize(OLD_SHAPE), PINNED_PREIMAGE)
  })

  it('JCS refuses the old shape outright', () => {
    // Before #101 this returned 380 bytes carrying five coerced nulls, which is
    // the divergence the issue reports. It is now a refusal.
    assert.throws(
      () => canonicalizeJCS(OLD_SHAPE),
      (e: unknown) => e instanceof TypeError && /^canonicalizeJCS: undefined at \$\./.test((e as Error).message),
    )
  })

  it('JCS and legacy agree on the post-change body, which is why the profile must be declared', () => {
    // Worth stating precisely, because it is easy to assume otherwise. Once the
    // absent optionals are genuinely omitted, this body carries no null and no
    // undefined, and the two profiles emit the same bytes. They diverge only on
    // bodies that carry null or undefined members. So byte equality here is NOT
    // evidence that a receipt is JCS-canonicalized, and a receipt cannot be
    // classified by inspecting its bytes: the profile has to be declared.
    assert.strictEqual(canonicalizeJCS(FIXED), canonicalize(FIXED))
    assert.strictEqual(canonicalizeJCS(FIXED), PINNED_PREIMAGE)
  })
})
