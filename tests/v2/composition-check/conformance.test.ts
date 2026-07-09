// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// APS Composition Check Receipt v0: in-suite conformance + over-claim gate.
// Runs the stateless ANCHOR verifier against the frozen conformance vectors and pins the
// locked invariants: there is NO "safe" boolean anywhere, gateway_self never reads as a
// second anchor, and a self-declared independence the trust context does not back is
// downgraded, never upgraded.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { CompositionCheckV0 } from '../../../src/index.js'

const { verifyCompositionCheck, COMPOSITION_CHECK_RESULTS } = CompositionCheckV0

type Vec = {
  id: string
  scenario: string
  input_receipt: Parameters<typeof verifyCompositionCheck>[0]
  verification_context: Parameters<typeof verifyCompositionCheck>[1]
  expected: {
    anchor_verified: boolean
    independence_is_second_anchor?: boolean
    violations_include: string[]
  }
}
const doc = JSON.parse(
  readFileSync(join(process.cwd(), 'conformance/composition-check/v0/vectors.json'), 'utf8'),
) as { profile: string; count: number; vectors: Vec[] }

describe('CompositionCheck v0 conformance vectors (anchor verifier)', () => {
  it('has the frozen vector count', () => {
    assert.equal(doc.count, doc.vectors.length)
    assert.ok(doc.vectors.length >= 6, 'at least the six required cases')
  })

  for (const v of doc.vectors) {
    it(`${v.id}: ${v.scenario}`, () => {
      const r = verifyCompositionCheck(v.input_receipt, v.verification_context)
      assert.equal(r.anchor_verified, v.expected.anchor_verified, `${v.id} anchor_verified`)
      for (const need of v.expected.violations_include) {
        assert.ok(r.violations.includes(need), `${v.id} expected violation '${need}', got [${r.violations}]`)
      }
      if (v.expected.anchor_verified) {
        assert.deepEqual(r.violations, [], `${v.id} accepted receipt must have no violations`)
      }
      if (typeof v.expected.independence_is_second_anchor === 'boolean') {
        assert.equal(
          r.independence_is_second_anchor,
          v.expected.independence_is_second_anchor,
          `${v.id} independence_is_second_anchor`,
        )
      }
    })
  }
})

describe('CompositionCheck v0 locked invariants (no over-claim)', () => {
  it('the verifier output NEVER carries a "safe"-style field', () => {
    for (const v of doc.vectors) {
      const r = verifyCompositionCheck(v.input_receipt, v.verification_context) as Record<string, unknown>
      const offending = Object.keys(r).filter((k) => /safe/i.test(k))
      assert.deepEqual(offending, [], `${v.id} output keys must not include any /safe/ field, got: ${offending}`)
      // And no key anywhere claims a global verdict.
      for (const k of ['safe', 'composition_safe', 'is_safe', 'globally_safe']) {
        assert.equal(k in r, false, `${v.id} must not expose '${k}'`)
      }
    }
  })

  it('the result enum has no safe/unsafe member (per-check results only)', () => {
    for (const m of COMPOSITION_CHECK_RESULTS) {
      assert.ok(!/safe/i.test(m), `result enum member '${m}' must not mention safe`)
    }
    assert.deepEqual([...COMPOSITION_CHECK_RESULTS].sort(), ['fail', 'indeterminate', 'not_checked', 'pass'])
  })

  it('gateway_self / uncorroborated independence is NEVER a second anchor', () => {
    for (const v of doc.vectors) {
      const r = verifyCompositionCheck(v.input_receipt, v.verification_context)
      if (r.attestor_independence_class === 'gateway_self') {
        assert.equal(r.independence_is_second_anchor, false, `${v.id} gateway_self must be weak`)
      }
    }
  })

  it('strong (second anchor) requires context-corroborated independence, not self-declaration', () => {
    // V01 and V07 both CLAIM independent_registered; only V01 is corroborated by the context.
    const v01 = doc.vectors.find((v) => v.id === 'V01')!
    const v07 = doc.vectors.find((v) => v.id === 'V07')!
    const r1 = verifyCompositionCheck(v01.input_receipt, v01.verification_context)
    const r7 = verifyCompositionCheck(v07.input_receipt, v07.verification_context)
    assert.equal(r1.attestor_independence_class, 'independent_registered')
    assert.equal(r7.attestor_independence_class, 'independent_registered')
    assert.equal(r1.independence_is_second_anchor, true, 'corroborated -> second anchor')
    assert.equal(r7.independence_is_second_anchor, false, 'uncorroborated self-claim -> downgraded')
  })

  it('surfaces per-check results verbatim and computes no aggregate over them', () => {
    const v01 = doc.vectors.find((v) => v.id === 'V01')!
    const r = verifyCompositionCheck(v01.input_receipt, v01.verification_context)
    assert.deepEqual(r.result_per_check, v01.input_receipt.result_per_check, 'echoed, not aggregated')
    // anchor_verified is independent of the result VALUES: it is about the anchor, not the findings.
    assert.equal('anchor_verified' in r, true)
  })

  it('independence_is_second_anchor is gated on anchor_verified (a failed anchor is not a second anchor)', () => {
    // V09: an independent attestor whose receipt is expired. anchor fails, so even though the
    // attestor is independent it must NOT read as a usable second anchor.
    const v09 = doc.vectors.find((v) => v.id === 'V09')!
    const r = verifyCompositionCheck(v09.input_receipt, v09.verification_context)
    assert.equal(r.anchor_verified, false)
    assert.equal(r.attestor_independence_class, 'independent_registered', 'raw claimed class still echoed')
    assert.equal(r.independence_is_second_anchor, false, 'a dead anchor is never a second anchor')
  })

  it('fails CLOSED on a non-finite now_ms (undefined / NaN) instead of bypassing freshness', () => {
    // Use a genuinely expired receipt: with a broken clock it must not slip through.
    const v09 = doc.vectors.find((v) => v.id === 'V09')!
    for (const badNow of [undefined as unknown as number, NaN]) {
      const r = verifyCompositionCheck(v09.input_receipt, { ...v09.verification_context, now_ms: badNow })
      assert.equal(r.anchor_verified, false, 'broken clock must not anchor-verify')
      assert.ok(r.violations.includes('now_malformed'), `expected now_malformed for now_ms=${String(badNow)}`)
    }
  })
})
