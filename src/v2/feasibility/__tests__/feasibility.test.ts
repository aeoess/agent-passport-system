// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import {
  buildProofRef,
  validateProofRef,
  proofRefMatchesArtifact,
  proofRefScopeNote,
  PROOF_REF_ALGORITHM,
} from '../proof-ref.js'
import {
  compileFeasibility,
  emitSmtLib,
  compileToSmtLib,
  FEASIBILITY_IR_VERSION,
  FEASIBILITY_LOGIC,
  type CompileFeasibilityInput,
} from '../compiler.js'
import type { PolicyReceipt, ProofRef } from '../../../types/policy.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// The single known input the on-disk fixture was generated from.
const KNOWN_INPUT: CompileFeasibilityInput = {
  policy: {
    scopeRequired: 'data:read',
    spend: 10,
    evaluatedAt: '2026-06-15T12:00:00Z',
  },
  delegation: {
    scope: ['data:write', 'data:read', 'commerce:checkout'],
    spendLimit: 100,
    spentAmount: 5,
    maxDepth: 3,
    currentDepth: 1,
    expiresAt: '2026-12-31T00:00:00Z',
    notBefore: '2026-01-01T00:00:00Z',
    revoked: false,
  },
}

// ── proof_ref ──────────────────────────────────────────────────────────

describe('proof_ref slot', () => {
  it('builds a sha256 reference from artifact bytes', () => {
    const ref = buildProofRef({ artifact: 'an external proof artifact' })
    assert.equal(ref.algorithm, PROOF_REF_ALGORITHM)
    assert.match(ref.hash, /^[0-9a-f]{64}$/)
  })

  it('is deterministic: same artifact yields the same hash', () => {
    const a = buildProofRef({ artifact: 'proof-A' })
    const b = buildProofRef({ artifact: 'proof-A' })
    assert.equal(a.hash, b.hash)
  })

  it('carries optional proofSystem and locator only when supplied', () => {
    const bare = buildProofRef({ artifact: 'x' })
    assert.equal(bare.proofSystem, undefined)
    assert.equal(bare.locator, undefined)

    const annotated = buildProofRef({
      artifact: 'x',
      proofSystem: 'smtlib2',
      locator: 'ipfs://example',
    })
    assert.equal(annotated.proofSystem, 'smtlib2')
    assert.equal(annotated.locator, 'ipfs://example')
  })

  it('round-trips on a PolicyReceipt and is absent by default', () => {
    const base: PolicyReceipt = {
      policyReceiptId: 'pr-1',
      intentId: 'i-1',
      decisionId: 'd-1',
      receiptId: 'r-1',
      chain: { intentSignature: 's1', decisionSignature: 's2', receiptSignature: 's3' },
      verifiedAt: '2026-06-15T12:00:00Z',
      signature: 'sig',
    }
    // OPTIONAL: a receipt with no proof_ref is valid and the field is absent.
    assert.equal(base.proof_ref, undefined)
    assert.ok(!('proof_ref' in base))

    const ref = buildProofRef({ artifact: 'proof', proofSystem: 'smtlib2' })
    const withRef: PolicyReceipt = { ...base, proof_ref: ref }

    // Survives a serialization round-trip unchanged.
    const round = JSON.parse(JSON.stringify(withRef)) as PolicyReceipt
    assert.deepEqual(round.proof_ref, ref)
  })

  it('confirms an artifact matches its reference and rejects a mismatch', () => {
    const ref = buildProofRef({ artifact: 'the real proof' })
    assert.equal(proofRefMatchesArtifact(ref, 'the real proof'), true)
    // Negative path: different bytes do not match.
    assert.equal(proofRefMatchesArtifact(ref, 'a different proof'), false)
  })

  describe('validateProofRef negative paths', () => {
    it('flags a missing reference', () => {
      const r = validateProofRef(undefined)
      assert.equal(r.wellFormed, false)
      assert.deepEqual(r.errors, ['MISSING_REF'])
    })

    it('flags an unsupported algorithm', () => {
      const bad = { algorithm: 'md5', hash: 'a'.repeat(64) } as unknown as ProofRef
      const r = validateProofRef(bad)
      assert.equal(r.wellFormed, false)
      assert.ok(r.errors.includes('UNSUPPORTED_ALGORITHM'))
    })

    it('flags a malformed hash', () => {
      const bad = { algorithm: 'sha256', hash: 'not-a-hash' } as ProofRef
      const r = validateProofRef(bad)
      assert.equal(r.wellFormed, false)
      assert.ok(r.errors.includes('MALFORMED_HASH'))
    })

    it('accepts a well-formed reference', () => {
      const r = validateProofRef(buildProofRef({ artifact: 'ok' }))
      assert.deepEqual(r, { wellFormed: true, errors: [] })
    })
  })

  it('exposes an honest scope note for emitters to dogfood', () => {
    assert.match(proofRefScopeNote(), /not validated by this system/)
  })
})

// ── feasibility IR compiler ────────────────────────────────────────────

describe('feasibility IR compiler', () => {
  it('emits versioned, logic-tagged IR with a source hash', () => {
    const ir = compileFeasibility(KNOWN_INPUT)
    assert.equal(ir.version, FEASIBILITY_IR_VERSION)
    assert.equal(ir.logic, FEASIBILITY_LOGIC)
    assert.match(ir.sourceHash, /^[0-9a-f]{64}$/)
  })

  it('sorts variables by name and constraints by id (deterministic order)', () => {
    const ir = compileFeasibility(KNOWN_INPUT)
    const varNames = ir.variables.map((v) => v.name)
    assert.deepEqual(varNames, [...varNames].sort())
    const ids = ir.constraints.map((c) => c.id)
    assert.deepEqual(ids, [...ids].sort())
  })

  it('is deterministic across repeated runs for a fixed policy (IR)', () => {
    const a = JSON.stringify(compileFeasibility(KNOWN_INPUT))
    for (let i = 0; i < 5; i++) {
      const b = JSON.stringify(compileFeasibility(KNOWN_INPUT))
      assert.equal(b, a)
    }
  })

  it('is deterministic across repeated runs for a fixed policy (SMT-LIB)', () => {
    const a = compileToSmtLib(KNOWN_INPUT)
    for (let i = 0; i < 5; i++) {
      assert.equal(compileToSmtLib(KNOWN_INPUT), a)
    }
  })

  it('source hash is independent of delegation scope ordering', () => {
    const reordered: CompileFeasibilityInput = {
      ...KNOWN_INPUT,
      delegation: {
        ...KNOWN_INPUT.delegation,
        scope: ['data:read', 'commerce:checkout', 'data:write'],
      },
    }
    assert.equal(
      compileFeasibility(KNOWN_INPUT).sourceHash,
      compileFeasibility(reordered).sourceHash,
    )
  })

  it('compiles the known policy to the expected SMT-LIB fixture string', () => {
    const expected = readFileSync(
      join(__dirname, '..', 'fixtures', 'known-policy.smt2'),
      'utf-8',
    )
    const actual = compileToSmtLib(KNOWN_INPUT)
    assert.equal(actual, expected)
  })

  it('omits spend constraints when the delegation carries no spend limit', () => {
    const input: CompileFeasibilityInput = {
      policy: { scopeRequired: 'data:read' },
      delegation: {
        scope: ['data:read'],
        maxDepth: 2,
        currentDepth: 1,
        expiresAt: '2026-12-31T00:00:00Z',
      },
    }
    const ir = compileFeasibility(input)
    assert.ok(!ir.constraints.some((c) => c.id === 'spend_within_limit'))
    assert.ok(!ir.variables.some((v) => v.name === 'spend_limit'))
  })

  it('omits the validity-window constraint when no evaluatedAt is given', () => {
    const input: CompileFeasibilityInput = {
      policy: { scopeRequired: 'data:read' },
      delegation: {
        scope: ['data:read'],
        maxDepth: 2,
        currentDepth: 1,
        expiresAt: '2026-12-31T00:00:00Z',
      },
    }
    const smt = compileToSmtLib(input)
    assert.ok(!smt.includes('within_validity_window'))
    // delegation_active is always present.
    assert.ok(smt.includes('delegation_active'))
  })

  describe('negative-path obligations', () => {
    it('emits an unsatisfiable membership term for an empty grant set', () => {
      const input: CompileFeasibilityInput = {
        policy: { scopeRequired: 'data:read' },
        delegation: {
          scope: [],
          maxDepth: 2,
          currentDepth: 1,
          expiresAt: '2026-12-31T00:00:00Z',
        },
      }
      const smt = compileToSmtLib(input)
      // An empty grant set means the scope obligation can never hold: assert false.
      assert.ok(smt.includes('(assert false) ; scope_granted'))
    })

    it('still encodes the obligation when the requested scope is not granted', () => {
      // The compiler states the obligation; it does NOT decide it. A scope the
      // delegation does not grant produces a membership term that no assignment
      // can satisfy, but the compiler emits it without judging feasibility.
      const input: CompileFeasibilityInput = {
        policy: { scopeRequired: 'admin:root' },
        delegation: {
          scope: ['data:read'],
          maxDepth: 2,
          currentDepth: 1,
          expiresAt: '2026-12-31T00:00:00Z',
        },
      }
      const smt = compileToSmtLib(input)
      assert.ok(smt.includes('(= action_scope "data:read")'))
      assert.ok(!smt.includes('admin:root'))
      // (check-sat) is emitted but never run here: nothing solves the obligation.
      assert.ok(smt.includes('(check-sat)'))
    })

    it('writes negative integer literals in SMT-LIB form', () => {
      const input: CompileFeasibilityInput = {
        policy: { scopeRequired: 'data:read', spend: -50 },
        delegation: {
          scope: ['data:read'],
          spendLimit: 100,
          spentAmount: 10,
          maxDepth: 2,
          currentDepth: 1,
          expiresAt: '2026-12-31T00:00:00Z',
        },
      }
      const smt = compileToSmtLib(input)
      // cumulative = 10 + (-50) = -40, rendered as (- 40).
      assert.ok(smt.includes('(= cumulative_spend (- 40))'))
    })
  })

  it('emitSmtLib is a pure function of the IR', () => {
    const ir = compileFeasibility(KNOWN_INPUT)
    assert.equal(emitSmtLib(ir), emitSmtLib(ir))
  })
})
