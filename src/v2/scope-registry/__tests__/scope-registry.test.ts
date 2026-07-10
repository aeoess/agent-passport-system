// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  SCOPE_REGISTRY_VERSION,
  CANONICAL_DIMENSIONS,
  buildRegistry,
  classifyDimensions,
  compileStrictDimensions,
  checkSetNarrowing,
  canHardDeny,
  type DimensionDeclaration,
  type ScopeDimensionRegistry,
} from '../index.js'
import type { CompileFeasibilityInput } from '../../feasibility/index.js'

// ── registry construction ──────────────────────────────────────────────

describe('scope dimension registry: construction', () => {
  it('builds the canonical registry deterministically', () => {
    const a = buildRegistry()
    const b = buildRegistry()
    assert.equal(a.version, SCOPE_REGISTRY_VERSION)
    assert.equal(a.registryHash, b.registryHash)
    assert.match(a.registryHash, /^[0-9a-f]{64}$/)
  })

  it('declarations are sorted by id', () => {
    const reg = buildRegistry()
    const ids = reg.dimensions.map((d) => d.id)
    const sorted = [...ids].sort()
    assert.deepEqual(ids, sorted)
  })

  it('ships data_class and destination as decidable strict dimensions', () => {
    const reg = buildRegistry()
    const dataClass = reg.dimensions.find((d) => d.id === 'data_class')
    const destination = reg.dimensions.find((d) => d.id === 'destination')
    assert.ok(dataClass, 'data_class registered')
    assert.ok(destination, 'destination registered')
    assert.equal(dataClass!.decidable, true)
    assert.equal(dataClass!.enforcement_strength, 'strict')
    assert.equal(dataClass!.assurance_class, 'mechanically_enforceable')
    assert.equal(destination!.decidable, true)
    assert.equal(destination!.enforcement_strength, 'strict')
    // data_class reuses the canonical 'data' facet; destination is a new
    // dimension and must NOT alias cross_chain analytics.
    assert.equal(dataClass!.facet, 'data')
    assert.equal(destination!.facet, 'cross_chain')
  })

  it('rejects a duplicate dimension id', () => {
    const dup = [...CANONICAL_DIMENSIONS, CANONICAL_DIMENSIONS[0]]
    assert.throws(() => buildRegistry(dup), /Duplicate dimension id/)
  })

  it('rejects a non-decidable dimension marked strict', () => {
    const bad: DimensionDeclaration = {
      id: 'bogus',
      facet: 'scope',
      valueType: 'text',
      decidable: false,
      enforcement_strength: 'strict', // illegal: text is never strict
      assurance_class: 'socially_adjudicated',
      comment: 'free text marked strict',
    }
    assert.throws(() => buildRegistry([bad]), /cannot be 'strict'/)
  })

  it('rejects a free-text value type marked decidable', () => {
    const bad: DimensionDeclaration = {
      id: 'bogus',
      facet: 'scope',
      valueType: 'text',
      decidable: true, // illegal: text is never decidable
      enforcement_strength: 'advisory',
      assurance_class: 'evidentially_auditable',
      comment: 'free text marked decidable',
    }
    assert.throws(() => buildRegistry([bad]), /cannot be marked decidable/)
  })
})

// ── classification: strict vs advisory ──────────────────────────────────

describe('scope dimension registry: classification', () => {
  const reg = buildRegistry()
  const cls = classifyDimensions(reg)

  it('routes the four M6 dimensions plus data_class and destination as strict', () => {
    for (const id of ['scope', 'spend', 'depth', 'temporal', 'data_class', 'destination']) {
      assert.ok(cls.strict_decidable.includes(id), `${id} is strict decidable`)
    }
  })

  it('excludes free-text purpose as advisory, with a reason, never silently dropped', () => {
    assert.ok(cls.advisory_excluded.includes('purpose'))
    assert.ok(cls.excluded_reasons['purpose'])
    assert.match(cls.excluded_reasons['purpose'], /not decidable/)
  })

  it('partitions every dimension into exactly one bucket', () => {
    const all = [...cls.strict_decidable, ...cls.advisory_excluded].sort()
    const ids = reg.dimensions.map((d) => d.id).sort()
    assert.deepEqual(all, ids)
  })

  it('carries an honest-scope note that it does not decide advisory dimensions', () => {
    assert.ok(cls.scopeNote.does_not_assert.length >= 1)
    assert.ok(
      cls.scopeNote.does_not_assert.some((s) => /advisory/.test(s) && /hard deny/.test(s)),
    )
  })
})

// ── canHardDeny invariant ───────────────────────────────────────────────

describe('scope dimension registry: advisory dimensions never hard-deny', () => {
  const reg = buildRegistry()

  it('a strict decidable dimension may hard-deny', () => {
    const scope = reg.dimensions.find((d) => d.id === 'scope')!
    assert.equal(canHardDeny(scope), true)
  })

  it('an advisory dimension can NOT hard-deny', () => {
    const purpose = reg.dimensions.find((d) => d.id === 'purpose')!
    assert.equal(canHardDeny(purpose), false)
  })

  it('checkSetNarrowing on an advisory dimension is not_applicable, never fail', () => {
    const purpose = reg.dimensions.find((d) => d.id === 'purpose')!
    // Even when the "child" obviously diverges, an advisory dimension cannot
    // be the basis of a hard deny: status is not_applicable, not fail.
    const res = checkSetNarrowing(purpose, ['summarize'], ['exfiltrate'])
    assert.equal(res.status, 'not_applicable')
    assert.equal(res.narrows, false)
    assert.ok(/cannot hard-deny/.test(res.message))
  })
})

// ── strict set-narrowing partial order ──────────────────────────────────

describe('scope dimension registry: strict dimension narrows totally (subset)', () => {
  const reg = buildRegistry()
  const destination = reg.dimensions.find((d) => d.id === 'destination')!

  it('a child subset narrows (pass)', () => {
    const res = checkSetNarrowing(
      destination,
      ['api.example.com', 'db.example.com', 'cdn.example.com'],
      ['api.example.com', 'db.example.com'],
    )
    assert.equal(res.narrows, true)
    assert.equal(res.status, 'pass')
    assert.deepEqual(res.widened, [])
  })

  it('an equal set narrows (pass)', () => {
    const res = checkSetNarrowing(destination, ['a', 'b'], ['b', 'a'])
    assert.equal(res.narrows, true)
    assert.equal(res.status, 'pass')
  })

  it('NEGATIVE: a child that adds a destination the parent did not grant fails (widening)', () => {
    const res = checkSetNarrowing(
      destination,
      ['api.example.com'],
      ['api.example.com', 'evil.example.com'],
    )
    assert.equal(res.narrows, false)
    assert.equal(res.status, 'fail')
    assert.deepEqual(res.widened, ['evil.example.com'])
  })

  it('NEGATIVE: an empty parent allow-list rejects any non-empty child', () => {
    const res = checkSetNarrowing(destination, [], ['anything'])
    assert.equal(res.status, 'fail')
    assert.deepEqual(res.widened, ['anything'])
  })
})

describe('scope dimension registry: data_class subset narrows correctly', () => {
  const reg = buildRegistry()
  const dataClass = reg.dimensions.find((d) => d.id === 'data_class')!

  it('a child subset of the parent data classes narrows (pass)', () => {
    const res = checkSetNarrowing(
      dataClass,
      ['public', 'internal', 'confidential'],
      ['public', 'internal'],
    )
    assert.equal(res.narrows, true)
    assert.equal(res.status, 'pass')
    assert.deepEqual(res.widened, [])
  })

  it('NEGATIVE: a child that adds a data class the parent did not grant fails', () => {
    const res = checkSetNarrowing(dataClass, ['public'], ['public', 'pii'])
    assert.equal(res.narrows, false)
    assert.equal(res.status, 'fail')
    assert.deepEqual(res.widened, ['pii'])
  })

  it('NEGATIVE: a value outside the closed vocabulary is rejected', () => {
    const res = checkSetNarrowing(dataClass, ['public'], ['public', 'top_secret'])
    assert.equal(res.status, 'fail')
    assert.equal(res.narrows, false)
    assert.ok(res.widened.includes('top_secret'))
    assert.ok(/closed vocabulary/.test(res.message))
  })
})

// ── M6 routing pass-through ─────────────────────────────────────────────

describe('scope dimension registry: strict dimensions route into M6', () => {
  const input: CompileFeasibilityInput = {
    policy: { scopeRequired: 'data:read', spend: 10, evaluatedAt: '2026-06-15T12:00:00Z' },
    delegation: {
      scope: ['data:read', 'data:write'],
      spendLimit: 100,
      spentAmount: 5,
      maxDepth: 3,
      currentDepth: 1,
      expiresAt: '2026-12-31T00:00:00Z',
      notBefore: '2026-01-01T00:00:00Z',
      revoked: false,
    },
  }

  it('compileStrictDimensions emits the same IR as the M6 compiler', () => {
    const ir = compileStrictDimensions(input)
    // It must produce the canonical M6 obligation, not a reimplementation.
    assert.equal(ir.logic, 'QF_SLIA')
    const constraintIds = ir.constraints.map((c) => c.id).sort()
    assert.ok(constraintIds.includes('scope_granted'))
    assert.ok(constraintIds.includes('spend_within_limit'))
    assert.ok(constraintIds.includes('depth_within_bound'))
    assert.ok(constraintIds.includes('delegation_active'))
  })

  it('routing is deterministic (byte-identical sourceHash)', () => {
    const a = compileStrictDimensions(input)
    const b = compileStrictDimensions(input)
    assert.equal(a.sourceHash, b.sourceHash)
  })
})

// ── determinism of the registry as a whole ──────────────────────────────

describe('scope dimension registry: determinism', () => {
  it('two independently built registries have identical hashes and dimensions', () => {
    const a: ScopeDimensionRegistry = buildRegistry()
    const b: ScopeDimensionRegistry = buildRegistry()
    assert.equal(a.registryHash, b.registryHash)
    assert.deepEqual(a.dimensions, b.dimensions)
  })
})
