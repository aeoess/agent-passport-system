// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { selectJurisdictionPacks, RESOLVER_VERSION } from '../src/core/jurisdiction-selection.js'
import type { JurisdictionFacts, PolicyPackRef } from '../src/types/jurisdiction-selection.js'

const AT = '2026-07-10T00:00:00Z'

function pack(over: Partial<PolicyPackRef> & Pick<PolicyPackRef, 'id' | 'jurisdiction'>): PolicyPackRef {
  return { version: '1.0.0', issuer: 'issuer-x', digest: 'sha256:0000', ...over }
}

describe('Jurisdiction Selection Provenance', () => {
  it('three-country case surfaces a residency conflict, never auto-resolves', () => {
    // Principal in US, executor in DE, resource in JP. Two packs whose
    // residency constraint values differ. Expect exactly one conflict.
    const facts: JurisdictionFacts = {
      principal_jurisdiction: 'US',
      execution_jurisdiction: 'DE',
      resource_jurisdiction: 'JP',
    }
    const packs = [
      pack({ id: 'pack-us-base', jurisdiction: 'US', constraints: { residency: 'local-only' } }),
      pack({ id: 'pack-de-base', jurisdiction: 'DE', constraints: { residency: 'in-jurisdiction' } }),
    ]
    const record = selectJurisdictionPacks(facts, packs, { selected_at: AT })

    assert.equal(record.selected_packs.length, 2)
    assert.equal(record.conflicts.length, 1)
    assert.equal(record.resolution, 'conflict-surfaced')
    assert.equal(record.conflicts[0].dimension, 'residency')
    assert.deepEqual(record.conflicts[0].packs, ['pack-de-base@1.0.0', 'pack-us-base@1.0.0'])
    assert.deepEqual(record.conflicts[0].values, ['in-jurisdiction', 'local-only'])
    assert.equal(record.resolver_version, RESOLVER_VERSION)
    assert.equal(record.selected_at, AT)
    assert.equal(record.precedence_used, undefined)
  })

  it('no-conflict two-pack case selects with deterministic ordering', () => {
    const facts: JurisdictionFacts = {
      principal_jurisdiction: 'US',
      execution_jurisdiction: 'US',
      resource_jurisdiction: 'DE',
    }
    const packs = [
      pack({ id: 'pack-a-de', jurisdiction: 'DE', constraints: { retention: 'short' } }),
      pack({ id: 'pack-x-none', jurisdiction: 'BR' }),
      pack({ id: 'pack-z-us', jurisdiction: 'US', constraints: { logging: 'required' } }),
    ]
    const record = selectJurisdictionPacks(facts, packs, { selected_at: AT })

    // pack-z-us matches two dimensions so it ranks first despite its
    // later id; pack-x-none matches nothing and is excluded.
    assert.deepEqual(record.selected_packs.map(p => p.id), ['pack-z-us', 'pack-a-de'])
    assert.deepEqual(record.conflicts, [])
    assert.equal(record.resolution, 'selected')

    // Equal match counts fall back to id order, regardless of input order.
    const tied = selectJurisdictionPacks(facts, [
      pack({ id: 'pack-b', jurisdiction: 'DE' }),
      pack({ id: 'pack-a', jurisdiction: 'DE' }),
    ], { selected_at: AT })
    assert.deepEqual(tied.selected_packs.map(p => p.id), ['pack-a', 'pack-b'])
  })

  it('explicit precedence covering all declaring packs resolves the key and is recorded', () => {
    const facts: JurisdictionFacts = {
      principal_jurisdiction: 'US',
      execution_jurisdiction: 'DE',
      resource_jurisdiction: 'JP',
    }
    const packs = [
      pack({ id: 'pack-us-base', jurisdiction: 'US', constraints: { residency: 'local-only' } }),
      pack({ id: 'pack-de-base', jurisdiction: 'DE', constraints: { residency: 'in-jurisdiction' } }),
    ]
    const record = selectJurisdictionPacks(facts, packs, {
      precedence: ['pack-us-base', 'pack-de-base'],
      selected_at: AT,
    })
    assert.deepEqual(record.conflicts, [])
    assert.equal(record.resolution, 'selected')
    assert.deepEqual(record.precedence_used, ['pack-us-base', 'pack-de-base'])

    // Partial coverage does not resolve: the conflict stays surfaced.
    const partial = selectJurisdictionPacks(facts, packs, {
      precedence: ['pack-us-base'],
      selected_at: AT,
    })
    assert.equal(partial.conflicts.length, 1)
    assert.equal(partial.resolution, 'conflict-surfaced')
  })
})
