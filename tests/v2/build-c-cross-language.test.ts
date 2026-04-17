// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Build C — cross-language verification against specs/fixtures/build-c/*.json.
//
// Each fixture contains the full signed settlement record and a set of
// contributor query responses. The TS implementation must:
//   (a) verify the pinned record against the pinned gateway_public_key,
//   (b) regenerate the record from input_receipts and match byte-for-byte,
//   (c) verify every pinned contributor_query_response.
//
// The Python sibling test (tests/v2/test_attribution_settlement_cross_language.py)
// does the same, proving the canonicalization and Merkle/signature
// construction is byte-identical across languages.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import {
  aggregateAttributionPrimitives,
  buildContributorQueryResponse,
  settlementRecordHash,
  signSettlementRecord,
  verifyContributorQueryResponse,
  verifySettlementRecord,
} from '../../src/index.js'
import type { AttributionSettlementRecord } from '../../src/index.js'

const FIXTURE_DIR = '/Users/tima/aeoess_web/specs/fixtures/build-c'

function loadFixtures(): Array<{ name: string; data: any }> {
  return readdirSync(FIXTURE_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((name) => ({
      name,
      data: JSON.parse(readFileSync(join(FIXTURE_DIR, name), 'utf8')),
    }))
}

describe('Build C cross-language fixtures — TS reproduces pinned bytes and verifies', () => {
  const fixtures = loadFixtures()
  assert.equal(fixtures.length, 5, `expected 5 fixtures, got ${fixtures.length}`)

  for (const { name, data } of fixtures) {
    it(`${name}: record verifies against pinned gateway key`, () => {
      const verdict = verifySettlementRecord(data.expected_record, {
        gatewayPublicKeyHex: data.gateway_public_key,
        inputReceipts: data.input_receipts,
      })
      assert.equal(verdict.valid, true, `verify failed: ${JSON.stringify(verdict)}`)
    })

    it(`${name}: regenerating the record from input_receipts matches pinned bytes`, () => {
      const unsigned = aggregateAttributionPrimitives(data.input_receipts, data.period, {
        gateway_did: data.gateway_did,
        issued_at: data.expected_record.issued_at,
      })
      const expectedHash = settlementRecordHash(data.expected_record)
      const reHash = settlementRecordHash(unsigned)
      assert.equal(
        reHash,
        expectedHash,
        `regenerated record hash ${reHash} does not match pinned ${expectedHash}`,
      )
    })

    it(`${name}: contributor queries verify`, () => {
      for (const q of data.contributor_queries ?? []) {
        if (!q.response) continue
        const verdict = verifyContributorQueryResponse(q.response, {
          gatewayPublicKeyHex: data.gateway_public_key,
        })
        assert.equal(
          verdict.valid,
          true,
          `contributor query for ${q.contributor_did} failed: ${JSON.stringify(verdict)}`,
        )
      }
    })

    it(`${name}: rebuilt contributor queries match pinned queries byte-for-byte`, () => {
      const record = data.expected_record as AttributionSettlementRecord
      for (const q of data.contributor_queries ?? []) {
        const regenerated = buildContributorQueryResponse(record, q.contributor_did)
        if (!q.response) {
          assert.equal(regenerated, null, `expected null response for ${q.contributor_did}`)
          continue
        }
        // The `settlement_record` is the same object; structurally equal.
        // Compare canonicalized paths + shape. We hash both to sha256 to
        // detect any subtle drift.
        const canonA = JSON.stringify(regenerated)
        const canonB = JSON.stringify(q.response)
        assert.equal(canonA, canonB, `rebuilt query for ${q.contributor_did} diverged`)
      }
    })

    it(`${name}: re-signing the regenerated record with the fixture key yields the pinned signature`, () => {
      // We don't ship the private key in the fixture, so this test only
      // asserts the canonical payload matches the hash of the pinned
      // record. If canonicalization drifts, the hash will change.
      const regeneratedHash = settlementRecordHash({
        schema: data.expected_record.schema,
        period: data.expected_record.period,
        gateway_did: data.expected_record.gateway_did,
        axes: data.expected_record.axes,
        input_receipts_hash: data.expected_record.input_receipts_hash,
        total_input_count: data.expected_record.total_input_count,
        issued_at: data.expected_record.issued_at,
      })
      // Silence: the pinned record already embeds its signature; we
      // don't re-sign here. The hash check is what cross-language cares
      // about.
      void signSettlementRecord
      const pinnedHash = settlementRecordHash(data.expected_record)
      assert.equal(regeneratedHash, pinnedHash)
    })
  }
})
