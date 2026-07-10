// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Conformance golden negative-fixture suite
// ══════════════════════════════════════════════════════════════════
// A conformant verifier MUST:
//   - accept the golden valid fixture, AND
//   - reject every negative fixture for the stated reason.
//
// This suite asserts both directions against the shipped SDK verifier.
// It also re-derives the pinned SHA-256 receipt_id from the canonical
// JCS preimage so the golden fixture stays byte-stable across changes.
//
// SCOPE OF CLAIM (dogfooded):
//   Proves: the SDK's Ed25519 + RFC 8785 JCS verifier accepts the
//     golden valid receipt and rejects each negative for its cited
//     reason, and the pinned receipt_id matches its preimage.
//   Does NOT prove: that protocol behavior changed (it did not), that
//     the receipts describe real-world events, or that the signing key
//     was honestly held.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync, existsSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'
import { verify } from '../../src/crypto/keys.js'
import { verifyActionReceipt } from '../../src/v2/accountability/verify/action.js'
import {
  buildGoldenValid,
  buildNegatives,
  verifyReceiptContext,
} from './generate.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURES_DIR = join(__dirname, 'golden-fixtures')

// Serialize a fixture the same way write-fixtures.ts does, so the
// on-disk JSON and the regenerated value can be compared byte for byte.
function stable(value: unknown): string {
  return (
    JSON.stringify(
      value,
      (_k, v) => (typeof v === 'bigint' ? v.toString() : v),
      2,
    ) + '\n'
  )
}

describe('conformance: golden valid fixture', () => {
  const golden = buildGoldenValid()

  it('verifies clean under the crypto-layer verifier', () => {
    const r = verifyActionReceipt(golden.receipt)
    assert.equal(r.valid, true, JSON.stringify(r))
  })

  it('receipt_id equals sha256 of the pinned canonical preimage', () => {
    const reHash = createHash('sha256')
      .update(golden.canonical_preimage_for_id, 'utf8')
      .digest('hex')
    assert.equal(reHash, golden.expected_receipt_id_sha256)
    assert.equal(golden.receipt.receipt_id, golden.expected_receipt_id_sha256)
  })

  it('the pinned id preimage matches a freshly canonicalized empty-id form', () => {
    const fresh = canonicalizeJCS({
      ...golden.receipt,
      receipt_id: '',
      signature: '',
    })
    assert.equal(fresh, golden.canonical_preimage_for_id)
  })

  it('the pinned signature preimage matches the empty-signature form', () => {
    const fresh = canonicalizeJCS({ ...golden.receipt, signature: '' })
    assert.equal(fresh, golden.canonical_preimage_for_signature)
  })

  it('the Ed25519 signature verifies over the pinned signature preimage', () => {
    const ok = verify(
      golden.canonical_preimage_for_signature,
      golden.receipt.signature,
      golden.receipt.signer_did,
    )
    assert.equal(ok, true)
  })

  it('verifies clean under the full context verifier when context is sound', () => {
    const r = verifyReceiptContext(golden.receipt, {
      now: '2026-05-01T12:00:00.000Z',
      active_delegation_root: golden.receipt.delegation_chain_root,
      delegation_expires_at: '2027-01-01T00:00:00.000Z',
      revoked_delegation_roots: [],
      budget_base_units: 1_000_000n,
      action_cost_base_units: 1_000n,
      expected_principal_did: golden.receipt.agent_did,
      active_policy_version: 3,
      evaluated_policy_version: 3,
      seen_receipt_ids: [],
      presented_as_claim_type: 'aps:action:v1',
      execution_attested: true,
    })
    assert.equal(r.valid, true, JSON.stringify(r))
  })
})

describe('conformance: negative fixtures are each rejected for the stated reason', () => {
  const negatives = buildNegatives()

  it('there is at least one negative per documented misuse category', () => {
    // The eight required misuse categories, mapped to fixture ids.
    const required = [
      'NEG-SIGNATURE-INVALID',
      'NEG-MISMATCHED-HASH',
      'NEG-WRONG-CLAIM-TYPE',
      'NEG-DELEGATION-EXPIRED',
      'NEG-STALE-REVOCATION',
      'NEG-OVER-BUDGET',
      'NEG-WRONG-PRINCIPAL',
      'NEG-STALE-POLICY',
      'NEG-REPLAYED',
      'NEG-WRONG-CLAIM',
      'NEG-POLICY-NOT-EXECUTED',
      'NEG-UNVERIFIED-EXTERNAL-EVIDENCE',
    ]
    const ids = new Set(negatives.map((n) => n.id))
    for (const id of required) {
      assert.equal(ids.has(id), true, `missing negative fixture ${id}`)
    }
  })

  for (const neg of negatives) {
    it(`${neg.id} is rejected with ${neg.expected_reject_reason}`, () => {
      const r = verifyReceiptContext(neg.receipt, neg.context)
      assert.equal(r.valid, false, `${neg.id} unexpectedly verified`)
      assert.equal(
        r.reason,
        neg.expected_reject_reason,
        `${neg.id} rejected for ${r.reason}, expected ${neg.expected_reject_reason}`,
      )
    })
  }

  it('every crypto-layer negative is also rejected by the bare crypto verifier', () => {
    for (const neg of negatives.filter((n) => n.layer === 'crypto')) {
      const r = verifyActionReceipt(neg.receipt)
      assert.equal(r.valid, false, `${neg.id} passed the crypto verifier`)
    }
  })

  it('no two negatives share an identical receipt_id and reason pair', () => {
    const seen = new Set<string>()
    for (const neg of negatives) {
      const key = `${neg.receipt.receipt_id}:${neg.expected_reject_reason}`
      assert.equal(seen.has(key), false, `duplicate negative ${key}`)
      seen.add(key)
    }
  })
})

describe('conformance: on-disk golden JSON matches the generator', () => {
  it('the golden valid JSON file is byte-identical to the regenerated fixture', () => {
    const golden = buildGoldenValid()
    const p = join(FIXTURES_DIR, `${golden.id}.json`)
    assert.equal(existsSync(p), true, `missing fixture file ${p}`)
    const onDisk = readFileSync(p, 'utf8')
    assert.equal(
      onDisk,
      stable(golden),
      'GOLD-VALID-001.json drifted from the generator. Re-run write-fixtures.ts.',
    )
  })

  for (const neg of buildNegatives()) {
    it(`${neg.id}.json is byte-identical to the regenerated fixture`, () => {
      const p = join(FIXTURES_DIR, `${neg.id}.json`)
      assert.equal(existsSync(p), true, `missing fixture file ${p}`)
      const onDisk = readFileSync(p, 'utf8')
      assert.equal(
        onDisk,
        stable(neg),
        `${neg.id}.json drifted from the generator. Re-run write-fixtures.ts.`,
      )
    })
  }
})
