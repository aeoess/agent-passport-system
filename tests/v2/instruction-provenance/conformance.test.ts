// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// IPR — conformance tests against fixture-vector positive paths.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  canonicalizeEnvelope,
  computeContextRoot,
  sha256Hex,
  verifyActionTimeContextRoot,
  verifyInstructionProvenanceReceipt,
} from '../../../src/v2/instruction-provenance/index.js'
import type {
  InstructionProvenanceReceipt,
} from '../../../src/v2/instruction-provenance/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = join(__dirname, '..', '..', '..', 'fixtures', 'instruction-provenance', 'canonicalize-fixture-v1.json')

interface FixtureFile {
  version: string
  primitive: string
  keypair: { publicKeyHex: string }
  vectors: Array<{
    name: string
    description: string
    expected_verification: boolean
    canonical_bytes_hex?: string
    canonical_sha256?: string
    receipt_id?: string
    context_root?: string
    ed25519_signature?: string
    envelope?: InstructionProvenanceReceipt
  }>
}

const fixture: FixtureFile = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'))
const PUBKEY = fixture.keypair.publicKeyHex
const POSITIVES = fixture.vectors.filter(v => v.expected_verification === true)

describe('IPR conformance — fixture positives', () => {
  for (const v of POSITIVES) {
    describe(v.name, () => {
      it('envelope is present and serializes deterministically', () => {
        assert.ok(v.envelope, 'positive vector missing envelope field')
        const env = v.envelope!
        const canon = canonicalizeEnvelope(env)
        const canonHex = Buffer.from(canon, 'utf8').toString('hex')
        assert.equal(canonHex, v.canonical_bytes_hex, 'canonical_bytes_hex mismatch')
        assert.equal(sha256Hex(canon), v.canonical_sha256, 'canonical_sha256 mismatch')
      })

      it('receipt_id derives from canonical bytes', () => {
        const env = v.envelope!
        const canon = canonicalizeEnvelope(env)
        assert.equal(env.receipt_id, sha256Hex(canon))
        assert.equal(env.receipt_id, v.receipt_id)
      })

      it('context_root recomputes deterministically', () => {
        const env = v.envelope!
        assert.equal(env.context_root, computeContextRoot(env.instruction_files))
        assert.equal(env.context_root, v.context_root)
      })

      it('attestation_tier is self-asserted (v0.2 lock)', () => {
        assert.equal(v.envelope!.attestation_tier, 'self-asserted')
      })

      it('verifyInstructionProvenanceReceipt returns valid', () => {
        const r = verifyInstructionProvenanceReceipt({ envelope: v.envelope!, publicKeyHex: PUBKEY })
        assert.equal(r.valid, true, `expected valid; errors: ${r.errors.join('; ')}`)
        assert.equal(r.tier, 'self-asserted')
        assert.equal(r.contextRoot, v.envelope!.context_root)
      })
    })
  }

  it('every positive vector signature matches the deterministic key', () => {
    for (const v of POSITIVES) {
      const env = v.envelope!
      assert.equal(env.signature, v.ed25519_signature, `signature drift in ${v.name}`)
    }
  })
})

describe('IPR conformance — verifyActionTimeContextRoot', () => {
  const recompute = POSITIVES.find(v => v.name === 'recompute-at-action-true')

  it('matches when action-time root equals envelope root', () => {
    assert.ok(recompute, 'fixture vector recompute-at-action-true missing')
    const env = recompute!.envelope!
    const r = verifyActionTimeContextRoot({
      envelope: env,
      context_root_at_action_time: env.context_root,
    })
    assert.equal(r.valid, true, r.errors.join('; '))
  })

  it('rejects mismatch (context_drift)', () => {
    const env = recompute!.envelope!
    const r = verifyActionTimeContextRoot({
      envelope: env,
      context_root_at_action_time: '0'.repeat(64),
    })
    assert.equal(r.valid, false)
    assert.match(r.errors[0]!, /context_drift/)
  })

  it('rejects when IPR did not declare recompute_at_action: true', () => {
    const minimal = POSITIVES.find(v => v.name === 'minimal-valid-envelope')!
    const env = minimal.envelope!
    const r = verifyActionTimeContextRoot({
      envelope: env,
      context_root_at_action_time: env.context_root,
    })
    assert.equal(r.valid, false)
    assert.match(r.errors[0]!, /recompute_at_action/)
  })
})
