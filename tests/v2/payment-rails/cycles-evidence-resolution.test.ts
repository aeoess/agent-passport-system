// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Cycles external-evidence resolution: claimed vs resolved (W2-A2)
// ══════════════════════════════════════════════════════════════════
// PROOF BOX
// ─────────
// PROVES:    Resolution shows whether the external envelope at the
//            claimed hash was fetched and matched. A receipt whose
//            signature is green but whose cycles_evidence_url serves a
//            DIFFERENT envelope verifies on signature yet reports
//            claimed-not-resolved (observation_basis = signature_only).
//            A matching envelope reports counterparty_resolved.
//
// DOES NOT PROVE:
//            - that a signature-only receipt's envelope exists at all
//              (someone signed a pointer to a hash, not the bytes);
//            - that a resolved envelope is truthful about the rail event;
//            - that a budget reservation settled (no finality evidence).
//            A resolution failure is RECORDED in the result, never thrown.
// ══════════════════════════════════════════════════════════════════

import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import {
  signCyclesPermitReceipt,
  signCyclesReleaseReceipt,
  signCyclesDenial,
  verifyCyclesPermitReceipt,
  verifyCyclesPermitReceiptWithEvidence,
  verifyCyclesReleaseReceiptWithEvidence,
  verifyCyclesDenialWithEvidence,
  resolveEvidenceRef,
  recomputeEvidenceContentHash,
  toEvidenceDescriptorInput,
} from '../../../src/v2/payment-rails/cycles/index.js'
import type {
  EvidenceResolver,
  EvidenceFetchResult,
  FetchedCyclesEvidenceEnvelope,
} from '../../../src/v2/payment-rails/cycles/index.js'
import type { CyclesEvidenceRef } from '../../../src/v2/payment-rails/cycles/types.js'

// ── Fixtures ──────────────────────────────────────────────────────

const EVIDENCE_URL = 'https://cycles.example.com/v1/evidence/abc'

/** A representative signed CyclesEvidence envelope (structural subset).
 *  evidence_id and signature are present and non-empty: the recipe
 *  empties them before hashing, so their values do not affect the hash. */
function sampleEnvelope(): FetchedCyclesEvidenceEnvelope {
  return {
    evidence_id: 'evid_01HZZ8N4F8FBQX5K6TGYR0M0A3',
    signature: 'deadbeef'.repeat(16),
    schema_version: 'cycles-evidence/v0.1',
    artifact_type: 'reserve',
    trace_id: '0af7651916cd43dd8448eb211c80319c',
    payload: {
      reserve: {
        request: { amount: 2000000, unit: 'USD_MICROCENTS', dry_run: false },
        response: { decision: 'ALLOW', reservation_id: 'rsv_001' },
      },
    },
  }
}

/** Build an evidence ref whose claimed hash matches the given envelope. */
function matchingRef(env: FetchedCyclesEvidenceEnvelope): CyclesEvidenceRef {
  return {
    cycles_evidence_url: EVIDENCE_URL,
    cycles_evidence_id_sha256: recomputeEvidenceContentHash(env),
    action_ref: 'aps:action:cycles-ev-001',
    delegation_ref: 'aps:delegation:cycles-ev-001',
  }
}

/** Build an evidence ref with a bogus (non-matching) claimed hash. */
function bogusRef(): CyclesEvidenceRef {
  return {
    cycles_evidence_url: EVIDENCE_URL,
    cycles_evidence_id_sha256: 'b'.repeat(64),
    action_ref: 'aps:action:cycles-ev-001',
    delegation_ref: 'aps:delegation:cycles-ev-001',
  }
}

/** A resolver that always serves the given envelope. */
function fixedResolver(env: FetchedCyclesEvidenceEnvelope): EvidenceResolver {
  return {
    canResolve: () => true,
    resolve: async (): Promise<EvidenceFetchResult> => ({ ok: true, envelope: env }),
  }
}

/** A resolver that reports a non-fetch status (records failure). */
function failingResolver(
  status: 'not_found' | 'unreachable' | 'malformed',
): EvidenceResolver {
  return {
    canResolve: () => true,
    resolve: async (): Promise<EvidenceFetchResult> => ({ ok: false, status, reason: `simulated ${status}` }),
  }
}

function permitFixture(ref: CyclesEvidenceRef, privateKey: string) {
  return signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-ev-001',
      delegation_ref: ref.delegation_ref,
      action_ref: ref.action_ref,
      reservation_id: 'rsv_001',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: ref,
    },
    privateKey,
  )
}

// ── recomputeEvidenceContentHash: recipe contract ────────────────

test('recomputeEvidenceContentHash: empties evidence_id and signature before hashing', () => {
  const a = sampleEnvelope()
  const b = { ...sampleEnvelope(), evidence_id: 'DIFFERENT', signature: 'feed'.repeat(20) }
  // The two envelopes differ ONLY in the two members the recipe empties,
  // so their recomputed content hashes must be identical.
  assert.equal(recomputeEvidenceContentHash(a), recomputeEvidenceContentHash(b))
  assert.match(recomputeEvidenceContentHash(a), /^[0-9a-f]{64}$/)
})

test('recomputeEvidenceContentHash: a body difference DOES change the hash', () => {
  const a = sampleEnvelope()
  const c: FetchedCyclesEvidenceEnvelope = { ...sampleEnvelope(), trace_id: 'a'.repeat(32) }
  assert.notEqual(recomputeEvidenceContentHash(a), recomputeEvidenceContentHash(c))
})

// ── Matching envelope → resolved / counterparty_resolved ──────────

test('verifyCyclesPermitReceiptWithEvidence: matching envelope → verify green AND resolved', async () => {
  const { privateKey } = generateKeyPair()
  const env = sampleEnvelope()
  const receipt = permitFixture(matchingRef(env), privateKey)

  const out = await verifyCyclesPermitReceiptWithEvidence(receipt, {
    resolveEvidence: fixedResolver(env),
  })
  assert.deepEqual(out.verify, { valid: true })
  assert.equal(out.evidence.resolved, true)
  assert.equal(out.evidence.status, 'matched')
  assert.equal(out.evidence.resolved_sha256, receipt.cycles_evidence.cycles_evidence_id_sha256)
  assert.equal(out.descriptor.observation_basis, 'counterparty_resolved')
  assert.equal(out.descriptor.envelope_matched, true)
})

// ── Bogus envelope → verify green BUT claimed-not-resolved ────────

test('verifyCyclesPermitReceiptWithEvidence: bogus claimed hash → signature green, claimed-not-resolved (hash_mismatch)', async () => {
  const { privateKey } = generateKeyPair()
  const env = sampleEnvelope()
  // Receipt claims a hash the served envelope does NOT produce.
  const receipt = permitFixture(bogusRef(), privateKey)

  // Sanity: the receipt signature itself is valid (it signs the bogus ref).
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })

  const out = await verifyCyclesPermitReceiptWithEvidence(receipt, {
    resolveEvidence: fixedResolver(env),
  })
  // Signature still green: someone signed a pointer to a hash.
  assert.deepEqual(out.verify, { valid: true })
  // But the fetched envelope does not match the claimed hash.
  assert.equal(out.evidence.resolved, false)
  assert.equal(out.evidence.status, 'hash_mismatch')
  assert.equal(out.evidence.resolved_sha256, recomputeEvidenceContentHash(env))
  assert.notEqual(out.evidence.resolved_sha256, out.evidence.claimed_sha256)
  assert.equal(out.descriptor.observation_basis, 'signature_only')
  assert.equal(out.descriptor.envelope_matched, false)
})

// ── No resolver supplied → claimed only, never thrown ─────────────

test('verifyCyclesPermitReceiptWithEvidence: no resolver → signature green, no_resolver (claimed not tested)', async () => {
  const { privateKey } = generateKeyPair()
  const receipt = permitFixture(matchingRef(sampleEnvelope()), privateKey)

  const out = await verifyCyclesPermitReceiptWithEvidence(receipt)
  assert.deepEqual(out.verify, { valid: true })
  assert.equal(out.evidence.resolved, false)
  assert.equal(out.evidence.status, 'no_resolver')
  assert.equal(out.descriptor.observation_basis, 'signature_only')
  assert.equal(out.evidence.claimed_sha256, receipt.cycles_evidence.cycles_evidence_id_sha256)
})

// ── Resolution failure is RECORDED, not thrown ────────────────────

test('resolveEvidenceRef: not_found → recorded, fail-closed, not thrown', async () => {
  const ref = matchingRef(sampleEnvelope())
  const r = await resolveEvidenceRef(ref, failingResolver('not_found'))
  assert.equal(r.resolved, false)
  assert.equal(r.status, 'not_found')
  assert.equal(r.degraded, undefined)
  assert.equal(r.claimed_sha256, ref.cycles_evidence_id_sha256)
})

test('resolveEvidenceRef: malformed → recorded, fail-closed always', async () => {
  const ref = matchingRef(sampleEnvelope())
  const r = await resolveEvidenceRef(ref, failingResolver('malformed'), { failurePolicy: 'open' })
  // malformed never relaxes, even under fail-open.
  assert.equal(r.resolved, false)
  assert.equal(r.status, 'malformed')
  assert.notEqual(r.degraded, true)
})

test('resolveEvidenceRef: unreachable under fail-closed → recorded, not degraded, not resolved', async () => {
  const ref = matchingRef(sampleEnvelope())
  const r = await resolveEvidenceRef(ref, failingResolver('unreachable'))
  assert.equal(r.resolved, false)
  assert.equal(r.status, 'unreachable')
  assert.equal(r.degraded, false)
})

test('resolveEvidenceRef: unreachable under fail-OPEN → degraded but STILL not resolved', async () => {
  const ref = matchingRef(sampleEnvelope())
  const r = await resolveEvidenceRef(ref, failingResolver('unreachable'), { failurePolicy: 'open' })
  assert.equal(r.degraded, true)
  // A degraded result MUST NOT read as a positive match.
  assert.equal(r.resolved, false)
  assert.equal(r.status, 'unreachable')
})

test('resolveEvidenceRef: a resolver that THROWS is caught and recorded as unreachable', async () => {
  const ref = matchingRef(sampleEnvelope())
  const throwingResolver: EvidenceResolver = {
    canResolve: () => true,
    resolve: async () => {
      throw new Error('boom')
    },
  }
  const r = await resolveEvidenceRef(ref, throwingResolver)
  assert.equal(r.resolved, false)
  assert.equal(r.status, 'unreachable')
  assert.match(r.reason ?? '', /resolver threw/)
})

test('resolveEvidenceRef: resolver that declines the url → no_resolver', async () => {
  const ref = matchingRef(sampleEnvelope())
  const decliner: EvidenceResolver = {
    canResolve: () => false,
    resolve: async () => ({ ok: false, status: 'unreachable' }),
  }
  const r = await resolveEvidenceRef(ref, decliner)
  assert.equal(r.status, 'no_resolver')
  assert.equal(r.resolved, false)
})

// ── Descriptor projection is total and mechanical ─────────────────

test('toEvidenceDescriptorInput: matched → counterparty_resolved, carries resolved hash', () => {
  const env = sampleEnvelope()
  const ref = matchingRef(env)
  const matched = {
    claimed_sha256: ref.cycles_evidence_id_sha256,
    resolved: true,
    status: 'matched' as const,
    resolved_sha256: ref.cycles_evidence_id_sha256,
  }
  const d = toEvidenceDescriptorInput(matched)
  assert.equal(d.observation_basis, 'counterparty_resolved')
  assert.equal(d.envelope_matched, true)
  assert.equal(d.resolution_status, 'matched')
  assert.equal(d.resolved_sha256, ref.cycles_evidence_id_sha256)
})

test('toEvidenceDescriptorInput: every non-matched status → signature_only', () => {
  for (const status of ['hash_mismatch', 'malformed', 'not_found', 'unreachable', 'no_resolver'] as const) {
    const d = toEvidenceDescriptorInput({
      claimed_sha256: 'c'.repeat(64),
      resolved: false,
      status,
    })
    assert.equal(d.observation_basis, 'signature_only', `status ${status}`)
    assert.equal(d.envelope_matched, false)
    assert.equal(d.resolution_status, status)
  }
})

test('toEvidenceDescriptorInput: descriptor carries NO assurance scalar (mechanical facts only)', () => {
  const d = toEvidenceDescriptorInput({
    claimed_sha256: 'c'.repeat(64),
    resolved: true,
    status: 'matched',
    resolved_sha256: 'c'.repeat(64),
  })
  // The descriptor input reports only mechanical facts; it must not carry
  // an issuer- or verifier-set assurance/score field.
  assert.equal('assurance' in d, false)
  assert.equal('score' in d, false)
  assert.equal('evidence_assurance' in d, false)
})

// ── Additive-field safety: WithEvidence does not change receipt bytes ─

test('WithEvidence path does not mutate the receipt nor its signed bytes', async () => {
  const { privateKey } = generateKeyPair()
  const env = sampleEnvelope()
  const receipt = permitFixture(matchingRef(env), privateKey)
  const before = JSON.stringify(receipt)
  await verifyCyclesPermitReceiptWithEvidence(receipt, { resolveEvidence: fixedResolver(env) })
  assert.equal(JSON.stringify(receipt), before)
  // The receipt with no evidence options still verifies byte-identically.
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })
})

// ── Release + denial paths thread evidence too ────────────────────

test('verifyCyclesReleaseReceiptWithEvidence: matching envelope → resolved', async () => {
  const { privateKey } = generateKeyPair()
  const env = sampleEnvelope()
  const ref = matchingRef(env)
  const receipt = signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-ev-001',
      delegation_ref: ref.delegation_ref,
      action_ref: ref.action_ref,
      reservation_id: 'rsv_001',
      released: { unit: 'USD_MICROCENTS', amount: 2000000 },
      cycles_evidence: ref,
    },
    privateKey,
  )
  const out = await verifyCyclesReleaseReceiptWithEvidence(receipt, {
    resolveEvidence: fixedResolver(env),
  })
  assert.deepEqual(out.verify, { valid: true })
  assert.equal(out.descriptor.observation_basis, 'counterparty_resolved')
})

test('verifyCyclesDenialWithEvidence: bogus hash → signature green, claimed-not-resolved', async () => {
  const { privateKey } = generateKeyPair()
  const env = sampleEnvelope()
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-ev-001',
      delegation_ref: 'aps:delegation:cycles-ev-001',
      action_ref: 'aps:action:cycles-ev-001',
      denial_reason: 'spend_limit_exceeded',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'ErrorCode',
          code: 'BUDGET_EXCEEDED',
          http_status: 409,
        },
      },
      cycles_evidence: bogusRef(),
    },
    privateKey,
  )
  const out = await verifyCyclesDenialWithEvidence(denial, {
    resolveEvidence: fixedResolver(env),
  })
  assert.deepEqual(out.verify, { valid: true })
  assert.equal(out.evidence.status, 'hash_mismatch')
  assert.equal(out.descriptor.observation_basis, 'signature_only')
})

// ── Verify-failure still surfaces a descriptor ────────────────────

test('verifyCyclesPermitReceiptWithEvidence: tampered receipt → verify fails BUT descriptor still reports basis', async () => {
  const { privateKey } = generateKeyPair()
  const env = sampleEnvelope()
  const receipt = permitFixture(matchingRef(env), privateKey)
  const tampered = { ...receipt, reservation_id: 'rsv_tampered' }
  const out = await verifyCyclesPermitReceiptWithEvidence(tampered, {
    resolveEvidence: fixedResolver(env),
  })
  // Signature verify fails (the body was altered)...
  assert.equal(out.verify.valid, false)
  // ...yet the evidence ref (unaltered) still resolves and matches, so the
  // descriptor records counterparty_resolved independently of the receipt
  // verdict. The two axes are reported separately.
  assert.equal(out.evidence.status, 'matched')
  assert.equal(out.descriptor.observation_basis, 'counterparty_resolved')
})

// ── scope_of_claim is dogfooded on the resolution result ──────────

test('resolveEvidenceRef: matched result carries an honest scope_of_claim', async () => {
  const env = sampleEnvelope()
  const r = await resolveEvidenceRef(matchingRef(env), fixedResolver(env))
  assert.ok(r.scope_of_claim)
  assert.match(r.scope_of_claim!.asserts, /matched/)
  // It explicitly disclaims settlement and downstream truth.
  assert.ok(r.scope_of_claim!.does_not_assert.some(s => /settled/.test(s)))
})
