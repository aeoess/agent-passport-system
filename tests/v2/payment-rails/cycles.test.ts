// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license.
import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { generateKeyPair, publicKeyFromPrivate, sign } from '../../../src/crypto/keys.js'
import { canonicalizeJCS } from '../../../src/core/canonical-jcs.js'
import { sha256Hex } from '../../../src/v2/payment-rails/canonicalize.js'
import {
  mapCyclesDenialToFoundation,
  RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
  signCyclesDenial,
  signCyclesPermitReceipt,
  signCyclesReleaseReceipt,
  verifyCyclesDenial,
  verifyCyclesPermitReceipt,
  verifyCyclesReleaseReceipt,
} from '../../../src/v2/payment-rails/cycles/index.js'
import type {
  AuthorityStateSnapshot,
  CyclesEvidenceEnvelopeInput,
  CyclesEvidenceRef,
  CyclesEvidenceView,
} from '../../../src/v2/payment-rails/cycles/types.js'

// ── Authority-state-at-admission fixture (Track B, aps#25) ────────
// The authority/revocation/expiry state APS saw at admission, carried
// inline on the permit-receipt (delegation identity is not duplicated —
// the receipt's own delegation_ref names it).

const ADMISSION_SNAPSHOT_FIXTURE: AuthorityStateSnapshot = {
  checked_at: '2026-05-30T12:00:00.000Z',
  delegation_revoked: false,
  delegation_expires_at: '2026-06-30T00:00:00.000Z',
  source: 'aps_admission',
}

// ── Test helpers ──────────────────────────────────────────────────

const FIXTURE_DIR = join(dirname(fileURLToPath(import.meta.url)), 'cycles-fixtures')

function loadFixture(filename: string): CyclesEvidenceView {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, filename), 'utf-8'))
}

function evidenceRef(): CyclesEvidenceRef {
  return {
    cycles_evidence_url: 'https://cycles.example.com/v1/evidence/abc',
    cycles_evidence_id_sha256: 'a'.repeat(64),
    action_ref: 'aps:action:cycles-test-001',
    delegation_ref: 'aps:delegation:cycles-test-001',
  }
}

// ── mapCyclesDenialToFoundation: 3 golden fixtures ────────────────

test('mapCyclesDenialToFoundation: 03-reserve-dry-run-deny → spend_limit_exceeded / DecisionReasonCode / BUDGET_EXCEEDED', () => {
  const env = loadFixture('03-reserve-dry-run-deny.json')
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r, 'mapping should return non-null')
  assert.equal(r.denial_reason, 'spend_limit_exceeded')
  assert.equal(r.cycles.denial_detail.source, 'DecisionReasonCode')
  assert.equal(r.cycles.denial_detail.code, 'BUDGET_EXCEEDED')
})

test('mapCyclesDenialToFoundation: 11-reserve-live-budget-exceeded → spend_limit_exceeded / ErrorCode / BUDGET_EXCEEDED', () => {
  const env = loadFixture('11-reserve-live-budget-exceeded.json')
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r)
  assert.equal(r.denial_reason, 'spend_limit_exceeded')
  assert.equal(r.cycles.denial_detail.source, 'ErrorCode')
  assert.equal(r.cycles.denial_detail.code, 'BUDGET_EXCEEDED')
  assert.equal(r.cycles.denial_detail.http_status, 409)
})

test('mapCyclesDenialToFoundation: 12-decide-live-forbidden → no_commerce_scope / ErrorCode / FORBIDDEN', () => {
  const env = loadFixture('12-decide-live-forbidden.json')
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r)
  assert.equal(r.denial_reason, 'no_commerce_scope')
  assert.equal(r.cycles.denial_detail.source, 'ErrorCode')
  assert.equal(r.cycles.denial_detail.code, 'FORBIDDEN')
  assert.equal(r.cycles.denial_detail.http_status, 403)
})

test('mapCyclesDenialToFoundation: unknown ErrorCode → rail_error fallback', () => {
  const env: CyclesEvidenceView = {
    artifact_type: 'error',
    payload: {
      error: {
        endpoint: 'POST /v1/reservations',
        http_status: 500,
        response: {
          error: 'FUTURE_UNKNOWN_CODE',
          message: 'something new',
          request_id: 'req_x',
        },
      },
    },
  }
  const r = mapCyclesDenialToFoundation(env)
  assert.ok(r)
  assert.equal(r.denial_reason, 'rail_error')
  assert.equal(r.cycles.denial_detail.code, 'FUTURE_UNKNOWN_CODE')
})

// ── Permit receipt sign/verify round-trip ─────────────────────────

test('signCyclesPermitReceipt + verifyCyclesPermitReceipt: happy-path round-trip', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_01HZZ8N4F8FBQX5K6TGYR0M0A3',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      expires_at_ms: 1810000030100,
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(receipt.claim_type, RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE)
  assert.equal(receipt.rail_name, 'cycles')
  assert.equal(receipt.decision, 'ALLOW')
  assert.match(receipt.receipt_id, /^cycles_permit_/)
  assert.equal(receipt.signature.length, 128)
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })
})

test('verifyCyclesPermitReceipt: tampered reservation_id → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_original',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = { ...receipt, reservation_id: 'rsv_tampered' }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

test('verifyCyclesPermitReceipt: missing cycles_evidence → MISSING_REQUIRED_FIELD', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // Strip the join shape and re-verify (this also corrupts signature
  // but we check the missing-field path runs before signature verify).
  const broken = {
    ...receipt,
    cycles_evidence: { ...receipt.cycles_evidence, cycles_evidence_id_sha256: '' },
  }
  const result = verifyCyclesPermitReceipt(broken)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'MISSING_REQUIRED_FIELD')
})

test('verifyCyclesPermitReceipt: wrong claim_type → INVALID_CLAIM_TYPE', () => {
  const { privateKey } = generateKeyPair()
  const release = signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      released: { unit: 'TOKENS', amount: 8000 },
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // Feed a release receipt to the permit verifier.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const result = verifyCyclesPermitReceipt(release as any)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'INVALID_CLAIM_TYPE')
})

// ── Release receipt sign/verify round-trip ────────────────────────

test('signCyclesReleaseReceipt + verifyCyclesReleaseReceipt: happy-path round-trip with reason', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_release_001',
      released: { unit: 'USD_MICROCENTS', amount: 500000 },
      reason: 'handler_timeout',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(receipt.claim_type, RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE)
  assert.equal(receipt.reason, 'handler_timeout')
  assert.match(receipt.receipt_id, /^cycles_release_/)
  assert.deepEqual(verifyCyclesReleaseReceipt(receipt), { valid: true })
})

test('verifyCyclesReleaseReceipt: tampered released amount → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesReleaseReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_release_001',
      released: { unit: 'USD_MICROCENTS', amount: 500000 },
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = {
    ...receipt,
    released: { ...receipt.released, amount: 999999999 },
  }
  const result = verifyCyclesReleaseReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

// ── Denial sign/verify round-trip ─────────────────────────────────

test('signCyclesDenial + verifyCyclesDenial: ErrorCode-sourced denial round-trip', () => {
  const { privateKey } = generateKeyPair()
  const env = loadFixture('11-reserve-live-budget-exceeded.json')
  const mapped = mapCyclesDenialToFoundation(env)
  assert.ok(mapped, 'mapping must succeed')
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: mapped.denial_reason,
      cycles: mapped.cycles,
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(denial.claim_type, RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE)
  assert.equal(denial.denial_reason, 'spend_limit_exceeded')
  assert.equal(denial.cycles.denial_detail.code, 'BUDGET_EXCEEDED')
  assert.equal(denial.cycles.denial_detail.source, 'ErrorCode')
  assert.match(denial.receipt_id, /^cycles_denial_/)
  assert.deepEqual(verifyCyclesDenial(denial), { valid: true })
})

test('signCyclesDenial + verifyCyclesDenial: DecisionReasonCode-sourced denial round-trip (dry-run)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadFixture('03-reserve-dry-run-deny.json')
  const mapped = mapCyclesDenialToFoundation(env)
  assert.ok(mapped)
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: mapped.denial_reason,
      cycles: mapped.cycles,
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  assert.equal(denial.denial_reason, 'spend_limit_exceeded')
  assert.equal(denial.cycles.denial_detail.source, 'DecisionReasonCode')
  assert.deepEqual(verifyCyclesDenial(denial), { valid: true })
})

test('verifyCyclesDenial: tampered cycles.denial_detail.code → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: 'spend_limit_exceeded',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'ErrorCode',
          code: 'BUDGET_EXCEEDED',
          http_status: 409,
        },
      },
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = {
    ...denial,
    cycles: {
      denial_detail: {
        ...denial.cycles.denial_detail,
        code: 'TAMPERED',
      },
    },
  }
  const result = verifyCyclesDenial(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

// ── Signer-mismatch + expected_signer option ──────────────────────

test('verifyCyclesPermitReceipt: expected_signer mismatch → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const result = verifyCyclesPermitReceipt(receipt, {
    expected_signer: 'f'.repeat(64),
  })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

// ── TTL / EXPIRED ─────────────────────────────────────────────────

test('verifyCyclesPermitReceipt: past-TTL → EXPIRED', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const future = new Date(Date.parse(receipt.issued_at) + 48 * 60 * 60 * 1000)
  const result = verifyCyclesPermitReceipt(receipt, { now: future, ttl_seconds: 24 * 60 * 60 })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EXPIRED')
})

// ── rail_name invariant ───────────────────────────────────────────

test('verifyCyclesPermitReceipt: tampered rail_name → SIGNATURE_INVALID (signature catches it)', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // Cast to assign a non-literal rail_name for testing the structural check.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const tampered: any = { ...receipt, rail_name: 'cycles_v2' }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'INVALID_RAIL_NAME')
})

// ── Accountability-shape invariants ───────────────────────────────

test('verifyCyclesPermitReceipt: timestamp != issued_at → MISSING_REQUIRED_FIELD', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = { ...receipt, timestamp: '2020-01-01T00:00:00.000Z' }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'MISSING_REQUIRED_FIELD')
})

test('verifyCyclesPermitReceipt: empty scope_of_claim.asserts → MISSING_REQUIRED_FIELD', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  const tampered = {
    ...receipt,
    scope_of_claim: { ...receipt.scope_of_claim!, asserts: '' },
  }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'MISSING_REQUIRED_FIELD')
})

// ── DID URI signers ───────────────────────────────────────────────

test('verifyCyclesPermitReceipt (sync): DID URI signer → DID_RESOLVER_MISSING', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_x',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
      issuer_agent_id: 'did:cycles:example',
      issuer_key_ref: 'key-1',
    },
    privateKey,
  )
  assert.equal(receipt.signer, 'did:cycles:example#key-1')
  const result = verifyCyclesPermitReceipt(receipt)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'DID_RESOLVER_MISSING')
})

// ── Authority-state-at-admission (Track B, aps#25, staged, inline) ─

test('signCyclesPermitReceipt: WITH authority_state_at_admission → carries the inline object and verifies', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-admission-001',
      action_ref: 'aps:action:cycles-admission-001',
      reservation_id: 'rsv_admission_001',
      reserved: { unit: 'USD_MICROCENTS', amount: 1500000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
      authority_state_at_admission: ADMISSION_SNAPSHOT_FIXTURE,
    },
    privateKey,
  )
  // (a) the inline snapshot is carried verbatim on the receipt...
  assert.deepEqual(receipt.authority_state_at_admission, ADMISSION_SNAPSHOT_FIXTURE)
  // ...and the receipt (with the object inside the signed body) verifies.
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })
})

test('signCyclesPermitReceipt: tampering a field inside authority_state_at_admission → SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-admission-001',
      action_ref: 'aps:action:cycles-admission-001',
      reservation_id: 'rsv_admission_001',
      reserved: { unit: 'USD_MICROCENTS', amount: 1500000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
      authority_state_at_admission: ADMISSION_SNAPSHOT_FIXTURE,
    },
    privateKey,
  )
  // (b) flip delegation_revoked inside the inline object — the snapshot is
  // part of the signed body, so the signature must catch it.
  const tampered = {
    ...receipt,
    authority_state_at_admission: {
      ...receipt.authority_state_at_admission!,
      delegation_revoked: true,
    },
  }
  const result = verifyCyclesPermitReceipt(tampered)
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'SIGNATURE_INVALID')
})

test('signCyclesPermitReceipt: WITHOUT the snapshot → field absent, receipt verifies unchanged', () => {
  const { privateKey } = generateKeyPair()
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_no_snapshot',
      reserved: { unit: 'USD_MICROCENTS', amount: 1000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(),
    },
    privateKey,
  )
  // (c) callers that pass nothing get the field absent from the object (so
  // existing fixtures/canonical bytes are unchanged) and verify.
  assert.equal(Object.prototype.hasOwnProperty.call(receipt, 'authority_state_at_admission'), false)
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })
})

// ── Join-integrity: receipt ↔ CyclesEvidence envelope binding ─────
// The load-bearing offline-audit guarantee (aps#25, lowkey-divine). When
// the fetched envelope is supplied, verify recomputes its content hash and
// confirms it matches BOTH the envelope's own evidence_id AND the receipt's
// cycles_evidence.cycles_evidence_id_sha256. The fixtures' evidence_id was
// derived by the Cycles server; reproducing it here proves APS's JCS +
// sha256 is byte-compatible with cycles-evidence-v0.1's normative algorithm.

/** A full CyclesEvidence envelope (with evidence_id + signature). */
function loadEnvelope(filename: string): CyclesEvidenceEnvelopeInput {
  return JSON.parse(readFileSync(join(FIXTURE_DIR, filename), 'utf-8'))
}

/** A permit receipt whose cycles_evidence binds to `env` by content hash. */
function permitBoundTo(env: CyclesEvidenceEnvelopeInput, privateKey: string) {
  return signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_join_integrity',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: { ...evidenceRef(), cycles_evidence_id_sha256: env.evidence_id },
    },
    privateKey,
  )
}

test('join-integrity: permit receipt + matching envelope → valid', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // Envelope supplied → join + envelope-signature both checked; the passing
  // result tags the unpinned authenticity state (APS#43 (a)).
  assert.deepEqual(verifyCyclesPermitReceipt(receipt, { evidence: env }), {
    valid: true,
    evidence_authenticity: 'signature_valid',
  })
})

test('join-integrity: envelope omitted → check skipped, signature-only verify still passes', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // No options.evidence → backward-compatible signature-only path.
  assert.deepEqual(verifyCyclesPermitReceipt(receipt), { valid: true })
})

test('join-integrity: tampered envelope (recomputed != evidence_id) → EVIDENCE_REF_HASH_MISMATCH', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // Mutate any signed field; evidence_id no longer matches the bytes.
  const tampered = { ...env, server_id: 'https://evil.example.com/v1' }
  const result = verifyCyclesPermitReceipt(receipt, { evidence: tampered })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

test('join-integrity: receipt bound to a different envelope → EVIDENCE_REF_HASH_MISMATCH', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  // Receipt binds to the DEFAULT placeholder hash, not env.evidence_id.
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_wrong_binding',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: evidenceRef(), // cycles_evidence_id_sha256 = 'a'*64
    },
    privateKey,
  )
  const result = verifyCyclesPermitReceipt(receipt, { evidence: env })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

test('join-integrity: applies on the denial path too (shared core verifier)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('11-reserve-live-budget-exceeded.json')
  const mapping = mapCyclesDenialToFoundation(loadFixture('11-reserve-live-budget-exceeded.json'))
  assert.ok(mapping)
  const denial = signCyclesDenial(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      denial_reason: mapping.denial_reason,
      cycles: mapping.cycles,
      cycles_evidence: { ...evidenceRef(), cycles_evidence_id_sha256: env.evidence_id },
    },
    privateKey,
  )
  assert.deepEqual(verifyCyclesDenial(denial, { evidence: env }), {
    valid: true,
    evidence_authenticity: 'signature_valid',
  })
  // And a mismatched binding is caught on the denial path.
  const wrong = verifyCyclesDenial(denial, {
    evidence: { ...env, server_id: 'https://evil.example.com/v1' },
  })
  assert.equal(wrong.valid, false)
  if (!wrong.valid) assert.equal(wrong.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

test('join-integrity: non-string envelope evidence_id → EVIDENCE_REF_HASH_MISMATCH', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // A malformed envelope whose evidence_id is not the canonical hex string.
  // The recompute (a 64-char lowercase hex) can never equal a non-string,
  // so the self-consistency check (a) fails closed.
  const malformed = { ...env, evidence_id: ['not', 'a', 'string'] as unknown as string }
  const result = verifyCyclesPermitReceipt(receipt, { evidence: malformed })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

test('join-integrity: receipt hash correct but uppercase → EVIDENCE_REF_HASH_MISMATCH (byte-exact, no case-folding)', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  // Bind the receipt to the UPPERCASE form of the (lowercase) evidence_id.
  // The recompute is lowercase hex; the comparison is byte-exact, so an
  // otherwise-correct hash that differs only in case must be rejected.
  const receipt = signCyclesPermitReceipt(
    {
      agent_id: 'agent-cycles-001',
      delegation_ref: 'aps:delegation:cycles-001',
      action_ref: 'aps:action:cycles-001',
      reservation_id: 'rsv_uppercase_hash',
      reserved: { unit: 'USD_MICROCENTS', amount: 2000000 },
      decision: 'ALLOW',
      cycles_evidence: { ...evidenceRef(), cycles_evidence_id_sha256: env.evidence_id.toUpperCase() },
    },
    privateKey,
  )
  const result = verifyCyclesPermitReceipt(receipt, { evidence: env })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_REF_HASH_MISMATCH')
})

// ── Envelope authenticity: APS#43 (a) — envelope Ed25519 signature ─
// Beyond the hash binding, a supplied envelope's OWN signature is verified
// against its signer_did (signature emptied, evidence_id populated — the
// cycles-evidence-v0.1 "Signature derivation" canonicalization, distinct
// from the content-hash recipe). A passing verify tags evidence_authenticity:
// 'signature_valid' (bytes verify against signer_did) or 'pinned_issuer'
// (that PLUS expected_signer pinning the receipt issuer = full authenticity
// for the pinned case). Dynamic signer-AUTHORITY resolution is (b), gated on
// runcycles/cycles-protocol#103 and intentionally NOT done here.

/** Re-derive a fully self-consistent envelope signed by `privateKey`:
 *  re-points signer_did to that key, recomputes evidence_id, and re-signs.
 *  Models an envelope an arbitrary key produced (used for the (a)/(b)
 *  boundary test). */
function resignEnvelope(
  env: CyclesEvidenceEnvelopeInput,
  privateKey: string,
): CyclesEvidenceEnvelopeInput {
  const signer_did = publicKeyFromPrivate(privateKey)
  const evidence_id = sha256Hex(
    canonicalizeJCS({ ...env, signer_did, evidence_id: '', signature: '' }),
  )
  const signature = sign(
    canonicalizeJCS({ ...env, signer_did, evidence_id, signature: '' }),
    privateKey,
  )
  return { ...env, signer_did, evidence_id, signature }
}

test('envelope-authenticity: valid signature + pinned receipt issuer → pinned_issuer', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // expected_signer pins the receipt issuer (the trust anchor / manual (b)).
  const result = verifyCyclesPermitReceipt(receipt, {
    evidence: env,
    expected_signer: publicKeyFromPrivate(privateKey),
  })
  assert.deepEqual(result, { valid: true, evidence_authenticity: 'pinned_issuer' })
})

test('envelope-authenticity: hash-consistent envelope with a bad signature → EVIDENCE_SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // Zero the signature. The hash recompute empties `signature`, so the
  // binding/self-consistency check still PASSES — only the (a) signature
  // check catches it. This is the core (a) guarantee.
  const forged = { ...env, signature: '0'.repeat(128) }
  const result = verifyCyclesPermitReceipt(receipt, { evidence: forged })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_SIGNATURE_INVALID')
})

test('envelope-authenticity: (a)/(b) boundary — attacker self-signs, signature_valid still holds (NOT authenticity)', () => {
  const { privateKey: issuerKey } = generateKeyPair()
  const { privateKey: attackerKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  // Attacker re-signs the envelope with THEIR OWN key and embeds their own
  // pubkey as signer_did — a fully self-consistent forgery.
  const forged = resignEnvelope(env, attackerKey)
  const receipt = permitBoundTo(forged, issuerKey)
  // (a) alone passes: the bytes verify against the embedded signer_did. This
  // is exactly why signature_valid is NOT authenticity — it is the (b) gap
  // that did:cycles / JWKS resolution (cycles-protocol#103) closes.
  assert.deepEqual(verifyCyclesPermitReceipt(receipt, { evidence: forged }), {
    valid: true,
    evidence_authenticity: 'signature_valid',
  })
})

test('envelope-authenticity: self-consistent envelope missing signer_did → EVIDENCE_SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  // Drop signer_did and recompute evidence_id over the reduced shape, so the
  // hash binding still passes and the missing-signer_did guard is what fires.
  const { signer_did: _omit, ...noDid } = env
  const evidence_id = sha256Hex(canonicalizeJCS({ ...noDid, evidence_id: '', signature: '' }))
  const consistent = { ...noDid, evidence_id } as unknown as CyclesEvidenceEnvelopeInput
  const receipt = permitBoundTo(consistent, privateKey)
  const result = verifyCyclesPermitReceipt(receipt, { evidence: consistent })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_SIGNATURE_INVALID')
})

test('envelope-authenticity: empty signature (hash-consistent) → EVIDENCE_SIGNATURE_INVALID', () => {
  const { privateKey } = generateKeyPair()
  const env = loadEnvelope('02-reserve-allow.json')
  const receipt = permitBoundTo(env, privateKey)
  // `signature` is emptied during the hash recompute, so an empty signature
  // leaves the binding intact — the empty-signature guard is what fires.
  const result = verifyCyclesPermitReceipt(receipt, { evidence: { ...env, signature: '' } })
  assert.equal(result.valid, false)
  if (!result.valid) assert.equal(result.reason, 'EVIDENCE_SIGNATURE_INVALID')
})
