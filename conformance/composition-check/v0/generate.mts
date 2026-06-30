// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Generator for the APS Composition Check Receipt v0 conformance vectors.
//
// Produces conformance/composition-check/v0/vectors.json: signed receipts + caller trust
// contexts + HAND-SPECIFIED expectations (the expectations are NOT computed by the verifier,
// so the conformance test is a real check, not a tautology). Run:
//   cd <repo> && npx tsx conformance/composition-check/v0/generate.mts
// Keys are fresh per run; the committed vectors.json is the pinned artifact.
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { generateKeyPair, sign, CompositionCheckV0 } from '../../../src/index.js'

const { compositionCheckSigningPayload, COMPOSITION_CHECK_PROFILE } = CompositionCheckV0

const ISSUED = '2026-06-29T00:00:00.000Z'
const EXPIRES = '2026-06-30T00:00:00.000Z'
const NOW_OK = Date.parse('2026-06-29T12:00:00.000Z')
const NOW_AFTER = Date.parse('2026-07-01T00:00:00.000Z')

const att = generateKeyPair()
const KEY_ID = 'attestor-key-1'
const PROFILES = ['sanctions-routing-v3', 'data-exfil-v2']

function baseReceipt(over: Record<string, unknown> = {}) {
  return {
    profile: COMPOSITION_CHECK_PROFILE,
    receipt_id: 'cc-' + (over.receipt_id ?? 'x'),
    chain_hash: 'chain-abc',
    action_ref: 'act-xyz',
    context_hash: 'ctx-123',
    policy_profile_ids: [...PROFILES],
    checks_run: ['sanctions-routing-v3:routing', 'data-exfil-v2:egress'],
    result_per_check: ['pass', 'indeterminate'],
    attestor_key_id: KEY_ID,
    attestor_independence_class: 'independent_registered',
    issued_at: ISSUED,
    expires_at: EXPIRES,
    ...over,
  }
}

function signed(receipt: Record<string, unknown>) {
  const signature = sign(compositionCheckSigningPayload(receipt as never), att.privateKey)
  return { ...receipt, signature }
}

// Trust contexts. independent => registered_by_operator false (a genuine second anchor).
const ctxIndependent = (overProfiles?: string[]) => ({
  trusted_attestors: {
    [KEY_ID]: { publicKey: att.publicKey, registered_by_operator: false, profiles: overProfiles ?? [...PROFILES] },
  },
  expected_chain_hash: 'chain-abc',
  expected_action_ref: 'act-xyz',
  expected_context_hash: 'ctx-123',
  now_ms: NOW_OK,
})
const ctxOperator = () => ({
  trusted_attestors: {
    [KEY_ID]: { publicKey: att.publicKey, registered_by_operator: true, profiles: [...PROFILES] },
  },
  expected_chain_hash: 'chain-abc',
  expected_action_ref: 'act-xyz',
  expected_context_hash: 'ctx-123',
  now_ms: NOW_OK,
})

const vectors: unknown[] = []

// V01 valid independent attestor (STRONG, second anchor)
vectors.push({
  id: 'V01',
  scenario: 'valid receipt from an independently registered attestor (strong, second anchor)',
  input_receipt: signed(baseReceipt({ receipt_id: 'V01' })),
  verification_context: ctxIndependent(),
  expected: { anchor_verified: true, independence_is_second_anchor: true, violations_include: [] },
})

// V02 gateway_self (WEAK, must surface as weak, still a valid anchor)
vectors.push({
  id: 'V02',
  scenario: 'gateway_self attestor: valid anchor but one trust domain, surfaced as weak',
  input_receipt: signed(baseReceipt({ receipt_id: 'V02', attestor_independence_class: 'gateway_self' })),
  verification_context: ctxOperator(),
  expected: { anchor_verified: true, independence_is_second_anchor: false, violations_include: [] },
})

// V03 expired (now > expires_at) -> rejected
vectors.push({
  id: 'V03',
  scenario: 'receipt presented after expires_at',
  input_receipt: signed(baseReceipt({ receipt_id: 'V03' })),
  verification_context: { ...ctxIndependent(), now_ms: NOW_AFTER },
  expected: { anchor_verified: false, violations_include: ['expired'] },
})

// V04 wrong binding (chain_hash does not match the chain the caller is asking about) -> rejected
vectors.push({
  id: 'V04',
  scenario: 'receipt bound to a different chain_hash than the caller asks about',
  input_receipt: signed(baseReceipt({ receipt_id: 'V04', chain_hash: 'chain-OTHER' })),
  verification_context: ctxIndependent(),
  expected: { anchor_verified: false, violations_include: ['chain_binding'] },
})

// V05 tampered signature -> rejected
const v05 = signed(baseReceipt({ receipt_id: 'V05' }))
v05.signature = (v05.signature as string).slice(0, -2) + (((v05.signature as string).slice(-2) === '00') ? 'ff' : '00')
vectors.push({
  id: 'V05',
  scenario: 'signature byte flipped after signing',
  input_receipt: v05,
  verification_context: ctxIndependent(),
  expected: { anchor_verified: false, violations_include: ['signature'] },
})

// V06 result outside the fixed enum -> rejected (signed over the bad value, so ONLY result_enum fails)
vectors.push({
  id: 'V06',
  scenario: 'a result_per_check value outside the allowed enum',
  input_receipt: signed(baseReceipt({ receipt_id: 'V06', result_per_check: ['pass', 'maybe'] })),
  verification_context: ctxIndependent(),
  expected: { anchor_verified: false, violations_include: ['result_enum'] },
})

// V07 over-claimed independence: claims independent_registered, but context registers the key
// as operator-registered -> still a valid anchor, but downgraded to NOT a second anchor.
vectors.push({
  id: 'V07',
  scenario: 'claims independent_registered but the trust context registers the key as operator-registered (honest floor: downgraded, never upgraded)',
  input_receipt: signed(baseReceipt({ receipt_id: 'V07' })),
  verification_context: ctxOperator(),
  expected: { anchor_verified: true, independence_is_second_anchor: false, violations_include: [] },
})

// V08 attestor not trusted for one of the named profiles -> rejected
vectors.push({
  id: 'V08',
  scenario: 'attestor trusted for only one of the two named policy profiles',
  input_receipt: signed(baseReceipt({ receipt_id: 'V08' })),
  verification_context: ctxIndependent(['sanctions-routing-v3']),
  expected: { anchor_verified: false, violations_include: ['attestor_not_trusted_for_profiles'] },
})

const doc = {
  profile: COMPOSITION_CHECK_PROFILE,
  description:
    'APS Composition Check Receipt v0 conformance vectors. The verifier checks the ANCHOR ' +
    '(signature, binding, freshness, well-formedness, attestor trust) and surfaces independence; ' +
    'it never emits a "safe" verdict and runs no policy. independence_is_second_anchor is ' +
    'corroborated from the trust context, never the receipt self-declaration. The set only grows.',
  count: vectors.length,
  vectors,
}

const out = join(process.cwd(), 'conformance/composition-check/v0/vectors.json')
writeFileSync(out, JSON.stringify(doc, null, 2) + '\n')
console.log(`wrote ${vectors.length} vectors -> ${out}`)
