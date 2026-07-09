// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license.
import test from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import {
  ACP_API_VERSION,
  acpSessionToDelegationHints,
  apsToAcpError,
  checkAcpSessionUnderBudget,
  delegationToAcpAllowed,
  mapAcpDenialToFoundation,
  preAuthorizeAcpCheckout,
  signAcpDenial,
  signAcpReceipt,
  verifyAcpDenial,
  verifyAcpReceipt,
} from '../../../src/v2/payment-rails/acp/index.js'
import type { DenialReason as FoundationDenialReason } from '../../../src/v2/payment-rails/types.js'
import {
  recordOwnerConfirmation,
  requestOwnerConfirmation,
} from '../../../src/v2/human-escalation.js'
import type {
  AcpCheckoutSession,
  AcpCreateCheckoutSessionRequest,
  AcpDenialReason,
} from '../../../src/v2/payment-rails/acp/types.js'
import type {
  EscalationRequirement,
  OwnerConfirmation,
  V2Delegation,
} from '../../../src/v2/types.js'

// ── Test helpers ──────────────────────────────────────────────────

function commerceDelegation(overrides: Partial<{
  spend_limit_cents: number
  allowed_merchants: string
  allowed_currencies: string
  valid_until: string
  action_categories: string[]
  escalation_requirements: EscalationRequirement[]
  delegator: string
  id: string
}> = {}): V2Delegation {
  const validUntil =
    overrides.valid_until ?? new Date(Date.now() + 60 * 60 * 1000).toISOString()
  const validFrom = new Date(Date.now() - 60 * 1000).toISOString()
  const scope: V2Delegation['scope'] = {
    action_categories: overrides.action_categories ?? ['commerce'],
    resource_limits: {
      spend_limit_cents: overrides.spend_limit_cents ?? 5000,
    },
    constraints: {
      allowed_merchants: overrides.allowed_merchants ?? 'stripe',
      allowed_currencies: overrides.allowed_currencies ?? 'usd',
    },
  }
  if (overrides.escalation_requirements !== undefined) {
    scope.escalation_requirements = overrides.escalation_requirements
  }
  return {
    id: overrides.id ?? 'del_acp_test_001',
    version: 1,
    supersedes: null,
    supersession_justification: null,
    delegator: overrides.delegator ?? 'agent-001',
    delegatee: 'agent-002',
    scope,
    policy_context: {
      policy_version: '2.0.0',
      values_floor_version: '1.0.0',
      trust_epoch: 1,
      issuer_id: 'agent-001',
      created_at: validFrom,
      valid_from: validFrom,
      valid_until: validUntil,
    },
    signature: 'stub_signature_for_test',
    status: 'active',
    renewal_reason: null,
    expansion_reviewer: null,
    expansion_review_sig: null,
    assurance_class: 'mechanically_enforceable',
  }
}

/** Build a delegation flagged for owner-confirmation on 'commerce',
 *  paired with the keypair so a test can mint a matching OwnerConfirmation
 *  via recordOwnerConfirmation. Uses time_window scope to avoid per-action
 *  details-hash binding noise. */
function escalatedCommerceDelegation(
  overrides: { confirmation_ttl_ms?: number; confirmation_scope?: EscalationRequirement['confirmation_scope'] } = {},
): { delegation: V2Delegation; ownerKey: ReturnType<typeof generateKeyPair> } {
  const ownerKey = generateKeyPair()
  const requirement: EscalationRequirement = {
    action_class: 'commerce',
    requires_owner_confirmation: true,
    confirmation_ttl_ms: overrides.confirmation_ttl_ms ?? 5 * 60 * 1000,
    confirmation_scope: overrides.confirmation_scope ?? 'time_window',
  }
  const delegation = commerceDelegation({
    delegator: ownerKey.publicKey,
    escalation_requirements: [requirement],
  })
  return { delegation, ownerKey }
}

function mintConfirmation(
  delegation: V2Delegation,
  ownerKey: ReturnType<typeof generateKeyPair>,
  details: Record<string, unknown>,
): OwnerConfirmation {
  const request = requestOwnerConfirmation(delegation, {
    action_class: 'commerce',
    action_details: details,
  })
  return recordOwnerConfirmation({
    request,
    delegation,
    owner_private_key: ownerKey.privateKey,
  })
}

function happySession(overrides: Partial<AcpCheckoutSession> = {}): AcpCheckoutSession {
  return {
    id: 'cs_acp_test_001',
    status: 'ready_for_payment',
    currency: 'usd',
    line_items: [
      {
        id: 'li_001',
        item: { id: 'item_widget', quantity: 1 },
        base_amount: 1000,
        discount: 0,
        subtotal: 1000,
        tax: 100,
        total: 1100,
      },
    ],
    payment_provider: { provider: 'stripe', supported_payment_methods: ['card'] },
    totals: [
      { type: 'items_base_amount', display_text: 'Items', amount: 1000 },
      { type: 'tax', display_text: 'Tax', amount: 100 },
      { type: 'total', display_text: 'Total', amount: 1100 },
    ],
    ...overrides,
  }
}

// ── Crosswalk ─────────────────────────────────────────────────────

test('delegationToAcpAllowed — extracts cap, merchants, currencies', () => {
  const d = commerceDelegation({
    spend_limit_cents: 2500,
    allowed_merchants: 'stripe,shopify',
    allowed_currencies: 'usd,eur',
  })
  const allowed = delegationToAcpAllowed(d)
  assert.equal(allowed.max_total, 2500)
  assert.deepEqual(allowed.allowed_merchants, ['stripe', 'shopify'])
  assert.deepEqual(allowed.allowed_currencies, ['usd', 'eur'])
})

test('delegationToAcpAllowed — handles CSV with whitespace', () => {
  const d = commerceDelegation({ allowed_merchants: 'stripe, shopify ,etsy' })
  const allowed = delegationToAcpAllowed(d)
  assert.deepEqual(allowed.allowed_merchants, ['stripe', 'shopify', 'etsy'])
})

test('delegationToAcpAllowed — null cap when resource_limits.spend_limit_cents missing', () => {
  const d = commerceDelegation()
  delete (d.scope as { resource_limits?: Record<string, number> }).resource_limits
  delete (d.scope as { constraints?: Record<string, string> }).constraints?.spend_limit_cents
  const allowed = delegationToAcpAllowed(d)
  assert.equal(allowed.max_total, null)
})

test('delegationToAcpAllowed — falls back to constraints.spend_limit_cents string', () => {
  const d = commerceDelegation()
  delete (d.scope as { resource_limits?: Record<string, number> }).resource_limits
  ;(d.scope.constraints as Record<string, string>).spend_limit_cents = '7500'
  const allowed = delegationToAcpAllowed(d)
  assert.equal(allowed.max_total, 7500)
})

test('delegationToAcpAllowed — picks valid_until from policy_context', () => {
  const future = new Date(Date.now() + 30 * 60 * 1000).toISOString()
  const d = commerceDelegation({ valid_until: future })
  const allowed = delegationToAcpAllowed(d)
  assert.equal(allowed.valid_until, future)
})

test('acpSessionToDelegationHints — produces commerce scope from session', () => {
  const s = happySession()
  const hints = acpSessionToDelegationHints(s)
  assert.deepEqual(hints.scope.action_categories, ['commerce'])
  assert.equal(hints.scope.constraints.spend_limit_cents, 1100)
  assert.deepEqual(hints.scope.constraints.allowed_currencies, ['usd'])
  assert.deepEqual(hints.scope.constraints.allowed_merchants, ['stripe'])
  assert.ok(hints.notes.length >= 1, 'should document lossy aspects')
})

// ── Pre-authorization gate ────────────────────────────────────────

test('preAuthorizeAcpCheckout — happy create allows', () => {
  const d = commerceDelegation()
  const req: AcpCreateCheckoutSessionRequest = {
    items: [{ id: 'item_1', quantity: 1 }],
    buyer: { first_name: 'A', last_name: 'B', email: 'a@b.com' },
  }
  const r = preAuthorizeAcpCheckout(req, d, 'usd')
  assert.equal(r.allow, true)
})

test('preAuthorizeAcpCheckout — denies missing commerce scope', () => {
  const d = commerceDelegation({ action_categories: ['analysis'] })
  const r = preAuthorizeAcpCheckout(
    { items: [{ id: 'i1', quantity: 1 }] },
    d,
  )
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'no_commerce_scope')
})

test('preAuthorizeAcpCheckout — denies expired delegation', () => {
  const d = commerceDelegation({ valid_until: new Date(Date.now() - 1000).toISOString() })
  const r = preAuthorizeAcpCheckout({ items: [{ id: 'i1', quantity: 1 }] }, d)
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'delegation_expired')
})

test('preAuthorizeAcpCheckout — denies wrong currency', () => {
  const d = commerceDelegation({ allowed_currencies: 'usd' })
  const r = preAuthorizeAcpCheckout({ items: [{ id: 'i1', quantity: 1 }] }, d, 'eur')
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'currency_mismatch')
})

test('preAuthorizeAcpCheckout — denies empty items', () => {
  const d = commerceDelegation()
  const r = preAuthorizeAcpCheckout({ items: [] }, d, 'usd')
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'invalid_session_state')
})

test('checkAcpSessionUnderBudget — denies over-cap session', () => {
  const d = commerceDelegation({ spend_limit_cents: 500 })
  const s = happySession() // total = 1100
  const r = checkAcpSessionUnderBudget(s, d)
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'spend_limit_exceeded')
})

test('checkAcpSessionUnderBudget — allows under-cap session', () => {
  const d = commerceDelegation({ spend_limit_cents: 5000 })
  const r = checkAcpSessionUnderBudget(happySession(), d)
  assert.equal(r.allow, true)
})

test('checkAcpSessionUnderBudget — denies wrong currency on session', () => {
  const d = commerceDelegation({ allowed_currencies: 'usd' })
  const s = happySession({ currency: 'eur' })
  const r = checkAcpSessionUnderBudget(s, d)
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'currency_mismatch')
})

// ── APS → ACP error mapping ───────────────────────────────────────

test('apsToAcpError — every denial reason maps deterministically', () => {
  const reasons: AcpDenialReason[] = [
    'spend_limit_exceeded',
    'merchant_not_allowed',
    'delegation_expired',
    'currency_mismatch',
    'wallet_revoked',
    'no_commerce_scope',
    'idempotency_conflict',
    'invalid_session_state',
    'api_version_mismatch',
    'requires_owner_confirmation',
  ]
  const seen = new Set<string>()
  for (const r of reasons) {
    const m = apsToAcpError(r)
    assert.ok(m.type, `${r} must produce ACP error type`)
    assert.ok(m.code, `${r} must produce ACP error code`)
    seen.add(`${m.type}|${m.code}`)
  }
  assert.ok(seen.size >= 4, `expected >=4 distinct ACP envelopes, got ${seen.size}`)
})

test('apsToAcpError — idempotency_conflict maps to request_not_idempotent', () => {
  const m = apsToAcpError('idempotency_conflict')
  assert.equal(m.type, 'request_not_idempotent')
  assert.equal(m.code, 'invalid')
})

// ── Receipt sign / verify ─────────────────────────────────────────

test('signAcpReceipt + verifyAcpReceipt — round-trip', () => {
  const kp = generateKeyPair()
  const r = signAcpReceipt(
    {
      op: 'create',
      session_id: 'cs_001',
      request_body: { items: [{ id: 'i1', quantity: 1 }] },
      session_state: happySession(),
      delegation_ref: 'del_acp_test_001',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  assert.equal(r.acp_version, ACP_API_VERSION)
  assert.equal(r.receipt_kind, 'acp.checkout_session_op')
  assert.equal(r.signer, kp.publicKey)
  assert.ok(r.signature.length > 0)

  const v = verifyAcpReceipt(r)
  assert.equal(v.valid, true)
})

test('verifyAcpReceipt — rejects tampered session_state', () => {
  const kp = generateKeyPair()
  const r = signAcpReceipt(
    {
      op: 'complete',
      session_id: 'cs_002',
      request_body: { payment_data: { token: 'tok_x', provider: 'stripe' } },
      session_state: happySession(),
      delegation_ref: 'd1',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  r.session_state.totals[2].amount = 99999
  const v = verifyAcpReceipt(r)
  assert.equal(v.valid, false)
  if (v.valid === false) assert.equal(v.reason, 'SIGNATURE_INVALID')
})

test('verifyAcpReceipt — rejects expired receipt (ttl)', () => {
  const kp = generateKeyPair()
  const r = signAcpReceipt(
    {
      op: 'create',
      session_id: 'cs_003',
      request_body: {},
      session_state: happySession(),
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  r.issued_at = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString()
  const v = verifyAcpReceipt(r)
  assert.equal(v.valid, false)
  if (v.valid === false) assert.equal(v.reason, 'EXPIRED')
})

test('verifyAcpReceipt — rejects wrong api version', () => {
  const kp = generateKeyPair()
  const r = signAcpReceipt(
    {
      op: 'create',
      session_id: 'cs_004',
      request_body: {},
      session_state: happySession(),
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  ;(r as { acp_version: string }).acp_version = '2024-01-01'
  const v = verifyAcpReceipt(r)
  assert.equal(v.valid, false)
  if (v.valid === false) assert.equal(v.reason, 'INVALID_API_VERSION')
})

test('verifyAcpReceipt — rejects expected_signer mismatch', () => {
  const kp1 = generateKeyPair()
  const kp2 = generateKeyPair()
  const r = signAcpReceipt(
    {
      op: 'create',
      session_id: 'cs_005',
      request_body: {},
      session_state: happySession(),
      agent_id: 'agent-001',
    },
    kp1.privateKey,
  )
  const v = verifyAcpReceipt(r, { expected_signer: kp2.publicKey })
  assert.equal(v.valid, false)
})

// ── Denial sign / verify ──────────────────────────────────────────

test('signAcpDenial + verifyAcpDenial — round-trip and stable mapping', () => {
  const kp = generateKeyPair()
  const denial = signAcpDenial(
    {
      op: 'create',
      session_id: 'cs_denied_001',
      request_body: { items: [{ id: 'over_budget', quantity: 100 }] },
      reason: 'spend_limit_exceeded',
      delegation_ref: 'd1',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  assert.equal(denial.acp_error_type, 'invalid_request')
  assert.equal(denial.acp_error_code, 'invalid')
  assert.equal(denial.acp_error_param, '$.items')

  const v = verifyAcpDenial(denial)
  assert.equal(v.valid, true)
})

test('verifyAcpDenial — rejects tampered acp_error_code (mapping invariant)', () => {
  const kp = generateKeyPair()
  const denial = signAcpDenial(
    {
      op: 'create',
      session_id: 'cs_t1',
      request_body: {},
      reason: 'merchant_not_allowed',
      agent_id: 'agent-001',
    },
    kp.privateKey,
  )
  ;(denial as { acp_error_code: string }).acp_error_code = 'requires_3ds'
  const v = verifyAcpDenial(denial)
  assert.equal(v.valid, false)
  if (v.valid === false) assert.equal(v.reason, 'SIGNATURE_INVALID')
})

test('verifyAcpDenial — every denial reason produces a verifiable denial', () => {
  const reasons: AcpDenialReason[] = [
    'spend_limit_exceeded',
    'merchant_not_allowed',
    'delegation_expired',
    'currency_mismatch',
    'wallet_revoked',
    'no_commerce_scope',
    'idempotency_conflict',
    'invalid_session_state',
    'api_version_mismatch',
    'requires_owner_confirmation',
  ]
  const kp = generateKeyPair()
  for (const r of reasons) {
    const d = signAcpDenial(
      {
        op: 'create',
        session_id: `cs_${r}`,
        request_body: {},
        reason: r,
        agent_id: 'agent-001',
      },
      kp.privateKey,
    )
    const v = verifyAcpDenial(d)
    assert.equal(v.valid, true, `denial for ${r} should verify; got ${JSON.stringify(v)}`)
  }
})

// ── HumanEscalationFlag — Audit B P9 ─────────────────────────────

test('preAuthorizeAcpCheckout — no escalation_requirements: existing behavior unchanged', () => {
  const d = commerceDelegation()
  const req: AcpCreateCheckoutSessionRequest = {
    items: [{ id: 'item_1', quantity: 1 }],
  }
  const r = preAuthorizeAcpCheckout(req, d, 'usd')
  assert.equal(r.allow, true)
})

test('preAuthorizeAcpCheckout — escalation matches commerce, no confirmation: denies', () => {
  const { delegation } = escalatedCommerceDelegation()
  const req: AcpCreateCheckoutSessionRequest = {
    items: [{ id: 'item_1', quantity: 1 }],
  }
  const r = preAuthorizeAcpCheckout(req, delegation, 'usd')
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'requires_owner_confirmation')
})

test('preAuthorizeAcpCheckout — escalation matches, valid time_window confirmation: allows', () => {
  const { delegation, ownerKey } = escalatedCommerceDelegation()
  const req: AcpCreateCheckoutSessionRequest = {
    items: [{ id: 'item_1', quantity: 1 }],
  }
  const confirmation = mintConfirmation(delegation, ownerKey, { kind: 'any' })
  const r = preAuthorizeAcpCheckout(req, delegation, 'usd', {
    owner_confirmation: confirmation,
  })
  assert.equal(r.allow, true)
})

test('preAuthorizeAcpCheckout — escalation matches, expired confirmation: denies', () => {
  const { delegation, ownerKey } = escalatedCommerceDelegation({ confirmation_ttl_ms: 1 })
  const req: AcpCreateCheckoutSessionRequest = {
    items: [{ id: 'item_1', quantity: 1 }],
  }
  const confirmation = mintConfirmation(delegation, ownerKey, { kind: 'any' })
  // Roll the gate clock 5 minutes forward so the 1ms-TTL confirmation is expired.
  const future = new Date(Date.now() + 5 * 60 * 1000)
  const r = preAuthorizeAcpCheckout(req, delegation, 'usd', {
    owner_confirmation: confirmation,
    now: future,
  })
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'requires_owner_confirmation')
})

test('preAuthorizeAcpCheckout — escalation matches, confirmation signed by wrong key: denies', () => {
  const { delegation } = escalatedCommerceDelegation()
  const wrongOwner = generateKeyPair()
  // Mint a confirmation against the same delegation but signed by a key
  // that is NOT delegator.
  const tamperedConf = mintConfirmation(delegation, wrongOwner, { kind: 'any' })
  const req: AcpCreateCheckoutSessionRequest = {
    items: [{ id: 'item_1', quantity: 1 }],
  }
  const r = preAuthorizeAcpCheckout(req, delegation, 'usd', {
    owner_confirmation: tamperedConf,
  })
  assert.equal(r.allow, false)
  if (r.allow === false) assert.equal(r.reason, 'requires_owner_confirmation')
})

test('preAuthorizeAcpCheckout — escalation requirement on different action_class: existing behavior unchanged', () => {
  // Delegation flags 'org_creation' for confirmation but not 'commerce'.
  const ownerKey = generateKeyPair()
  const delegation = commerceDelegation({
    delegator: ownerKey.publicKey,
    escalation_requirements: [
      {
        action_class: 'org_creation',
        requires_owner_confirmation: true,
        confirmation_ttl_ms: 5 * 60 * 1000,
        confirmation_scope: 'time_window',
      },
    ],
  })
  const req: AcpCreateCheckoutSessionRequest = {
    items: [{ id: 'item_1', quantity: 1 }],
  }
  const r = preAuthorizeAcpCheckout(req, delegation, 'usd')
  assert.equal(r.allow, true)
})

// ── Tier-2 → Tier-1 vocab crosswalk — Audit B P5 ─────────────────

test('mapAcpDenialToFoundation — every AcpDenialReason maps to a foundation reason', () => {
  // Listing the AcpDenialReason union values literally so a future
  // type extension that forgets to update this test fails.
  const reasons: AcpDenialReason[] = [
    'spend_limit_exceeded',
    'merchant_not_allowed',
    'delegation_expired',
    'currency_mismatch',
    'wallet_revoked',
    'no_commerce_scope',
    'idempotency_conflict',
    'invalid_session_state',
    'api_version_mismatch',
    'requires_owner_confirmation',
  ]
  const validFoundation: FoundationDenialReason[] = [
    'no_commerce_scope',
    'spend_limit_exceeded',
    'wallet_revoked',
    'time_window_violation',
    'rail_error',
    'requires_owner_confirmation',
  ]
  for (const r of reasons) {
    const mapped = mapAcpDenialToFoundation(r)
    assert.ok(
      validFoundation.includes(mapped),
      `${r} mapped to invalid foundation reason: ${mapped}`,
    )
  }
})

test('mapAcpDenialToFoundation — deterministic (same input → same output)', () => {
  const reasons: AcpDenialReason[] = [
    'spend_limit_exceeded',
    'merchant_not_allowed',
    'delegation_expired',
    'currency_mismatch',
    'wallet_revoked',
    'no_commerce_scope',
    'idempotency_conflict',
    'invalid_session_state',
    'api_version_mismatch',
    'requires_owner_confirmation',
  ]
  for (const r of reasons) {
    const a = mapAcpDenialToFoundation(r)
    const b = mapAcpDenialToFoundation(r)
    assert.equal(a, b, `${r} not deterministic: got ${a} then ${b}`)
  }
})

test('mapAcpDenialToFoundation — known-fixture mappings hold', () => {
  // Spot-check the policy decisions documented in the vocabulary doc.
  assert.equal(mapAcpDenialToFoundation('spend_limit_exceeded'), 'spend_limit_exceeded')
  assert.equal(mapAcpDenialToFoundation('wallet_revoked'), 'wallet_revoked')
  assert.equal(mapAcpDenialToFoundation('no_commerce_scope'), 'no_commerce_scope')
  assert.equal(mapAcpDenialToFoundation('delegation_expired'), 'time_window_violation')
  assert.equal(mapAcpDenialToFoundation('merchant_not_allowed'), 'rail_error')
  assert.equal(mapAcpDenialToFoundation('currency_mismatch'), 'rail_error')
  assert.equal(mapAcpDenialToFoundation('idempotency_conflict'), 'rail_error')
  assert.equal(mapAcpDenialToFoundation('invalid_session_state'), 'rail_error')
  assert.equal(mapAcpDenialToFoundation('api_version_mismatch'), 'rail_error')
  assert.equal(
    mapAcpDenialToFoundation('requires_owner_confirmation'),
    'requires_owner_confirmation',
  )
})

// ── Phase 4.1 / Q1 — accountability shape ─────────────────────────

test('Q1: signAcpReceipt with accountability_shape populates claim_type rail.acp.v1, timestamp, scope_of_claim', () => {
  const kp = generateKeyPair()
  const r = signAcpReceipt(
    {
      op: 'create',
      session_id: 'cs_test_001',
      request_body: { items: [{ id: 'i', quantity: 1 }] },
      session_state: happySession(),
      delegation_ref: 'del_acp_test_001',
      agent_id: 'agent-002',
      accountability_shape: true,
    },
    kp.privateKey,
  )
  assert.equal(r.claim_type, 'rail.acp.v1')
  assert.equal(r.timestamp, r.issued_at)
  assert.ok(r.scope_of_claim)
  assert.ok(r.scope_of_claim!.asserts.length > 0)
  assert.equal(verifyAcpReceipt(r).valid, true)
})

test('Q1: legacy-shape AcpReceipt (no claim_type) still verifies', () => {
  const kp = generateKeyPair()
  const r = signAcpReceipt(
    {
      op: 'create',
      session_id: 'cs_test_002',
      request_body: { items: [{ id: 'i', quantity: 1 }] },
      session_state: happySession(),
      delegation_ref: 'del_acp_test_001',
      agent_id: 'agent-002',
    },
    kp.privateKey,
  )
  assert.equal(r.claim_type, undefined)
  assert.equal(r.timestamp, undefined)
  assert.equal(verifyAcpReceipt(r).valid, true)
})

test('Q1: AcpReceipt with mismatched claim_type literal rejected', () => {
  const kp = generateKeyPair()
  const r = signAcpReceipt(
    {
      op: 'create',
      session_id: 'cs_test_003',
      request_body: { items: [{ id: 'i', quantity: 1 }] },
      session_state: happySession(),
      delegation_ref: 'del_acp_test_001',
      agent_id: 'agent-002',
      accountability_shape: true,
    },
    kp.privateKey,
  )
  const tampered = { ...r, claim_type: 'rail.payment.v1' as unknown as 'rail.acp.v1' }
  assert.equal(verifyAcpReceipt(tampered).valid, false)
})

test('Q1: scope_of_claim override propagates', () => {
  const kp = generateKeyPair()
  const custom = {
    asserts: 'custom acp claim',
    does_not_assert: ['custom non-assertion'],
    capture_mode: 'gateway_observed' as const,
    completeness: 'complete' as const,
    self_attested: false,
  }
  const r = signAcpReceipt(
    {
      op: 'create',
      session_id: 'cs_test_004',
      request_body: { items: [{ id: 'i', quantity: 1 }] },
      session_state: happySession(),
      delegation_ref: 'del_acp_test_001',
      agent_id: 'agent-002',
      scope_of_claim: custom,
    },
    kp.privateKey,
  )
  assert.deepEqual(r.scope_of_claim, custom)
})
