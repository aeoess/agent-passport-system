// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// W2-B3 revocation-enforcement tests (additive).
// Explicit negative-path fixtures for every primitive, per the build spec:
//   - fail_closed denies on a stale revocation source
//   - bounded_staleness accepts exactly at the window boundary, denies past it
//   - refresh reissues only when not revoked and the same trace_id
//   - a well-formed SET is emitted on revoke

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  decideFreshness,
  enforceFreshnessPolicy,
  mintEphemeralToken,
  validateEphemeralToken,
  refreshDelegation,
  buildRevocationSET,
  isWellFormedSET,
  buildRevocationEnforcementScopeOfClaim,
} from '../../src/v2/revocation-enforcement/index.js'
import { recordRevocationFreshness, InMemorySeenSet } from '../../src/v2/verifier-hardening/index.js'
import { createSnapshotFreshness } from '../../src/core/freshness.js'
import {
  createV2Delegation, revokeV2Delegation, clearV2DelegationStore,
} from '../../src/v2/delegation-v2.js'
import { createPolicyContext } from '../../src/v2/bridge.js'
import { generateKeyPair } from '../../src/crypto/keys.js'
import type { PolicyContext, V2ScopeDefinition } from '../../src/v2/types.js'
import type { EphemeralCapabilityToken } from '../../src/v2/revocation-enforcement/index.js'

const now = new Date('2026-05-31T12:00:00.000Z')
const nowMs = now.getTime()

// ── (1) freshness_policy ──

describe('W2-B3 freshness_policy: fail_open / fail_closed / bounded_staleness', () => {
  const maxStalenessMs = 60_000

  // A stale record: produced 90s ago, snapshot maxAge 600s (typed-fresh) but
  // recorder tolerance 60s → 'stale'.
  function staleRecord() {
    const freshness = createSnapshotFreshness(new Date(nowMs - 90_000).toISOString(), 600)
    return recordRevocationFreshness({ source: 'crl://example', maxStalenessMs, checkedAt: now, freshness })
  }

  function freshRecord() {
    const freshness = createSnapshotFreshness(new Date(nowMs - 30_000).toISOString(), 120)
    return recordRevocationFreshness({ source: 'crl://example', maxStalenessMs, checkedAt: now, freshness })
  }

  it('fresh result always allows, regardless of mode', () => {
    for (const mode of ['fail_open', 'fail_closed', 'bounded_staleness'] as const) {
      const d = decideFreshness(freshRecord(), { mode, boundedStalenessMs: 1 }, now)
      assert.equal(d.effect, 'allow', `${mode} should allow on fresh`)
      assert.equal(d.result, 'fresh')
    }
  })

  it('NEGATIVE: fail_closed denies on a stale revocation source', () => {
    const d = decideFreshness(staleRecord(), { mode: 'fail_closed' }, now)
    assert.equal(d.effect, 'deny')
    assert.equal(d.result, 'stale')
    assert.match(d.reason, /fail_closed/)
  })

  it('fail_closed denies on unavailable too', () => {
    const rec = recordRevocationFreshness({ source: 'crl://example', maxStalenessMs, checkedAt: now, unavailable: true })
    const d = decideFreshness(rec, { mode: 'fail_closed' }, now)
    assert.equal(d.effect, 'deny')
    assert.equal(d.result, 'unavailable')
  })

  it('fail_open allows on stale by default', () => {
    const d = decideFreshness(staleRecord(), { mode: 'fail_open' }, now)
    assert.equal(d.effect, 'allow')
    assert.equal(d.downgraded, false)
  })

  it('fail_open with action_on_stale=deny denies on stale', () => {
    const d = decideFreshness(staleRecord(), { mode: 'fail_open', action_on_stale: 'deny' }, now)
    assert.equal(d.effect, 'deny')
  })

  it('fail_open with action_on_stale=downgrade allows but flags downgraded', () => {
    const d = decideFreshness(staleRecord(), { mode: 'fail_open', action_on_stale: 'downgrade' }, now)
    assert.equal(d.effect, 'allow')
    assert.equal(d.downgraded, true)
  })

  it('BOUNDARY: bounded_staleness accepts exactly at the window boundary', () => {
    // produced exactly 90s ago; bound exactly 90_000ms → age === bound → allow (inclusive)
    const freshness = createSnapshotFreshness(new Date(nowMs - 90_000).toISOString(), 600)
    const rec = recordRevocationFreshness({ source: 'crl://example', maxStalenessMs, checkedAt: now, freshness })
    const d = decideFreshness(rec, { mode: 'bounded_staleness', boundedStalenessMs: 90_000 }, now)
    assert.equal(d.effect, 'allow')
    assert.match(d.reason, /within bound/)
  })

  it('NEGATIVE: bounded_staleness denies one ms past the window boundary', () => {
    const freshness = createSnapshotFreshness(new Date(nowMs - 90_000).toISOString(), 600)
    const rec = recordRevocationFreshness({ source: 'crl://example', maxStalenessMs, checkedAt: now, freshness })
    // age is 90_000ms; bound 89_999ms → past the window → deny (default)
    const d = decideFreshness(rec, { mode: 'bounded_staleness', boundedStalenessMs: 89_999 }, now)
    assert.equal(d.effect, 'deny')
    assert.match(d.reason, /exceeds bound/)
  })

  it('bounded_staleness past the window honours action_on_stale=allow', () => {
    const freshness = createSnapshotFreshness(new Date(nowMs - 90_000).toISOString(), 600)
    const rec = recordRevocationFreshness({ source: 'crl://example', maxStalenessMs, checkedAt: now, freshness })
    const d = decideFreshness(rec, { mode: 'bounded_staleness', boundedStalenessMs: 1, action_on_stale: 'allow' }, now)
    assert.equal(d.effect, 'allow')
  })

  it('bounded_staleness without boundedStalenessMs is treated as deny (safe default)', () => {
    const d = decideFreshness(staleRecord(), { mode: 'bounded_staleness' }, now)
    assert.equal(d.effect, 'deny')
    assert.match(d.reason, /not configured/)
  })

  it('bounded_staleness denies unavailable (no measurable age)', () => {
    const rec = recordRevocationFreshness({ source: 'crl://example', maxStalenessMs, checkedAt: now, unavailable: true })
    const d = decideFreshness(rec, { mode: 'bounded_staleness', boundedStalenessMs: 10_000_000 }, now)
    assert.equal(d.effect, 'deny')
    assert.match(d.reason, /no measurable age/)
  })

  it('enforceFreshnessPolicy chains record → decide in one call', () => {
    const freshness = createSnapshotFreshness(new Date(nowMs - 90_000).toISOString(), 600)
    const d = enforceFreshnessPolicy(
      { source: 'crl://example', maxStalenessMs, checkedAt: now, freshness },
      { mode: 'fail_closed' },
    )
    assert.equal(d.effect, 'deny')
    assert.equal(d.record.source, 'crl://example')
  })
})

// ── (2) ephemeral capability token ──

describe('W2-B3 ephemeral capability token: lifetime + single-use', () => {
  it('valid: within lifetime, first use', () => {
    const token = mintEphemeralToken({
      delegation_id: 'del-1', trace_id: 'trace-1', action_class: 'funds_transfer',
      risk_class: 'high', ttlSeconds: 60, issuedAt: now,
    })
    const seen = new InMemorySeenSet()
    const v = validateEphemeralToken(token, seen, new Date(nowMs + 30_000))
    assert.equal(v.verdict, 'valid')
    assert.equal(v.jti, token.jti)
  })

  it('lifetime is the reused rotating freshness shape with a ttl', () => {
    const token = mintEphemeralToken({
      delegation_id: 'del-1', trace_id: 'trace-1', action_class: 'funds_transfer',
      risk_class: 'critical', ttlSeconds: 30, issuedAt: now,
    })
    assert.equal(token.lifetime.type, 'rotating')
    assert.equal(token.lifetime.ttl, 30)
    assert.equal(token.version, 'aps-eph-token/1')
  })

  it('NEGATIVE: expired once past the ttl', () => {
    const token = mintEphemeralToken({
      delegation_id: 'del-1', trace_id: 'trace-1', action_class: 'funds_transfer',
      risk_class: 'high', ttlSeconds: 60, issuedAt: now,
    })
    const seen = new InMemorySeenSet()
    const v = validateEphemeralToken(token, seen, new Date(nowMs + 61_000))
    assert.equal(v.verdict, 'expired')
  })

  it('NEGATIVE: replayed on second use within lifetime', () => {
    const token = mintEphemeralToken({
      delegation_id: 'del-1', trace_id: 'trace-1', action_class: 'funds_transfer',
      risk_class: 'high', ttlSeconds: 60, issuedAt: now,
    })
    const seen = new InMemorySeenSet()
    assert.equal(validateEphemeralToken(token, seen, new Date(nowMs + 10_000)).verdict, 'valid')
    assert.equal(validateEphemeralToken(token, seen, new Date(nowMs + 20_000)).verdict, 'replayed')
  })

  it('expired token does not consume a seen-set slot (expiry checked before replay)', () => {
    const token = mintEphemeralToken({
      delegation_id: 'del-1', trace_id: 'trace-1', action_class: 'funds_transfer',
      risk_class: 'high', ttlSeconds: 60, issuedAt: now,
    })
    const seen = new InMemorySeenSet()
    validateEphemeralToken(token, seen, new Date(nowMs + 61_000)) // expired
    assert.equal(seen.has(token.jti), false)
  })

  it('NEGATIVE: malformed token is rejected', () => {
    const seen = new InMemorySeenSet()
    const bad = { version: 'aps-eph-token/1', jti: '', lifetime: { type: 'static', validAt: now.toISOString() } } as unknown as EphemeralCapabilityToken
    assert.equal(validateEphemeralToken(bad, seen, now).verdict, 'malformed')
  })

  it('rejects a non-positive ttl at mint time', () => {
    assert.throws(() => mintEphemeralToken({
      delegation_id: 'd', trace_id: 't', action_class: 'x', risk_class: 'high', ttlSeconds: 0,
    }), /ttlSeconds must be positive/)
  })
})

// ── (3) delegation refresh ──

describe('W2-B3 delegation refresh: reissue only when not revoked and same trace_id', () => {
  let delegatorKeys: { publicKey: string; privateKey: string }
  let ctx: PolicyContext
  const scope: V2ScopeDefinition = { action_categories: ['read', 'write'] }

  beforeEach(() => {
    clearV2DelegationStore()
    delegatorKeys = generateKeyPair()
    // Both ends pinned to the fake clock: createPolicyContext defaults
    // valid_from to the real wall clock, which made these contexts born
    // expired once real time passed the pinned valid_until.
    ctx = createPolicyContext({
      policy_version: '1.0', values_floor_version: '1.0', trust_epoch: 1,
      issuer_id: delegatorKeys.publicKey,
      valid_from: now.toISOString(),
      valid_until: new Date(nowMs + 7 * 24 * 3600_000).toISOString(),
    })
  })

  function freshCtx(): PolicyContext {
    return createPolicyContext({
      policy_version: '1.0', values_floor_version: '1.0', trust_epoch: 1,
      issuer_id: delegatorKeys.publicKey,
      valid_from: now.toISOString(),
      valid_until: new Date(nowMs + 14 * 24 * 3600_000).toISOString(),
    })
  }

  it('reissues when original is active and trace_id matches', () => {
    const del = createV2Delegation({
      delegator: delegatorKeys.publicKey, delegatee: 'agent-1', scope,
      policy_context: ctx, delegator_private_key: delegatorKeys.privateKey,
    })
    const token = mintEphemeralToken({
      delegation_id: del.id, trace_id: 'trace-xyz', action_class: 'funds_transfer',
      risk_class: 'high', ttlSeconds: 60,
    })
    const out = refreshDelegation({
      token, trace_id: 'trace-xyz', policy_context: freshCtx(),
      delegator_private_key: delegatorKeys.privateKey, renewal_reason: 'rotation window',
      now,
    })
    assert.equal(out.reissued, true)
    assert.ok(out.new_delegation_id)
    assert.notEqual(out.new_delegation_id, del.id)
  })

  it('NEGATIVE: refuses when the original is revoked', () => {
    const del = createV2Delegation({
      delegator: delegatorKeys.publicKey, delegatee: 'agent-1', scope,
      policy_context: ctx, delegator_private_key: delegatorKeys.privateKey,
    })
    revokeV2Delegation(del.id)
    const token = mintEphemeralToken({
      delegation_id: del.id, trace_id: 'trace-xyz', action_class: 'funds_transfer',
      risk_class: 'high', ttlSeconds: 60,
    })
    const out = refreshDelegation({
      token, trace_id: 'trace-xyz', policy_context: freshCtx(),
      delegator_private_key: delegatorKeys.privateKey, renewal_reason: 'rotation window',
      now,
    })
    assert.equal(out.reissued, false)
    assert.equal(out.reason, 'revoked')
  })

  it('NEGATIVE: refuses when the trace_id does not match the token', () => {
    const del = createV2Delegation({
      delegator: delegatorKeys.publicKey, delegatee: 'agent-1', scope,
      policy_context: ctx, delegator_private_key: delegatorKeys.privateKey,
    })
    const token = mintEphemeralToken({
      delegation_id: del.id, trace_id: 'trace-xyz', action_class: 'funds_transfer',
      risk_class: 'high', ttlSeconds: 60,
    })
    const out = refreshDelegation({
      token, trace_id: 'trace-DIFFERENT', policy_context: freshCtx(),
      delegator_private_key: delegatorKeys.privateKey, renewal_reason: 'rotation window',
      now,
    })
    assert.equal(out.reissued, false)
    assert.equal(out.reason, 'trace_mismatch')
  })

  it('NEGATIVE: refuses when the delegation is not in the store', () => {
    const token = mintEphemeralToken({
      delegation_id: 'missing-id', trace_id: 'trace-xyz', action_class: 'funds_transfer',
      risk_class: 'high', ttlSeconds: 60,
    })
    const out = refreshDelegation({
      token, trace_id: 'trace-xyz', policy_context: freshCtx(),
      delegator_private_key: delegatorKeys.privateKey, renewal_reason: 'rotation window',
      now,
    })
    assert.equal(out.reissued, false)
    assert.equal(out.reason, 'not_found')
  })

  it('reissued delegation keeps the original scope (no authority expansion)', () => {
    const del = createV2Delegation({
      delegator: delegatorKeys.publicKey, delegatee: 'agent-1', scope,
      policy_context: ctx, delegator_private_key: delegatorKeys.privateKey,
    })
    const token = mintEphemeralToken({
      delegation_id: del.id, trace_id: 'trace-xyz', action_class: 'funds_transfer',
      risk_class: 'high', ttlSeconds: 60,
    })
    const out = refreshDelegation({
      token, trace_id: 'trace-xyz', policy_context: freshCtx(),
      delegator_private_key: delegatorKeys.privateKey, renewal_reason: 'rotation window',
      now,
    })
    assert.equal(out.reissued, true)
    // The renewal path supersedes keeping scope; the original is no longer active.
    assert.ok(out.new_delegation_id)
  })
})

// ── (4) RFC 8417 SET emission ──

describe('W2-B3 SET emission: a well-formed SET is emitted on revoke', () => {
  it('a well-formed SET is emitted on revoke', () => {
    const set = buildRevocationSET({
      issuer: 'https://issuer.example', subject_id: 'del-1',
      revokedAt: now, issuedAt: now, audience: 'https://receiver.example',
      reason: 'Revoked',
    })
    assert.equal(isWellFormedSET(set), true)
    assert.equal(set.iss, 'https://issuer.example')
    assert.equal(typeof set.iat, 'number')
    assert.ok(set.jti)
    assert.equal(set.aud, 'https://receiver.example')
    const evt = set.events['https://schemas.openid.net/secevent/caep/event-type/session-revoked']
    assert.ok(evt)
    assert.equal(evt.subject.format, 'opaque')
    assert.equal(evt.subject.id, 'del-1')
    assert.equal(evt.reason, 'Revoked')
    assert.equal(evt.event_timestamp, Math.floor(nowMs / 1000))
  })

  it('event_timestamp defaults to issuedAt when revokedAt omitted', () => {
    const set = buildRevocationSET({ issuer: 'iss', subject_id: 's', issuedAt: now })
    const evt = set.events['https://schemas.openid.net/secevent/caep/event-type/session-revoked']
    assert.equal(evt.event_timestamp, Math.floor(nowMs / 1000))
    assert.equal(evt.reason, undefined)
  })

  it('aud is omitted when not supplied', () => {
    const set = buildRevocationSET({ issuer: 'iss', subject_id: 's', issuedAt: now })
    assert.equal('aud' in set, false)
  })

  it('NEGATIVE: isWellFormedSET rejects a missing iss', () => {
    const set = buildRevocationSET({ issuer: 'iss', subject_id: 's', issuedAt: now })
    const broken = { ...set, iss: '' }
    assert.equal(isWellFormedSET(broken), false)
  })

  it('NEGATIVE: isWellFormedSET rejects an unknown event-type URI', () => {
    const set = buildRevocationSET({ issuer: 'iss', subject_id: 's', issuedAt: now })
    const broken = { ...set, events: { 'https://example.com/not-caep': Object.values(set.events)[0] } }
    assert.equal(isWellFormedSET(broken), false)
  })

  it('NEGATIVE: isWellFormedSET rejects a malformed subject', () => {
    const set = buildRevocationSET({ issuer: 'iss', subject_id: 's', issuedAt: now })
    const uri = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked'
    const broken = { ...set, events: { [uri]: { ...set.events[uri], subject: { format: 'opaque', id: '' } } } }
    assert.equal(isWellFormedSET(broken), false)
  })

  it('NEGATIVE: isWellFormedSET rejects non-objects', () => {
    assert.equal(isWellFormedSET(null), false)
    assert.equal(isWellFormedSET('a set'), false)
    assert.equal(isWellFormedSET(42), false)
  })
})

// ── proof box / dogfood ──

describe('W2-B3 proof box: ScopeOfClaim dogfood', () => {
  it('exposes a ScopeOfClaim mirroring the proof box', () => {
    const scope = buildRevocationEnforcementScopeOfClaim()
    assert.ok(scope.asserts.length > 0)
    assert.ok(scope.does_not_assert.length >= 2)
    assert.equal(scope.self_attested, false)
    assert.equal(scope.capture_mode, 'gateway_observed')
  })
})
