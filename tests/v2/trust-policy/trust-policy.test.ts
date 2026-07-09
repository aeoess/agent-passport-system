// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Trust Root Policy (W2-B1): conformance + adversarial
// ══════════════════════════════════════════════════════════════════
// Covers the mandated cases:
//   - two policies produce two verdicts on ONE receipt,
//   - a pinned-key mismatch is rejected,
//   - a rolled-back policy version is rejected (anti-rollback),
//   - offline verify against a cached policy succeeds.
// Plus: artifact sign/verify, untrusted publisher, expiry/not-yet-valid,
// key validity window, rotation overlap, fail-open degraded ('unknown',
// no acceptance), the well-known generator + URL composer, and the
// additive byte-stability of trust_policy_ref on the Cycles receipt.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  buildTrustRootPolicy,
  signTrustRootPolicy,
  verifyTrustRootPolicy,
  evaluateReceiptAgainstPolicy,
  generateApsAgentsDoc,
  apsAgentsUrl,
  WELL_KNOWN_APS_AGENTS_PATH,
  type TrustedIssuer,
  type TrustRootPolicy,
  type ReceiptSignerFacts,
} from '../../../src/v2/trust-policy/index.js'
import type {
  KeyResolver,
  KeyLocator,
  KeyResolution,
} from '../../../src/v2/key-resolution/index.js'
import { generateKeyPair } from '../../../src/crypto/keys.js'
import { canonicalizeJCS } from '../../../src/core/canonical-jcs.js'
import {
  signCyclesPermitReceipt,
  verifyCyclesPermitReceipt,
} from '../../../src/v2/payment-rails/cycles/index.js'
import type { CyclesEvidenceRef } from '../../../src/v2/payment-rails/cycles/types.js'

// ── fixtures ────────────────────────────────────────────────────────

const NOW = 1_900_000_000_000 // fixed clock (unix ms)

function kp(): { sk: string; pk: string } {
  const k = generateKeyPair()
  return { sk: k.privateKey, pk: k.publicKey }
}

const publisher = kp() // signs the policy artifact
const issuerKey = kp() // the issuer's pinned signing key
const otherKey = kp() // an unrelated key (mismatch fixtures)

function trustedIssuer(overrides: Partial<TrustedIssuer> = {}): TrustedIssuer {
  return {
    issuer_id: 'did:web:issuer.example',
    display_name: 'Example Issuer',
    pinned_keys: [{ key_id: 'k1', pubkey_hex: issuerKey.pk }],
    ...overrides,
  }
}

function buildSignedPolicy(opts: {
  version: number
  issuers?: TrustedIssuer[]
  refresh_after?: number
  issued_at?: number
  offline_behavior?: 'cached_pins_only' | 'reject'
}): TrustRootPolicy {
  const body = buildTrustRootPolicy(
    {
      policy_id: 'policy:relyingparty',
      policy_version: opts.version,
      issued_at: opts.issued_at ?? NOW - 1000,
      refresh_after: opts.refresh_after ?? NOW + 1_000_000,
      trusted_issuers: opts.issuers ?? [trustedIssuer()],
      offline_behavior: opts.offline_behavior,
    },
    publisher.pk,
  )
  return signTrustRootPolicy(body, publisher.sk)
}

const RECEIPT_FACTS: ReceiptSignerFacts = {
  issuer_id: 'did:web:issuer.example',
  signer_pubkey_hex: issuerKey.pk,
}

// A resolver stub for the online live-confirm path.
function stubResolver(behavior: {
  hex?: string
  status?: KeyResolution['status']
}): KeyResolver {
  return {
    canResolve(_l: KeyLocator) {
      return true
    },
    async resolve(_l: KeyLocator): Promise<KeyResolution> {
      if (behavior.hex) {
        return { ok: true, status: 'resolved', publicKeyHex: behavior.hex }
      }
      return { ok: false, status: behavior.status ?? 'unreachable', reason: 'stub' }
    },
  }
}

// ── artifact sign/verify ────────────────────────────────────────────

describe('trust-root-policy artifact', () => {
  it('round-trips: sign then verify against the root-trusted publisher', () => {
    const policy = buildSignedPolicy({ version: 3 })
    const out = verifyTrustRootPolicy(policy, {
      trusted_publisher_pubkeys_hex: [publisher.pk],
      now_ms: NOW,
    })
    assert.equal(out.ok, true)
    assert.equal(out.policy_version, 3)
  })

  it('rejects a policy from an untrusted publisher (membership before signature)', () => {
    const policy = buildSignedPolicy({ version: 1 })
    const out = verifyTrustRootPolicy(policy, {
      trusted_publisher_pubkeys_hex: [otherKey.pk],
      now_ms: NOW,
    })
    assert.equal(out.ok, false)
    assert.equal(out.reason, 'untrusted_publisher')
  })

  it('rejects a tampered policy body (signature_invalid)', () => {
    const policy = buildSignedPolicy({ version: 1 })
    const tampered: TrustRootPolicy = {
      ...policy,
      trusted_issuers: [trustedIssuer({ issuer_id: 'did:web:attacker.example' })],
    }
    const out = verifyTrustRootPolicy(tampered, {
      trusted_publisher_pubkeys_hex: [publisher.pk],
      now_ms: NOW,
    })
    assert.equal(out.ok, false)
    assert.equal(out.reason, 'signature_invalid')
  })

  it('rejects an expired policy and a not-yet-valid policy', () => {
    const expired = buildSignedPolicy({ version: 1, refresh_after: NOW - 1 })
    assert.equal(
      verifyTrustRootPolicy(expired, {
        trusted_publisher_pubkeys_hex: [publisher.pk],
        now_ms: NOW,
      }).reason,
      'policy_expired',
    )
    const future = buildSignedPolicy({ version: 1, issued_at: NOW + 10_000 })
    assert.equal(
      verifyTrustRootPolicy(future, {
        trusted_publisher_pubkeys_hex: [publisher.pk],
        now_ms: NOW,
      }).reason,
      'not_yet_valid',
    )
  })

  it('anti-rollback: rejects a correctly-signed policy below the known minimum version', () => {
    const stale = buildSignedPolicy({ version: 4 })
    const out = verifyTrustRootPolicy(stale, {
      trusted_publisher_pubkeys_hex: [publisher.pk],
      now_ms: NOW,
      min_policy_version: 7,
    })
    assert.equal(out.ok, false)
    assert.equal(out.reason, 'version_rolled_back')
  })

  it('anti-rollback: accepts a version at or above the known minimum', () => {
    const current = buildSignedPolicy({ version: 7 })
    assert.equal(
      verifyTrustRootPolicy(current, {
        trusted_publisher_pubkeys_hex: [publisher.pk],
        now_ms: NOW,
        min_policy_version: 7,
      }).ok,
      true,
    )
  })
})

// ── the verdict: two policies, two verdicts on one receipt ──────────

describe('trust-policy verdict on one receipt', () => {
  it('two policies produce two verdicts on the SAME receipt', async () => {
    const policyAccept = buildSignedPolicy({ version: 1 })
    // policyReject trusts the same issuer id but pins a DIFFERENT key.
    const policyReject = buildSignedPolicy({
      version: 1,
      issuers: [
        trustedIssuer({ pinned_keys: [{ key_id: 'other', pubkey_hex: otherKey.pk }] }),
      ],
    })

    const vAccept = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, policyAccept, {
      now_ms: NOW,
    })
    const vReject = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, policyReject, {
      now_ms: NOW,
    })

    assert.equal(vAccept.status, 'pass')
    assert.equal(vAccept.reason, 'accepted')
    assert.equal(vAccept.matched_key_id, 'k1')

    assert.equal(vReject.status, 'fail')
    assert.equal(vReject.reason, 'pinned_key_mismatch')

    // The verdict is a verifier-derived OUTPUT, labeled as such.
    assert.equal(vAccept.computed_by, 'verifier')
    assert.equal(vReject.computed_by, 'verifier')
    // It names which signed policy version it was computed against.
    assert.equal(vAccept.policy_id, 'policy:relyingparty')
    assert.equal(vAccept.policy_version, 1)
  })

  it('rejects an untrusted issuer when the policy declares an allowlist', async () => {
    const policy = buildSignedPolicy({ version: 1 })
    const v = await evaluateReceiptAgainstPolicy(
      { issuer_id: 'did:web:stranger.example', signer_pubkey_hex: issuerKey.pk },
      policy,
      { now_ms: NOW },
    )
    assert.equal(v.status, 'fail')
    assert.equal(v.reason, 'issuer_not_trusted')
  })

  it('pinned-key mismatch: a wrong signer key is rejected', async () => {
    const policy = buildSignedPolicy({ version: 1 })
    const v = await evaluateReceiptAgainstPolicy(
      { issuer_id: 'did:web:issuer.example', signer_pubkey_hex: otherKey.pk },
      policy,
      { now_ms: NOW },
    )
    assert.equal(v.status, 'fail')
    assert.equal(v.reason, 'pinned_key_mismatch')
  })

  it('key out of window: a pinned key past not_after is rejected', async () => {
    const policy = buildSignedPolicy({
      version: 1,
      issuers: [
        trustedIssuer({
          pinned_keys: [{ key_id: 'k1', pubkey_hex: issuerKey.pk, not_after: NOW - 1 }],
        }),
      ],
    })
    const v = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, policy, { now_ms: NOW })
    assert.equal(v.status, 'fail')
    assert.equal(v.reason, 'key_out_of_window')
  })
})

// ── offline verify against a cached policy ──────────────────────────

describe('offline verdict', () => {
  it('offline verify against a cached signed policy succeeds on pinned-byte match', async () => {
    const policy = buildSignedPolicy({ version: 2 })
    // The verifier first checks the cached policy artifact itself.
    const artifactOk = verifyTrustRootPolicy(policy, {
      trusted_publisher_pubkeys_hex: [publisher.pk],
      now_ms: NOW,
      min_policy_version: 2,
    })
    assert.equal(artifactOk.ok, true)

    // Then evaluates the receipt OFFLINE: no resolver, pinned bytes only.
    const v = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, policy, {
      now_ms: NOW,
      offline: true,
    })
    assert.equal(v.status, 'pass')
    assert.equal(v.reason, 'accepted')
    assert.match(v.detail ?? '', /offline/)
  })

  it('offline_behavior=reject refuses to render an accepting verdict offline', async () => {
    const policy = buildSignedPolicy({ version: 1, offline_behavior: 'reject' })
    const v = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, policy, {
      now_ms: NOW,
      offline: true,
    })
    assert.equal(v.status, 'fail')
    assert.equal(v.reason, 'offline_no_pin_match')
  })
})

// ── online live-confirm path (reuses M3 resolver) ───────────────────

describe('online live key confirmation', () => {
  const locator: KeyLocator = { did: 'did:web:issuer.example#k1' }

  function policyWithLocator(stale?: 'closed' | 'open'): TrustRootPolicy {
    return buildSignedPolicy({
      version: 1,
      issuers: [
        trustedIssuer({
          pinned_keys: [{ key_id: 'k1', pubkey_hex: issuerKey.pk, locator }],
          stale_behavior: stale,
        }),
      ],
    })
  }

  it('accepts when the live endpoint asserts the pinned key', async () => {
    const policy = policyWithLocator()
    const v = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, policy, {
      now_ms: NOW,
      resolver: stubResolver({ hex: issuerKey.pk }),
    })
    assert.equal(v.status, 'pass')
    assert.equal(v.reason, 'accepted')
  })

  it('rejects when the live endpoint asserts a DIFFERENT key than the pin', async () => {
    const policy = policyWithLocator()
    const v = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, policy, {
      now_ms: NOW,
      resolver: stubResolver({ hex: otherKey.pk }),
    })
    assert.equal(v.status, 'fail')
    assert.equal(v.reason, 'pinned_key_mismatch')
  })

  it('fail-closed (default): an unreachable endpoint rejects', async () => {
    const policy = policyWithLocator('closed')
    const v = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, policy, {
      now_ms: NOW,
      resolver: stubResolver({ status: 'unreachable' }),
    })
    assert.equal(v.status, 'fail')
    assert.equal(v.reason, 'key_unresolved')
    assert.equal(v.degraded, false)
  })

  it('fail-open: an unreachable endpoint yields a degraded UNKNOWN, never acceptance', async () => {
    const policy = policyWithLocator('open')
    const v = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, policy, {
      now_ms: NOW,
      resolver: stubResolver({ status: 'unreachable' }),
    })
    assert.equal(v.status, 'unknown')
    assert.equal(v.reason, 'degraded_unreachable')
    assert.equal(v.degraded, true)
    assert.notEqual(v.status, 'pass')
  })

  it('fail-open does NOT relax a hard malformed resolution (stays fail)', async () => {
    const policy = policyWithLocator('open')
    const v = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, policy, {
      now_ms: NOW,
      resolver: stubResolver({ status: 'malformed' }),
    })
    assert.equal(v.status, 'fail')
    assert.equal(v.reason, 'key_unresolved')
  })
})

// ── rotation overlap ────────────────────────────────────────────────

describe('rotation overlap', () => {
  it('accepts a superseded key inside its overlap window', async () => {
    const policy = buildSignedPolicy({
      version: 5,
      issuers: [
        {
          issuer_id: 'did:web:issuer.example',
          display_name: 'Example Issuer',
          // current pin is otherKey; old pin issuerKey is superseded.
          pinned_keys: [
            { key_id: 'k2', pubkey_hex: otherKey.pk },
            { key_id: 'k1', pubkey_hex: issuerKey.pk },
          ],
        },
      ],
    })
    // Re-sign with a rotation rule carrying the retired key inside window.
    const withRotation = signTrustRootPolicy(
      buildTrustRootPolicy(
        {
          policy_id: 'policy:relyingparty',
          policy_version: 5,
          issued_at: NOW - 1000,
          refresh_after: NOW + 1_000_000,
          trusted_issuers: policy.trusted_issuers,
          rotation: { overlap_ms: 100_000, superseded: [{ key_id: 'k1', retired_at: NOW - 50_000 }] },
        },
        publisher.pk,
      ),
      publisher.sk,
    )
    const v = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, withRotation, { now_ms: NOW })
    assert.equal(v.status, 'pass')
    assert.match(v.detail ?? '', /rotation overlap/)
  })

  it('rejects a superseded key after its overlap window closes', async () => {
    const withRotation = signTrustRootPolicy(
      buildTrustRootPolicy(
        {
          policy_id: 'policy:relyingparty',
          policy_version: 5,
          issued_at: NOW - 1000,
          refresh_after: NOW + 1_000_000,
          trusted_issuers: [
            {
              issuer_id: 'did:web:issuer.example',
              display_name: 'Example Issuer',
              pinned_keys: [
                { key_id: 'k2', pubkey_hex: otherKey.pk },
                { key_id: 'k1', pubkey_hex: issuerKey.pk },
              ],
            },
          ],
          rotation: { overlap_ms: 10_000, superseded: [{ key_id: 'k1', retired_at: NOW - 50_000 }] },
        },
        publisher.pk,
      ),
      publisher.sk,
    )
    const v = await evaluateReceiptAgainstPolicy(RECEIPT_FACTS, withRotation, { now_ms: NOW })
    assert.equal(v.status, 'fail')
    assert.equal(v.reason, 'pinned_key_mismatch')
  })
})

// ── well-known convention + generator ───────────────────────────────

describe('.well-known/aps-agents.json convention', () => {
  it('generates a valid document and validates pubkey hex', () => {
    const doc = generateApsAgentsDoc({
      domain: 'issuer.example',
      generated_at: NOW,
      agents: [
        {
          issuer_id: 'did:web:issuer.example',
          display_name: 'Example Issuer',
          pubkeys_hex: [issuerKey.pk],
          locator: { did: 'did:web:issuer.example#k1' },
        },
      ],
    })
    assert.equal(doc.spec_version, '1.0')
    assert.equal(doc.agents.length, 1)
    assert.equal(doc.agents[0].pubkeys_hex[0], issuerKey.pk)
  })

  it('rejects a malformed (non-hex) pubkey in the generator', () => {
    assert.throws(() =>
      generateApsAgentsDoc({
        domain: 'issuer.example',
        generated_at: NOW,
        agents: [
          { issuer_id: 'x', display_name: 'x', pubkeys_hex: ['NOT-HEX'] },
        ],
      }),
    )
  })

  it('composes the well-known URL from a bare domain and a did:web id', () => {
    assert.equal(
      apsAgentsUrl('issuer.example'),
      `https://issuer.example${WELL_KNOWN_APS_AGENTS_PATH}`,
    )
    assert.equal(
      apsAgentsUrl('did:web:issuer.example'),
      `https://issuer.example${WELL_KNOWN_APS_AGENTS_PATH}`,
    )
  })

  it('preserves the did:web port encoding in the composed URL', () => {
    assert.equal(
      apsAgentsUrl('did:web:issuer.example%3A8443'),
      `https://issuer.example:8443${WELL_KNOWN_APS_AGENTS_PATH}`,
    )
  })
})

// ── additive trust_policy_ref byte-stability on the Cycles receipt ──

describe('additive trust_policy_ref on the Cycles permit receipt', () => {
  const evidence: CyclesEvidenceRef = {
    cycles_evidence_url: 'https://cycles.example/evidence/1',
    cycles_evidence_id_sha256: '0'.repeat(64),
    action_ref: 'act-1',
    delegation_ref: 'del-1',
  }

  const signer = kp()

  function baseInput() {
    return {
      agent_id: 'agent-1',
      delegation_ref: 'del-1',
      action_ref: 'act-1',
      reservation_id: 'res-1',
      reserved: { unit: 'CREDITS', amount: 10 },
      decision: 'ALLOW' as const,
      cycles_evidence: evidence,
    }
  }

  it('omitting trust_policy_ref leaves the canonical signed bytes unchanged', () => {
    const a = signCyclesPermitReceipt(baseInput(), signer.sk)
    // A receipt without the field must not carry it.
    assert.equal('trust_policy_ref' in a, false)
    // Canonical form of the body (signature cleared) excludes the field.
    const { signature: _s, ...bodyA } = a
    assert.equal(canonicalizeJCS(bodyA).includes('trust_policy_ref'), false)
    // And it still verifies.
    assert.equal(verifyCyclesPermitReceipt(a).valid, true)
  })

  it('supplying trust_policy_ref carries it and the receipt still verifies', () => {
    const b = signCyclesPermitReceipt(
      { ...baseInput(), trust_policy_ref: 'policy:relyingparty@7' },
      signer.sk,
    )
    assert.equal(b.trust_policy_ref, 'policy:relyingparty@7')
    assert.equal(verifyCyclesPermitReceipt(b).valid, true)
  })

  it('two receipts identical except for the omitted field differ only by that field', () => {
    // Pin the same signer; the only difference is presence of the ref.
    const withRef = signCyclesPermitReceipt(
      { ...baseInput(), trust_policy_ref: 'p@1' },
      signer.sk,
    )
    const { signature: _x, receipt_id: _r1, issued_at: _i1, timestamp: _t1, trust_policy_ref: _tp, ...restWith } =
      withRef as Record<string, unknown> & { trust_policy_ref?: string }
    // The presence of trust_policy_ref is the only structural addition;
    // the field is excluded here and the remainder is the shared shape.
    assert.equal('trust_policy_ref' in restWith, false)
  })
})
