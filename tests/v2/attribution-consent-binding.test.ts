// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// A consent receipt proves consent only if the consenting key is the
// principal's key.
// ══════════════════════════════════════════════════════════════════
// The receipt names each party twice: `citer` beside `citer_public_key`, and
// `cited_principal` beside `cited_principal_public_key`. Nothing bound either
// pair, and both signatures were checked against the keys the receipt carries.
// So the principal whose consent is being proved supplied the key that proves
// it.
//
// That is the purpose of the primitive inverted. The module header says it
// exists so that citing a position a principal never took is not possible
// inside binding artifacts, and `charter.ts` and `completion.ts` gate on it.
//
// The binding is the session 1 self-certifying helper and nothing else: each
// party's DID must commit to the key beside it. A DID that commits to no key
// cannot be bound without a DID document, this SDK resolves none on these
// surfaces, so it is refused rather than assumed.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createAttributionReceipt,
  signAttributionConsent,
  verifyAttributionConsent,
  checkArtifactCitations,
  generateKeyPair,
  toDIDKey,
  createCharter,
  verifyCharter,
  verifyCompletionReceipt,
  createCompletionReceipt,
} from '../../src/index.js'
import type { AttributionReceipt, CitingArtifact } from '../../src/index.js'
import type { HybridTimestamp } from '../../src/types/time.js'

const EARLY: HybridTimestamp = { logicalTime: 1, wallClockEarliest: 1, wallClockLatest: 2, gatewayId: 'gw' }
// Far future in real wall-clock ms: the two gates call checkArtifactCitations
// without a `now`, so they compare against the actual clock.
const LATE: HybridTimestamp = { logicalTime: 9, wallClockEarliest: 4e12, wallClockLatest: 4e12, gatewayId: 'gw' }

type Party = { publicKey: string; privateKey: string }

function receipt(opts: {
  citerKp: Party; citedKp: Party
  citerDid?: string; citedDid?: string
  citerKey?: string; citedKey?: string
  consentKp?: Party
}): AttributionReceipt {
  const r = createAttributionReceipt({
    citer: opts.citerDid ?? toDIDKey(opts.citerKp.publicKey),
    citer_public_key: opts.citerKey ?? opts.citerKp.publicKey,
    citer_private_key: opts.citerKp.privateKey,
    cited_principal: opts.citedDid ?? toDIDKey(opts.citedKp.publicKey),
    cited_principal_public_key: opts.citedKey ?? opts.citedKp.publicKey,
    citation_content: 'The principal endorsed narrowing scope, not widening it.',
    binding_context: 'ctx-1',
    created_at: EARLY,
    expires_at: LATE,
  })
  return signAttributionConsent(r, (opts.consentKp ?? opts.citedKp).privateKey)
}

function artifactCiting(r: AttributionReceipt): CitingArtifact {
  return {
    citations: [{
      receipt_id: r.id,
      citation_content: r.citation_content,
      cited_principal: r.cited_principal,
    }],
  } as CitingArtifact
}

describe('attribution consent binds each party to the key beside it', () => {
  it('an honest receipt still verifies', () => {
    const citer = generateKeyPair(), cited = generateKeyPair()
    const result = verifyAttributionConsent(receipt({ citerKp: citer, citedKp: cited }), EARLY)
    assert.equal(result.valid, true, result.reason)
  })

  it('a victim DID beside an attacker key on the cited principal is refused', () => {
    // The finding: the attacker names the victim, supplies their own key for
    // the victim, and signs the consent themselves.
    const attacker = generateKeyPair(), victim = generateKeyPair()
    const r = receipt({
      citerKp: attacker, citedKp: victim,
      citedDid: toDIDKey(victim.publicKey), citedKey: attacker.publicKey,
      consentKp: attacker,
    })
    const result = verifyAttributionConsent(r, EARLY)
    assert.equal(result.valid, false)
    assert.match(result.reason ?? '', /cited_principal/)
  })

  it('a victim DID beside an attacker key on the citer is refused', () => {
    const attacker = generateKeyPair(), victim = generateKeyPair(), cited = generateKeyPair()
    const r = receipt({
      citerKp: attacker, citedKp: cited,
      citerDid: toDIDKey(victim.publicKey), citerKey: attacker.publicKey,
    })
    const result = verifyAttributionConsent(r, EARLY)
    assert.equal(result.valid, false)
    assert.match(result.reason ?? '', /citer/)
  })

  it('the two parties keys swapped is refused', () => {
    const a = generateKeyPair(), b = generateKeyPair()
    // signAttributionConsent already refuses to build this, which is itself
    // part of the contract. Assemble it directly, as an attacker would.
    const honest = receipt({ citerKp: a, citedKp: b })
    const swapped: AttributionReceipt = {
      ...honest,
      citer_public_key: honest.cited_principal_public_key,
      cited_principal_public_key: honest.citer_public_key,
    }
    assert.equal(verifyAttributionConsent(swapped, EARLY).valid, false)
  })

  it('consent signed by a key that does not bind to the consenting DID is refused', () => {
    const citer = generateKeyPair(), cited = generateKeyPair(), stranger = generateKeyPair()
    assert.throws(() => receipt({ citerKp: citer, citedKp: cited, consentKp: stranger }),
      /consent signature does not verify/)
  })

  for (const did of ['did:aps:cited-principal', 'agent:citer', 'did:web:example.com', 'did:example:1', '', 'not-a-did']) {
    it(`a DID that commits to no key is refused rather than assumed: ${did || '(empty)'}`, () => {
      const citer = generateKeyPair(), cited = generateKeyPair()
      const r = receipt({ citerKp: citer, citedKp: cited, citedDid: did })
      const result = verifyAttributionConsent(r, EARLY)
      assert.equal(result.valid, false)
      assert.ok(result.reason)
    })
  }

  it('one DID naming both parties with different keys is refused', () => {
    const a = generateKeyPair(), b = generateKeyPair()
    const shared = toDIDKey(a.publicKey)
    const r = receipt({
      citerKp: a, citedKp: b,
      citerDid: shared, citedDid: shared, citedKey: b.publicKey, consentKp: b,
    })
    // The DID commits to a's key, so it cannot also stand for b's.
    assert.equal(verifyAttributionConsent(r, EARLY).valid, false)
  })

  it('a non-canonical did:key is refused', () => {
    // Re-attack, not in the brief. A did:key that is not the canonical
    // spelling of the key it decodes to would give one signer two identities.
    const citer = generateKeyPair(), cited = generateKeyPair()
    const r = receipt({ citerKp: citer, citedKp: cited, citedDid: toDIDKey(cited.publicKey) + 'z' })
    assert.equal(verifyAttributionConsent(r, EARLY).valid, false)
  })
})

describe('the gates reject the spoof and keep accepting honest receipts', () => {
  const policy = (key: string) => ({
    policyId: 'policy_test',
    requirements: [{ role: 'board', requiredSignatures: 1, eligibleKeys: [key] }],
    collectionTimeoutSeconds: 3600,
    onTimeout: 'reject' as const,
    reevaluateOnRevocation: true,
  })

  function charterWith(citations: CitingArtifact['citations']) {
    const founder = generateKeyPair()
    const charter = createCharter({
      name: 'Test Institution',
      offices: [{
        officeId: 'treasury', name: 'Treasury', holderMode: 'single',
        holderSet: [{
          publicKey: generateKeyPair().publicKey, appointedAt: new Date().toISOString(),
          appointedBy: 'charter_founding', isInterim: false,
        }],
        delegationPolicy: { allowedScopes: ['*'], maxSpendPerAction: 1000, maxDelegationDepth: 3 },
        successionOrder: [], status: 'active', effectiveAt: new Date().toISOString(),
      }],
      amendmentPolicy: policy(founder.publicKey),
      dissolutionPolicy: {
        requiresThreshold: policy(founder.publicKey),
        gracePeriodSeconds: 86400, activeEscrowHandling: 'settle_first',
      },
      delegationSurvival: { onOfficeChange: 'require_reconfirmation', onCharterAmendment: 'survive_if_compatible' },
      founderPrivateKey: founder.privateKey,
      founderPublicKey: founder.publicKey,
      founderRole: 'board',
    } as never)
    return { ...charter, citations } as never
  }

  it('charter accepts an honest citation and rejects the spoof', () => {
    const citer = generateKeyPair(), cited = generateKeyPair(), attacker = generateKeyPair()
    const honest = receipt({ citerKp: citer, citedKp: cited })
    const ok = verifyCharter(charterWith(artifactCiting(honest).citations), [honest])
    assert.ok(!ok.errors.some(e => e.startsWith('AttributionConsent')), ok.errors.join('; '))

    const spoof = receipt({
      citerKp: attacker, citedKp: cited,
      citedDid: toDIDKey(cited.publicKey), citedKey: attacker.publicKey, consentKp: attacker,
    })
    const bad = verifyCharter(charterWith(artifactCiting(spoof).citations), [spoof])
    assert.equal(bad.valid, false)
    assert.ok(bad.errors.some(e => e.startsWith('AttributionConsent')), bad.errors.join('; '))
  })

  it('completion receipt accepts an honest citation and rejects the spoof', () => {
    const signer = generateKeyPair()
    const citer = generateKeyPair(), cited = generateKeyPair(), attacker = generateKeyPair()
    const build = (citations: CitingArtifact['citations']) =>
      createCompletionReceipt({
        permitReceiptHash: 'a'.repeat(64), executionResult: 'success',
        executedAt: new Date().toISOString(), privateKey: signer.privateKey, citations,
      } as never)
    const honest = receipt({ citerKp: citer, citedKp: cited })
    const okErrors = verifyCompletionReceipt(build(artifactCiting(honest).citations), signer.publicKey, [honest]).errors
    assert.ok(!okErrors.some(e => e.startsWith('AttributionConsent')), okErrors.join('; '))

    const spoof = receipt({
      citerKp: attacker, citedKp: cited,
      citedDid: toDIDKey(cited.publicKey), citedKey: attacker.publicKey, consentKp: attacker,
    })
    const badErrors = verifyCompletionReceipt(build(artifactCiting(spoof).citations), signer.publicKey, [spoof]).errors
    assert.ok(badErrors.some(e => e.startsWith('AttributionConsent')), badErrors.join('; '))
  })

  it('an artifact citing the spoof is refused by checkArtifactCitations itself', () => {
    const attacker = generateKeyPair(), victim = generateKeyPair()
    const spoof = receipt({
      citerKp: attacker, citedKp: victim,
      citedDid: toDIDKey(victim.publicKey), citedKey: attacker.publicKey, consentKp: attacker,
    })
    const r = checkArtifactCitations(artifactCiting(spoof), [spoof], { binding_context: 'ctx-1', now: EARLY })
    assert.equal(r.valid, false)
  })
})
