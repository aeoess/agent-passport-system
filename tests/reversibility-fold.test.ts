// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Reversibility fold - foundation tests (spec v2, steps 1-2)
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  enforcementFrom,
  classifyV0,
  getClassificationProfile,
  registeredProfileIds,
  reversibilityMappingV0,
  REVERSIBILITY_MAPPING_V0_ID,
  recomputeEffect,
  recomputeBlock,
  verifyAssertedClass,
  rapvExternalityToEffectFacts,
  type RealizedClass,
  type EffectFacts,
  type EffectInstantiationElement,
  type EffectInstantiationBlock,
} from '../src/core/reversibility-fold.js'

// A well-formed base element; individual tests override the fields under test.
function element(over: Partial<EffectInstantiationElement> = {}): EffectInstantiationElement {
  return {
    effect_scope: 'external',
    effect_target_ref: 'urn:target:acme-merchant',
    finality_state: 'pending',
    recovery_mechanism_ref: null,
    recovery_controller: null,
    recovery_deadline: null,
    evidence_status: 'resolved',
    classification_profile_id: REVERSIBILITY_MAPPING_V0_ID,
    ...over,
  }
}

// ══════════════════════════════════════
// STEP 1 - projection realized -> enforcement (spec section 0)
// ══════════════════════════════════════

describe('reversibility-fold step 1 - enforcementFrom projection', () => {
  // The full projection table, exhaustive over every RealizedClass input.
  const table: Array<[RealizedClass, string]> = [
    ['tentative', 'tentative'],
    ['compensable', 'compensable'],
    ['irreversible', 'irreversible'],
    ['unresolved', 'irreversible'],
  ]

  for (const [realized, expected] of table) {
    it(`${realized} -> ${expected}`, () => {
      assert.equal(enforcementFrom(realized), expected)
    })
  }

  it('unresolved is the ONLY value that changes under the projection', () => {
    // Identity for every non-unresolved value; unresolved conservatively lifts.
    const all: RealizedClass[] = ['tentative', 'compensable', 'irreversible', 'unresolved']
    for (const r of all) {
      if (r === 'unresolved') {
        assert.equal(enforcementFrom(r), 'irreversible')
        assert.notEqual(enforcementFrom(r), r)
      } else {
        assert.equal(enforcementFrom(r), r)
      }
    }
  })

  it('the table covers every RealizedClass input (no gaps)', () => {
    const covered = new Set(table.map(([r]) => r))
    const all: RealizedClass[] = ['tentative', 'compensable', 'irreversible', 'unresolved']
    for (const r of all) assert.ok(covered.has(r), `missing projection case: ${r}`)
    assert.equal(covered.size, all.length)
  })
})

// ══════════════════════════════════════
// STEP 2 - versioned mapping-profile registry + v0 classifier (spec section 4)
// ══════════════════════════════════════

const PRINCIPAL = 'did:aps:principal-acting'
const OTHER_DOMAIN = 'did:aps:merchant-counterparty'

describe('reversibility-fold step 2 - v0 classifier, one per section-4 branch', () => {
  it('external-irreversible -> irreversible, upper_bound when finality/target not verified', () => {
    const facts: EffectFacts = { externality: 'external-irreversible', finalityState: 'pending' }
    const r = classifyV0(facts)
    assert.equal(r.realized, 'irreversible')
    assert.equal(r.label, 'upper_bound')
  })

  it('external-irreversible -> irreversible, definitive (no label) when settled AND target bound', () => {
    const facts: EffectFacts = {
      externality: 'external-irreversible',
      finalityState: 'settled',
      targetBindingVerified: true,
    }
    const r = classifyV0(facts)
    assert.equal(r.realized, 'irreversible')
    assert.equal(r.label, undefined)
  })

  it('external-reversible -> compensable when controller is the principal AND external reversal-right present', () => {
    const facts: EffectFacts = {
      externality: 'external-reversible',
      actingPrincipal: PRINCIPAL,
      recoveryController: PRINCIPAL,
      reversalRight: { signer: OTHER_DOMAIN },
    }
    const r = classifyV0(facts)
    assert.equal(r.realized, 'compensable')
    assert.equal(r.label, undefined)
  })

  it('internal with observable recovery mechanism -> compensable', () => {
    const facts: EffectFacts = { externality: 'internal', recoveryMechanismRef: 'snapshot://backup-2026-07-13' }
    assert.equal(classifyV0(facts).realized, 'compensable')
  })

  it('unbound / missing externality -> unresolved', () => {
    assert.equal(classifyV0({}).realized, 'unresolved')
  })
})

describe('reversibility-fold step 2 - mandated regressions (section 4 fail-closed)', () => {
  it('external-reversible WITHOUT the external reversal-right signature -> irreversible', () => {
    const facts: EffectFacts = {
      externality: 'external-reversible',
      actingPrincipal: PRINCIPAL,
      recoveryController: PRINCIPAL,
      // no reversalRight
    }
    assert.equal(classifyV0(facts).realized, 'irreversible')
  })

  it('external-reversible with a SELF-attested reversal-right (signer is the principal) -> irreversible', () => {
    // Self-attestation does not establish the right; the signer must be a
    // domain other than the acting principal.
    const facts: EffectFacts = {
      externality: 'external-reversible',
      actingPrincipal: PRINCIPAL,
      recoveryController: PRINCIPAL,
      reversalRight: { signer: PRINCIPAL },
    }
    assert.equal(classifyV0(facts).realized, 'irreversible')
  })

  it('external-reversible with a degenerate empty-signer reversal-right -> irreversible', () => {
    // An empty signer is not a real external domain; fail closed.
    const facts: EffectFacts = {
      externality: 'external-reversible',
      actingPrincipal: PRINCIPAL,
      recoveryController: PRINCIPAL,
      reversalRight: { signer: '' },
    }
    assert.equal(classifyV0(facts).realized, 'irreversible')
  })

  it('external-reversible where the controller is NOT the acting principal -> irreversible', () => {
    // A counterparty who CAN reverse but is not our controllable lever.
    const facts: EffectFacts = {
      externality: 'external-reversible',
      actingPrincipal: PRINCIPAL,
      recoveryController: OTHER_DOMAIN,
      reversalRight: { signer: OTHER_DOMAIN },
    }
    assert.equal(classifyV0(facts).realized, 'irreversible')
  })

  it('internal key-destruction facts (no observable recovery) -> irreversible', () => {
    assert.equal(classifyV0({ externality: 'internal', recoveryMechanismRef: null }).realized, 'irreversible')
    assert.equal(classifyV0({ externality: 'internal' }).realized, 'irreversible')
    assert.equal(classifyV0({ externality: 'internal', recoveryMechanismRef: '' }).realized, 'irreversible')
  })

  it('missing facts -> unresolved (externality absent even if other fields present)', () => {
    assert.equal(classifyV0({ actingPrincipal: PRINCIPAL, recoveryController: PRINCIPAL }).realized, 'unresolved')
  })
})

describe('reversibility-fold step 2 - projection ties enforcement to the classifier', () => {
  it('unbound facts classify unresolved and enforce irreversible', () => {
    const realized = classifyV0({}).realized
    assert.equal(realized, 'unresolved')
    assert.equal(enforcementFrom(realized), 'irreversible')
  })

  it('a compensable realization enforces compensable (no over-restriction)', () => {
    const realized = classifyV0({
      externality: 'external-reversible',
      actingPrincipal: PRINCIPAL,
      recoveryController: PRINCIPAL,
      reversalRight: { signer: OTHER_DOMAIN },
    }).realized
    assert.equal(realized, 'compensable')
    assert.equal(enforcementFrom(realized), 'compensable')
  })
})

describe('reversibility-fold step 2 - versioned profile registry', () => {
  it('resolves the v0 profile by its classification_profile_id', () => {
    const p = getClassificationProfile(REVERSIBILITY_MAPPING_V0_ID)
    assert.ok(p)
    assert.equal(p.id, REVERSIBILITY_MAPPING_V0_ID)
    assert.equal(p, reversibilityMappingV0)
  })

  it('the profile id is stable and non-empty (version binding is mandatory)', () => {
    assert.equal(REVERSIBILITY_MAPPING_V0_ID, 'reversibility-mapping-v0')
    assert.ok(REVERSIBILITY_MAPPING_V0_ID.length > 0)
    assert.ok(registeredProfileIds().includes(REVERSIBILITY_MAPPING_V0_ID))
  })

  it('returns undefined for an unknown profile id (not conflated with unbound facts)', () => {
    assert.equal(getClassificationProfile('no-such-profile-vX'), undefined)
  })

  it('an unrecognized externality bucket fails closed to unresolved', () => {
    // Defensive: a runtime value outside the union must not fall open to a
    // compensable internal classification.
    const rogue = { externality: 'external-maybe', recoveryMechanismRef: 'snapshot://x' } as unknown as EffectFacts
    assert.equal(classifyV0(rogue).realized, 'unresolved')
  })

  it('the resolved profile classify matches classifyV0 for the same facts', () => {
    const p = getClassificationProfile(REVERSIBILITY_MAPPING_V0_ID)
    assert.ok(p)
    const facts: EffectFacts = { externality: 'external-irreversible', finalityState: 'pending' }
    assert.deepEqual(p.classify(facts), classifyV0(facts))
  })
})

// ══════════════════════════════════════
// STEP 3a - effect-instantiation block + recompute (spec section 3)
// ══════════════════════════════════════

describe('reversibility-fold step 3a - recompute over each externality bucket via the block', () => {
  it('internal effect with an observable recovery mechanism -> compensable', () => {
    const out = recomputeEffect(element({ effect_scope: 'internal', recovery_mechanism_ref: 'snapshot://db-2026-07-13' }))
    assert.equal(out.status, 'recomputed')
    assert.equal(out.status === 'recomputed' && out.result.realized, 'compensable')
  })

  it('internal effect with no recovery mechanism (key destruction) -> irreversible', () => {
    const out = recomputeEffect(element({ effect_scope: 'internal', recovery_mechanism_ref: null }))
    assert.equal(out.status === 'recomputed' && out.result.realized, 'irreversible')
  })

  it('external effect with no recovery (external-irreversible) -> irreversible + upper_bound (unverified)', () => {
    const out = recomputeEffect(element({ effect_scope: 'external', recovery_mechanism_ref: null }))
    assert.equal(out.status, 'recomputed')
    if (out.status === 'recomputed') {
      assert.equal(out.result.realized, 'irreversible')
      assert.equal(out.result.label, 'upper_bound')
    }
  })

  it('external effect with a recovery mechanism (external-reversible) fails closed to irreversible pre-actor-axis', () => {
    // In step 3 the actor axis (external reversal-right signer) is not supplied,
    // so an external-reversible effect cannot reach compensable and fails closed.
    const out = recomputeEffect(element({
      effect_scope: 'external',
      recovery_mechanism_ref: 'refund://acme/settle',
      recovery_controller: 'urn:principal:me',
    }))
    assert.equal(out.status === 'recomputed' && out.result.realized, 'irreversible')
  })
})

describe('reversibility-fold step 3a - targetBindingVerified hard rule (verifier only)', () => {
  it('external-irreversible stays upper_bound when the verifier does not pass targetBindingVerified', () => {
    const out = recomputeEffect(element({ effect_scope: 'external', recovery_mechanism_ref: null, finality_state: 'settled' }))
    assert.equal(out.status === 'recomputed' && out.result.label, 'upper_bound')
  })

  it('external-irreversible becomes definitive (no label) only when the verifier passes targetBindingVerified AND finality is settled', () => {
    const el = element({ effect_scope: 'external', recovery_mechanism_ref: null, finality_state: 'settled' })
    const out = recomputeEffect(el, { targetBindingVerified: true })
    assert.equal(out.status, 'recomputed')
    if (out.status === 'recomputed') {
      assert.equal(out.result.realized, 'irreversible')
      assert.equal(out.result.label, undefined)
    }
  })

  it('verifier targetBindingVerified without settled finality still reads upper_bound', () => {
    const el = element({ effect_scope: 'external', recovery_mechanism_ref: null, finality_state: 'pending' })
    const out = recomputeEffect(el, { targetBindingVerified: true })
    assert.equal(out.status === 'recomputed' && out.result.label, 'upper_bound')
  })
})

describe('reversibility-fold step 3a - unknown profile is a distinct failure', () => {
  it('an unknown classification_profile_id surfaces as unknown_profile, NOT unresolved', () => {
    const out = recomputeEffect(element({ classification_profile_id: 'reversibility-mapping-v999' }))
    assert.equal(out.status, 'unknown_profile')
    assert.equal(out.status === 'unknown_profile' && out.classificationProfileId, 'reversibility-mapping-v999')
  })
})

describe('reversibility-fold step 3a - asserted cache class is never trusted', () => {
  it('a matching asserted cache passes', () => {
    // internal + no recovery recomputes irreversible; cache agrees.
    const el = element({ effect_scope: 'internal', recovery_mechanism_ref: null, asserted_realized_class: 'irreversible' })
    const check = verifyAssertedClass(el)
    assert.equal(check.ok, true)
  })

  it('a mismatching asserted cache FAILS with the recomputed class named', () => {
    // internal + no recovery recomputes irreversible; cache lies "compensable".
    const el = element({ effect_scope: 'internal', recovery_mechanism_ref: null, asserted_realized_class: 'compensable' })
    const check = verifyAssertedClass(el)
    assert.equal(check.ok, false)
    if (check.ok === false && check.reason === 'mismatch') {
      assert.equal(check.asserted, 'compensable')
      assert.equal(check.recomputed, 'irreversible')
    } else {
      assert.fail('expected a mismatch failure')
    }
  })

  it('an absent asserted cache passes', () => {
    const check = verifyAssertedClass(element({ effect_scope: 'internal', recovery_mechanism_ref: 'snapshot://x' }))
    assert.equal(check.ok, true)
  })

  it('an unknown profile cannot verify an asserted cache', () => {
    const el = element({ classification_profile_id: 'nope', asserted_realized_class: 'irreversible' })
    const check = verifyAssertedClass(el)
    assert.equal(check.ok === false && check.reason, 'unknown_profile')
  })
})

describe('reversibility-fold step 3a - RAPV0 externality adapter', () => {
  it("RAPV0 'none' -> undefined -> unresolved", () => {
    assert.equal(rapvExternalityToEffectFacts('none'), undefined)
    assert.equal(classifyV0({ externality: rapvExternalityToEffectFacts('none') }).realized, 'unresolved')
  })

  it('RAPV0 absent/null -> undefined -> unresolved', () => {
    assert.equal(rapvExternalityToEffectFacts(undefined), undefined)
    assert.equal(rapvExternalityToEffectFacts(null), undefined)
    assert.equal(classifyV0({ externality: rapvExternalityToEffectFacts(undefined) }).realized, 'unresolved')
  })

  it('RAPV0 substantive buckets pass through to EffectFacts.externality', () => {
    assert.equal(rapvExternalityToEffectFacts('internal'), 'internal')
    assert.equal(rapvExternalityToEffectFacts('external-reversible'), 'external-reversible')
    assert.equal(rapvExternalityToEffectFacts('external-irreversible'), 'external-irreversible')
  })
})

describe('reversibility-fold step 3a - multi-effect block recomputes per element', () => {
  it('a block with three distinct effects recomputes each independently, preserving order', () => {
    const block: EffectInstantiationBlock = {
      instantiated_effects: [
        // compensable payment authorization (internal, snapshot recovery)
        element({ effect_scope: 'internal', recovery_mechanism_ref: 'snapshot://ledger' }),
        // irreversible external email (external, no recovery)
        element({ effect_scope: 'external', recovery_mechanism_ref: null }),
        // internal irreversible key deletion (internal, no recovery)
        element({ effect_scope: 'internal', recovery_mechanism_ref: null }),
      ],
    }
    const outs = recomputeBlock(block)
    assert.equal(outs.length, 3)
    assert.equal(outs[0].status === 'recomputed' && outs[0].result.realized, 'compensable')
    assert.equal(outs[1].status === 'recomputed' && outs[1].result.realized, 'irreversible')
    assert.equal(outs[1].status === 'recomputed' && outs[1].result.label, 'upper_bound')
    assert.equal(outs[2].status === 'recomputed' && outs[2].result.realized, 'irreversible')
    // no collapse to a single max: three separate outcomes preserved.
  })
})
