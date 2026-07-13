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
  type RealizedClass,
  type EffectFacts,
} from '../src/core/reversibility-fold.js'

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
