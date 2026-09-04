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
  REVERSIBILITY_MAPPING_V0_DIGEST,
  REVERSIBILITY_PROFILE_V0_CONTENT,
  profileContentDigest,
  getRegisteredProfile,
  getProfileDigest,
  verifyProfileBinding,
  recomputeEffect,
  recomputeBlock,
  verifyAssertedClass,
  rapvExternalityToEffectFacts,
  type RealizedClass,
  type EffectFacts,
  hashExecutionReceipt,
  createReconciliationReceipt,
  validateTransition,
  admittedEnforcementClass,
  hashEffectState,
  effectStatePreimage,
  validateEffectLineage,
  deriveEffectId,
  latestValidEffectStates,
  type EffectInstantiationElement,
  type EffectInstantiationBlock,
  type ExecutionStageReceipt,
} from '../src/core/reversibility-fold.js'
import { createMinimalEnvelope, verifyExecutionEnvelope } from '../src/index.js'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalize } from '../src/core/canonical.js'
import { createHash } from 'node:crypto'

// A well-formed base element; individual tests override the fields under test.
// effect_id is DETERMINISTIC (no mutable counter): derived from action_ref +
// action_instance_id + a stable local id (default 'default'). Callers wanting a
// distinct effect pass a distinct localId or override effect_id directly.
function element(over: Partial<EffectInstantiationElement> = {}, localId = 'default'): EffectInstantiationElement {
  const action_ref = over.action_ref ?? 'action_ref:acme-req-1'
  const action_instance_id = over.action_instance_id ?? 'action-instance:1'
  return {
    effect_scope: 'external',
    effect_target_ref: 'urn:target:acme-merchant',
    finality_state: 'pending',
    recovery_mechanism_ref: null,
    recovery_controller: null,
    recovery_deadline: null,
    evidence_status: 'resolved',
    classification_profile_id: REVERSIBILITY_MAPPING_V0_ID,
    classification_profile_digest: REVERSIBILITY_MAPPING_V0_DIGEST,
    action_ref,
    action_instance_id,
    effect_id: deriveEffectId(action_ref, action_instance_id, localId),
    predecessor_effect_state_hash: null,
    sequence: 0,
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

  it('external-reversible -> irreversible + upper_bound in v0 (no external-compensable path, v4 s4/s10)', () => {
    // The legacy external-reversible taxonomy value is treated exactly as
    // external-irreversible in v0. Even a controller-is-principal plus a
    // different-domain reversal-right does NOT reach compensable.
    const facts: EffectFacts = {
      externality: 'external-reversible',
      actingPrincipal: PRINCIPAL,
      recoveryController: PRINCIPAL,
      reversalRight: { signer: OTHER_DOMAIN },
    }
    const r = classifyV0(facts)
    assert.equal(r.realized, 'irreversible')
    assert.equal(r.label, 'upper_bound')
  })

  it('internal with a self-declared recovery_mechanism_ref -> irreversible + upper_bound (v4 s4: derives nothing)', () => {
    const facts: EffectFacts = { externality: 'internal', recoveryMechanismRef: 'snapshot://backup-2026-07-13' }
    const r = classifyV0(facts)
    assert.equal(r.realized, 'irreversible')
    assert.equal(r.label, 'upper_bound')
  })

  it('unbound / missing externality -> unresolved', () => {
    assert.equal(classifyV0({}).realized, 'unresolved')
  })
})

describe('reversibility-fold step 2 - v0 fail-closed regressions', () => {
  it('external-reversible input is irreversible + upper_bound regardless of any reversal-right or controller facts', () => {
    // In v0 the reversal-right and controller facts are RESERVED and never read
    // by the classifier, so no combination of them changes the external verdict.
    // Every one of these once fed the removed compensable branch; all are now
    // irreversible + upper_bound.
    const variants: EffectFacts[] = [
      { externality: 'external-reversible', actingPrincipal: PRINCIPAL, recoveryController: PRINCIPAL }, // no reversalRight
      { externality: 'external-reversible', actingPrincipal: PRINCIPAL, recoveryController: PRINCIPAL, reversalRight: { signer: PRINCIPAL } }, // self-attested
      { externality: 'external-reversible', actingPrincipal: PRINCIPAL, recoveryController: PRINCIPAL, reversalRight: { signer: '' } }, // empty signer
      { externality: 'external-reversible', actingPrincipal: PRINCIPAL, recoveryController: OTHER_DOMAIN, reversalRight: { signer: OTHER_DOMAIN } }, // controller != principal
      { externality: 'external-reversible', actingPrincipal: PRINCIPAL, recoveryController: PRINCIPAL, reversalRight: { signer: OTHER_DOMAIN } }, // the once-compensable config
    ]
    for (const facts of variants) {
      const r = classifyV0(facts)
      assert.equal(r.realized, 'irreversible')
      assert.equal(r.label, 'upper_bound')
    }
  })

  it('internal is irreversible + upper_bound regardless of recovery_mechanism_ref (present, null, or empty)', () => {
    for (const rmr of ['snapshot://x', null, ''] as (string | null)[]) {
      const r = classifyV0({ externality: 'internal', recoveryMechanismRef: rmr })
      assert.equal(r.realized, 'irreversible')
      assert.equal(r.label, 'upper_bound')
    }
    assert.equal(classifyV0({ externality: 'internal' }).realized, 'irreversible')
  })

  it('missing facts -> unresolved (externality absent even if other fields present)', () => {
    assert.equal(classifyV0({ actingPrincipal: PRINCIPAL, recoveryController: PRINCIPAL }).realized, 'unresolved')
  })
})

describe('reversibility-fold v0-7 - no self-attested internal-compensable path (v4 s4)', () => {
  it('a bare (self-declared) recovery_mechanism_ref does NOT yield compensable', () => {
    const r = classifyV0({ externality: 'internal', recoveryMechanismRef: 'snapshot://ledger' })
    assert.notEqual(r.realized, 'compensable')
    assert.equal(r.realized, 'irreversible')
    assert.equal(r.label, 'upper_bound')
  })

  it('NO v0 entry point produces a compensable outcome for an internal effect', () => {
    // (1) direct classifier, over every recovery-ref shape
    for (const rmr of ['snapshot://x', null, ''] as (string | null)[]) {
      assert.notEqual(classifyV0({ externality: 'internal', recoveryMechanismRef: rmr }).realized, 'compensable')
    }
    // (2) block pipeline: deriveExternality -> classify
    const out = recomputeEffect(element({ effect_scope: 'internal', recovery_mechanism_ref: 'snapshot://x' }))
    assert.equal(out.status === 'recomputed' && out.result.realized !== 'compensable', true)
    // (3) RAPV0 adapter path
    assert.notEqual(
      classifyV0({ externality: rapvExternalityToEffectFacts('internal'), recoveryMechanismRef: 'snapshot://x' }).realized,
      'compensable',
    )
  })

  it('classifyV0 never returns compensable for ANY externality bucket in v0, even with every recovery/actor fact set', () => {
    const buckets = [undefined, 'internal', 'external-reversible', 'external-irreversible'] as const
    for (const ext of buckets) {
      const r = classifyV0({
        externality: ext as EffectFacts['externality'],
        recoveryMechanismRef: 'snapshot://x',
        recoveryController: PRINCIPAL,
        actingPrincipal: PRINCIPAL,
        reversalRight: { signer: OTHER_DOMAIN },
        finalityState: 'settled',
        targetBindingVerified: true,
      })
      assert.notEqual(r.realized, 'compensable')
    }
  })
})

describe('reversibility-fold step 2 - projection ties enforcement to the classifier', () => {
  it('unbound facts classify unresolved and enforce irreversible', () => {
    const realized = classifyV0({}).realized
    assert.equal(realized, 'unresolved')
    assert.equal(enforcementFrom(realized), 'irreversible')
  })

  it('the enforcement projection preserves compensable (no over-restriction)', () => {
    // v0 produces no compensable outcome, but the projection must stay the
    // identity on compensable so a future verified-recovery class is not lifted.
    assert.equal(enforcementFrom('compensable'), 'compensable')
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
  it('internal effect with a self-declared recovery mechanism -> irreversible + upper_bound (v4 s4)', () => {
    const out = recomputeEffect(element({ effect_scope: 'internal', recovery_mechanism_ref: 'snapshot://db-2026-07-13' }))
    assert.equal(out.status, 'recomputed')
    if (out.status === 'recomputed') {
      assert.equal(out.result.realized, 'irreversible')
      assert.equal(out.result.label, 'upper_bound')
    }
  })

  it('internal effect with no recovery mechanism (key destruction) -> irreversible + upper_bound', () => {
    const out = recomputeEffect(element({ effect_scope: 'internal', recovery_mechanism_ref: null }))
    assert.equal(out.status, 'recomputed')
    if (out.status === 'recomputed') {
      assert.equal(out.result.realized, 'irreversible')
      assert.equal(out.result.label, 'upper_bound')
    }
  })

  it('external effect with no recovery (external-irreversible) -> irreversible + upper_bound (unverified)', () => {
    const out = recomputeEffect(element({ effect_scope: 'external', recovery_mechanism_ref: null }))
    assert.equal(out.status, 'recomputed')
    if (out.status === 'recomputed') {
      assert.equal(out.result.realized, 'irreversible')
      assert.equal(out.result.label, 'upper_bound')
    }
  })

  it('external effect with a self-declared recovery_mechanism_ref -> irreversible + upper_bound (v4 s4.1: recovery-ref derives nothing)', () => {
    // v0: external always derives external-irreversible. A self-declared
    // recovery_mechanism_ref is a carried raw fact and derives nothing about the
    // class, so this is identical to an external effect with no recovery ref:
    // irreversible + upper_bound, never external-reversible and never compensable.
    const out = recomputeEffect(element({
      effect_scope: 'external',
      recovery_mechanism_ref: 'refund://acme/settle',
      recovery_controller: 'urn:principal:me',
    }))
    assert.equal(out.status, 'recomputed')
    if (out.status === 'recomputed') {
      assert.equal(out.result.realized, 'irreversible')
      assert.equal(out.result.label, 'upper_bound')
    }
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

  it('RAPV0 external-reversible collapses to external-irreversible in v0 (no compensable backdoor, v4 s4/s10)', () => {
    assert.equal(rapvExternalityToEffectFacts('internal'), 'internal')
    // The legacy external-reversible taxonomy is NOT passed through as-is; it
    // maps to external-irreversible so it cannot be a backdoor into compensability.
    assert.equal(rapvExternalityToEffectFacts('external-reversible'), 'external-irreversible')
    assert.equal(rapvExternalityToEffectFacts('external-irreversible'), 'external-irreversible')
  })
})

describe('reversibility-fold step 3a - multi-effect block recomputes per element', () => {
  it('a block with three distinct effects recomputes each independently, preserving order', () => {
    const block: EffectInstantiationBlock = {
      instantiated_effects: [
        // internal effect with a self-declared recovery ref (irreversible + upper_bound in v0)
        element({ effect_id: 'eff:pay', effect_scope: 'internal', recovery_mechanism_ref: 'snapshot://ledger' }),
        // irreversible external email (external, no recovery)
        element({ effect_id: 'eff:email', effect_scope: 'external', recovery_mechanism_ref: null }),
        // internal irreversible key deletion (internal, no recovery)
        element({ effect_id: 'eff:keydel', effect_scope: 'internal', recovery_mechanism_ref: null }),
      ],
    }
    const outs = recomputeBlock(block)
    assert.equal(outs.length, 3)
    assert.equal(outs[0].status === 'recomputed' && outs[0].result.realized, 'irreversible')
    assert.equal(outs[0].status === 'recomputed' && outs[0].result.label, 'upper_bound')
    assert.equal(outs[1].status === 'recomputed' && outs[1].result.realized, 'irreversible')
    assert.equal(outs[1].status === 'recomputed' && outs[1].result.label, 'upper_bound')
    assert.equal(outs[2].status === 'recomputed' && outs[2].result.realized, 'irreversible')
    // no collapse to a single max: three separate outcomes preserved.
  })
})

// ══════════════════════════════════════
// STEP 3b - optional block on the common execution-receipt envelope
// ══════════════════════════════════════

// Build a valid minimal ExecutionEnvelope carrying no block.
function minimalEnvelope(signer: { publicKey: string; privateKey: string }) {
  return createMinimalEnvelope({
    agentDid: 'did:aps:agent',
    runId: 'run-3b',
    actionId: 'act-3b',
    scope: ['data:read'],
    revocationStatus: 'active',
    decisionHash: 'sha256:deadbeef',
    policyRef: 'floor.v1',
    evaluationMethod: 'deterministic',
    verdict: 'permit',
    evaluatedAt: new Date().toISOString(),
    evaluatorDid: 'did:aps:evaluator',
    evaluatorSignature: 'evsig',
    receiptHash: 'sha256:cafef00d',
    signerPrivateKey: signer.privateKey,
    signerPublicKey: signer.publicKey,
  })
}

const SAMPLE_BLOCK: EffectInstantiationBlock = {
  instantiated_effects: [
    {
      effect_scope: 'external',
      effect_target_ref: 'urn:target:acme',
      finality_state: 'settled',
      recovery_mechanism_ref: null,
      recovery_controller: null,
      recovery_deadline: null,
      evidence_status: 'resolved',
      classification_profile_id: REVERSIBILITY_MAPPING_V0_ID,
      classification_profile_digest: REVERSIBILITY_MAPPING_V0_DIGEST,
      action_ref: 'action_ref:sample-req',
      action_instance_id: 'action-instance:sample',
      effect_id: 'eff:sample',
      predecessor_effect_state_hash: null,
      sequence: 0,
    },
  ],
}

describe('reversibility-fold step 3b - optional effect_instantiation block on ExecutionEnvelope', () => {
  it('an existing receipt with NO block still validates (back-compat)', () => {
    const signer = generateKeyPair()
    const env = minimalEnvelope(signer)
    assert.equal(env.effect_instantiation, undefined)
    const v = verifyExecutionEnvelope(env)
    // What this case is about is the SIGNATURE over the body: a blockless
    // envelope's bytes still verify. It used to assert `valid` as well, which
    // for a minimal envelope carrying the placeholder evaluator signature
    // 'evsig' and no trust inputs at all was the fail-open the repair closed.
    // A minimal envelope carries no decision, so its evaluator signature can
    // never be established and `valid` is never true for one.
    assert.equal(v.signatureValid, true)
    assert.equal(v.valid, false)
    assert.equal(v.evaluatorAuthority, 'unresolved')
  })

  it('a receipt carrying a well-formed block validates', () => {
    const signer = generateKeyPair()
    const env = minimalEnvelope(signer)
    // Attach the block and re-sign the body (the block is part of the signed body).
    const { signature, ...body } = env
    const bodyWithBlock = { ...body, effect_instantiation: SAMPLE_BLOCK }
    const value = sign(canonicalize(bodyWithBlock), signer.privateKey)
    const envWithBlock = { ...bodyWithBlock, signature: { ...signature, value } }
    const v = verifyExecutionEnvelope(envWithBlock)
    // Same reasoning as the blockless case: the property under test is that
    // the block sits inside the signed body, which is `signatureValid`.
    assert.equal(v.signatureValid, true)
    assert.deepEqual(envWithBlock.effect_instantiation, SAMPLE_BLOCK)
  })

  it("the block is inside the signed body: adding it WITHOUT re-signing fails the signature", () => {
    const signer = generateKeyPair()
    const env = minimalEnvelope(signer)
    // Tamper: attach a block but keep the original blockless signature.
    const tampered = { ...env, effect_instantiation: SAMPLE_BLOCK }
    const v = verifyExecutionEnvelope(tampered)
    assert.equal(v.signatureValid, false)
    assert.equal(v.valid, false)
  })

  it('presence of the block does not alter any existing validation aspect', () => {
    const signer = generateKeyPair()
    const env = minimalEnvelope(signer)
    const { signature, ...body } = env
    const bodyWithBlock = { ...body, effect_instantiation: SAMPLE_BLOCK }
    const value = sign(canonicalize(bodyWithBlock), signer.privateKey)
    const envWithBlock = { ...bodyWithBlock, signature: { ...signature, value } }

    const without = verifyExecutionEnvelope(env)
    const withBlock = verifyExecutionEnvelope(envWithBlock)
    // Every existing validation aspect is identical whether or not the block is present.
    assert.equal(withBlock.capabilityActive, without.capabilityActive)
    assert.equal(withBlock.decisionFresh, without.decisionFresh)
    assert.equal(withBlock.evaluatorSignatureValid, without.evaluatorSignatureValid)
    assert.deepEqual(withBlock.errors, without.errors)
    assert.equal(withBlock.valid, without.valid)
  })
})

// ══════════════════════════════════════
// STEP 5a - two-stage lifecycle (spec section 5)
// ══════════════════════════════════════

function execReceipt(over: Partial<ExecutionStageReceipt> = {}): ExecutionStageReceipt {
  return {
    stage: 'execution',
    action_ref: 'act:xyz',
    run_id: 'run:1',
    effect_instantiation: {
      instantiated_effects: [element({ effect_id: 'eff:exec', effect_scope: 'external', recovery_mechanism_ref: null })],
    },
    evidence_status: 'pending',
    admitted_enforcement_class: 'irreversible',
    created_at: '2026-07-13T00:00:00.000Z',
    ...over,
  }
}

describe('reversibility-fold step 5a - monotonic transitions', () => {
  it('pending -> compensable is a valid monotonic transition', () => {
    const signer = generateKeyPair()
    const exec = execReceipt()
    const recon = createReconciliationReceipt(exec, {
      realized_class: 'compensable',
      evidence_status: 'resolved',
      reconciled_at: '2026-07-13T01:00:00.000Z',
      signerPrivateKey: signer.privateKey,
      signerPublicKey: signer.publicKey,
    })
    const check = validateTransition(exec, recon)
    assert.equal(check.ok, true, check.errors.join('; '))
  })

  it('pending -> irreversible is a valid monotonic transition', () => {
    const signer = generateKeyPair()
    const exec = execReceipt()
    const recon = createReconciliationReceipt(exec, {
      realized_class: 'irreversible',
      evidence_status: 'resolved',
      reconciled_at: '2026-07-13T01:00:00.000Z',
      signerPrivateKey: signer.privateKey,
      signerPublicKey: signer.publicKey,
    })
    assert.equal(validateTransition(exec, recon).ok, true)
  })

  it('an arbitrary replacement (tentative or unresolved) is rejected', () => {
    const signer = generateKeyPair()
    const exec = execReceipt()
    for (const bad of ['tentative', 'unresolved'] as const) {
      const recon = createReconciliationReceipt(exec, {
        realized_class: bad,
        evidence_status: 'resolved',
        reconciled_at: '2026-07-13T01:00:00.000Z',
        signerPrivateKey: signer.privateKey,
        signerPublicKey: signer.publicKey,
      })
      const check = validateTransition(exec, recon)
      assert.equal(check.ok, false)
      assert.ok(check.errors.some((e) => e.includes('non-monotonic')))
    }
  })
})

describe('reversibility-fold step 5a - hash-link integrity and no-rewrite', () => {
  it('a tampered hash-link fails', () => {
    const signer = generateKeyPair()
    const exec = execReceipt()
    const recon = createReconciliationReceipt(exec, {
      realized_class: 'irreversible',
      evidence_status: 'resolved',
      reconciled_at: '2026-07-13T01:00:00.000Z',
      signerPrivateKey: signer.privateKey,
      signerPublicKey: signer.publicKey,
    })
    const tampered = { ...recon, execution_receipt_hash: 'sha256:0000' }
    const check = validateTransition(exec, tampered)
    assert.equal(check.ok, false)
    assert.ok(check.errors.some((e) => e.includes('hash-link mismatch')))
  })

  it('rewriting the execution receipt after reconciliation breaks the link (rewrite rejected)', () => {
    const signer = generateKeyPair()
    const exec = execReceipt({ admitted_enforcement_class: 'irreversible' })
    const recon = createReconciliationReceipt(exec, {
      realized_class: 'compensable',
      evidence_status: 'resolved',
      reconciled_at: '2026-07-13T01:00:00.000Z',
      signerPrivateKey: signer.privateKey,
      signerPublicKey: signer.publicKey,
    })
    // Attacker tries to rewrite the execution receipt after the fact.
    const rewritten = { ...exec, admitted_enforcement_class: 'compensable' as const }
    const check = validateTransition(rewritten, recon)
    assert.equal(check.ok, false)
    assert.ok(check.errors.some((e) => e.includes('hash-link mismatch')))
  })

  it('a reconciliation with a tampered realized_class fails the signature', () => {
    const signer = generateKeyPair()
    const exec = execReceipt()
    const recon = createReconciliationReceipt(exec, {
      realized_class: 'compensable',
      evidence_status: 'resolved',
      reconciled_at: '2026-07-13T01:00:00.000Z',
      signerPrivateKey: signer.privateKey,
      signerPublicKey: signer.publicKey,
    })
    const forged = { ...recon, realized_class: 'irreversible' as const }
    const check = validateTransition(exec, forged)
    assert.equal(check.ok, false)
    assert.ok(check.errors.some((e) => e.includes('signature invalid')))
  })
})

describe('reversibility-fold step 5a - no retroactive enforcement', () => {
  it('the reconciliation does not change the enforcement class the execution receipt carried', () => {
    const signer = generateKeyPair()
    // Admission gated at irreversible (fail-closed during pending).
    const exec = execReceipt({ admitted_enforcement_class: 'irreversible' })
    // Audit later refines the realized truth down to compensable.
    const recon = createReconciliationReceipt(exec, {
      realized_class: 'compensable',
      evidence_status: 'resolved',
      reconciled_at: '2026-07-13T01:00:00.000Z',
      signerPrivateKey: signer.privateKey,
      signerPublicKey: signer.publicKey,
    })
    assert.equal(validateTransition(exec, recon).ok, true)
    // The enforcement binding that gated the action is unchanged: you cannot
    // un-admit a settled action. admittedEnforcementClass reads only the exec.
    assert.equal(admittedEnforcementClass(exec), 'irreversible')
    assert.equal(exec.admitted_enforcement_class, 'irreversible')
    // The reconciliation's realized class is audit-only and differs.
    assert.equal(recon.realized_class, 'compensable')
    assert.notEqual(admittedEnforcementClass(exec), recon.realized_class)
  })

  it('hashExecutionReceipt is stable for identical receipts and changes on any edit', () => {
    const a = execReceipt()
    const b = execReceipt()
    assert.equal(hashExecutionReceipt(a), hashExecutionReceipt(b))
    assert.notEqual(hashExecutionReceipt(a), hashExecutionReceipt(execReceipt({ admitted_enforcement_class: 'compensable' })))
  })
})

// ══════════════════════════════════════
// STEP v0-2 - effect identity and lineage (v4 section 2)
// ══════════════════════════════════════

// Build a valid lineage of `count` states for one effect_id: sequence 0..count-1,
// first predecessor null, each later state references the prior state's hash.
function lineage(effectId: string, count: number): EffectInstantiationElement[] {
  const states: EffectInstantiationElement[] = []
  let prev: string | null = null
  for (let i = 0; i < count; i++) {
    const el = element({ effect_id: effectId, sequence: i, predecessor_effect_state_hash: prev })
    states.push(el)
    prev = hashEffectState(el)
  }
  return states
}

function shuffle<T>(xs: T[]): T[] {
  // Deterministic reversal is enough to show the result does not depend on order.
  return [...xs].reverse()
}

describe('reversibility-fold v0-2 - lineage identity fields', () => {
  it('the element carries effect_id, predecessor_effect_state_hash, and sequence', () => {
    const el = element()
    assert.equal(typeof el.effect_id, 'string')
    assert.equal(el.predecessor_effect_state_hash, null)
    assert.equal(el.sequence, 0)
  })

  it('a valid single-state lineage (null predecessor) is ok', () => {
    const r = validateEffectLineage({ instantiated_effects: [element()] })
    assert.equal(r.status, 'ok')
    assert.equal(r.duplicate_count, 0)
  })

  it('a valid multi-state lineage (chained) is ok', () => {
    const r = validateEffectLineage({ instantiated_effects: lineage('eff:A', 3) })
    assert.equal(r.status, 'ok')
  })

  it('multiple distinct effects, each a valid lineage, are ok together', () => {
    const block: EffectInstantiationBlock = {
      instantiated_effects: [...lineage('eff:A', 2), ...lineage('eff:B', 3), element({ effect_id: 'eff:C' })],
    }
    assert.equal(validateEffectLineage(block).status, 'ok')
  })
})

// A root and two distinct successors of that root (a fork), plus helpers for the
// other malformed shapes.
function forkBlock(): EffectInstantiationBlock {
  const root = element({ effect_id: 'eff:F', sequence: 0, predecessor_effect_state_hash: null })
  const h = hashEffectState(root)
  const a = element({ effect_id: 'eff:F', sequence: 1, predecessor_effect_state_hash: h, effect_target_ref: 'urn:a' })
  const b = element({ effect_id: 'eff:F', sequence: 1, predecessor_effect_state_hash: h, effect_target_ref: 'urn:b' })
  return { instantiated_effects: [root, a, b] }
}

describe('reversibility-fold v0-4b - typed lineage validation (v4 s2)', () => {
  it('a fork (one predecessor, two distinct successors) -> lineage_conflicted', () => {
    assert.equal(validateEffectLineage(forkBlock()).status, 'lineage_conflicted')
  })

  it('a fork whose branches sit at different sequences is still lineage_conflicted', () => {
    // root -> A@1 and root -> B@2 both reference the root: one predecessor, two
    // distinct successors, even though they do not share a sequence.
    const root = element({ effect_id: 'eff:FD', sequence: 0, predecessor_effect_state_hash: null })
    const h = hashEffectState(root)
    const a = element({ effect_id: 'eff:FD', sequence: 1, predecessor_effect_state_hash: h, effect_target_ref: 'urn:a' })
    const b = element({ effect_id: 'eff:FD', sequence: 2, predecessor_effect_state_hash: h, effect_target_ref: 'urn:b' })
    assert.equal(validateEffectLineage({ instantiated_effects: [root, a, b] }).status, 'lineage_conflicted')
  })

  it('a gap in sequences -> lineage_incomplete', () => {
    const root = element({ effect_id: 'eff:G', sequence: 0, predecessor_effect_state_hash: null })
    const s2 = element({ effect_id: 'eff:G', sequence: 2, predecessor_effect_state_hash: 'sha256:missing' })
    assert.equal(validateEffectLineage({ instantiated_effects: [root, s2] }).status, 'lineage_incomplete')
  })

  it('a non-zero origin (root not at sequence 0) -> lineage_incomplete', () => {
    const s = element({ effect_id: 'eff:N', sequence: 1, predecessor_effect_state_hash: null })
    assert.equal(validateEffectLineage({ instantiated_effects: [s] }).status, 'lineage_incomplete')
  })

  it('two distinct roots sharing an effect_id -> equivocation (multiple-roots)', () => {
    const r1 = element({ effect_id: 'eff:R', sequence: 0, predecessor_effect_state_hash: null, effect_target_ref: 'urn:1' })
    const r2 = element({ effect_id: 'eff:R', sequence: 0, predecessor_effect_state_hash: null, effect_target_ref: 'urn:2' })
    assert.equal(validateEffectLineage({ instantiated_effects: [r1, r2] }).status, 'equivocation')
  })

  it('same (effect_id, sequence) with different hashes and no shared predecessor -> equivocation', () => {
    const root = element({ effect_id: 'eff:E', sequence: 0, predecessor_effect_state_hash: null })
    const a = element({ effect_id: 'eff:E', sequence: 1, predecessor_effect_state_hash: hashEffectState(root), effect_target_ref: 'urn:a' })
    const b = element({ effect_id: 'eff:E', sequence: 1, predecessor_effect_state_hash: 'sha256:phantom', effect_target_ref: 'urn:b' })
    assert.equal(validateEffectLineage({ instantiated_effects: [root, a, b] }).status, 'equivocation')
  })

  it('a broken chain link (wrong predecessor hash at n>0) -> invalid_state', () => {
    const root = element({ effect_id: 'eff:I', sequence: 0, predecessor_effect_state_hash: null })
    const s1 = element({ effect_id: 'eff:I', sequence: 1, predecessor_effect_state_hash: 'sha256:wrong' })
    assert.equal(validateEffectLineage({ instantiated_effects: [root, s1] }).status, 'invalid_state')
  })

  it('an exact-duplicate state is deduped with duplicate_count > 0 and the lineage stays ok', () => {
    const chain = lineage('eff:D', 2)
    const r = validateEffectLineage({ instantiated_effects: [...chain, chain[1]] })
    assert.equal(r.status, 'ok')
    assert.equal(r.duplicate_count, 1)
  })
})

describe('reversibility-fold v0-4b - reorder invariance and latest-state', () => {
  it('reordering instantiated_effects does not change the typed result', () => {
    const items = [...lineage('eff:A', 3), ...lineage('eff:B', 2)]
    const forward = validateEffectLineage({ instantiated_effects: items })
    const reversed = validateEffectLineage({ instantiated_effects: shuffle(items) })
    assert.deepEqual(forward, reversed)
    assert.equal(forward.status, 'ok')
  })

  it('reordering does not change per-effect recompute results', () => {
    const items = [
      element({ effect_id: 'eff:A', effect_scope: 'internal', recovery_mechanism_ref: 'snapshot://x' }),
      element({ effect_id: 'eff:B', effect_scope: 'external', recovery_mechanism_ref: null }),
      element({ effect_id: 'eff:C', effect_scope: 'internal', recovery_mechanism_ref: null }),
    ]
    const byId = (block: EffectInstantiationBlock) => {
      const m: Record<string, string> = {}
      for (const el of block.instantiated_effects) {
        const out = recomputeEffect(el)
        m[el.effect_id] = out.status === 'recomputed' ? out.result.realized : out.status
      }
      return m
    }
    assert.deepEqual(byId({ instantiated_effects: items }), byId({ instantiated_effects: shuffle(items) }))
  })

  it('adding an unrelated effect does not change the result for existing effects', () => {
    const base = lineage('eff:A', 2)
    const withExtra = [...base, element({ effect_id: 'eff:Z', effect_scope: 'internal', recovery_mechanism_ref: 'snapshot://z' })]
    assert.equal(validateEffectLineage({ instantiated_effects: base }).status, 'ok')
    assert.equal(validateEffectLineage({ instantiated_effects: withExtra }).status, 'ok')
    const aOut = recomputeEffect(base[base.length - 1])
    const aOut2 = recomputeEffect(withExtra[1])
    assert.deepEqual(aOut, aOut2)
  })

  it('latestValidEffectStates returns the unambiguous latest for an ok lineage, order-invariant', () => {
    const chain = lineage('eff:L', 3)
    const latest = latestValidEffectStates({ instantiated_effects: chain })
    assert.ok(latest)
    assert.equal(latest.get('eff:L')?.sequence, 2)
    const latestShuffled = latestValidEffectStates({ instantiated_effects: shuffle(chain) })
    assert.ok(latestShuffled)
    assert.equal(latestShuffled.get('eff:L')?.sequence, 2)
  })

  it('latestValidEffectStates returns nothing for a non-ok lineage', () => {
    assert.equal(latestValidEffectStates(forkBlock()), undefined)
    const s = element({ effect_id: 'eff:N', sequence: 1, predecessor_effect_state_hash: null })
    assert.equal(latestValidEffectStates({ instantiated_effects: [s] }), undefined)
  })

  it('the deterministic effect_id helper is stable across retries and binds action_ref + action_instance_id', () => {
    const id1 = deriveEffectId('action_ref:r', 'action-instance:1', 'local-a')
    const id2 = deriveEffectId('action_ref:r', 'action-instance:1', 'local-a')
    assert.equal(id1, id2) // stable across retries (an id, not a nonce)
    assert.notEqual(id1, deriveEffectId('action_ref:r', 'action-instance:2', 'local-a'))
    assert.notEqual(id1, deriveEffectId('action_ref:r', 'action-instance:1', 'local-b'))
  })
})

describe('reversibility-fold v0-2 - hashEffectState', () => {
  it('is stable for identical states and changes on any edit', () => {
    const a = element({ effect_id: 'eff:A', sequence: 0 })
    const b = element({ effect_id: 'eff:A', sequence: 0 })
    assert.equal(hashEffectState(a), hashEffectState(b))
    assert.notEqual(hashEffectState(a), hashEffectState({ ...a, sequence: 1 }))
  })
})

// ══════════════════════════════════════
// v0-3 - NO external-compensable path exists in v0 (v4 s4/s10)
// ══════════════════════════════════════

describe('reversibility-fold v0-3 - no entry point yields external + compensable', () => {
  it('the block pipeline (deriveExternality -> classify) never yields compensable for an external effect', () => {
    // Try to trick the derivation with a self-declared recovery mechanism and
    // controller; the block pipeline still yields irreversible.
    const outs = [
      recomputeEffect(element({ effect_scope: 'external', recovery_mechanism_ref: 'refund://acme', recovery_controller: 'urn:principal:me' })),
      recomputeEffect(element({ effect_scope: 'external', recovery_mechanism_ref: null })),
      recomputeEffect(element({ effect_scope: 'external', recovery_mechanism_ref: 'refund://acme', finality_state: 'settled' })),
    ]
    for (const out of outs) {
      assert.equal(out.status, 'recomputed')
      if (out.status === 'recomputed') assert.equal(out.result.realized, 'irreversible')
    }
  })

  it('the RAPV0 adapter path (rapvExternalityToEffectFacts -> classify) never yields compensable', () => {
    for (const rapv of ['external-reversible', 'external-irreversible'] as const) {
      const realized = classifyV0({
        externality: rapvExternalityToEffectFacts(rapv),
        actingPrincipal: PRINCIPAL,
        recoveryController: PRINCIPAL,
        reversalRight: { signer: OTHER_DOMAIN },
        recoveryMechanismRef: 'refund://acme',
      }).realized
      assert.equal(realized, 'irreversible')
    }
  })

  it('classifyV0 called directly with external-reversible plus a hand-built reversal-right and principal -> irreversible', () => {
    // The exact configuration that once produced compensable.
    const realized = classifyV0({
      externality: 'external-reversible',
      actingPrincipal: PRINCIPAL,
      recoveryController: PRINCIPAL,
      reversalRight: { signer: OTHER_DOMAIN },
    }).realized
    assert.equal(realized, 'irreversible')
    assert.notEqual(realized, 'compensable')
  })

  it('internal is ALSO not compensable in v0 (v0-7 removed the self-attested internal path)', () => {
    assert.notEqual(classifyV0({ externality: 'internal', recoveryMechanismRef: 'snapshot://x' }).realized, 'compensable')
    const out = recomputeEffect(element({ effect_scope: 'internal', recovery_mechanism_ref: 'snapshot://x' }))
    assert.equal(out.status === 'recomputed' && out.result.realized !== 'compensable', true)
  })

  it('NO externality bucket yields compensable in v0, with maximal reversibility facts set', () => {
    // Sweep every EffectExternality bucket with every recovery/actor fact set;
    // compensable appears nowhere in v0.
    const buckets = ['internal', 'external-reversible', 'external-irreversible'] as const
    for (const b of buckets) {
      const realized = classifyV0({
        externality: b,
        actingPrincipal: PRINCIPAL,
        recoveryController: PRINCIPAL,
        reversalRight: { signer: OTHER_DOMAIN },
        recoveryMechanismRef: 'snapshot://x',
        finalityState: 'settled',
        targetBindingVerified: true,
      }).realized
      assert.notEqual(realized, 'compensable')
    }
  })
})

// ══════════════════════════════════════
// v0-5b - immutable content-addressed profile registry + digest + reason codes
// ══════════════════════════════════════

// The v0 profile digest, pinned. Reproduced byte-for-byte by TS/Python/Go (see
// the separate reversibility-profile-parity test). Any change to an authoritative
// profile field changes this value and must be updated deliberately.
const GOLDEN_V0_DIGEST = 'sha256:12f270844b11c828eb42087c443e8d0272f60551cb098067028113e3b91f1d6b'

describe('reversibility-fold v0-5b - profile content digest', () => {
  it('the v0 digest is stable and equals the pinned golden value', () => {
    assert.equal(REVERSIBILITY_MAPPING_V0_DIGEST, GOLDEN_V0_DIGEST)
    assert.equal(profileContentDigest(REVERSIBILITY_PROFILE_V0_CONTENT), GOLDEN_V0_DIGEST)
  })

  it('the domain-separated construction differs from a bare SHA-256 of the JCS', () => {
    const bare = 'sha256:' + createHash('sha256').update(canonicalize(REVERSIBILITY_PROFILE_V0_CONTENT)).digest('hex')
    assert.notEqual(REVERSIBILITY_MAPPING_V0_DIGEST, bare)
  })

  it('changing any authoritative profile field changes the digest', () => {
    assert.notEqual(profileContentDigest({ ...REVERSIBILITY_PROFILE_V0_CONTENT, external_compensable: true }), REVERSIBILITY_MAPPING_V0_DIGEST)
    assert.notEqual(profileContentDigest({ ...REVERSIBILITY_PROFILE_V0_CONTENT, schema_version: 'v1' }), REVERSIBILITY_MAPPING_V0_DIGEST)
    assert.notEqual(profileContentDigest({ ...REVERSIBILITY_PROFILE_V0_CONTENT, reason_codes: [] }), REVERSIBILITY_MAPPING_V0_DIGEST)
  })

  it('excluded diagnostic metadata is NOT part of the digest', () => {
    // The registry entry carries display_name/description; they are not in the
    // content, so the digest is over content only and a metadata change cannot
    // move it.
    const reg = getRegisteredProfile(REVERSIBILITY_MAPPING_V0_ID)
    assert.ok(reg)
    assert.equal(reg.digest, profileContentDigest(reg.content))
    // The content object itself carries no display_name/description.
    assert.equal((REVERSIBILITY_PROFILE_V0_CONTENT as Record<string, unknown>).display_name, undefined)
    assert.equal((REVERSIBILITY_PROFILE_V0_CONTENT as Record<string, unknown>).description, undefined)
  })
})

describe('reversibility-fold v0-5b - immutable registry and binding failures', () => {
  it('the registry resolves the v0 profile with its content and digest', () => {
    const reg = getRegisteredProfile(REVERSIBILITY_MAPPING_V0_ID)
    assert.ok(reg)
    assert.equal(reg.profile, reversibilityMappingV0)
    assert.equal(reg.digest, REVERSIBILITY_MAPPING_V0_DIGEST)
    assert.equal(getProfileDigest(REVERSIBILITY_MAPPING_V0_ID), REVERSIBILITY_MAPPING_V0_DIGEST)
  })

  it('verifyProfileBinding: an unknown id fails unknown_profile (distinct from mismatch)', () => {
    const r = verifyProfileBinding('reversibility-mapping-vX', REVERSIBILITY_MAPPING_V0_DIGEST)
    assert.equal(r.ok, false)
    assert.equal(r.ok === false && r.reason, 'unknown_profile')
  })

  it('verifyProfileBinding: a known id with the wrong digest fails digest_mismatch (distinct from unknown)', () => {
    const r = verifyProfileBinding(REVERSIBILITY_MAPPING_V0_ID, 'sha256:0000')
    assert.equal(r.ok, false)
    if (r.ok === false && r.reason === 'digest_mismatch') {
      assert.equal(r.declaredDigest, 'sha256:0000')
      assert.equal(r.expectedDigest, REVERSIBILITY_MAPPING_V0_DIGEST)
    } else {
      assert.fail('expected digest_mismatch')
    }
  })

  it('verifyProfileBinding: matching id + digest passes', () => {
    const r = verifyProfileBinding(REVERSIBILITY_MAPPING_V0_ID, REVERSIBILITY_MAPPING_V0_DIGEST)
    assert.equal(r.ok, true)
  })

  it('recomputeEffect: an element whose declared digest is wrong fails profile_digest_mismatch (distinct from unknown_profile)', () => {
    const badDigest = recomputeEffect(element({ classification_profile_digest: 'sha256:deadbeef' }))
    assert.equal(badDigest.status, 'profile_digest_mismatch')
    if (badDigest.status === 'profile_digest_mismatch') {
      assert.equal(badDigest.declaredDigest, 'sha256:deadbeef')
      assert.equal(badDigest.expectedDigest, REVERSIBILITY_MAPPING_V0_DIGEST)
    }
    const badId = recomputeEffect(element({ classification_profile_id: 'no-such-profile' }))
    assert.equal(badId.status, 'unknown_profile')
  })

  it('verifyAssertedClass: a wrong digest surfaces profile_digest_mismatch', () => {
    const check = verifyAssertedClass(element({ classification_profile_digest: 'sha256:deadbeef', asserted_realized_class: 'irreversible' }))
    assert.equal(check.ok === false && check.reason, 'profile_digest_mismatch')
  })
})

describe('reversibility-fold v0-5b - deterministic reason codes', () => {
  it('each mapping branch emits its reason code', () => {
    assert.equal(classifyV0({}).reason, 'RM_V0_UNBOUND')
    assert.equal(classifyV0({ externality: 'external-irreversible', finalityState: 'pending' }).reason, 'RM_V0_EXTERNAL_UPPER_BOUND')
    assert.equal(classifyV0({ externality: 'external-irreversible', finalityState: 'settled', targetBindingVerified: true }).reason, 'RM_V0_EXTERNAL_DEFINITIVE')
    assert.equal(classifyV0({ externality: 'external-reversible' }).reason, 'RM_V0_EXTERNAL_UPPER_BOUND')
    assert.equal(classifyV0({ externality: 'internal', finalityState: 'pending' }).reason, 'RM_V0_INTERNAL_UPPER_BOUND')
    assert.equal(classifyV0({ externality: 'internal', finalityState: 'settled', targetBindingVerified: true }).reason, 'RM_V0_INTERNAL_DEFINITIVE')
  })

  it('the profile content lists exactly the reason codes the classifier can emit', () => {
    const emitted = new Set([
      classifyV0({}).reason,
      classifyV0({ externality: 'external-irreversible', finalityState: 'pending' }).reason,
      classifyV0({ externality: 'external-irreversible', finalityState: 'settled', targetBindingVerified: true }).reason,
      classifyV0({ externality: 'internal', finalityState: 'pending' }).reason,
      classifyV0({ externality: 'internal', finalityState: 'settled', targetBindingVerified: true }).reason,
    ])
    const declared = new Set((REVERSIBILITY_PROFILE_V0_CONTENT as { reason_codes: string[] }).reason_codes)
    assert.deepEqual([...emitted].sort(), [...declared].sort())
  })
})

// ══════════════════════════════════════
// v0-4a - domain-separated effect-state hash over the signed preimage (v4 s2)
// ══════════════════════════════════════

describe('reversibility-fold v0-4a - effect-state hash hardening', () => {
  it('changing ANY signed effect-state field changes the hash', () => {
    const base = element({ effect_id: 'eff:h', sequence: 0 })
    const h0 = hashEffectState(base)
    const mutations: Partial<EffectInstantiationElement>[] = [
      { effect_scope: 'internal' },
      { effect_target_ref: 'urn:other' },
      { finality_state: 'settled' },
      { recovery_mechanism_ref: 'refund://x' },
      { recovery_controller: 'urn:ctrl' },
      { recovery_deadline: '2026-12-31T00:00:00Z' },
      { evidence_status: 'pending' },
      { classification_profile_id: 'reversibility-mapping-vX' },
      { classification_profile_digest: 'sha256:other' },
      { action_ref: 'action_ref:other' },
      { action_instance_id: 'action-instance:other' },
      { effect_id: 'eff:h2' },
      { sequence: 1 },
      { predecessor_effect_state_hash: 'sha256:prev' },
    ]
    for (const m of mutations) {
      assert.notEqual(hashEffectState({ ...base, ...m }), h0, `mutation did not change the hash: ${JSON.stringify(m)}`)
    }
  })

  it('changing the asserted class changes the state hash but NOT the recomputed classification', () => {
    const withCache = element({ effect_id: 'eff:ac', asserted_realized_class: 'irreversible' })
    const other = { ...withCache, asserted_realized_class: 'compensable' as const }
    assert.notEqual(hashEffectState(withCache), hashEffectState(other))
    // The recompute ignores the asserted cache: same facts, same realized class.
    const a = recomputeEffect(withCache)
    const b = recomputeEffect(other)
    assert.equal(a.status, 'recomputed')
    assert.equal(b.status, 'recomputed')
    if (a.status === 'recomputed' && b.status === 'recomputed') {
      assert.equal(a.result.realized, b.result.realized)
      assert.equal(a.result.reason, b.result.reason)
    }
  })

  it('a computed verification output on the element object does NOT change the state hash', () => {
    const base = element({ effect_id: 'eff:cv' })
    const h0 = hashEffectState(base)
    // Extra computed keys (a classification result) are not in the allowlist, so
    // the preimage builder ignores them.
    const decorated = { ...base, realized: 'irreversible', enforcement: 'irreversible', reason: 'RM_V0_INTERNAL_UPPER_BOUND' } as unknown as EffectInstantiationElement
    assert.equal(hashEffectState(decorated), h0)
    // And the preimage carries no computed-output keys.
    const p = effectStatePreimage(base)
    for (const k of ['realized', 'enforcement', 'label', 'reason']) {
      assert.equal(k in p, false, `preimage must not contain computed output ${k}`)
    }
  })

  it('the domain-separated construction differs from a bare SHA-256 of the JCS preimage', () => {
    const el = element({ effect_id: 'eff:ds' })
    const bare = 'sha256:' + createHash('sha256').update(canonicalize(effectStatePreimage(el))).digest('hex')
    assert.notEqual(hashEffectState(el), bare)
  })

  it('the preimage is null-free even when nullable fields are null', () => {
    const el = element({ effect_id: 'eff:nf', recovery_mechanism_ref: null, recovery_controller: null, recovery_deadline: null, predecessor_effect_state_hash: null })
    const p = effectStatePreimage(el)
    for (const [, v] of Object.entries(p)) assert.notEqual(v, null)
    assert.equal('recovery_mechanism_ref' in p, false)
    assert.equal('predecessor_effect_state_hash' in p, false)
  })
})
