// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Cognitive Attestation — envelope/canonicalization/signing tests

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync as fsRead } from 'node:fs'
import {
  buildAttestation,
  canonicalizeAttestation,
  signCognitiveAttestation as signAttestation,
  cognitiveAttestationDigest,
  sortFeatureActivations,
  validateAttestationShape,
  generateKeyPair,
} from '../../../src/index.js'
import type {
  BuildAttestationInput,
  CognitiveAttestation,
  FeatureActivation,
} from '../../../src/index.js'

function sha256(s: string): string {
  return createHash('sha256').update(s).digest('hex')
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) out[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  return out
}

function baseInput(overrides: Partial<BuildAttestationInput> = {}): BuildAttestationInput {
  return {
    model_id: 'meta-llama/Llama-3.1-8B-Instruct',
    model_version_hash: sha256('model-weights-v1'),
    tokenizer_version_hash: sha256('tokenizer-v1'),
    inference_provider: null,
    hardware_family: 'apple-silicon/m-series/m3-max',
    precision: 'fp32',
    inference_engine: 'pytorch@2.4',
    deterministic_mode: true,
    dictionary_id: 'neuronpedia/llama3-8b/l19-res-32k',
    dictionary_version_hash: sha256('sae-weights'),
    training_corpus_hash: null,
    layer_index: 19,
    attachment_point: 'residual_stream',
    sae_type: 'topk',
    absolute_sequence_hash: sha256('seq'),
    prior_state_hash: null,
    start_token_index: 0,
    end_token_index: 47,
    token_count: 47,
    feature_activations: [
      { feature_id: 2871, feature_label: 'x', activation_statistic: 'max', activation_value: 0.72, tokens_active: 12 },
    ],
    aggregation_policy: {
      top_k: 32,
      threshold: null,
      attestation_epsilon: 0.5,
      feature_allowlist_hash: null,
      completeness_claim: 'top_k_only',
      tiebreaker_rule: 'lowest_feature_id',
      required_signer_roles: ['agent'],
    },
    timestamp: '2026-04-18T20:00:00Z',
    ...overrides,
  }
}

describe('buildAttestation', () => {
  it('produces a shape-valid envelope once signed', () => {
    const kp = generateKeyPair()
    const att = buildAttestation(baseInput())
    const signed = signAttestation(att, hexToBytes(kp.privateKey), 'did:aps:test', 'agent')
    const r = validateAttestationShape(signed)
    assert.equal(r.ok, true, `shape errors: ${r.errors.join(' | ')}`)
  })

  it('rejects unsigned envelope at shape-check (signatures array must be non-empty)', () => {
    const att = buildAttestation(baseInput())
    const r = validateAttestationShape(att)
    assert.equal(r.ok, false)
    assert.ok(r.errors.some((e) => e.startsWith('signatures:')))
  })

  it('sorts feature_activations by (feature_id, activation_statistic)', () => {
    const unsorted: FeatureActivation[] = [
      { feature_id: 42, feature_label: null, activation_statistic: 'mean', activation_value: 0.1, tokens_active: 1 },
      { feature_id: 7, feature_label: null, activation_statistic: 'max', activation_value: 0.2, tokens_active: 2 },
      { feature_id: 42, feature_label: null, activation_statistic: 'max', activation_value: 0.3, tokens_active: 3 },
    ]
    const att = buildAttestation(baseInput({ feature_activations: unsorted }))
    assert.deepEqual(
      att.feature_activations.map((f) => [f.feature_id, f.activation_statistic]),
      [[7, 'max'], [42, 'max'], [42, 'mean']],
    )
  })

  it('sortFeatureActivations is idempotent on already-sorted input', () => {
    const sorted: FeatureActivation[] = [
      { feature_id: 1, feature_label: null, activation_statistic: 'max', activation_value: 0.1, tokens_active: 1 },
      { feature_id: 2, feature_label: null, activation_statistic: 'max', activation_value: 0.2, tokens_active: 2 },
    ]
    assert.deepEqual(sortFeatureActivations(sorted), sorted)
  })
})

describe('canonicalizeAttestation', () => {
  it('is deterministic across unsorted vs sorted feature_activations with identical contents', () => {
    const feats: FeatureActivation[] = [
      { feature_id: 42, feature_label: 'x', activation_statistic: 'max', activation_value: 0.3, tokens_active: 3 },
      { feature_id: 7, feature_label: 'y', activation_statistic: 'max', activation_value: 0.2, tokens_active: 2 },
      { feature_id: 42, feature_label: 'x', activation_statistic: 'mean', activation_value: 0.1, tokens_active: 1 },
    ]
    const a = buildAttestation(baseInput({ feature_activations: feats }))
    const b = buildAttestation(baseInput({ feature_activations: feats.slice().reverse() }))
    const ca = new TextDecoder().decode(canonicalizeAttestation(a))
    const cb = new TextDecoder().decode(canonicalizeAttestation(b))
    assert.equal(ca, cb)
  })

  it('elides signatures during canonicalization', () => {
    const kp = generateKeyPair()
    const att = buildAttestation(baseInput())
    const signed = signAttestation(att, hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    const cUnsigned = new TextDecoder().decode(canonicalizeAttestation(att))
    const cSigned = new TextDecoder().decode(canonicalizeAttestation(signed))
    assert.equal(cUnsigned, cSigned, 'canonical bytes must be identical with or without signatures present')
  })

  it('preserves null fields per RFC 8785 JCS', () => {
    // inference_provider and prior_state_hash are null in baseInput
    const att = buildAttestation(baseInput())
    const c = new TextDecoder().decode(canonicalizeAttestation(att))
    assert.ok(c.includes('"inference_provider":null'), 'null must be preserved (not stripped) for cross-language parity')
    assert.ok(c.includes('"prior_state_hash":null'))
  })
})

describe('signAttestation', () => {
  it('never mutates input', () => {
    const kp = generateKeyPair()
    const att = buildAttestation(baseInput())
    const before = JSON.stringify(att)
    signAttestation(att, hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    assert.equal(JSON.stringify(att), before)
    assert.equal(att.signatures.length, 0)
  })

  it('produces byte-identical canonical input regardless of existing signature set', () => {
    const a = generateKeyPair()
    const b = generateKeyPair()
    const att = buildAttestation(baseInput())
    const s1 = signAttestation(att, hexToBytes(a.privateKey), 'did:aps:a', 'agent')
    const s2 = signAttestation(s1, hexToBytes(b.privateKey), 'did:aps:b', 'provider')
    const c0 = new TextDecoder().decode(canonicalizeAttestation(att))
    const c1 = new TextDecoder().decode(canonicalizeAttestation(s1))
    const c2 = new TextDecoder().decode(canonicalizeAttestation(s2))
    assert.equal(c0, c1)
    assert.equal(c0, c2)
  })

  it('rejects non-32-byte private keys', () => {
    const att = buildAttestation(baseInput())
    assert.throws(
      () => signAttestation(att, new Uint8Array(16), 'did:aps:a', 'agent'),
      /32-byte/,
    )
  })

  it('rejects empty signer DID', () => {
    const kp = generateKeyPair()
    const att = buildAttestation(baseInput())
    assert.throws(
      () => signAttestation(att, hexToBytes(kp.privateKey), '', 'agent'),
      /signerDid/,
    )
  })
})

describe('cognitiveAttestationDigest', () => {
  it('is deterministic for the same signed envelope', () => {
    const kp = generateKeyPair()
    const att = buildAttestation(baseInput())
    const signed = signAttestation(att, hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    const d1 = cognitiveAttestationDigest(signed)
    const d2 = cognitiveAttestationDigest(signed)
    assert.equal(d1, d2)
    assert.match(d1, /^[0-9a-f]{64}$/)
  })

  it('changes when any field is tampered', () => {
    const kp = generateKeyPair()
    const att = buildAttestation(baseInput())
    const signed = signAttestation(att, hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    const d1 = cognitiveAttestationDigest(signed)
    const tampered: CognitiveAttestation = {
      ...signed,
      feature_activations: signed.feature_activations.map((f) => ({ ...f, activation_value: f.activation_value + 0.01 })),
    }
    const d2 = cognitiveAttestationDigest(tampered)
    assert.notEqual(d1, d2)
  })
})

describe('validateAttestationShape — paper example', () => {
  it('accepts the canonical valid_envelope.json example from the paper', () => {
    // Source: papers/paper-4/poc/schema/examples/valid_envelope.json
    const examplePath = '/Users/tima/aeoess_web/papers/paper-4/poc/schema/examples/valid_envelope.json'
    const raw = fsRead(examplePath, 'utf-8')
    const parsed = JSON.parse(raw)
    const r = validateAttestationShape(parsed)
    assert.equal(r.ok, true, `paper example should parse cleanly: ${r.errors.join(' | ')}`)
  })

  it('flags missing required fields', () => {
    const r = validateAttestationShape({})
    assert.equal(r.ok, false)
    assert.ok(r.errors.length > 0)
  })

  it('flags bad precision enum', () => {
    const kp = generateKeyPair()
    const att = buildAttestation(baseInput())
    const signed = signAttestation(att, hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    const bad = { ...signed, model_ref: { ...signed.model_ref, execution_environment: { ...signed.model_ref.execution_environment, precision: 'fp4' as any } } }
    const r = validateAttestationShape(bad)
    assert.equal(r.ok, false)
    assert.ok(r.errors.some((e) => e.includes('precision')))
  })

  it('flags missing aggregation_policy.attestation_epsilon (Python-reference bug)', () => {
    const kp = generateKeyPair()
    const att = buildAttestation(baseInput())
    const signed = signAttestation(att, hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    // Simulate the Python smoke-test omission: strip attestation_epsilon + required_signer_roles
    const { attestation_epsilon, required_signer_roles, ...rest } = signed.aggregation_policy
    void attestation_epsilon
    void required_signer_roles
    const bad = { ...signed, aggregation_policy: rest }
    const r = validateAttestationShape(bad)
    assert.equal(r.ok, false)
    assert.ok(r.errors.some((e) => e.includes('attestation_epsilon')))
    assert.ok(r.errors.some((e) => e.includes('required_signer_roles')))
  })
})

