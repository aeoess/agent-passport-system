// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Cognitive Attestation — Stage 1/2/3 verification tests

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  buildAttestation,
  signCognitiveAttestation as signAttestation,
  verifyCognitiveAttestationSignature as verifySignature,
  verifyRequiredSignerRoles,
  verifyAgainstRegistry,
  verifyByReplay,
  generateKeyPair,
} from '../../../src/index.js'
import type {
  BuildAttestationInput,
  RegistryResolver,
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
    model_id: 'm', model_version_hash: sha256('m'), tokenizer_version_hash: sha256('t'),
    inference_provider: null, hardware_family: 'apple-silicon/m/m3', precision: 'fp32',
    inference_engine: 'pytorch@2.4', deterministic_mode: true,
    dictionary_id: 'd', dictionary_version_hash: sha256('d'), training_corpus_hash: null,
    layer_index: 19, attachment_point: 'residual_stream', sae_type: 'topk',
    absolute_sequence_hash: sha256('s'), prior_state_hash: null,
    start_token_index: 0, end_token_index: 10, token_count: 10,
    feature_activations: [{ feature_id: 1, feature_label: null, activation_statistic: 'max', activation_value: 0.5, tokens_active: 2 }],
    aggregation_policy: {
      top_k: 32, threshold: null, attestation_epsilon: 0.5, feature_allowlist_hash: null,
      completeness_claim: 'top_k_only', tiebreaker_rule: 'lowest_feature_id',
      required_signer_roles: ['agent', 'provider'],
    },
    timestamp: '2026-04-18T20:00:00Z',
    ...overrides,
  }
}

describe('verifySignature — Stage 1a', () => {
  it('returns true for a valid signature', () => {
    const kp = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    assert.equal(verifySignature(signed, hexToBytes(kp.publicKey), 'did:aps:a'), true)
  })

  it('returns false when the ciphertext is tampered', () => {
    const kp = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    const tampered = {
      ...signed,
      feature_activations: signed.feature_activations.map((f) => ({ ...f, activation_value: f.activation_value + 0.01 })),
    }
    assert.equal(verifySignature(tampered, hexToBytes(kp.publicKey), 'did:aps:a'), false)
  })

  it('returns false for the wrong DID', () => {
    const kp = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    assert.equal(verifySignature(signed, hexToBytes(kp.publicKey), 'did:aps:somebody-else'), false)
  })

  it('returns false when the public key does not match the signer', () => {
    const a = generateKeyPair()
    const b = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(a.privateKey), 'did:aps:a', 'agent')
    assert.equal(verifySignature(signed, hexToBytes(b.publicKey), 'did:aps:a'), false)
  })

  it('returns false for malformed public-key size', () => {
    const kp = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    assert.equal(verifySignature(signed, new Uint8Array(16), 'did:aps:a'), false)
  })
})

describe('verifyRequiredSignerRoles — Stage 1b', () => {
  it('returns ok when every required role has a signature', () => {
    const a = generateKeyPair()
    const p = generateKeyPair()
    let signed = signAttestation(buildAttestation(baseInput()), hexToBytes(a.privateKey), 'did:aps:a', 'agent')
    signed = signAttestation(signed, hexToBytes(p.privateKey), 'did:aps:p', 'provider')
    const r = verifyRequiredSignerRoles(signed)
    assert.equal(r.ok, true)
    assert.deepEqual(r.missing, [])
    assert.ok(r.present.includes('agent'))
    assert.ok(r.present.includes('provider'))
  })

  it('flags missing roles when only partial coverage', () => {
    const a = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(a.privateKey), 'did:aps:a', 'agent')
    const r = verifyRequiredSignerRoles(signed)
    assert.equal(r.ok, false)
    assert.deepEqual(r.missing, ['provider'])
  })
})

describe('verifyAgainstRegistry — Stage 2', () => {
  const okResolver: RegistryResolver = {
    async isKnownModel() { return true },
    async isKnownDictionary() { return true },
  }
  const modelUnknown: RegistryResolver = {
    async isKnownModel() { return false },
    async isKnownDictionary() { return true },
  }
  const throwing: RegistryResolver = {
    async isKnownModel() { throw new Error('network down') },
    async isKnownDictionary() { return true },
  }

  it('returns ok when both registries accept', async () => {
    const kp = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    const r = await verifyAgainstRegistry(signed, okResolver)
    assert.equal(r.ok, true)
    assert.equal(r.model_known, true)
    assert.equal(r.dictionary_known, true)
    assert.deepEqual(r.errors, [])
  })

  it('reports unknown model_version_hash', async () => {
    const kp = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    const r = await verifyAgainstRegistry(signed, modelUnknown)
    assert.equal(r.ok, false)
    assert.equal(r.model_known, false)
    assert.ok(r.errors.some((e) => e.includes('unknown model_version_hash')))
  })

  it('captures resolver exceptions in errors array', async () => {
    const kp = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    const r = await verifyAgainstRegistry(signed, throwing)
    assert.equal(r.ok, false)
    assert.ok(r.errors.some((e) => e.includes('network down')))
  })
})

describe('verifyByReplay — Stage 3 stub', () => {
  it('throws when no backend is injected', async () => {
    const kp = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    await assert.rejects(
      () => verifyByReplay(signed, null as any),
      /not implemented/i,
    )
  })

  it('delegates to an injected backend', async () => {
    const kp = generateKeyPair()
    const signed = signAttestation(buildAttestation(baseInput()), hexToBytes(kp.privateKey), 'did:aps:a', 'agent')
    const result = await verifyByReplay(signed, {
      async replay() {
        return { ok: true, per_feature_delta: {}, over_epsilon: [], missing_from_replay: [], unexpected_in_replay: [] }
      },
    })
    assert.equal(result.ok, true)
  })
})
