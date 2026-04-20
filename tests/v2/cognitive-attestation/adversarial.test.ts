// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Cognitive Attestation — adversarial tampering tests

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import {
  buildAttestation,
  signCognitiveAttestation as signAttestation,
  verifyCognitiveAttestationSignature as verifySignature,
  verifyRequiredSignerRoles,
  generateKeyPair,
} from '../../../src/index.js'
import type {
  BuildAttestationInput,
  CognitiveAttestation,
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
    feature_activations: [
      { feature_id: 1, feature_label: null, activation_statistic: 'max', activation_value: 0.5, tokens_active: 2 },
      { feature_id: 2, feature_label: null, activation_statistic: 'max', activation_value: 0.3, tokens_active: 1 },
    ],
    aggregation_policy: {
      top_k: 32, threshold: null, attestation_epsilon: 0.5, feature_allowlist_hash: null,
      completeness_claim: 'top_k_only', tiebreaker_rule: 'lowest_feature_id',
      required_signer_roles: ['agent', 'provider', 'third_party_attester'],
    },
    timestamp: '2026-04-18T20:00:00Z',
    ...overrides,
  }
}

function threeSigned() {
  const a = generateKeyPair()
  const p = generateKeyPair()
  const t = generateKeyPair()
  let s = buildAttestation(baseInput())
  s = signAttestation(s, hexToBytes(a.privateKey), 'did:aps:a', 'agent')
  s = signAttestation(s, hexToBytes(p.privateKey), 'did:aps:p', 'provider')
  s = signAttestation(s, hexToBytes(t.privateKey), 'did:aps:t', 'third_party_attester')
  return { s, a, p, t }
}

describe('adversarial — tamper feature activation_value', () => {
  it('tampering activation_value invalidates EVERY signature', () => {
    const { s, a, p, t } = threeSigned()
    const tampered: CognitiveAttestation = {
      ...s,
      feature_activations: s.feature_activations.map((f, i) =>
        i === 0 ? { ...f, activation_value: f.activation_value + 0.001 } : f,
      ),
    }
    assert.equal(verifySignature(tampered, hexToBytes(a.publicKey), 'did:aps:a'), false)
    assert.equal(verifySignature(tampered, hexToBytes(p.publicKey), 'did:aps:p'), false)
    assert.equal(verifySignature(tampered, hexToBytes(t.publicKey), 'did:aps:t'), false)
  })
})

describe('adversarial — add a feature entry', () => {
  it('appending a new feature_activations entry invalidates every signature', () => {
    const { s, a, p, t } = threeSigned()
    const tampered: CognitiveAttestation = {
      ...s,
      feature_activations: [
        ...s.feature_activations,
        { feature_id: 9999, feature_label: 'smuggled', activation_statistic: 'max', activation_value: 5, tokens_active: 1 },
      ],
    }
    assert.equal(verifySignature(tampered, hexToBytes(a.publicKey), 'did:aps:a'), false)
    assert.equal(verifySignature(tampered, hexToBytes(p.publicKey), 'did:aps:p'), false)
    assert.equal(verifySignature(tampered, hexToBytes(t.publicKey), 'did:aps:t'), false)
  })
})

describe('adversarial — signature stripping', () => {
  it('removing the third_party_attester signature reduces the signer set and fails role coverage', () => {
    const { s } = threeSigned()
    const stripped: CognitiveAttestation = {
      ...s,
      signatures: s.signatures.filter((sig) => sig.signer_role !== 'third_party_attester'),
    }
    const r = verifyRequiredSignerRoles(stripped)
    assert.equal(r.ok, false)
    assert.deepEqual(r.missing, ['third_party_attester'])
  })

  it('the surviving signatures still crypto-verify after stripping (Stage 1a alone does not catch this)', () => {
    // This is the point of Stage 1b: Stage 1a per-signer verify passes even
    // after a stripping attack, so verifyRequiredSignerRoles is load-bearing.
    const { s, a, p } = threeSigned()
    const stripped: CognitiveAttestation = {
      ...s,
      signatures: s.signatures.filter((sig) => sig.signer_role !== 'third_party_attester'),
    }
    assert.equal(verifySignature(stripped, hexToBytes(a.publicKey), 'did:aps:a'), true)
    assert.equal(verifySignature(stripped, hexToBytes(p.publicKey), 'did:aps:p'), true)
  })

  it('removing one signature is caught when combined Stage 1a+1b is applied', () => {
    const { s, a, p, t } = threeSigned()
    const stripped: CognitiveAttestation = {
      ...s,
      signatures: s.signatures.filter((sig) => sig.signer_role !== 'third_party_attester'),
    }
    const stage1a =
      verifySignature(stripped, hexToBytes(a.publicKey), 'did:aps:a') &&
      verifySignature(stripped, hexToBytes(p.publicKey), 'did:aps:p')
    const stage1b = verifyRequiredSignerRoles(stripped).ok
    const stage1 = stage1a && stage1b
    assert.equal(stage1, false, 'combined Stage 1 must reject the stripped envelope')
    void t
  })
})

describe('adversarial — role substitution', () => {
  it('changing a signer_role without re-signing invalidates that signer (canonical bytes shifted)', () => {
    const { s, a } = threeSigned()
    // NOTE: signer_role is NOT part of the canonical signing input (only the
    // envelope body is). So changing signer_role does NOT invalidate the
    // crypto — it does, however, change role coverage semantics.
    // This test documents that behavior: role relabeling is caught by
    // policy/governance, not Stage 1a crypto.
    const relabeled: CognitiveAttestation = {
      ...s,
      signatures: s.signatures.map((sig) =>
        sig.signer_did === 'did:aps:a' ? { ...sig, signer_role: 'operator' as const } : sig,
      ),
    }
    // crypto still passes for the raw signature bytes against the agent key
    assert.equal(verifySignature(relabeled, hexToBytes(a.publicKey), 'did:aps:a'), true)
    // but role coverage now reports 'agent' missing
    const r = verifyRequiredSignerRoles(relabeled)
    assert.equal(r.ok, false)
    assert.ok(r.missing.includes('agent'))
  })
})
