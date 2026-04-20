// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cognitive Attestation — envelope construction, JCS, signing, digest
// ══════════════════════════════════════════════════════════════════
// Paper: "Cognitive Attestation" — Zenodo DOI 10.5281/zenodo.19646276
// Normative schema: papers/paper-4/poc/schema/cognitive_attestation.schema.json
//
// Wire compatibility with the Python reference impl at
// papers/paper-4/poc/src/envelope.py is preserved via:
//   - canonicalizeJCS (RFC 8785, nulls preserved)
//   - base64 signatures
//   - feature_activations sorted by (feature_id, activation_statistic)
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign as edSignHex } from '../../crypto/keys.js'
import type {
  CognitiveAttestation,
  BuildAttestationInput,
  FeatureActivation,
  SignerRole,
} from './types.js'

const SPEC_VERSION = '1.0' as const

function bytesToHex(bytes: Uint8Array): string {
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0')
  return out
}

function hexToBase64(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64')
}

/**
 * Sort feature_activations canonically. Per schema: sort by
 * (feature_id ascending, activation_statistic alphabetically).
 * Returns a new array; does not mutate input.
 */
export function sortFeatureActivations(acts: FeatureActivation[]): FeatureActivation[] {
  return acts.slice().sort((a, b) => {
    if (a.feature_id !== b.feature_id) return a.feature_id - b.feature_id
    if (a.activation_statistic < b.activation_statistic) return -1
    if (a.activation_statistic > b.activation_statistic) return 1
    return 0
  })
}

/**
 * Construct an unsigned cognitive attestation. The returned object has
 * `signatures: []` and canonically-sorted `feature_activations`. Callers
 * sign it via `signAttestation`.
 */
export function buildAttestation(input: BuildAttestationInput): CognitiveAttestation {
  const timestamp = input.timestamp ?? new Date().toISOString()
  return {
    spec_version: SPEC_VERSION,
    model_ref: {
      model_id: input.model_id,
      model_version_hash: input.model_version_hash,
      tokenizer_version_hash: input.tokenizer_version_hash,
      inference_provider: input.inference_provider,
      execution_environment: {
        hardware_family: input.hardware_family,
        precision: input.precision,
        inference_engine: input.inference_engine,
        deterministic_mode: input.deterministic_mode,
      },
    },
    dictionary_ref: {
      dictionary_id: input.dictionary_id,
      dictionary_version_hash: input.dictionary_version_hash,
      training_corpus_hash: input.training_corpus_hash,
      layer_index: input.layer_index,
      attachment_point: input.attachment_point,
      sae_type: input.sae_type,
    },
    token_range: {
      absolute_sequence_hash: input.absolute_sequence_hash,
      prior_state_hash: input.prior_state_hash,
      start_token_index: input.start_token_index,
      end_token_index: input.end_token_index,
      token_count: input.token_count,
    },
    feature_activations: sortFeatureActivations(input.feature_activations),
    aggregation_policy: {
      ...input.aggregation_policy,
      required_signer_roles: input.aggregation_policy.required_signer_roles.slice(),
    },
    signatures: [],
    attestation_timestamp: timestamp,
  }
}

/**
 * JCS-canonicalize the attestation for signing. Signatures are elided
 * (`signatures: []`) so all signers over the same payload produce the
 * same input bytes regardless of signing order.
 *
 * Returns UTF-8 bytes. To obtain the canonical string, decode with TextDecoder.
 */
export function canonicalizeAttestation(att: CognitiveAttestation): Uint8Array {
  const view: CognitiveAttestation = {
    ...att,
    feature_activations: sortFeatureActivations(att.feature_activations),
    signatures: [],
  }
  const s = canonicalizeJCS(view)
  return new TextEncoder().encode(s)
}

/**
 * Sign an attestation with a 32-byte Ed25519 seed. Appends a new entry to
 * `signatures`. Returns a new object; never mutates input.
 *
 * The signature covers `canonicalizeAttestation(att)`, i.e. the envelope
 * with `signatures: []`. Additional signers produce byte-identical canonical
 * input, so the signing order does not affect any individual signature.
 */
export function signAttestation(
  att: CognitiveAttestation,
  privateKey: Uint8Array,
  signerDid: string,
  signerRole: SignerRole,
): CognitiveAttestation {
  if (!(privateKey instanceof Uint8Array) || privateKey.length !== 32) {
    throw new Error('signAttestation: privateKey must be a 32-byte Uint8Array (Ed25519 seed)')
  }
  if (typeof signerDid !== 'string' || signerDid.length === 0) {
    throw new Error('signAttestation: signerDid must be a non-empty string')
  }

  const canonicalBytes = canonicalizeAttestation(att)
  const canonicalString = new TextDecoder().decode(canonicalBytes)
  const privateKeyHex = bytesToHex(privateKey)
  const sigHex = edSignHex(canonicalString, privateKeyHex)
  const sigB64 = hexToBase64(sigHex)

  return {
    ...att,
    feature_activations: sortFeatureActivations(att.feature_activations),
    signatures: [
      ...att.signatures,
      { signer_did: signerDid, signer_role: signerRole, signature: sigB64 },
    ],
  }
}

/**
 * Cross-primitive anchor. Returns lowercase hex sha256 of the full signed
 * envelope (including signatures) under JCS. Use this when an APS action
 * receipt needs to reference a cognitive attestation by content hash.
 *
 * Matches the hashing pattern of other v2 primitives (wallet-binding digest,
 * attribution-primitive canonical hash).
 */
export function cognitiveAttestationDigest(att: CognitiveAttestation): string {
  const withSortedFeatures: CognitiveAttestation = {
    ...att,
    feature_activations: sortFeatureActivations(att.feature_activations),
  }
  const canonical = canonicalizeJCS(withSortedFeatures)
  return createHash('sha256').update(canonical, 'utf-8').digest('hex')
}

// ──────────────────────────────────────────────────────────────────
// Shape validation — hand-rolled check of the normative JSON schema.
// No new runtime deps. The schema file is the source of truth; this
// function mirrors its required fields, enums, and patterns.
// ──────────────────────────────────────────────────────────────────

const HEX64 = /^[0-9a-f]{64}$/
const PRECISIONS = new Set(['fp32', 'fp16', 'bf16', 'int8'])
const ATTACHMENT_POINTS = new Set(['residual_stream', 'attention_output', 'mlp_output'])
const SAE_TYPES = new Set(['standard', 'topk', 'jumprelu', 'gated', 'batchtopk'])
const STATS = new Set(['max', 'mean', 'sum', 'integral', 'last'])
const COMPLETENESS = new Set(['top_k_only', 'all_above_threshold', 'dictionary_exhaustive'])
const TIEBREAKERS = new Set(['lowest_feature_id', 'highest_feature_id'])
const ROLES = new Set(['agent', 'operator', 'provider', 'third_party_attester'])

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isInteger(v)
}

function checkHex64(errs: string[], path: string, v: unknown): void {
  if (typeof v !== 'string' || !HEX64.test(v)) errs.push(`${path}: expected 64-char lowercase hex`)
}

function checkHex64Nullable(errs: string[], path: string, v: unknown): void {
  if (v === null) return
  checkHex64(errs, path, v)
}

export function validateAttestationShape(att: unknown): { ok: boolean; errors: string[] } {
  const errors: string[] = []
  if (!isObject(att)) return { ok: false, errors: ['root: expected object'] }

  if (att.spec_version !== '1.0') errors.push('spec_version: must be "1.0"')

  // model_ref
  const m = att.model_ref
  if (!isObject(m)) {
    errors.push('model_ref: expected object')
  } else {
    if (typeof m.model_id !== 'string') errors.push('model_ref.model_id: expected string')
    checkHex64(errors, 'model_ref.model_version_hash', m.model_version_hash)
    checkHex64(errors, 'model_ref.tokenizer_version_hash', m.tokenizer_version_hash)
    if (m.inference_provider !== null && typeof m.inference_provider !== 'string') {
      errors.push('model_ref.inference_provider: expected string|null')
    }
    const ee = m.execution_environment
    if (!isObject(ee)) {
      errors.push('model_ref.execution_environment: expected object')
    } else {
      if (typeof ee.hardware_family !== 'string') errors.push('execution_environment.hardware_family: expected string')
      if (typeof ee.precision !== 'string' || !PRECISIONS.has(ee.precision)) {
        errors.push('execution_environment.precision: must be fp32|fp16|bf16|int8')
      }
      if (typeof ee.inference_engine !== 'string') errors.push('execution_environment.inference_engine: expected string')
      if (typeof ee.deterministic_mode !== 'boolean') errors.push('execution_environment.deterministic_mode: expected boolean')
    }
  }

  // dictionary_ref
  const d = att.dictionary_ref
  if (!isObject(d)) {
    errors.push('dictionary_ref: expected object')
  } else {
    if (typeof d.dictionary_id !== 'string') errors.push('dictionary_ref.dictionary_id: expected string')
    checkHex64(errors, 'dictionary_ref.dictionary_version_hash', d.dictionary_version_hash)
    checkHex64Nullable(errors, 'dictionary_ref.training_corpus_hash', d.training_corpus_hash)
    if (!isInt(d.layer_index) || (d.layer_index as number) < 0) {
      errors.push('dictionary_ref.layer_index: expected non-negative integer')
    }
    if (typeof d.attachment_point !== 'string' || !ATTACHMENT_POINTS.has(d.attachment_point)) {
      errors.push('dictionary_ref.attachment_point: must be residual_stream|attention_output|mlp_output')
    }
    if (typeof d.sae_type !== 'string' || !SAE_TYPES.has(d.sae_type)) {
      errors.push('dictionary_ref.sae_type: must be standard|topk|jumprelu|gated|batchtopk')
    }
  }

  // token_range
  const tr = att.token_range
  if (!isObject(tr)) {
    errors.push('token_range: expected object')
  } else {
    checkHex64(errors, 'token_range.absolute_sequence_hash', tr.absolute_sequence_hash)
    checkHex64Nullable(errors, 'token_range.prior_state_hash', tr.prior_state_hash)
    if (!isInt(tr.start_token_index) || (tr.start_token_index as number) < 0) {
      errors.push('token_range.start_token_index: expected non-negative integer')
    }
    if (!isInt(tr.end_token_index) || (tr.end_token_index as number) < 0) {
      errors.push('token_range.end_token_index: expected non-negative integer')
    }
    if (!isInt(tr.token_count) || (tr.token_count as number) < 1) {
      errors.push('token_range.token_count: expected integer >= 1')
    }
  }

  // feature_activations
  if (!Array.isArray(att.feature_activations)) {
    errors.push('feature_activations: expected array')
  } else {
    att.feature_activations.forEach((fa, i) => {
      if (!isObject(fa)) { errors.push(`feature_activations[${i}]: expected object`); return }
      if (!isInt(fa.feature_id) || (fa.feature_id as number) < 0) {
        errors.push(`feature_activations[${i}].feature_id: expected non-negative integer`)
      }
      if (fa.feature_label !== null && typeof fa.feature_label !== 'string') {
        errors.push(`feature_activations[${i}].feature_label: expected string|null`)
      }
      if (typeof fa.activation_statistic !== 'string' || !STATS.has(fa.activation_statistic)) {
        errors.push(`feature_activations[${i}].activation_statistic: must be max|mean|sum|integral|last`)
      }
      if (typeof fa.activation_value !== 'number' || (fa.activation_value as number) < 0) {
        errors.push(`feature_activations[${i}].activation_value: expected number >= 0`)
      }
      if (!isInt(fa.tokens_active) || (fa.tokens_active as number) < 0) {
        errors.push(`feature_activations[${i}].tokens_active: expected non-negative integer`)
      }
    })
  }

  // aggregation_policy
  const ap = att.aggregation_policy
  if (!isObject(ap)) {
    errors.push('aggregation_policy: expected object')
  } else {
    if (ap.top_k !== null && (!isInt(ap.top_k) || (ap.top_k as number) < 1)) {
      errors.push('aggregation_policy.top_k: expected integer >= 1 or null')
    }
    if (ap.threshold !== null && (typeof ap.threshold !== 'number' || (ap.threshold as number) < 0)) {
      errors.push('aggregation_policy.threshold: expected number >= 0 or null')
    }
    if (typeof ap.attestation_epsilon !== 'number' || (ap.attestation_epsilon as number) <= 0) {
      errors.push('aggregation_policy.attestation_epsilon: required, must be number > 0')
    }
    checkHex64Nullable(errors, 'aggregation_policy.feature_allowlist_hash', ap.feature_allowlist_hash)
    if (typeof ap.completeness_claim !== 'string' || !COMPLETENESS.has(ap.completeness_claim)) {
      errors.push('aggregation_policy.completeness_claim: must be top_k_only|all_above_threshold|dictionary_exhaustive')
    }
    if (typeof ap.tiebreaker_rule !== 'string' || !TIEBREAKERS.has(ap.tiebreaker_rule)) {
      errors.push('aggregation_policy.tiebreaker_rule: must be lowest_feature_id|highest_feature_id')
    }
    if (!Array.isArray(ap.required_signer_roles) || ap.required_signer_roles.length === 0) {
      errors.push('aggregation_policy.required_signer_roles: required, non-empty array')
    } else {
      const seen = new Set<string>()
      ap.required_signer_roles.forEach((r, i) => {
        if (typeof r !== 'string' || !ROLES.has(r)) {
          errors.push(`aggregation_policy.required_signer_roles[${i}]: must be agent|operator|provider|third_party_attester`)
        }
        if (seen.has(r as string)) errors.push(`aggregation_policy.required_signer_roles: duplicate "${r}"`)
        seen.add(r as string)
      })
    }
  }

  // signatures
  if (!Array.isArray(att.signatures) || att.signatures.length < 1) {
    errors.push('signatures: expected non-empty array')
  } else {
    att.signatures.forEach((s, i) => {
      if (!isObject(s)) { errors.push(`signatures[${i}]: expected object`); return }
      if (typeof s.signer_did !== 'string' || s.signer_did.length === 0) {
        errors.push(`signatures[${i}].signer_did: expected non-empty string`)
      }
      if (typeof s.signer_role !== 'string' || !ROLES.has(s.signer_role)) {
        errors.push(`signatures[${i}].signer_role: must be agent|operator|provider|third_party_attester`)
      }
      if (typeof s.signature !== 'string' || s.signature.length === 0) {
        errors.push(`signatures[${i}].signature: expected non-empty base64 string`)
      }
    })
  }

  // attestation_timestamp
  if (typeof att.attestation_timestamp !== 'string' || Number.isNaN(Date.parse(att.attestation_timestamp))) {
    errors.push('attestation_timestamp: expected ISO 8601 date-time string')
  }

  return { ok: errors.length === 0, errors }
}
