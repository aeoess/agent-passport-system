// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// read_fidelity_receipt (v2): create and verify
// ══════════════════════════════════════════════════════════════════
// Signature convention: sig is EXCLUDED from the signing preimage.
// The preimage is canonicalizeJCS(record with the sig key removed
// entirely). Verification order: shape checks and n consistency,
// then the Ed25519 signature against the embedded attester, then the
// seed derivation. A record tampered after signing fails on the
// signature; a record re-signed after a nonce or presentation swap
// carries a valid signature and fails on the seed derivation, which
// is the replay binding doing its job.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'

import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign, verify as edVerify, publicKeyFromPrivate } from '../../crypto/keys.js'

import { commitSpans, deriveSeed, sampleSpans, scoreResponses } from './sampler.js'
import type {
  CreateReadFidelityReceiptInput,
  ReadFidelityReceipt,
  ReadFidelityVerifyReason,
  ReadFidelityVerifyResult,
  VerifyAgainstSourceResult,
  VerifyResponsesResult,
} from './types.js'

const DIGEST_RE = /^sha256:[0-9a-f]{64}$/
const HEX64_RE = /^[0-9a-f]{64}$/
const HEX128_RE = /^[0-9a-f]{128}$/
const ISO_8601_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/

function sha256hex(input: string): string {
  return createHash('sha256').update(input, 'utf8').digest('hex')
}

/**
 * Canonical signing preimage: RFC 8785 JCS of the record with the
 * `sig` key removed entirely. Accepts a signed record (sig dropped)
 * or an unsigned draft (no sig key present).
 */
export function canonicalNoSig(record: object): string {
  const { sig: _sig, ...rest } = record as Record<string, unknown>
  return canonicalizeJCS(rest)
}

/**
 * Structural checks shared by verifyReadFidelityReceipt and
 * verifyAgainstSource. Returns the first failing reason, or null when
 * the value is structurally a ReadFidelityReceipt. Does NOT check the
 * signature or the seed derivation.
 */
function shapeReason(value: unknown): ReadFidelityVerifyReason | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return 'INVALID_TYPE'
  }
  const r = value as Record<string, unknown>
  if (r.type !== 'read_fidelity_receipt') return 'INVALID_TYPE'
  if (typeof r.content_digest !== 'string' || !DIGEST_RE.test(r.content_digest)) {
    return 'INVALID_CONTENT_DIGEST'
  }
  if (
    r.presentation_digest !== null &&
    (typeof r.presentation_digest !== 'string' ||
      !DIGEST_RE.test(r.presentation_digest))
  ) {
    return 'INVALID_PRESENTATION_DIGEST'
  }
  const challengeReason = challengeShapeReason(r.challenge)
  if (challengeReason !== null) return challengeReason
  const c = r.challenge as Record<string, unknown>
  const commitments = c.span_commitments as readonly string[]
  if (typeof r.n !== 'number' || !Number.isInteger(r.n) || r.n < 1) {
    return 'INVALID_N'
  }
  if (r.n !== commitments.length) return 'N_MISMATCH'
  if (
    typeof r.k !== 'number' ||
    !Number.isInteger(r.k) ||
    r.k < 0 ||
    r.k > r.n
  ) {
    return 'INVALID_K'
  }
  if (typeof r.response_digest !== 'string' || !DIGEST_RE.test(r.response_digest)) {
    return 'INVALID_RESPONSE_DIGEST'
  }
  if (r.scoring_method !== 'exact_match_v1') return 'INVALID_SCORING_METHOD'
  if (typeof r.attester !== 'string' || !HEX64_RE.test(r.attester)) {
    return 'INVALID_ATTESTER'
  }
  if (typeof r.model_claim !== 'string' || typeof r.runtime_claim !== 'string') {
    return 'INVALID_CLAIMS'
  }
  if (
    r.verification_method !== 'asserted' &&
    r.verification_method !== 'provider_attestation'
  ) {
    return 'INVALID_VERIFICATION_METHOD'
  }
  for (const field of [
    'challenge_issued_at',
    'response_observed_at',
    'receipt_issued_at',
  ] as const) {
    const t = r[field]
    if (typeof t !== 'string' || !ISO_8601_RE.test(t)) return 'INVALID_TIMESTAMP'
  }
  if ('lexicon_id' in r || 'lexicon_profile' in r) {
    if (typeof r.lexicon_id !== 'string' || !DIGEST_RE.test(r.lexicon_id)) {
      return 'INVALID_LEXICON_FIELDS'
    }
    if (
      'lexicon_profile' in r &&
      (typeof r.lexicon_profile !== 'string' || r.lexicon_profile.length === 0)
    ) {
      return 'INVALID_LEXICON_FIELDS'
    }
  }
  if (typeof r.sig !== 'string' || !HEX128_RE.test(r.sig)) {
    return 'INVALID_SIG_FORMAT'
  }
  return null
}

function challengeShapeReason(value: unknown): ReadFidelityVerifyReason | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return 'INVALID_CHALLENGE'
  }
  const c = value as Record<string, unknown>
  if (typeof c.nonce !== 'string' || c.nonce.length === 0) return 'INVALID_CHALLENGE'
  if (typeof c.seed !== 'string' || !HEX64_RE.test(c.seed)) return 'INVALID_CHALLENGE'
  if (c.algorithm !== 'span_sample_v1') return 'INVALID_CHALLENGE'
  if (c.version !== '1') return 'INVALID_CHALLENGE'
  if (
    typeof c.span_len !== 'number' ||
    !Number.isInteger(c.span_len) ||
    c.span_len < 1
  ) {
    return 'INVALID_CHALLENGE'
  }
  if (!Array.isArray(c.span_commitments) || c.span_commitments.length === 0) {
    return 'INVALID_CHALLENGE'
  }
  for (const s of c.span_commitments) {
    if (typeof s !== 'string' || !DIGEST_RE.test(s)) return 'INVALID_CHALLENGE'
  }
  return null
}

function seedMatches(record: ReadFidelityReceipt): boolean {
  return (
    record.challenge.seed ===
    deriveSeed(
      record.content_digest,
      record.presentation_digest,
      record.challenge.nonce,
      record.challenge.version,
    )
  )
}

/**
 * Build and sign a read fidelity receipt. Validates the input
 * (n MUST equal challenge.span_commitments.length, challenge.seed MUST
 * equal the seed derivation, every digest MUST be
 * "sha256:<64 lowercase hex>", timestamps MUST be ISO 8601), sets
 * `attester` from the private key, and signs the JCS canonical form of
 * the record with the sig key excluded. Throws on any validation
 * failure; nothing is signed unless the record is internally
 * consistent.
 */
export function createReadFidelityReceipt(
  fields: CreateReadFidelityReceiptInput,
  privateKeyHex: string,
): ReadFidelityReceipt {
  const attester = publicKeyFromPrivate(privateKeyHex)
  const draft: Omit<ReadFidelityReceipt, 'sig'> = {
    type: 'read_fidelity_receipt',
    content_digest: fields.content_digest,
    presentation_digest: fields.presentation_digest,
    challenge: {
      nonce: fields.challenge.nonce,
      seed: fields.challenge.seed,
      algorithm: fields.challenge.algorithm,
      version: fields.challenge.version,
      span_len: fields.challenge.span_len,
      span_commitments: [...fields.challenge.span_commitments],
    },
    response_digest: fields.response_digest,
    k: fields.k,
    n: fields.n,
    scoring_method: fields.scoring_method,
    attester,
    model_claim: fields.model_claim,
    runtime_claim: fields.runtime_claim,
    verification_method: fields.verification_method,
    challenge_issued_at: fields.challenge_issued_at,
    response_observed_at: fields.response_observed_at,
    receipt_issued_at: fields.receipt_issued_at,
    ...(fields.lexicon_id !== undefined ? { lexicon_id: fields.lexicon_id } : {}),
    ...(fields.lexicon_profile !== undefined
      ? { lexicon_profile: fields.lexicon_profile }
      : {}),
  }

  if (fields.n !== fields.challenge.span_commitments.length) {
    throw new Error(
      `n (${fields.n}) must equal challenge.span_commitments.length ` +
        `(${fields.challenge.span_commitments.length})`,
    )
  }
  // Full structural validation on the draft plus a placeholder sig so
  // create and verify enforce the identical shape rules.
  const reason = shapeReason({ ...draft, sig: '0'.repeat(128) })
  if (reason !== null) {
    throw new Error(`invalid read fidelity receipt input: ${reason}`)
  }
  const expectedSeed = deriveSeed(
    fields.content_digest,
    fields.presentation_digest,
    fields.challenge.nonce,
    fields.challenge.version,
  )
  if (fields.challenge.seed !== expectedSeed) {
    throw new Error(
      'challenge.seed does not match the seed derivation over ' +
        'content_digest, presentation_digest, nonce, and version',
    )
  }

  const sig = sign(canonicalNoSig(draft), privateKeyHex)
  return { ...draft, sig }
}

/**
 * Verify a read fidelity receipt: shape checks, n consistency against
 * challenge.span_commitments, Ed25519 signature against the embedded
 * attester, and the seed derivation recompute. Accepts unknown and
 * never throws on malformed input; failures carry a reason code.
 */
export function verifyReadFidelityReceipt(record: unknown): ReadFidelityVerifyResult {
  const reason = shapeReason(record)
  if (reason !== null) return { valid: false, reason }
  const r = record as ReadFidelityReceipt
  if (!edVerify(canonicalNoSig(r), r.sig, r.attester)) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }
  if (!seedMatches(r)) {
    return { valid: false, reason: 'SEED_MISMATCH' }
  }
  return { valid: true }
}

/**
 * Verify a receipt against the source text it claims to sample:
 * everything verifyReadFidelityReceipt checks, plus a recompute of the
 * spans from challenge.seed / n / span_len over `sourceText`, a sha256
 * commitment of each recomputed span, and a positionwise comparison
 * against challenge.span_commitments. ALL commitments must match.
 * `signature_valid` and `seed_valid` are reported independently.
 */
export function verifyAgainstSource(
  record: unknown,
  sourceText: string,
): VerifyAgainstSourceResult {
  const reason = shapeReason(record)
  if (reason !== null) {
    return {
      valid: false,
      reason,
      commitment_matches: [],
      signature_valid: false,
      seed_valid: false,
    }
  }
  const r = record as ReadFidelityReceipt
  const signature_valid = edVerify(canonicalNoSig(r), r.sig, r.attester)
  const seed_valid = seedMatches(r)

  let commitment_matches: boolean[] = []
  let spanReason: ReadFidelityVerifyReason | null = null
  try {
    const spans = sampleSpans(
      sourceText,
      r.challenge.seed,
      r.n,
      r.challenge.span_len,
    )
    const recomputed = commitSpans(spans.map((s) => s.text))
    commitment_matches = recomputed.map(
      (c, i) => c === r.challenge.span_commitments[i],
    )
  } catch {
    spanReason = 'SPAN_RECOMPUTE_FAILED'
  }

  const allMatch =
    spanReason === null && commitment_matches.every((m) => m === true)
  const valid = signature_valid && seed_valid && allMatch
  let failure: ReadFidelityVerifyReason | undefined
  if (!signature_valid) failure = 'SIGNATURE_INVALID'
  else if (!seed_valid) failure = 'SEED_MISMATCH'
  else if (spanReason !== null) failure = spanReason
  else if (!allMatch) failure = 'COMMITMENT_MISMATCH'
  return valid
    ? { valid, commitment_matches, signature_valid, seed_valid }
    : { valid, reason: failure, commitment_matches, signature_valid, seed_valid }
}

/**
 * Recompute k for a set of readback responses against the source text:
 * resample the spans the record commits to, score `responses` under
 * exact_match_v1, and compare the recomputed k with the recorded k and
 * the responses JCS digest with the recorded response_digest. Throws
 * when the source cannot produce the spans (wrong length) or when
 * `responses` has the wrong length; use verifyAgainstSource first to
 * establish that the record matches the source at all.
 */
export function verifyResponses(
  record: ReadFidelityReceipt,
  sourceText: string,
  responses: readonly string[],
): VerifyResponsesResult {
  const spans = sampleSpans(
    sourceText,
    record.challenge.seed,
    record.n,
    record.challenge.span_len,
  )
  const { k } = scoreResponses(
    spans.map((s) => s.text),
    responses,
  )
  const digest = `sha256:${sha256hex(canonicalizeJCS(responses))}`
  return {
    k_recomputed: k,
    matches_claimed_k: k === record.k,
    response_digest_ok: digest === record.response_digest,
  }
}
