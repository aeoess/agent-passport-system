// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// read_fidelity_receipt (v2): TypeScript types
// ══════════════════════════════════════════════════════════════════
// A signed record of a sampled readback challenge: a verifier supplies
// a nonce, the seed binds that nonce to the exact content digest and
// presentation digest, spans are sampled deterministically from the
// seed, and the record commits to the span hashes and the scored
// readback result (k of n). The raw span texts and responses are NOT
// in the record; only their commitments and digests are.
//
// Signature convention: `sig` is EXCLUDED from the signing preimage.
// The preimage is canonicalizeJCS(record with the sig key removed
// entirely), NOT a record with sig set to an empty string.
// ══════════════════════════════════════════════════════════════════

/** Literal tag for record discrimination at the wire level. */
export type ReadFidelityReceiptType = 'read_fidelity_receipt'

/** The v1 sampling algorithm identifier. */
export type ReadFidelitySamplingAlgorithm = 'span_sample_v1'

/** The v1 scoring method identifier: exact string equality per span. */
export type ReadFidelityScoringMethod = 'exact_match_v1'

/**
 * How the executor claims were checked. `asserted` means the attester
 * simply asserts model_claim and runtime_claim; `provider_attestation`
 * means a provider-level attestation backs them.
 */
export type ReadFidelityVerificationMethod = 'asserted' | 'provider_attestation'

/**
 * The challenge block. The nonce is verifier-supplied and never
 * derivable from the document alone. The seed MUST equal
 *   sha256hex(utf8( canonicalizeJCS({
 *     content_digest, presentation_digest, nonce, version }) ))
 * the RFC 8785 JCS preimage of those four fields (presentation_digest
 * null when absent); verifiers recompute and reject on mismatch, which
 * is the replay binding: reusing commitments under a different nonce,
 * content, or presentation breaks the derivation.
 */
export interface ReadFidelityChallenge {
  /** Verifier-supplied; never derivable from the document alone. */
  readonly nonce: string
  /** MUST equal the seed derivation over content, presentation, nonce, version. */
  readonly seed: string
  readonly algorithm: ReadFidelitySamplingAlgorithm
  readonly version: '1'
  /** Span length in code points; required to recompute spans. */
  readonly span_len: number
  /**
   * sha256 of the UTF-8 bytes of each span text, in sampling order,
   * each as "sha256:<64 lowercase hex>". Raw span texts are NOT in
   * the record.
   */
  readonly span_commitments: readonly string[]
}

/**
 * A read fidelity receipt proves sampled readback fidelity at the stated n under the declared sampling
 * assumptions. It does not prove every byte was read correctly, does not prove perception or comprehension,
 * does not prove which channel was used, and carries no normative pass threshold: the consumer judges k of n.
 */
export interface ReadFidelityReceipt {
  readonly type: ReadFidelityReceiptType
  /** Digest of the canonical content bytes, "sha256:<64 lowercase hex>". */
  readonly content_digest: string
  /** Digest of the rendered presentation as served, or null. */
  readonly presentation_digest: string | null
  readonly challenge: ReadFidelityChallenge
  /**
   * "sha256:" + sha256hex(canonicalizeJCS(responses)) where responses
   * is the ordered array of readback strings.
   */
  readonly response_digest: string
  /** Count of responses that exactly matched their span text. */
  readonly k: number
  /** Sample count; MUST equal challenge.span_commitments.length. */
  readonly n: number
  readonly scoring_method: ReadFidelityScoringMethod
  /**
   * Ed25519 public key hex of the SIGNING identity. May differ from
   * the executing model; model_claim and runtime_claim are claims
   * about the executor, not proofs.
   */
  readonly attester: string
  readonly model_claim: string
  readonly runtime_claim: string
  readonly verification_method: ReadFidelityVerificationMethod
  /** ISO 8601, caller-provided; the library never reads a wall clock. */
  readonly challenge_issued_at: string
  /** ISO 8601, caller-provided; the library never reads a wall clock. */
  readonly response_observed_at: string
  /** ISO 8601, caller-provided; the library never reads a wall clock. */
  readonly receipt_issued_at: string
  /** Optional; present when word_digest_handles appear in the flow. */
  readonly lexicon_id?: string
  /** Optional; "single-list-v1", alongside lexicon_id. */
  readonly lexicon_profile?: string
  /** 128 hex chars, Ed25519 over canonicalizeJCS(record with sig excluded). */
  readonly sig: string
}

/**
 * Input to createReadFidelityReceipt: the record minus the fields the
 * library sets itself (`type` is the literal, `attester` is derived
 * from the private key, `sig` is computed).
 */
export type CreateReadFidelityReceiptInput = Omit<
  ReadFidelityReceipt,
  'type' | 'attester' | 'sig'
>

/** One sampled span: code-point position, length, and text. */
export interface SampledSpan {
  /** Start position in code points (Array.from indexing). */
  readonly pos: number
  /** Span length in code points; equals the requested spanLen. */
  readonly len: number
  readonly text: string
}

/** Result of scoreResponses: per-span exact-match flags and their count. */
export interface ScoreResponsesResult {
  readonly k: number
  readonly results: readonly boolean[]
}

/**
 * Failure reasons for verifyReadFidelityReceipt and verifyAgainstSource.
 * Check order in verifyReadFidelityReceipt: shape (INVALID_* and
 * N_MISMATCH), then SIGNATURE_INVALID, then SEED_MISMATCH. A record
 * tampered after signing therefore fails on the signature; a record
 * re-signed after a nonce or presentation swap carries a valid
 * signature and fails on the seed derivation instead.
 */
export type ReadFidelityVerifyReason =
  | 'INVALID_TYPE'
  | 'INVALID_CONTENT_DIGEST'
  | 'INVALID_PRESENTATION_DIGEST'
  | 'INVALID_CHALLENGE'
  | 'INVALID_N'
  | 'N_MISMATCH'
  | 'INVALID_K'
  | 'INVALID_RESPONSE_DIGEST'
  | 'INVALID_SCORING_METHOD'
  | 'INVALID_ATTESTER'
  | 'INVALID_CLAIMS'
  | 'INVALID_VERIFICATION_METHOD'
  | 'INVALID_TIMESTAMP'
  | 'INVALID_LEXICON_FIELDS'
  | 'INVALID_SIG_FORMAT'
  | 'SIGNATURE_INVALID'
  | 'SEED_MISMATCH'
  | 'SPAN_RECOMPUTE_FAILED'
  | 'COMMITMENT_MISMATCH'

/** Result of verifyReadFidelityReceipt. */
export interface ReadFidelityVerifyResult {
  readonly valid: boolean
  readonly reason?: ReadFidelityVerifyReason
}

/**
 * Result of verifyAgainstSource. `commitment_matches[i]` compares the
 * recomputed commitment of span i against challenge.span_commitments[i];
 * ALL must match for validity. `signature_valid` and `seed_valid` are
 * reported independently so a caller can see which binding broke.
 */
export interface VerifyAgainstSourceResult {
  readonly valid: boolean
  readonly reason?: ReadFidelityVerifyReason
  readonly commitment_matches: readonly boolean[]
  readonly signature_valid: boolean
  readonly seed_valid: boolean
}

/**
 * Result of verifyResponses: the recomputed k over the supplied
 * responses, whether it equals the recorded k, and whether the
 * responses JCS-hash to the recorded response_digest.
 */
export interface VerifyResponsesResult {
  readonly k_recomputed: number
  readonly matches_claimed_k: boolean
  readonly response_digest_ok: boolean
}
