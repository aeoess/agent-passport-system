// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Hash-and-Pointer Payloads + Field-Disclosure Profile - Type Definitions
// ══════════════════════════════════════════════════════════════════════
//
// A receipt should never embed a raw sensitive payload. Instead it commits
// to the payload by hash and carries a pointer (URI) to where the payload
// lives, plus a per-field disclosure policy that says how each field was
// handled. Hash-bound fields stay in the signed body so the receipt
// signature still validates over the profile.
//
// This module ships the SLOT and the FORMAT. It does not fetch URIs, run a
// storage service, or score anything. Availability of the payload at the
// URI is a separate concern (compose the resolver, W2-A2).
//
// Reuse, not duplication:
//   - canonicalHash / canonicalize (src/core/canonical.ts) for hashing.
//   - The '[REDACTED]' sentinel and the "hash chain and signature preserved"
//     invariant from src/storage/volatile-backend.ts.
//   - The TransformationType vocabulary from src/types/cross-chain.ts.
//   - The EvidenceCommitment hash-and-pointer convention
//     (src/types/bilateral-receipt.ts) - credentialHash + a pointer.
//   - The BBS selective-disclosure package (@aeoess/aps-bbs-credentials),
//     composed by structural interface only (copy, not import) to preserve
//     that package's isolation from core.
// ══════════════════════════════════════════════════════════════════════

/**
 * How a single field's value is disclosed inside a receipt.
 *
 *  - 'public'    - the value is present in cleartext in revealedFields.
 *  - 'hash_only' - only a SHA-256 of the value is present; the value is hidden
 *                  but verifiable by anyone who learns it out of band.
 *  - 'encrypted' - only ciphertext (or a ciphertext pointer) is present; the
 *                  value is hidden and recoverable only by key holders.
 *  - 'redacted'  - the value is removed entirely and replaced with the
 *                  '[REDACTED]' sentinel; a hash binding is still kept so the
 *                  signature verifies and the omission is itself provable.
 *
 * Aligns with the existing transform vocabulary: 'hash_only'/'redacted' map to
 * the cross-chain TransformationType values 'hashing'/'redaction'.
 */
export type FieldDisclosurePolicy =
  | 'public'
  | 'hash_only'
  | 'encrypted'
  | 'redacted'

/** The literal sentinel used across the codebase for a removed value.
 *  Matches src/storage/volatile-backend.ts exactly. */
export const REDACTED_SENTINEL = '[REDACTED]' as const

/** Hash algorithm label for a hash-and-pointer commitment. Fixed to sha256;
 *  the field exists so the format is self-describing and future algorithms can
 *  be added without changing the bytes of existing profiles. */
export type HashPointerAlgorithm = 'sha256'

/**
 * A hash-and-pointer commitment to a payload that is NOT embedded.
 *
 * The receipt commits to the payload by hash. The URI says where the payload
 * can be fetched. The verifier fetches out of band and checks the hash match.
 * This mirrors the EvidenceCommitment convention (credentialHash + jwks
 * pointer) generalized to an arbitrary payload behind a URI.
 */
export interface HashPointerPayload {
  /** Hash algorithm. Currently always 'sha256'. */
  algorithm: HashPointerAlgorithm
  /** SHA-256 of the canonical payload, lowercase hex. The commitment. */
  payload_sha256: string
  /** Where the payload can be fetched. The receipt does not resolve it.
   *  Any URI scheme the relying party understands (https, ipfs, data-vault,
   *  etc.). Presence of a URI does not assert availability. */
  uri: string
  /** Optional content type hint for the resolved payload. */
  content_type?: string
  /** ISO 8601 timestamp the commitment was created. */
  committed_at: string
}

/**
 * One field inside a field-disclosure profile.
 *
 * Exactly one of value / hash / ciphertext is populated according to `policy`.
 * `hash` is ALWAYS populated (for every policy) so the field is hash-bound:
 * the binding is what keeps the signed body stable and lets a redacted or
 * hidden field still verify.
 */
export interface DisclosedField {
  /** Field name as it appears in the source payload. */
  name: string
  /** How this field is disclosed. */
  policy: FieldDisclosurePolicy
  /** SHA-256 of the canonical field value, lowercase hex. Present for EVERY
   *  policy. This is the hash binding that survives redaction. */
  hash: string
  /** Cleartext value. Present only when policy === 'public'. */
  value?: unknown
  /** Ciphertext or a pointer to ciphertext. Present only when
   *  policy === 'encrypted'. Opaque to this module; this module never
   *  encrypts or decrypts. */
  ciphertext?: string
  /** Optional transform label aligned with the cross-chain TransformationType
   *  vocabulary ('hashing' | 'redaction'). Advisory; the policy is the
   *  authoritative descriptor. */
  transform?: 'hashing' | 'redaction'
}

/**
 * A reference to a BBS selective-disclosure presentation that proves a subset
 * of named fields without revealing the rest.
 *
 * STRUCTURAL COPY of @aeoess/aps-bbs-credentials' ScopeDisclosureProof, kept as
 * a copy (not an import) to preserve that package's isolation from core, the
 * same discipline the package itself uses for ScopeOfClaim. The byte arrays are
 * carried as base64 strings so the reference is JSON-canonicalizable inside a
 * signed receipt body.
 *
 * This module does NOT generate or verify BBS proofs. It carries the reference
 * so a relying party that has the isolated BBS package can verify it out of
 * band. The composition test wires the real package against this shape.
 */
export interface FieldDisclosureProofRef {
  /** Proof format tag. */
  format: 'bbs-2023'
  /** Ciphersuite the underlying credential was issued under. */
  ciphersuite: 'SHA-256' | 'SHAKE-256'
  /** Signer public key the proof verifies against, base64. */
  public_key_b64: string
  /** Domain-separation header bound at issue time, base64. */
  header_b64: string
  /** Verifier-supplied presentation header (replay binding), base64. */
  presentation_header_b64: string
  /** The disclosed field names, in disclosure order. */
  disclosed_fields: string[]
  /** Zero-based indexes of the disclosed fields, sorted ascending. */
  disclosed_indexes: number[]
  /** The BBS proof bytes, base64. */
  proof_b64: string
  /** Total number of fields in the original credential. */
  total_fields: number
}

/**
 * The field-disclosure profile attached to a receipt.
 *
 * It is the additive, versioned slot. A receipt that omits it is byte-identical
 * to one built before this module existed. The profile is signed as part of the
 * receipt body, so every hash binding it carries is covered by the signature.
 */
export interface FieldDisclosureProfile {
  /** Slot version. Additive: bump only, never reshape existing fields. */
  version: '1.0'
  /** The hash-and-pointer commitment to the full payload (optional: a profile
   *  may carry per-field commitments without a whole-payload pointer). */
  payload?: HashPointerPayload
  /** Per-field disclosure descriptors. Order is preserved and load-bearing for
   *  any BBS proof reference (indexes refer to this order). */
  fields: DisclosedField[]
  /** Optional BBS selective-disclosure proof reference for a subset of fields.
   *  Carried by reference only; verified out of band with the isolated BBS
   *  package. */
  bbs_proof?: FieldDisclosureProofRef
}

/** Input to the profile builder: the source payload plus the per-field policy
 *  map. Any field not named in the policy map defaults to 'public'. */
export interface BuildFieldDisclosureProfileInput {
  /** The source payload. Sensitive fields will be hashed/removed, never
   *  embedded raw, according to the policy map. */
  payload: Record<string, unknown>
  /** Per-field disclosure policy. Fields absent from this map are 'public'. */
  policies: Record<string, FieldDisclosurePolicy>
  /** Optional whole-payload pointer. When provided, the builder computes the
   *  payload_sha256 commitment over the canonical payload. */
  uri?: string
  /** Optional content type hint for the pointer. */
  content_type?: string
  /** Optional ciphertext map: field name to ciphertext, for 'encrypted' fields.
   *  This module does not encrypt; the caller supplies ciphertext. A field with
   *  policy 'encrypted' but no ciphertext is rejected. */
  ciphertexts?: Record<string, string>
  /** Optional names of fields the builder must treat as sensitive. A sensitive
   *  field MUST NOT be 'public'; the builder rejects the input if one is. This
   *  is the guard that stops raw PII reaching the signed body. */
  sensitive_fields?: string[]
  /** Optional BBS proof reference to attach. */
  bbs_proof?: FieldDisclosureProofRef
}

/** Result of verifying a field-disclosure profile against a source payload (or
 *  a subset of disclosed values). Per the claims discipline this reports
 *  mechanical facts only. */
export interface FieldDisclosureVerification {
  /** True when every binding present could be checked and held. */
  valid: boolean
  /** Per-field check outcome, keyed by field name. */
  fields: Record<
    string,
    {
      policy: FieldDisclosurePolicy
      /** 'bound' = hash binding present and self-consistent.
       *  'matched' = a supplied cleartext/value hashed to the bound hash.
       *  'mismatch' = a supplied value did NOT hash to the bound hash.
       *  'unchecked' = no value supplied to check against (hidden field). */
      status: 'bound' | 'matched' | 'mismatch' | 'unchecked'
    }
  >
  /** True when the whole-payload commitment (if any) matched a supplied
   *  payload, null when no payload was supplied to check. */
  payloadMatched: boolean | null
  errors: string[]
}
