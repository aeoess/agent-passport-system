// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Context Provenance Attestation (CPA) v0.1: TypeScript types
// ══════════════════════════════════════════════════════════════════
// CPA is the general partitioned-Merkle context-basis commitment. It is
// NOT an extension of memory_provenance (single-entry) or
// instruction-provenance (flat sha256(JCS) context_root). A producer
// commits to a context basis split across channels; each channel is a
// partition with its own subtree root; the top root commits over the
// present partition roots in CHANNEL_ORDER.
//
// What the primitive attests: custody of the declared context basis by a
// producer key at a producer-stated time, and admissibility of the disclosed
// evidence under a declared selection policy (the disclosure mode). The
// content of any item, and the question of whether the declared channel
// for an item reflects its real origin, are downstream consumer
// responsibilities. trust_tier is OPTIONAL producer-declared metadata
// only, NOT proof-bearing, and is EXCLUDED from the leaf preimage.
// ══════════════════════════════════════════════════════════════════

// merkle.ts owns the single InclusionProof / InclusionStep definition;
// types.ts imports and re-exports it so the module's type surface is one
// place. merkle.ts does NOT import from types.ts for these, so there is no
// cycle on the proof shapes.
import type { InclusionProof } from './merkle.js'
export type { InclusionProof, InclusionStep } from './merkle.js'

/**
 * The eight context channels. Producer discretionary labels
 * ("trusted"/"clean"/"safe") are BANNED as origin claims; the channel is
 * a structural partition key, not a trust assertion.
 */
export type ContextChannel =
  | 'system-config'
  | 'developer'
  | 'user-socket'
  | 'retrieval-store'
  | 'tool-result'
  | 'external'
  | 'memory'
  | 'quarantine'

/**
 * Canonical channel order. The top Merkle tree is built over present
 * partition roots taken in THIS order. Frozen for v0.1.
 */
export const CHANNEL_ORDER: readonly ContextChannel[] = [
  'system-config',
  'developer',
  'user-socket',
  'retrieval-store',
  'tool-result',
  'external',
  'memory',
  'quarantine',
] as const

/**
 * Disclosure mode for a CPA.
 *   - 'full-set': every partition carries ALL its leaves; the verifier
 *     recomputes every partition_root and the top root from disclosed
 *     leaves. A valid full-set CPA yields completeness 'PROVEN'.
 *   - 'inclusion': partitions carry counts (context_profile) and may
 *     carry a disclosed subset of leaves. Phase 1 adds inclusion proofs.
 *     A valid inclusion CPA yields completeness 'NOT_PROVEN'.
 */
export type DisclosureMode = 'inclusion' | 'full-set'

/**
 * A single context item (leaf). The tree commits to content_ref, NOT to
 * raw content. content + trust_tier are EXCLUDED from the leaf preimage
 * so that the partition and top roots are identical whether or not the
 * raw content is later disclosed.
 *
 * Invariants:
 *   - ctx_id: ordering key within a partition; ASCII-sortable; unique
 *     within its partition.
 *   - channel: MUST equal the partition's channel.
 *   - content_ref: 64-hex sha256 of the raw content bytes.
 *   - byte_len: >= 0.
 *   - trust_tier: OPTIONAL metadata; NOT in the leaf preimage.
 *   - content: OPTIONAL disclosed raw content, base64 of content bytes.
 */
export interface ContextItem {
  ctx_id: string
  channel: ContextChannel
  content_ref: string
  byte_len: number
  trust_tier?: string
  content?: string
}

/**
 * Per-partition count metadata, REQUIRED in inclusion mode and OMITTED
 * in full-set mode. hidden_leaf_count = leaf_count - (disclosed leaves).
 */
export interface ContextProfile {
  channel: ContextChannel
  hidden_leaf_count: number
}

/**
 * One present partition. Empty partitions are OMITTED entirely.
 *
 * Invariants:
 *   - channel: the partition's channel.
 *   - partition_root: 64-hex subtree root.
 *   - leaf_count: >= 1.
 *   - context_profile: REQUIRED in inclusion mode, OMITTED in full-set.
 *   - leaves: full-set => ALL leaves; inclusion => optional disclosed
 *     subset (Phase 1 adds inclusion proofs).
 *   - inclusion_proofs: present ONLY in inclusion mode when a leaf subset
 *     is disclosed; one entry per disclosed ctx_id. They are NOT part of
 *     any Merkle preimage and never appear in full-set CPAs, so the
 *     Phase-0 full-set bytes are unchanged. They DO live inside the signed
 *     CPA bytes, which is harmless: each proof is deterministic from the
 *     full leaf set under the frozen tree. The verifier checks each proof
 *     reconstructs the signed partition_root.
 */
export interface CpaPartition {
  channel: ContextChannel
  partition_root: string
  leaf_count: number
  context_profile?: ContextProfile
  leaves?: ContextItem[]
  inclusion_proofs?: InclusionProof[]
}

/**
 * Signed Context Provenance Attestation.
 *
 * Invariants:
 *   - version: literal 'cpa/0.1'.
 *   - action_ref: 64-hex; carries the action identity (intent-only,
 *     untouched; see src/core/action-ref.ts).
 *   - producer_did: DID string of the producer; MUST equal didDoc.id.
 *   - producer_pubkey: 64-hex Ed25519 pubkey that signs this CPA.
 *   - attested_at: ISO 8601 UTC; used for the key-active-at check.
 *   - mode: disclosure mode.
 *   - partitions: present partitions only, sorted by CHANNEL_ORDER.
 *   - root: 64-hex top Merkle root over partition roots.
 *   - producer_attestation: OPTIONAL additive slot, a hash-bound reference
 *     to an external producer attestation; absent on a CPA that does not
 *     carry one, and the absent form is byte-identical to the pre-slot
 *     shape (the builder adds the key by conditional spread, never as an
 *     explicitly-undefined key, which strict JCS would render as null).
 *   - signature: 128-hex Ed25519; '' in the unsigned/canonical shape.
 */
export interface ContextProvenanceAttestation {
  version: 'cpa/0.1'
  action_ref: string
  producer_did: string
  producer_pubkey: string
  attested_at: string
  mode: DisclosureMode
  partitions: CpaPartition[]
  root: string
  /** Optional hash-bound reference to an external producer attestation
   *  (an EAT, a TEE quote, a vendor report). When present it sits inside
   *  the signed bytes. APS does not parse or evaluate the attestation;
   *  see src/v2/producer-attestation. */
  producer_attestation?: import('../producer-attestation/types.js').CpaProducerAttestationRef
  signature: string
}

/**
 * Unsigned CPA shape: every field of ContextProvenanceAttestation, with
 * signature pinned to the empty string. These are the bytes-under-
 * signature once passed through canonicalizeJCS.
 */
export type UnsignedCPA = Omit<ContextProvenanceAttestation, 'signature'> & { signature: '' }

/**
 * Structured verifier reason codes. The Phase 0 verifier emits a subset
 * (the core checks); the remainder are reserved for Phase 1 (inclusion
 * proofs, content-ref membership, mutual binding against receipts).
 */
export type CpaReasonCode =
  | 'SHAPE_INVALID'
  | 'SIGNATURE_INVALID'
  | 'KEY_NOT_ACTIVE'
  | 'DID_MISMATCH'
  | 'ACTION_REF_MISMATCH'
  | 'CPA_REF_MISMATCH'
  | 'CONTENT_REF_MISMATCH'
  | 'PARTITION_ROOT_MISMATCH'
  | 'ROOT_MISMATCH'
  | 'CARDINALITY_MISMATCH'
  | 'INCLUSION_PROOF_INVALID'
  | 'DISCLOSURE_POLICY_UNSATISFIED'
  | 'DOMAIN_TAG_CONFUSION'

/**
 * Result of verifying a CPA.
 *   - valid: reasons.length === 0 (fail-closed).
 *   - reasons: every structured reason collected during verification.
 *   - completeness: 'PROVEN' for a valid full-set CPA (the disclosed
 *     leaves reconstruct the signed root); 'NOT_PROVEN' otherwise (a
 *     valid inclusion CPA carries counts, not a full reconstruction).
 */
export interface CpaVerifyResult {
  valid: boolean
  reasons: CpaReasonCode[]
  completeness: 'PROVEN' | 'NOT_PROVEN'
}
