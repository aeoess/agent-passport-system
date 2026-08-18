// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: producer (buildCPA) + content address (computeCpaRef)
// ══════════════════════════════════════════════════════════════════
// buildCPA groups a flat list of ContextItems by channel, builds one
// partition per non-empty channel, computes the top root over present
// partition roots in CHANNEL_ORDER, derives producer_pubkey from the
// private key, and signs the JCS-canonical form with signature emptied
// (the same canonical-bytes-then-sign pattern used by memory_provenance
// and instruction-provenance).
//
// computeCpaRef content-addresses the FULLY SIGNED object under SIGN_TAG.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../crypto/keys.js'

import {
  CHANNEL_ORDER,
  type ContextChannel,
  type ContextItem,
  type CpaPartition,
  type DisclosureMode,
  type ContextProvenanceAttestation,
  type UnsignedCPA,
} from './types.js'

import {
  SIGN_TAG,
  buildPartitionRootBytes,
  buildInclusionProof,
  buildTopRootBytes,
  bytesToHex,
  utf8Bytes,
  type InclusionProof,
} from './merkle.js'

/** Input to buildCPA. Items are a flat list across all channels; each
 *  item's channel decides its partition. */
export interface BuildCpaInput {
  privateKey: string
  action_ref: string
  producer_did: string
  attested_at: string
  mode: DisclosureMode
  items: ContextItem[]
  /**
   * Inclusion-mode-only selection policy: the set of ctx_ids to DISCLOSE.
   * For each disclosed ctx_id, buildCPA includes that leaf (with its
   * `content` if the input item carried one) in its partition's `leaves`
   * and adds the leaf's inclusion proof to `inclusion_proofs`. ctx_ids not
   * present in any partition are ignored. Convention: a single flat set of
   * ctx_ids across all channels (ctx_id is the disclosure selector).
   *
   * Ignored in full-set mode (full-set always discloses ALL leaves).
   * Omitted/empty in inclusion mode preserves Phase-0 count-only behavior
   * (no `leaves`, hidden_leaf_count = leaf_count).
   */
  disclose?: Set<string> | string[]
  /**
   * Optional hash-bound reference to an external producer attestation,
   * carried inside the signed bytes when supplied. Added to the unsigned
   * shape by CONDITIONAL SPREAD, never as an explicitly-undefined key
   * (strict JCS would render that as null and change the bytes); an
   * omitting CPA keeps its exact prior canonical form. See
   * src/v2/producer-attestation.
   */
  producer_attestation?: import('../producer-attestation/types.js').CpaProducerAttestationRef
}

/**
 * Build and sign a CPA from a flat list of context items.
 *
 * full-set: each present partition carries leaves = ALL its leaves and no
 *   context_profile.
 * inclusion: each present partition carries context_profile
 *   { channel, hidden_leaf_count = leaf_count - disclosed }. Phase 0
 *   builds inclusion CPAs count-only (no disclosed leaves, so
 *   hidden_leaf_count = leaf_count); Phase 1 adds disclosed subsets with
 *   inclusion proofs.
 *
 * producer_pubkey is derived from the private key. The signature covers
 * canonicalizeJCS({...cpa, signature:''}).
 */
export function buildCPA(input: BuildCpaInput): ContextProvenanceAttestation {
  const { privateKey, action_ref, producer_did, attested_at, mode, items } = input

  // Normalize the inclusion-mode disclosure selector to a Set of ctx_ids.
  const disclose: Set<string> = input.disclose
    ? input.disclose instanceof Set
      ? input.disclose
      : new Set(input.disclose)
    : new Set<string>()

  // Group items by channel, preserving every item.
  const byChannel = new Map<ContextChannel, ContextItem[]>()
  for (const item of items) {
    const bucket = byChannel.get(item.channel)
    if (bucket) bucket.push(item)
    else byChannel.set(item.channel, [item])
  }

  // Build one partition per present channel, in CHANNEL_ORDER.
  const partitions: CpaPartition[] = []
  const partitionRootBytes: Uint8Array[] = []

  for (const channel of CHANNEL_ORDER) {
    const leaves = byChannel.get(channel)
    if (!leaves || leaves.length === 0) continue // empty partitions omitted

    // partition_root is over ALL leaves, unchanged in either mode.
    const rootBytes = buildPartitionRootBytes(leaves)
    partitionRootBytes.push(rootBytes)
    const partition_root = bytesToHex(rootBytes)
    const leaf_count = leaves.length

    if (mode === 'full-set') {
      partitions.push({ channel, partition_root, leaf_count, leaves: [...leaves] })
    } else {
      // inclusion mode. Disclose the chosen subset (if any) for this
      // partition: include each disclosed leaf (with its content if it
      // carried one) and its inclusion proof. Leaves not selected stay
      // hidden (count-only).
      const disclosedLeaves: ContextItem[] = []
      const inclusion_proofs: InclusionProof[] = []
      for (const leaf of leaves) {
        if (disclose.has(leaf.ctx_id)) {
          disclosedLeaves.push({ ...leaf })
          inclusion_proofs.push(buildInclusionProof(leaves, leaf.ctx_id))
        }
      }
      const disclosedCount = disclosedLeaves.length

      const partition: CpaPartition = {
        channel,
        partition_root,
        leaf_count,
        context_profile: { channel, hidden_leaf_count: leaf_count - disclosedCount },
      }
      if (disclosedCount > 0) {
        // Disclosed leaves are emitted in the FROZEN ctx_id sort so the
        // wire order is deterministic and matches the tree ordering.
        disclosedLeaves.sort((a, b) =>
          a.ctx_id < b.ctx_id ? -1 : a.ctx_id > b.ctx_id ? 1 : 0,
        )
        inclusion_proofs.sort((a, b) =>
          a.ctx_id < b.ctx_id ? -1 : a.ctx_id > b.ctx_id ? 1 : 0,
        )
        partition.leaves = disclosedLeaves
        partition.inclusion_proofs = inclusion_proofs
      }
      partitions.push(partition)
    }
  }

  const root = bytesToHex(buildTopRootBytes(partitionRootBytes))

  const producer_pubkey = publicKeyFromPrivate(privateKey)

  const unsigned: UnsignedCPA = {
    version: 'cpa/0.1',
    action_ref,
    producer_did,
    producer_pubkey,
    attested_at,
    mode,
    partitions,
    root,
    // Conditional spread, not an undefined-valued key. An explicitly-set
    // undefined is rejected by the canonicalizer as of #101, and before that it
    // was rendered as null; either way it would not be the intended bytes.
    ...(input.producer_attestation !== undefined
      ? { producer_attestation: input.producer_attestation }
      : {}),
    signature: '',
  }

  const bytes = canonicalizeJCS(unsigned)
  const signature = sign(bytes, privateKey)

  return { ...unsigned, signature }
}

/**
 * Content address over the FULLY SIGNED CPA:
 *   cpa_ref = sha256( utf8(SIGN_TAG) || utf8(canonicalizeJCS(signedCpa)) )
 * Returns 64-hex lowercase.
 */
export function computeCpaRef(signedCpa: ContextProvenanceAttestation): string {
  const h = createHash('sha256')
  h.update(utf8Bytes(SIGN_TAG))
  h.update(utf8Bytes(canonicalizeJCS(signedCpa)))
  return h.digest('hex')
}

// ══════════════════════════════════════════════════════════════════
// Mutual binding helpers (lean, module-local; see BINDING.md)
// ══════════════════════════════════════════════════════════════════
// CPA is a pure protocol primitive. It does NOT own receipt orchestration
// or any gateway state. To bind a CPA into a decision/completion receipt,
// a caller carries the CPA's content address (cpa_ref) as a field on the
// receipt. These helpers compute and attach that field WITHOUT pulling any
// receipt-signing or gateway logic into the primitive.

/**
 * Carry the content address of a signed CPA as a one-field object, ready
 * to spread onto a receipt body BEFORE the receipt is signed. The verifier
 * later re-derives computeCpaRef(cpa) and checks equality against the
 * receipt's cpa_ref (the receipt -> CPA binding direction).
 */
export function carryCpaRef(cpa: ContextProvenanceAttestation): { cpa_ref: string } {
  return { cpa_ref: computeCpaRef(cpa) }
}

/**
 * Pure binder: return a NEW object equal to `receipt` plus a `cpa_ref`
 * field. Does not mutate the input and does not (re)sign anything; the
 * caller signs the resulting body with its own receipt machinery. Keeping
 * this pure keeps the primitive offline and side-effect free.
 */
export function bindCpaRefToReceipt<T extends object>(
  receipt: T,
  cpa_ref: string,
): T & { cpa_ref: string } {
  return { ...receipt, cpa_ref }
}
