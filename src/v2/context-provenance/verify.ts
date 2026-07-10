// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: offline verifier (Phase 0 core checks + Phase 1 stubs)
// ══════════════════════════════════════════════════════════════════
// The verifier is OFFLINE: it takes (cpa, didDoc, optional receipt,
// optional opts) and uses ONLY those plus public material. No network, no
// private keys, no gateway state. It is fail-closed: any failed check
// adds a structured reason; valid = reasons.length === 0.
//
// Phase 0 implements, in order: (1) strict shape decode, (2) DID binding,
// (3) signature, (4) key-active-at, (5) full-set Merkle recompute. Phase 1
// fills the clearly-marked stubs (inclusion-proof membership, content_ref
// check, action_ref / cpa_ref mutual binding against a receipt). The
// reason-code enum and the verifyCPA signature are frozen now so Phase 1
// only fills in bodies.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import { verify } from '../../crypto/keys.js'
import { isKeyActive, verifyRotationChain } from '../../core/key-rotation.js'
import { actionRefsMatch } from '../../core/action-ref.js'
import type { RotatableDIDDocument } from '../../types/passport.js'

import {
  CHANNEL_ORDER,
  type ContextChannel,
  type ContextItem,
  type CpaPartition,
  type CpaReasonCode,
  type CpaVerifyResult,
  type ContextProvenanceAttestation,
} from './types.js'

import {
  buildPartitionRootBytes,
  buildTopRootBytes,
  verifyInclusionProof,
  bytesToHex,
  hexToBytes,
  type InclusionProof,
} from './merkle.js'

import { computeCpaRef } from './cpa.js'

/**
 * Receipt carried for mutual binding. If `action_ref` is present, the CPA's
 * action_ref must match it (CPA -> action direction). If `cpa_ref` is
 * present, computeCpaRef(cpa) must equal it (receipt -> CPA direction). A
 * receipt may carry either, both, or neither; absent fields are not checked.
 */
export interface CpaReceipt {
  action_ref?: string
  cpa_ref?: string
}

export interface CpaVerifyOptions {
  /** Reserved: clock reference. Not consulted by the current checks. */
  now?: Date
  /**
   * Disclosure-policy selector. When true, the disclosed evidence MUST
   * include leaf content: the CPA must disclose at least one leaf, and
   * EVERY disclosed leaf (across all partitions) must carry a `content`
   * field. A CPA that discloses no leaves at all, or any disclosed leaf
   * that lacks `content`, fails with DISCLOSURE_POLICY_UNSATISFIED. This
   * is the "existence-only disclosure under a content-requiring policy"
   * rejection. Default (undefined/false) imposes no content requirement;
   * count-only and content-bearing disclosures both pass.
   */
  requireContent?: boolean
}

const HEX_64 = /^[0-9a-f]{64}$/
const HEX_128 = /^[0-9a-f]{128}$/
const CHANNEL_SET = new Set<string>(CHANNEL_ORDER)
const CHANNEL_INDEX = new Map<string, number>(CHANNEL_ORDER.map((c, i) => [c, i]))

/**
 * Verify a CPA against a DID document. Offline, fail-closed.
 *
 * @param cpa     the signed CPA (untrusted input; shape is checked).
 * @param didDoc  the producer's rotation-capable DID document.
 * @param receipt OPTIONAL receipt for Phase 1 mutual binding (unused in Phase 0).
 * @param opts    OPTIONAL verifier options (unused in Phase 0 core).
 */
export function verifyCPA(
  cpa: unknown,
  didDoc: RotatableDIDDocument,
  receipt?: CpaReceipt,
  opts?: CpaVerifyOptions,
): CpaVerifyResult {
  const reasons: CpaReasonCode[] = []
  // Default completeness; promoted to PROVEN only for a valid full-set CPA.
  let completeness: CpaVerifyResult['completeness'] = 'NOT_PROVEN'

  // ── 1. Strict decode / shape ───────────────────────────────────
  const shape = decodeShape(cpa)
  if (!shape.ok) {
    reasons.push(...shape.reasons)
    // Without a well-formed shape, no further check is meaningful.
    return { valid: false, reasons, completeness }
  }
  const c = shape.value

  // ── 2. DID binding ─────────────────────────────────────────────
  // Validate the DID-document SHAPE, not just `didDoc.id`. A malformed doc
  // (null, undefined, non-object, array, {}, or one whose rotationLog /
  // verificationMethod / authentication are not arrays) must NOT be
  // dereferenced by the key-active step below, or the verifier throws
  // instead of failing closed. verifyRotationChain iterates rotationLog and
  // isKeyActive reads verificationMethod and authentication, so all three
  // must be arrays for the step to run safely. A doc that fails the shape
  // check, or whose id does not bind to producer_did, is a DID_MISMATCH.
  const docRec = (typeof didDoc === 'object' && didDoc !== null && !Array.isArray(didDoc))
    ? (didDoc as { rotationLog?: unknown; verificationMethod?: unknown; authentication?: unknown })
    : undefined
  const docOk = !!docRec
    && Array.isArray(docRec.rotationLog)
    && Array.isArray(docRec.verificationMethod)
    && Array.isArray(docRec.authentication)
  if (!docOk || didDoc.id !== c.producer_did) {
    reasons.push('DID_MISMATCH')
  }

  // ── 3. Signature ───────────────────────────────────────────────
  const signingBytes = canonicalizeJCS({ ...c, signature: '' })
  if (!verify(signingBytes, c.signature, c.producer_pubkey)) {
    reasons.push('SIGNATURE_INVALID')
  }

  // ── 4. Key active at attested_at ───────────────────────────────
  // Guard the rotation-chain / key-active calls so they only run on a
  // well-shaped doc. A malformed doc yields KEY_NOT_ACTIVE (alongside the
  // DID_MISMATCH above) rather than a thrown TypeError.
  const attestedAt = new Date(c.attested_at)
  const chainOk = docOk && verifyRotationChain(didDoc)
  const active = chainOk && isKeyActive(didDoc, c.producer_pubkey, attestedAt)
  if (!active) {
    reasons.push('KEY_NOT_ACTIVE')
  }

  // ── 5. Merkle recompute ────────────────────────────────────────
  if (c.mode === 'full-set') {
    recomputeFullSet(c, reasons)
  } else {
    recomputeInclusion(c, reasons)
  }

  // ── 6. Content binding (both modes) ────────────────────────────
  // For every disclosed leaf that carries `content`, the base64 bytes
  // must hash (sha256) to content_ref AND byte_len must equal their
  // length. A disclosed leaf without `content` is not checked here.
  checkContentBinding(c, reasons)

  // ── 7. Mutual binding against a receipt ────────────────────────
  if (receipt) {
    if (typeof receipt.action_ref === 'string') {
      if (!actionRefsMatch(c.action_ref, receipt.action_ref)) {
        reasons.push('ACTION_REF_MISMATCH')
      }
    }
    if (typeof receipt.cpa_ref === 'string') {
      if (computeCpaRef(c) !== receipt.cpa_ref) {
        reasons.push('CPA_REF_MISMATCH')
      }
    }
  }

  // ── 8. Disclosure policy (opts.requireContent) ─────────────────
  if (opts?.requireContent === true) {
    checkContentRequiringPolicy(c, reasons)
  }

  const valid = reasons.length === 0
  if (valid && c.mode === 'full-set') {
    // A valid full-set CPA reconstructs the signed root from disclosed
    // leaves: the disclosed evidence is complete under its declaration.
    completeness = 'PROVEN'
  }
  // Inclusion completeness stays NOT_PROVEN by design (counts plus a
  // partial selection, not a full reconstruction).
  return { valid, reasons, completeness }
}

// ── Shape decode ──────────────────────────────────────────────────

type DecodeResult =
  | { ok: true; value: ContextProvenanceAttestation }
  | { ok: false; reasons: CpaReasonCode[] }

function decodeShape(input: unknown): DecodeResult {
  const reasons: CpaReasonCode[] = []
  const fail = (): DecodeResult => ({ ok: false, reasons: reasons.length ? reasons : ['SHAPE_INVALID'] })

  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    reasons.push('SHAPE_INVALID')
    return fail()
  }
  const v = input as Record<string, unknown>

  if (v.version !== 'cpa/0.1') reasons.push('SHAPE_INVALID')
  if (typeof v.action_ref !== 'string' || !HEX_64.test(v.action_ref)) reasons.push('SHAPE_INVALID')
  if (typeof v.producer_did !== 'string' || v.producer_did.length === 0) reasons.push('SHAPE_INVALID')
  if (typeof v.producer_pubkey !== 'string' || !HEX_64.test(v.producer_pubkey)) reasons.push('SHAPE_INVALID')
  if (typeof v.attested_at !== 'string' || !isIso8601(v.attested_at)) reasons.push('SHAPE_INVALID')
  if (v.mode !== 'full-set' && v.mode !== 'inclusion') reasons.push('SHAPE_INVALID')
  if (typeof v.root !== 'string' || !HEX_64.test(v.root)) reasons.push('SHAPE_INVALID')
  if (typeof v.signature !== 'string' || !HEX_128.test(v.signature)) reasons.push('SHAPE_INVALID')

  if (!Array.isArray(v.partitions)) {
    reasons.push('SHAPE_INVALID')
    return fail()
  }

  let lastChannelIndex = -1
  const seenChannels = new Set<string>()
  const mode = v.mode

  for (const p of v.partitions as unknown[]) {
    if (typeof p !== 'object' || p === null || Array.isArray(p)) {
      reasons.push('SHAPE_INVALID')
      continue
    }
    const part = p as Record<string, unknown>

    // channel ∈ the 8 and globally sorted by CHANNEL_ORDER with no repeats.
    if (typeof part.channel !== 'string' || !CHANNEL_SET.has(part.channel)) {
      reasons.push('SHAPE_INVALID')
    } else {
      const idx = CHANNEL_INDEX.get(part.channel)!
      if (idx <= lastChannelIndex || seenChannels.has(part.channel)) {
        reasons.push('SHAPE_INVALID') // out of CHANNEL_ORDER or duplicate partition
      }
      lastChannelIndex = Math.max(lastChannelIndex, idx)
      seenChannels.add(part.channel)
    }

    if (typeof part.partition_root !== 'string' || !HEX_64.test(part.partition_root)) {
      reasons.push('SHAPE_INVALID')
    }
    if (typeof part.leaf_count !== 'number' || !Number.isInteger(part.leaf_count) || part.leaf_count < 1) {
      reasons.push('SHAPE_INVALID')
    }

    // context_profile present iff mode === 'inclusion'.
    const hasProfile = part.context_profile !== undefined
    if (mode === 'inclusion' && !hasProfile) reasons.push('SHAPE_INVALID')
    if (mode === 'full-set' && hasProfile) reasons.push('SHAPE_INVALID')
    if (hasProfile) {
      const prof = part.context_profile
      if (typeof prof !== 'object' || prof === null) {
        reasons.push('SHAPE_INVALID')
      } else {
        const pr = prof as Record<string, unknown>
        if (pr.channel !== part.channel) reasons.push('SHAPE_INVALID')
        if (typeof pr.hidden_leaf_count !== 'number' || !Number.isInteger(pr.hidden_leaf_count) || pr.hidden_leaf_count < 0) {
          reasons.push('SHAPE_INVALID')
        }
      }
    }

    // leaves: optional in inclusion, REQUIRED (= ALL leaves) in full-set.
    if (mode === 'full-set' && part.leaves === undefined) {
      reasons.push('SHAPE_INVALID')
    }
    if (part.leaves !== undefined) {
      if (!Array.isArray(part.leaves)) {
        reasons.push('SHAPE_INVALID')
      } else {
        const ctxIds = new Set<string>()
        for (const leaf of part.leaves as unknown[]) {
          if (!isContextItemShape(leaf, part.channel as ContextChannel)) {
            reasons.push('SHAPE_INVALID')
            continue
          }
          const li = leaf as ContextItem
          if (ctxIds.has(li.ctx_id)) {
            // duplicate ctx_id within a partition
            reasons.push('DOMAIN_TAG_CONFUSION')
          }
          ctxIds.add(li.ctx_id)
        }
      }
    }

    // inclusion_proofs: only legal in inclusion mode; structural shape is
    // checked here so the verifier never folds malformed proof material.
    if (part.inclusion_proofs !== undefined) {
      if (mode !== 'inclusion') {
        reasons.push('SHAPE_INVALID') // proofs are inclusion-mode-only
      }
      if (!Array.isArray(part.inclusion_proofs)) {
        reasons.push('SHAPE_INVALID')
      } else {
        for (const proof of part.inclusion_proofs as unknown[]) {
          if (!isInclusionProofShape(proof)) reasons.push('SHAPE_INVALID')
        }
      }
    }
  }

  // producer_attestation: OPTIONAL additive slot. Absent is fine and keeps
  // the pre-slot bytes. Present-but-malformed is SHAPE_INVALID (fail
  // closed): a reference that cannot say what it binds is not carried.
  if (v.producer_attestation !== undefined) {
    const pa = v.producer_attestation
    if (typeof pa !== 'object' || pa === null || Array.isArray(pa)) {
      reasons.push('SHAPE_INVALID')
    } else {
      const p = pa as Record<string, unknown>
      if (typeof p.format !== 'string' || p.format.trim().length === 0) reasons.push('SHAPE_INVALID')
      if (typeof p.content_hash !== 'string' || !HEX_64.test(p.content_hash)) reasons.push('SHAPE_INVALID')
      if (p.locator_uri !== undefined && (typeof p.locator_uri !== 'string' || p.locator_uri.length === 0)) {
        reasons.push('SHAPE_INVALID')
      }
      if (p.binding_note !== undefined && typeof p.binding_note !== 'string') reasons.push('SHAPE_INVALID')
    }
  }

  if (reasons.length > 0) return fail()
  return { ok: true, value: v as unknown as ContextProvenanceAttestation }
}

function isContextItemShape(leaf: unknown, partitionChannel: ContextChannel): boolean {
  if (typeof leaf !== 'object' || leaf === null || Array.isArray(leaf)) return false
  const l = leaf as Record<string, unknown>
  if (typeof l.ctx_id !== 'string' || l.ctx_id.length === 0) return false
  if (typeof l.channel !== 'string' || l.channel !== partitionChannel) return false
  if (typeof l.content_ref !== 'string' || !HEX_64.test(l.content_ref)) return false
  if (typeof l.byte_len !== 'number' || !Number.isInteger(l.byte_len) || l.byte_len < 0) return false
  if (l.trust_tier !== undefined && typeof l.trust_tier !== 'string') return false
  if (l.content !== undefined && typeof l.content !== 'string') return false
  return true
}

function isInclusionProofShape(proof: unknown): boolean {
  if (typeof proof !== 'object' || proof === null || Array.isArray(proof)) return false
  const p = proof as Record<string, unknown>
  if (typeof p.ctx_id !== 'string' || p.ctx_id.length === 0) return false
  if (!Array.isArray(p.path)) return false
  for (const step of p.path as unknown[]) {
    if (typeof step !== 'object' || step === null || Array.isArray(step)) return false
    const s = step as Record<string, unknown>
    if (typeof s.sibling !== 'string' || !HEX_64.test(s.sibling)) return false
    if (s.side !== 'left' && s.side !== 'right') return false
  }
  return true
}

// ── Full-set Merkle recompute ─────────────────────────────────────

function recomputeFullSet(
  c: ContextProvenanceAttestation,
  reasons: CpaReasonCode[],
): void {
  const partitionRootBytes: Uint8Array[] = []

  for (const part of c.partitions) {
    const leaves = part.leaves as ContextItem[] // shape guarantees presence in full-set
    let recomputed: Uint8Array
    try {
      recomputed = buildPartitionRootBytes(leaves)
    } catch {
      // duplicate ctx_id or empty leaves surfaced during recompute
      reasons.push('PARTITION_ROOT_MISMATCH')
      continue
    }
    if (bytesToHex(recomputed) !== part.partition_root) {
      reasons.push('PARTITION_ROOT_MISMATCH')
    }
    if (leaves.length !== part.leaf_count) {
      reasons.push('CARDINALITY_MISMATCH')
    }
    // Use the producer-declared partition_root as the top-tree leaf so a
    // ROOT_MISMATCH is reported independently of a PARTITION_ROOT_MISMATCH.
    partitionRootBytes.push(hexToBytes(part.partition_root))
  }

  const recomputedTop = bytesToHex(buildTopRootBytes(partitionRootBytes))
  if (recomputedTop !== c.root) {
    reasons.push('ROOT_MISMATCH')
  }
}

// ── Inclusion-mode Merkle + cardinality ───────────────────────────

/**
 * Inclusion mode: the verifier does NOT recompute partition_root from the
 * full leaf set (it does not have it). Instead, for each partition that
 * discloses leaves, every disclosed leaf must carry a matching inclusion
 * proof that folds to the DECLARED partition_root. The declared
 * partition_roots are then folded in CHANNEL_ORDER to the declared top
 * root. Cardinality: hidden_leaf_count === leaf_count - disclosedCount.
 */
function recomputeInclusion(
  c: ContextProvenanceAttestation,
  reasons: CpaReasonCode[],
): void {
  const partitionRootBytes: Uint8Array[] = []

  for (const part of c.partitions) {
    const disclosed: ContextItem[] = part.leaves ?? []
    const proofs: InclusionProof[] = part.inclusion_proofs ?? []

    // Each disclosed ctx_id must have exactly one matching proof that
    // verifies against the DECLARED partition_root.
    const proofByCtx = new Map<string, InclusionProof>()
    for (const pr of proofs) proofByCtx.set(pr.ctx_id, pr)

    if (disclosed.length > 0 && proofs.length !== disclosed.length) {
      reasons.push('INCLUSION_PROOF_INVALID')
    }

    for (const leaf of disclosed) {
      const proof = proofByCtx.get(leaf.ctx_id)
      if (!proof || !verifyInclusionProof(leaf, proof, part.partition_root)) {
        reasons.push('INCLUSION_PROOF_INVALID')
      }
    }

    // A proof with no corresponding disclosed leaf is structurally wrong.
    for (const pr of proofs) {
      if (!disclosed.some(l => l.ctx_id === pr.ctx_id)) {
        reasons.push('INCLUSION_PROOF_INVALID')
      }
    }

    // Cardinality against the declared context_profile.
    const declaredHidden = part.context_profile?.hidden_leaf_count
    if (typeof declaredHidden !== 'number' || declaredHidden !== part.leaf_count - disclosed.length) {
      reasons.push('CARDINALITY_MISMATCH')
    }

    partitionRootBytes.push(hexToBytes(part.partition_root))
  }

  const recomputedTop = bytesToHex(buildTopRootBytes(partitionRootBytes))
  if (recomputedTop !== c.root) {
    reasons.push('ROOT_MISMATCH')
  }
}

// ── Content binding (both modes) ──────────────────────────────────

/**
 * For every disclosed leaf carrying `content`: decode the base64 to bytes,
 * require sha256(bytes) hex === content_ref AND byte_len === bytes.length.
 * A failure (bad base64, wrong hash, or wrong length) is CONTENT_REF_MISMATCH.
 * Disclosed leaves without `content` are not checked here (that is the
 * disclosure-policy concern, handled separately).
 */
function checkContentBinding(
  c: ContextProvenanceAttestation,
  reasons: CpaReasonCode[],
): void {
  let mismatch = false
  for (const part of c.partitions) {
    for (const leaf of part.leaves ?? []) {
      if (leaf.content === undefined) continue
      let bytes: Buffer
      try {
        bytes = decodeBase64Strict(leaf.content)
      } catch {
        mismatch = true
        continue
      }
      const digest = createHash('sha256').update(bytes).digest('hex')
      if (digest !== leaf.content_ref || leaf.byte_len !== bytes.length) {
        mismatch = true
      }
    }
  }
  if (mismatch) reasons.push('CONTENT_REF_MISMATCH')
}

/**
 * Strict base64 decode: re-encode the decoded bytes and require the
 * canonical base64 to round-trip, so malformed/loose base64 cannot slip a
 * mismatched-but-accepted content past the hash check.
 */
function decodeBase64Strict(s: string): Buffer {
  const bytes = Buffer.from(s, 'base64')
  if (bytes.toString('base64') !== s) {
    throw new Error('non-canonical base64')
  }
  return bytes
}

// ── Disclosure policy (opts.requireContent) ───────────────────────

/**
 * Content-requiring policy: the disclosed evidence must include content.
 * Reject (DISCLOSURE_POLICY_UNSATISFIED) when the CPA discloses NO leaves
 * at all, or when ANY disclosed leaf lacks a `content` field. This is the
 * existence-only-disclosure-under-a-content-requiring-policy rejection.
 */
function checkContentRequiringPolicy(
  c: ContextProvenanceAttestation,
  reasons: CpaReasonCode[],
): void {
  let disclosedAny = false
  let missingContent = false
  for (const part of c.partitions) {
    for (const leaf of part.leaves ?? []) {
      disclosedAny = true
      if (leaf.content === undefined) missingContent = true
    }
  }
  if (!disclosedAny || missingContent) {
    reasons.push('DISCLOSURE_POLICY_UNSATISFIED')
  }
}

// ── ISO 8601 gate (mirror of memory_provenance) ───────────────────

const ISO_8601 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/

function isIso8601(value: string): boolean {
  if (!ISO_8601.test(value)) return false
  return Number.isFinite(Date.parse(value))
}
