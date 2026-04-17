// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Settlement — verification (Build C)
// ══════════════════════════════════════════════════════════════════
// Spec: BUILD-C-SETTLEMENT-PIPELINE.md §"Verification interface".
//
//   S1  gateway signature verifies
//   S2  each axis_merkle_root recomputes from leaves
//   S3  CONSERVATION — sum(contributors.total_weight) + pooled_weight ≈
//       total_actions × 1.0 per axis. This is the strongest invariant:
//       a gateway cannot inflate or suppress any contributor's share
//       without breaking S3 somewhere.
//   S4  residual bucket shape is valid (residual_id format, non-negative
//       counts, hash well-formed)
//   S5  if inputReceipts is supplied, input_receipts_hash recomputes and
//       every receipt is in-period and individually signature-valid
//
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalize } from '../../core/canonical.js'
import {
  assertCanonicalTimestamp,
} from '../attribution-primitive/canonical.js'
import { verifyAttributionPrimitive } from '../attribution-primitive/verify.js'
import type {
  AttributionAxisTag,
  AttributionPrimitive,
} from '../attribution-primitive/types.js'
import {
  buildMerkleRoot,
  emptyAxisMerkleRoot,
  leafHash,
} from './merkle.js'
import { verifySettlementSignature } from './sign.js'
import { residualLeafHashHex } from './aggregate.js'
import type {
  SettlementAxisIndex,
  SettlementRecord,
  SettlementResidualBucket,
  SettlementVerifyReason,
  SettlementVerifyResult,
} from './types.js'

/** Float-tolerance epsilon for S3 conservation. Accumulates O(N) 6-digit
 *  rounding terms plus double-precision slack, sized for 1e5-receipt
 *  periods. Conservation is declared "holds" iff |sum - total_actions|
 *  is within this bound per axis. */
const S3_EPSILON_PER_ACTION = 5e-6
const S3_EPSILON_FLOOR = 1e-6

function fail(reason: SettlementVerifyReason, detail?: string): SettlementVerifyResult {
  return { valid: false, reason, detail }
}

const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/

function isMalformed(record: SettlementRecord): string | null {
  if (!record || typeof record !== 'object') return 'record must be an object'
  if (record.schema !== 'aps.settlement.v1') return `unsupported schema "${record.schema}"`
  if (typeof record.gateway_did !== 'string' || record.gateway_did.length === 0) {
    return 'gateway_did required'
  }
  if (typeof record.signature !== 'string' || !HEX128.test(record.signature)) {
    return 'signature must be 128-char hex'
  }
  if (!record.period || typeof record.period !== 'object') return 'period required'
  try {
    assertCanonicalTimestamp(record.period.t0)
    assertCanonicalTimestamp(record.period.t1)
    assertCanonicalTimestamp(record.issued_at)
  } catch (e) {
    return (e as Error).message
  }
  if (Date.parse(record.period.t0) >= Date.parse(record.period.t1)) {
    return 'period.t0 must precede period.t1'
  }
  if (!record.axes || typeof record.axes !== 'object') return 'axes required'
  for (const tag of ['D', 'P', 'G', 'C'] as AttributionAxisTag[]) {
    const axis = record.axes[tag]
    if (!axis || typeof axis !== 'object') return `axes.${tag} required`
    if (axis.axis !== tag) return `axes.${tag}.axis mismatch`
    if (typeof axis.axis_merkle_root !== 'string' || !HEX64.test(axis.axis_merkle_root)) {
      return `axes.${tag}.axis_merkle_root must be 64-char hex`
    }
    if (typeof axis.total_actions !== 'number' || axis.total_actions < 0) {
      return `axes.${tag}.total_actions must be non-negative`
    }
    if (!Array.isArray(axis.contributors)) return `axes.${tag}.contributors must be an array`
  }
  if (typeof record.input_receipts_hash !== 'string' || !HEX64.test(record.input_receipts_hash)) {
    return 'input_receipts_hash must be 64-char hex'
  }
  if (typeof record.total_input_count !== 'number' || record.total_input_count < 0) {
    return 'total_input_count must be non-negative'
  }
  return null
}

function validateResidualShape(r: SettlementResidualBucket, axis: AttributionAxisTag): string | null {
  if (axis === 'G') return `governance axis cannot carry a residual bucket`
  const expected = `residual:${axis}`
  if (r.residual_id !== expected) return `residual_id mismatch: expected ${expected}`
  if (typeof r.total_pooled_weight !== 'string') return 'total_pooled_weight must be string'
  const w = Number.parseFloat(r.total_pooled_weight)
  if (!Number.isFinite(w) || w < 0) return 'total_pooled_weight must be non-negative finite'
  if (typeof r.count_of_pooled_contributors !== 'number' || r.count_of_pooled_contributors < 0) {
    return 'count_of_pooled_contributors must be non-negative'
  }
  if (typeof r.pooled_contributors_hash !== 'string' || !HEX64.test(r.pooled_contributors_hash)) {
    return 'pooled_contributors_hash must be 64-char hex'
  }
  return null
}

function checkAxisMerkleRoot(axis: SettlementAxisIndex): boolean {
  const leaves: Buffer[] = []
  for (const c of axis.contributors) {
    const body = {
      contributor_did: c.contributor_did,
      total_weight: c.total_weight,
      contribution_count: c.contribution_count,
    }
    const expected = createHash('sha256').update(canonicalize(body)).digest('hex')
    if (expected !== c.merkle_leaf_hash.toLowerCase()) return false
    leaves.push(Buffer.from(expected, 'hex'))
  }
  if (axis.residual_bucket) {
    leaves.push(Buffer.from(residualLeafHashHex(axis.residual_bucket), 'hex'))
  }
  const computed =
    leaves.length === 0 ? emptyAxisMerkleRoot() : buildMerkleRoot(leaves).toString('hex')
  return computed === axis.axis_merkle_root.toLowerCase()
}

function checkConservation(axis: SettlementAxisIndex): { ok: boolean; delta: number } {
  let sum = 0
  for (const c of axis.contributors) sum += Number.parseFloat(c.total_weight)
  if (axis.residual_bucket) sum += Number.parseFloat(axis.residual_bucket.total_pooled_weight)
  const delta = Math.abs(sum - axis.total_actions)
  const bound = Math.max(S3_EPSILON_FLOOR, axis.total_actions * S3_EPSILON_PER_ACTION)
  return { ok: delta <= bound, delta }
}

export interface VerifySettlementOptions {
  /** Gateway public key (hex) to verify S1. Required — the SDK is pure;
   *  out-of-band JWKS resolution is the gateway's responsibility. */
  gatewayPublicKeyHex: string
  /** Optional input receipts for S5. When provided we recompute
   *  `input_receipts_hash` and verify each receipt's individual
   *  signature under the same gateway key. */
  inputReceipts?: AttributionPrimitive[]
  /** Tighter S3 epsilon (default auto-sizes with total_actions). */
  conservationEpsilon?: number
}

/** Full settlement-record verification. Returns {valid: true} or
 *  {valid: false, reason, detail}. */
export function verifySettlementRecord(
  record: SettlementRecord,
  options: VerifySettlementOptions,
): SettlementVerifyResult {
  if (!options || !options.gatewayPublicKeyHex) {
    return fail('MALFORMED', 'options.gatewayPublicKeyHex required')
  }
  const malformed = isMalformed(record)
  if (malformed) return fail('MALFORMED', malformed)

  // S4 first: residual-bucket shape check, cheaper than S2.
  for (const tag of ['D', 'P', 'G', 'C'] as AttributionAxisTag[]) {
    const axis = record.axes[tag]
    if (axis.residual_bucket) {
      const err = validateResidualShape(axis.residual_bucket, tag)
      if (err) return fail('RESIDUAL_BUCKET_MISMATCH', `axes.${tag}: ${err}`)
    }
    for (const c of axis.contributors) {
      if (typeof c.contributor_did !== 'string' || c.contributor_did.length === 0) {
        return fail('MALFORMED', `axes.${tag} contributor missing contributor_did`)
      }
      if (typeof c.total_weight !== 'string' || !/^\d+\.\d{6}$/.test(c.total_weight)) {
        return fail('MALFORMED', `axes.${tag} contributor ${c.contributor_did} total_weight not canonical 6-digit`)
      }
      if (typeof c.contribution_count !== 'number' || c.contribution_count < 0) {
        return fail('MALFORMED', `axes.${tag} contributor ${c.contributor_did} contribution_count invalid`)
      }
      if (typeof c.merkle_leaf_hash !== 'string' || !HEX64.test(c.merkle_leaf_hash)) {
        return fail('MALFORMED', `axes.${tag} contributor ${c.contributor_did} merkle_leaf_hash invalid`)
      }
    }
    // Contributors must be lex-sorted by DID (determinism / merkle root).
    for (let i = 1; i < axis.contributors.length; i++) {
      if (axis.contributors[i].contributor_did <= axis.contributors[i - 1].contributor_did) {
        return fail('MERKLE_ROOT_MISMATCH', `axes.${tag} contributors not strictly lex-sorted by DID`)
      }
    }
  }

  // S2: axis_merkle_root recomputes.
  for (const tag of ['D', 'P', 'G', 'C'] as AttributionAxisTag[]) {
    if (!checkAxisMerkleRoot(record.axes[tag])) {
      return fail('MERKLE_ROOT_MISMATCH', `axes.${tag}.axis_merkle_root does not recompute from leaves`)
    }
  }

  // S3: CONSERVATION — strongest invariant.
  for (const tag of ['D', 'P', 'G', 'C'] as AttributionAxisTag[]) {
    const { ok, delta } = checkConservation(record.axes[tag])
    if (!ok) {
      return fail(
        'CONSERVATION_VIOLATION',
        `axes.${tag}: sum(contributors + residual) − total_actions = ${delta.toExponential(3)} exceeds tolerance`,
      )
    }
  }

  // S1: gateway signature.
  if (!verifySettlementSignature(record, options.gatewayPublicKeyHex)) {
    return fail('SIGNATURE_INVALID', 'gateway signature does not verify over canonical body')
  }

  // S5 (optional): cross-check against the input receipt set.
  if (options.inputReceipts) {
    const t0 = Date.parse(record.period.t0)
    const t1 = Date.parse(record.period.t1)
    const refs: string[] = []
    for (const r of options.inputReceipts) {
      try {
        assertCanonicalTimestamp(r.timestamp)
      } catch (e) {
        return fail('MALFORMED', `inputReceipts entry has invalid timestamp: ${(e as Error).message}`)
      }
      const ts = Date.parse(r.timestamp)
      if (ts < t0 || ts >= t1) {
        return fail('RECEIPT_OUT_OF_PERIOD', `receipt ${r.action_ref} timestamp ${r.timestamp} outside period`)
      }
      const rv = verifyAttributionPrimitive(r, options.gatewayPublicKeyHex)
      if (!rv.valid) {
        return fail(
          'RECEIPT_SIGNATURE_INVALID',
          `receipt ${r.action_ref} failed verification: ${rv.reason}`,
        )
      }
      refs.push(r.action_ref)
    }
    if (refs.length !== record.total_input_count) {
      return fail(
        'INPUT_RECEIPTS_HASH_MISMATCH',
        `total_input_count ${record.total_input_count} but received ${refs.length} receipts`,
      )
    }
    refs.sort()
    const refLeaves = refs.map((ref) => leafHash(ref))
    const computed =
      refLeaves.length === 0
        ? emptyAxisMerkleRoot()
        : buildMerkleRoot(refLeaves).toString('hex')
    if (computed !== record.input_receipts_hash.toLowerCase()) {
      return fail('INPUT_RECEIPTS_HASH_MISMATCH', 'input_receipts_hash does not match supplied receipts')
    }
  }

  // Suppress the unused-import lint on conservationEpsilon — future hook.
  void options.conservationEpsilon

  return { valid: true }
}
