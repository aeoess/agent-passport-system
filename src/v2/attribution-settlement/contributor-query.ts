// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Attribution Settlement — contributor-query response (Build C)
// ══════════════════════════════════════════════════════════════════
// Spec: BUILD-C-SETTLEMENT-PIPELINE.md §"The contributor query".
//
// Given a signed SettlementRecord and a contributor DID, construct the
// per-axis proof bundle: for each axis where the contributor has a
// share, return the Merkle path from their leaf to that axis's root.
//
// Verification is fully self-contained: the response embeds the signed
// record so a third party can reproduce S1–S2 end-to-end with only the
// gateway public key.
// ══════════════════════════════════════════════════════════════════

import type { AttributionAxisTag } from '../attribution-primitive/types.js'
import {
  buildContributorMerklePath,
  verifyMerklePath,
} from './merkle.js'
import { residualLeafHashHex } from './aggregate.js'
import {
  settlementRecordHash,
  verifySettlementSignature,
} from './sign.js'
import { verifySettlementRecord } from './verify.js'
import type {
  ContributorQueryAxisBody,
  ContributorQueryResponse,
  SettlementAxisIndex,
  SettlementRecord,
  SettlementVerifyResult,
} from './types.js'

function buildAxisLeaves(axis: SettlementAxisIndex): Buffer[] {
  const leaves: Buffer[] = axis.contributors.map((c) => Buffer.from(c.merkle_leaf_hash, 'hex'))
  if (axis.residual_bucket) {
    leaves.push(Buffer.from(residualLeafHashHex(axis.residual_bucket), 'hex'))
  }
  return leaves
}

function findContributorIndex(
  axis: SettlementAxisIndex,
  contributorDid: string,
): number {
  for (let i = 0; i < axis.contributors.length; i++) {
    if (axis.contributors[i].contributor_did === contributorDid) return i
  }
  return -1
}

/** Build the per-contributor query response. Returns null if the
 *  contributor has no share on any axis — callers can surface that
 *  distinctly from "the gateway returned a response, here it is". */
export function buildContributorQueryResponse(
  record: SettlementRecord,
  contributorDid: string,
  opts?: { gateway_jwks?: string },
): ContributorQueryResponse | null {
  if (!contributorDid || typeof contributorDid !== 'string') {
    throw new Error('attribution-settlement: contributorDid required')
  }

  const per_axis: ContributorQueryResponse['per_axis'] = {}
  let anyFound = false

  for (const tag of ['D', 'P', 'G', 'C'] as AttributionAxisTag[]) {
    const axis = record.axes[tag]
    const idx = findContributorIndex(axis, contributorDid)
    if (idx < 0) continue
    const leaves = buildAxisLeaves(axis)
    const merkle_path = buildContributorMerklePath(leaves, idx)
    const body: ContributorQueryAxisBody = {
      total_weight: axis.contributors[idx].total_weight,
      contribution_count: axis.contributors[idx].contribution_count,
      leaf_index: idx,
      merkle_path,
      axis_root: axis.axis_merkle_root,
    }
    per_axis[tag] = body
    anyFound = true
  }

  if (!anyFound) return null

  const { signature: _unused, ...unsigned } = record
  void _unused

  return {
    settlement_record: record,
    settlement_record_hash: settlementRecordHash(unsigned as Omit<SettlementRecord, 'signature'>),
    contributor_did: contributorDid,
    per_axis,
    gateway_jwks: opts?.gateway_jwks,
  }
}

/** Verify a contributor-query response end-to-end. Checks:
 *
 *   (a) the embedded SettlementRecord passes S1–S4
 *   (b) each per_axis body's (leaf, leaf_index, merkle_path) reconstructs
 *       `axis_root`, which matches `record.axes[X].axis_merkle_root`
 *   (c) the claimed total_weight and contribution_count match the
 *       record's per-axis contributor row
 *   (d) settlement_record_hash recomputes
 *
 *  Returns the same discriminated result type as `verifySettlementRecord`. */
export function verifyContributorQueryResponse(
  response: ContributorQueryResponse,
  options: { gatewayPublicKeyHex: string },
): SettlementVerifyResult {
  if (!response || typeof response !== 'object') {
    return { valid: false, reason: 'MALFORMED', detail: 'response must be an object' }
  }
  if (!options || !options.gatewayPublicKeyHex) {
    return { valid: false, reason: 'MALFORMED', detail: 'options.gatewayPublicKeyHex required' }
  }
  if (!response.settlement_record) {
    return { valid: false, reason: 'MALFORMED', detail: 'settlement_record required' }
  }

  // (a) delegate to the settlement verifier for S1–S4.
  const inner = verifySettlementRecord(response.settlement_record, {
    gatewayPublicKeyHex: options.gatewayPublicKeyHex,
  })
  if (!inner.valid) return inner

  // Redundant sanity-check on the signature — verifySettlementRecord
  // already did this, but we want a distinct code path that future
  // refactors can't silently drop.
  if (!verifySettlementSignature(response.settlement_record, options.gatewayPublicKeyHex)) {
    return { valid: false, reason: 'SIGNATURE_INVALID' }
  }

  // (d) settlement_record_hash recomputes.
  const { signature: _unused, ...body } = response.settlement_record
  void _unused
  const expectedHash = settlementRecordHash(body as Omit<SettlementRecord, 'signature'>)
  if (expectedHash !== response.settlement_record_hash.toLowerCase()) {
    return { valid: false, reason: 'MERKLE_ROOT_MISMATCH', detail: 'settlement_record_hash mismatch' }
  }

  // (b, c) per-axis path and claim verification.
  for (const tag of Object.keys(response.per_axis) as AttributionAxisTag[]) {
    const axisBody = response.per_axis[tag]
    if (!axisBody) continue
    const axis = response.settlement_record.axes[tag]
    if (axisBody.axis_root.toLowerCase() !== axis.axis_merkle_root.toLowerCase()) {
      return { valid: false, reason: 'MERKLE_ROOT_MISMATCH', detail: `axes.${tag}.axis_root mismatch` }
    }
    if (axisBody.leaf_index < 0 || axisBody.leaf_index >= axis.contributors.length) {
      return { valid: false, reason: 'MALFORMED', detail: `axes.${tag}.leaf_index out of range` }
    }
    const row = axis.contributors[axisBody.leaf_index]
    if (row.contributor_did !== response.contributor_did) {
      return {
        valid: false,
        reason: 'MERKLE_ROOT_MISMATCH',
        detail: `axes.${tag}.leaf_index points to a different DID`,
      }
    }
    if (row.total_weight !== axisBody.total_weight) {
      return { valid: false, reason: 'MALFORMED', detail: `axes.${tag}.total_weight claim mismatch` }
    }
    if (row.contribution_count !== axisBody.contribution_count) {
      return {
        valid: false,
        reason: 'MALFORMED',
        detail: `axes.${tag}.contribution_count claim mismatch`,
      }
    }
    const leaf = Buffer.from(row.merkle_leaf_hash, 'hex')
    if (
      !verifyMerklePath(leaf, axisBody.leaf_index, axisBody.merkle_path, axisBody.axis_root)
    ) {
      return { valid: false, reason: 'MERKLE_ROOT_MISMATCH', detail: `axes.${tag} merkle_path does not reconstruct axis_root` }
    }
  }

  return { valid: true }
}
