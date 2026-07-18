// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { sign, verify } from '../../crypto/keys.js'
import { canonicalize } from '../../core/canonical.js'
import { assertExactKeys, strictJCS } from './jcs.js'
import type { EvidenceBundleBodyV2, EvidenceBundleMemberInputV2, EvidenceBundleMemberV2, EvidenceBundleProofStepV2, EvidenceBundleProofV2, JsonValue, SupportingRecordV1 } from './types.js'

export const SUPPORTING_RECORD_ID_TAG = 'APS-SUPPORTING-RECORD-ID-V1' as const
export const SUPPORTING_RECORD_SIG_TAG = 'APS-SUPPORTING-RECORD-SIG-V1' as const
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/
const UTC_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/
const sha256 = (value: string | Buffer): Buffer => createHash('sha256').update(value).digest()
const sha256Hex = (value: string | Buffer): string => sha256(value).toString('hex')
const isExactUtcMilliseconds = (value: string): boolean => {
  if (!UTC_MS.test(value)) return false
  const parsed = new Date(value)
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value
}

function without(record: SupportingRecordV1, ...keys: ('record_id' | 'sig')[]): Record<string, JsonValue> {
  const copy = { ...record } as unknown as Record<string, JsonValue>
  keys.forEach(key => delete copy[key])
  return copy
}

export function supportingRecordIdPayloadV1(record: SupportingRecordV1): string {
  return `${SUPPORTING_RECORD_ID_TAG}\0${record.record_type}\0${strictJCS(without(record, 'record_id', 'sig'))}`
}

export function computeSupportingRecordIdV1(record: SupportingRecordV1): string {
  return sha256Hex(supportingRecordIdPayloadV1(record))
}

export function supportingRecordSignaturePayloadV1(record: SupportingRecordV1): string {
  return `${SUPPORTING_RECORD_SIG_TAG}\0${record.record_type}\0${strictJCS(without(record, 'sig'))}`
}

export function validateSupportingRecordV1(record: SupportingRecordV1, requireCrypto = true): void {
  assertExactKeys(record as unknown as Record<string, unknown>,
    ['profile', 'record_id', 'record_type', 'issuer', 'issuer_key_id', 'issued_at', 'action_ref', 'body', 'sig_alg', 'sig'],
    ['profile', 'record_id', 'record_type', 'issuer', 'issuer_key_id', 'issued_at', 'body', 'sig_alg', 'sig'], 'SupportingRecordV1')
  strictJCS(record)
  if (record.profile !== 'aps-supporting-record-v1') throw new TypeError('SupportingRecordV1: profile')
  if (!record.record_type || !record.issuer || !record.issuer_key_id) throw new TypeError('SupportingRecordV1: identifier')
  if (!isExactUtcMilliseconds(record.issued_at)) throw new TypeError('SupportingRecordV1: issued_at')
  if (record.action_ref !== undefined && !HEX64.test(record.action_ref)) throw new TypeError('SupportingRecordV1: action_ref')
  if (typeof record.body !== 'object' || record.body === null || Array.isArray(record.body)) throw new TypeError('SupportingRecordV1: body')
  if (record.sig_alg !== 'Ed25519') throw new TypeError('SupportingRecordV1: sig_alg')
  if (requireCrypto && (!HEX64.test(record.record_id) || !HEX128.test(record.sig))) throw new TypeError('SupportingRecordV1: crypto encoding')
}

export function createSupportingRecordV1(
  fields: Omit<SupportingRecordV1, 'record_id' | 'sig'>,
  privateKey: string,
): SupportingRecordV1 {
  const record = { ...structuredClone(fields), record_id: '0'.repeat(64), sig: '' } as SupportingRecordV1
  validateSupportingRecordV1(record, false)
  record.record_id = computeSupportingRecordIdV1(record)
  record.sig = sign(supportingRecordSignaturePayloadV1(record), privateKey)
  validateSupportingRecordV1(record)
  return record
}

export function verifySupportingRecordV1(record: SupportingRecordV1, publicKey: string): { valid: boolean; id_valid: boolean; signature_valid: boolean } {
  try { validateSupportingRecordV1(record) } catch { return { valid: false, id_valid: false, signature_valid: false } }
  const id_valid = computeSupportingRecordIdV1(record) === record.record_id
  const signature_valid = verify(supportingRecordSignaturePayloadV1(record), record.sig, publicKey)
  return { valid: id_valid && signature_valid, id_valid, signature_valid }
}

function validateEvidenceBundleMemberV2(entry: EvidenceBundleMemberV2): void {
  assertExactKeys(entry as unknown as Record<string, unknown>, ['member_id', 'member_type', 'sha256'], ['member_id', 'member_type', 'sha256'], 'EvidenceBundleMemberV2')
  if (!entry.member_id || !entry.member_type || !HEX64.test(entry.sha256)) throw new TypeError('EvidenceBundleMemberV2: value')
}

function entryCanonical(entry: EvidenceBundleMemberV2): string {
  validateEvidenceBundleMemberV2(entry)
  return strictJCS(entry)
}

export function evidenceBundleMerkleRootV2(entries: EvidenceBundleMemberV2[]): string {
  if (entries.length === 0) throw new TypeError('EvidenceBundleV2: at least one member')
  const seen = new Set<string>()
  const canonicalEntries = entries.map((entry, i) => {
    const canonical = entryCanonical(entry)
    if (seen.has(entry.member_id)) throw new TypeError('EvidenceBundleV2: duplicate member_id')
    seen.add(entry.member_id)
    if (i > 0 && Buffer.compare(Buffer.from(entryCanonical(entries[i - 1]), 'utf8'), Buffer.from(canonical, 'utf8')) >= 0) {
      throw new TypeError('EvidenceBundleV2: members not sorted')
    }
    return canonical
  })
  let level = canonicalEntries.map(canonical => sha256(Buffer.concat([Buffer.from([0]), Buffer.from(canonical, 'utf8')])))
  while (level.length > 1) {
    const next: Buffer[] = []
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 === level.length) next.push(level[i])
      else next.push(sha256(Buffer.concat([Buffer.from([1]), level[i], level[i + 1]])))
    }
    level = next
  }
  return level[0].toString('hex')
}

export function buildEvidenceBundleBodyV2(members: EvidenceBundleMemberInputV2[]): EvidenceBundleBodyV2 {
  if (members.length === 0) throw new TypeError('EvidenceBundleV2: at least one member')
  const seen = new Set<string>()
  const entries = members.map(member => {
    assertExactKeys(member as unknown as Record<string, unknown>, ['member_id', 'member_type', 'payload'], ['member_id', 'member_type', 'payload'], 'EvidenceBundleMemberInputV2')
    if (!member.member_id || !member.member_type) throw new TypeError('EvidenceBundleV2: member identifier')
    if (seen.has(member.member_id)) throw new TypeError('EvidenceBundleV2: duplicate member_id')
    seen.add(member.member_id)
    return { member_id: member.member_id, member_type: member.member_type, sha256: sha256Hex(strictJCS(member.payload)) }
  }).sort((a, b) => Buffer.compare(Buffer.from(entryCanonical(a)), Buffer.from(entryCanonical(b))))
  return { members: entries, merkle_root: evidenceBundleMerkleRootV2(entries) }
}

export function verifyEvidenceBundleBodyV2(body: EvidenceBundleBodyV2, payloads?: Record<string, JsonValue>): boolean {
  try {
    assertExactKeys(body as unknown as Record<string, unknown>, ['members', 'merkle_root'], ['members', 'merkle_root'], 'EvidenceBundleBodyV2')
    if (!Array.isArray(body.members) || body.members.length === 0 || !HEX64.test(body.merkle_root)) return false
    const seen = new Set<string>()
    for (let i = 0; i < body.members.length; i++) {
      const entry = body.members[i]
      validateEvidenceBundleMemberV2(entry)
      if (seen.has(entry.member_id)) return false
      seen.add(entry.member_id)
      if (i > 0 && Buffer.compare(Buffer.from(entryCanonical(body.members[i - 1])), Buffer.from(entryCanonical(entry))) >= 0) return false
      if (payloads && (!Object.prototype.hasOwnProperty.call(payloads, entry.member_id) || sha256Hex(strictJCS(payloads[entry.member_id])) !== entry.sha256)) return false
    }
    return evidenceBundleMerkleRootV2(body.members) === body.merkle_root
  } catch { return false }
}

function evidenceLeaf(entry: EvidenceBundleMemberV2): Buffer {
  return sha256(Buffer.concat([Buffer.from([0]), Buffer.from(entryCanonical(entry), 'utf8')]))
}

/** Build an inclusion proof over the already-sorted manifest members.
 *  Odd nodes are promoted, never duplicated, and the promotion is explicit in
 *  the proof so a verifier can validate the tree shape from leaf_count. */
export function buildEvidenceBundleProofV2(entries: EvidenceBundleMemberV2[], memberId: string): EvidenceBundleProofV2 {
  evidenceBundleMerkleRootV2(entries)
  const leaf_index = entries.findIndex(entry => entry.member_id === memberId)
  if (leaf_index < 0) throw new TypeError('EvidenceBundleV2: member not found')
  let index = leaf_index
  let level = entries.map(evidenceLeaf)
  const path: EvidenceBundleProofStepV2[] = []
  while (level.length > 1) {
    if (index % 2 === 1) path.push({ position: 'left', sha256: level[index - 1].toString('hex') })
    else if (index + 1 < level.length) path.push({ position: 'right', sha256: level[index + 1].toString('hex') })
    else path.push({ position: 'promote' })
    const next: Buffer[] = []
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 === level.length) next.push(level[i])
      else next.push(sha256(Buffer.concat([Buffer.from([1]), level[i], level[i + 1]])))
    }
    index = Math.floor(index / 2)
    level = next
  }
  return { profile: 'aps-evidence-proof-v2', member: { ...entries[leaf_index] }, leaf_index, leaf_count: entries.length, path }
}

export function verifyEvidenceBundleProofV2(proof: EvidenceBundleProofV2, trustedRoot: string, payload?: JsonValue): boolean {
  try {
    assertExactKeys(proof as unknown as Record<string, unknown>, ['profile', 'member', 'leaf_index', 'leaf_count', 'path'], ['profile', 'member', 'leaf_index', 'leaf_count', 'path'], 'EvidenceBundleProofV2')
    if (proof.profile !== 'aps-evidence-proof-v2' || !HEX64.test(trustedRoot)) return false
    validateEvidenceBundleMemberV2(proof.member)
    if (!Number.isSafeInteger(proof.leaf_index) || !Number.isSafeInteger(proof.leaf_count) || proof.leaf_count < 1 || proof.leaf_index < 0 || proof.leaf_index >= proof.leaf_count || !Array.isArray(proof.path)) return false
    if (payload !== undefined && sha256Hex(strictJCS(payload)) !== proof.member.sha256) return false
    let index = proof.leaf_index
    let width = proof.leaf_count
    let hash = evidenceLeaf(proof.member)
    let pathIndex = 0
    while (width > 1) {
      const step = proof.path[pathIndex++]
      if (!step) return false
      const expected = index % 2 === 1 ? 'left' : index + 1 < width ? 'right' : 'promote'
      if (step.position !== expected) return false
      if (step.position === 'promote') {
        assertExactKeys(step as unknown as Record<string, unknown>, ['position'], ['position'], 'EvidenceBundleProofStepV2')
      } else {
        assertExactKeys(step as unknown as Record<string, unknown>, ['position', 'sha256'], ['position', 'sha256'], 'EvidenceBundleProofStepV2')
        if (!HEX64.test(step.sha256)) return false
        const sibling = Buffer.from(step.sha256, 'hex')
        hash = step.position === 'left'
          ? sha256(Buffer.concat([Buffer.from([1]), sibling, hash]))
          : sha256(Buffer.concat([Buffer.from([1]), hash, sibling]))
      }
      index = Math.floor(index / 2)
      width = Math.ceil(width / 2)
    }
    return pathIndex === proof.path.length && hash.toString('hex') === trustedRoot
  } catch { return false }
}

export type SupportingRecordFormat =
  | { format: 'supporting-record-v1'; canonicalization: 'rfc8785'; legacy: false }
  | { format: 'evidence-bundle-v1'; canonicalization: 'aps-legacy-null-dropping'; legacy: true }
  | { format: 'composition-check-v0'; canonicalization: 'rfc8785-tagged-v0'; legacy: true }
  | { format: 'accountability-record-0.1.0'; canonicalization: 'rfc8785-untagged'; legacy: true }
  | { format: 'read-fidelity-unwrapped'; canonicalization: 'rfc8785-untagged'; legacy: true }
  | { format: 'revocation-observation-unversioned'; canonicalization: 'aps-legacy-null-dropping'; legacy: true }
  | { format: 'unknown'; canonicalization: 'unknown'; legacy: false }

/** Explicit discriminator dispatch. Verification code must never try both canonicalizers. */
export function classifySupportingRecordFormat(value: unknown): SupportingRecordFormat {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return { format: 'unknown', canonicalization: 'unknown', legacy: false }
  const v = value as Record<string, unknown>
  if (v.profile === 'aps-supporting-record-v1') return { format: 'supporting-record-v1', canonicalization: 'rfc8785', legacy: false }
  if (v.profile === 'aps-composition-check-v0') return { format: 'composition-check-v0', canonicalization: 'rfc8785-tagged-v0', legacy: true }
  if (v.spec_version === '0.1.0' && v.record_type === 'accountability_record') return { format: 'accountability-record-0.1.0', canonicalization: 'rfc8785-untagged', legacy: true }
  if (v.type === 'read_fidelity_receipt') return { format: 'read-fidelity-unwrapped', canonicalization: 'rfc8785-untagged', legacy: true }
  if (typeof v.manifest === 'object' && v.manifest !== null && (v.manifest as Record<string, unknown>).profile === 'aps:evidence-bundle:v1') return { format: 'evidence-bundle-v1', canonicalization: 'aps-legacy-null-dropping', legacy: true }
  if ('authority_ref' in v && 'observer_key' in v && !('profile' in v)) return { format: 'revocation-observation-unversioned', canonicalization: 'aps-legacy-null-dropping', legacy: true }
  return { format: 'unknown', canonicalization: 'unknown', legacy: false }
}

/** Legacy canonical bytes are exposed only after explicit legacy classification. */
export function legacyNullDroppingPayload(value: JsonValue): string {
  return canonicalize(value)
}
