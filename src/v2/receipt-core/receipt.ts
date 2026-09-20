// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { createHash } from 'node:crypto'
import { sign, verify } from '../../crypto/keys.js'
import { assertExactKeys, IJsonResourceLimitError, parseStrictIJson, strictJCS } from './jcs.js'
// Function-level cycle with stage.ts, which imports validateReceiptV1 from here. Neither
// module reads the other during initialization, so the live bindings are resolved by the
// time either function is called.
import { validateReceiptStageV1 } from './stage.js'
import type { ReceiptStageOptionsV1, ReceiptStageResultV1 } from './stage.js'
import type { EvidenceRefV1, JsonValue, ReceiptSignatureV1, ReceiptSignerV1, ReceiptV1 } from './types.js'

export const RECEIPT_ID_TAG = 'APS-RECEIPT-ID-V1' as const
export const RECEIPT_SIG_TAG = 'APS-RECEIPT-SIG-V1' as const
const HEX64 = /^[0-9a-f]{64}$/
const HEX128 = /^[0-9a-f]{128}$/
const UTC_MS = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.\d{3}Z$/
/** delegation_ref carries the "sha256:" prefix of a delegation_id, not a bare digest.
 *  draft-pidlisnyi-aps-03 section 5.1 line 982 says delegation_ref identifies the selected
 *  AuthorityDelegationV1 leaf, the envelope example at line 964 writes it as
 *  "sha256:<64 lowercase hexadecimal characters>", and section 3.1 line 484 gives
 *  delegation_id that exact form. Binding the value to a leaf needs a supplied chain and is
 *  the section 5.6 composition point; this check is the standalone structural form only. */
const DELEGATION_REF = /^sha256:[0-9a-f]{64}$/
const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
const sha256Hex = (s: string): string => createHash('sha256').update(s, 'utf8').digest('hex')
const compareUtf8 = (a: string, b: string): number => Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8'))

function compareEvidence(a: EvidenceRefV1, b: EvidenceRefV1): number {
  return compareUtf8(a.artifact_type, b.artifact_type) || compareUtf8(a.sha256, b.sha256)
}

function compareSignatures(a: Pick<ReceiptSignatureV1, 'signer' | 'key_id'>, b: Pick<ReceiptSignatureV1, 'signer' | 'key_id'>): number {
  return compareUtf8(a.signer, b.signer) || compareUtf8(a.key_id, b.key_id)
}

function isLeapYear(year: number): boolean {
  return (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0
}

/**
 * Exact UTC milliseconds, YYYY-MM-DDTHH:MM:SS.sssZ (draft line 986, with lines 198-199).
 *
 * Second 60 is accepted only at 23:59 on the last day of its month in the proleptic
 * Gregorian calendar, and rejected everywhere else. RFC 3339 section 5.7 admits time-second
 * 60 only for a leap second and Appendix D writes it as "YYYY-MM-DDT23:59:60Z"; the hour,
 * minute and day settle it, so no leap-second table is consulted and none is needed. The
 * same rule is applied on the section 4.1 surface (src/v2/action-reference/v2.ts) and on the
 * section 3 surface, and it stays local to each of them rather than changing a shared
 * helper that other record families also use.
 *
 * The second-60 branch is integer arithmetic because Date cannot represent a leap second.
 * Every other timestamp keeps the previous Date round-trip check unchanged, so the set of
 * accepted values grows by the conforming second-60 instants and by nothing else.
 */
export function isExactUtcMilliseconds(value: string): boolean {
  const match = UTC_MS.exec(value)
  if (!match) return false
  const [, y, mo, d, h, mi, s] = match
  const year = Number(y)
  const month = Number(mo)
  const day = Number(d)
  const second = Number(s)
  if (second === 60) {
    if (month < 1 || month > 12) return false
    const maxDay = month === 2 && isLeapYear(year) ? 29 : DAYS_IN_MONTH[month - 1]
    return day === maxDay && Number(h) === 23 && Number(mi) === 59
  }
  const parsed = new Date(value)
  return !Number.isNaN(parsed.valueOf()) && parsed.toISOString() === value
}

/**
 * Order two values that isExactUtcMilliseconds has accepted: true when `later` is
 * strictly after `earlier`.
 *
 * The comparison is lexicographic on purpose. The accepted form is fixed width and
 * zero padded, YYYY-MM-DDTHH:MM:SS.sssZ, with the only letters at fixed positions, so
 * byte order is chronological order, and a leap second at :60 sorts after :59 in the
 * same minute, which is where it belongs. Date.parse cannot be used: it returns NaN
 * for a second-60 instant, so every comparison involving a conforming leap second
 * would silently answer false and reject a record the draft allows.
 */
export function isLaterUtcMillisecond(later: string, earlier: string): boolean {
  return later > earlier
}

function isNoncharacterCodePoint(codePoint: number): boolean {
  if (codePoint >= 0xfdd0 && codePoint <= 0xfdef) return true
  return (codePoint & 0xffff) === 0xfffe || (codePoint & 0xffff) === 0xffff
}

/** I-JSON walk local to the receipt surface.
 *
 *  Section 5.6 line 1213 has a verifier parse bounded I-JSON. strictJCS already rejects an
 *  unpaired surrogate; it does not reject one of the 66 Unicode noncharacters, and it also
 *  serves other record families, so the noncharacter rule is applied here rather than by
 *  changing that helper. The same reading and the same locality were used for the section
 *  4.1 and section 3 surfaces in the two preceding jobs.
 */
function assertNoNoncharacters(value: unknown, path: string): void {
  if (typeof value === 'string') {
    for (let index = 0; index < value.length; index++) {
      const codePoint = value.codePointAt(index) as number
      if (isNoncharacterCodePoint(codePoint)) {
        throw new TypeError(`${path}: noncharacter U+${codePoint.toString(16).toUpperCase()}`)
      }
      if (codePoint > 0xffff) index++
    }
    return
  }
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertNoNoncharacters(item, `${path}[${i}]`))
    return
  }
  if (typeof value === 'object' && value !== null) {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      assertNoNoncharacters(key, `${path} key`)
      assertNoNoncharacters(item, `${path}.${key}`)
    }
  }
}

function receiptWithout<T extends 'receipt_id' | 'signatures'>(receipt: ReceiptV1, ...keys: T[]): Omit<ReceiptV1, T> {
  const copy = { ...receipt } as Record<string, unknown>
  keys.forEach(k => delete copy[k])
  return copy as Omit<ReceiptV1, T>
}

export function receiptIdPayloadV1(receipt: ReceiptV1): string {
  return `${RECEIPT_ID_TAG}\0${strictJCS(receiptWithout(receipt, 'receipt_id', 'signatures'))}`
}

export function computeReceiptIdV1(receipt: ReceiptV1): string {
  return sha256Hex(receiptIdPayloadV1(receipt))
}

export function receiptSignaturePayloadV1(receipt: ReceiptV1, descriptor: Omit<ReceiptSignatureV1, 'value'>): string {
  const form = { receipt: receiptWithout(receipt, 'signatures'), signer: descriptor }
  return `${RECEIPT_SIG_TAG}\0${strictJCS(form)}`
}

/**
 * This entrypoint validates the standalone ReceiptV1 structure and the fields available
 * within the receipt. It does not establish cross-document constraints involving the
 * referenced decision, including the requirement that decision valid_until be later than
 * receipt issued_at. Use verifyReceiptWithDecisionV1 when both artifacts are available.
 */
export function validateReceiptV1(receipt: ReceiptV1, requireValues = true): void {
  assertExactKeys(receipt as unknown as Record<string, unknown>,
    ['profile', 'receipt_id', 'receipt_type', 'issuer', 'subject_agent', 'action_ref', 'delegation_ref', 'decision_ref', 'issued_at', 'evidence_refs', 'result', 'prev', 'signatures'],
    ['profile', 'receipt_id', 'receipt_type', 'issuer', 'subject_agent', 'action_ref', 'delegation_ref', 'issued_at', 'evidence_refs', 'result', 'signatures'], 'ReceiptV1')
  strictJCS(receipt)
  assertNoNoncharacters(receipt, 'ReceiptV1')
  if (receipt.profile !== 'aps-receipt-v1') throw new TypeError('ReceiptV1: profile')
  // Every member the draft types as a string is checked as a string before its form.
  // A regular expression coerces its argument, so ['<64 hex>'] passed HEX64.test here and
  // a number or object passed the truthiness test that preceded this. Section 9 lines
  // 1652-1660 require a defined result for a structurally malformed artifact, and nothing
  // in section 5.1 permits a non-string to stand in for a string member.
  for (const key of ['receipt_type', 'issuer', 'subject_agent'] as const) {
    if (typeof receipt[key] !== 'string' || receipt[key] === '') throw new TypeError('ReceiptV1: empty identifier')
  }
  if (typeof receipt.delegation_ref !== 'string' || !DELEGATION_REF.test(receipt.delegation_ref)) {
    throw new TypeError('ReceiptV1: delegation_ref')
  }
  if (requireValues && (typeof receipt.receipt_id !== 'string' || !HEX64.test(receipt.receipt_id))) throw new TypeError('ReceiptV1: receipt_id')
  if (typeof receipt.action_ref !== 'string' || !HEX64.test(receipt.action_ref)) throw new TypeError('ReceiptV1: action_ref')
  if (receipt.decision_ref !== undefined && (typeof receipt.decision_ref !== 'string' || !HEX64.test(receipt.decision_ref))) throw new TypeError('ReceiptV1: decision_ref')
  if (receipt.prev !== undefined && (typeof receipt.prev !== 'string' || !HEX64.test(receipt.prev))) throw new TypeError('ReceiptV1: prev')
  if (typeof receipt.issued_at !== 'string' || !isExactUtcMilliseconds(receipt.issued_at)) throw new TypeError('ReceiptV1: issued_at')
  if (typeof receipt.result !== 'object' || receipt.result === null || Array.isArray(receipt.result)) throw new TypeError('ReceiptV1: result')
  if (!Array.isArray(receipt.evidence_refs) || !Array.isArray(receipt.signatures)) throw new TypeError('ReceiptV1: arrays')
  const seenEvidence = new Set<string>()
  receipt.evidence_refs.forEach((ref, i) => {
    assertExactKeys(ref as unknown as Record<string, unknown>, ['artifact_type', 'sha256'], ['artifact_type', 'sha256'], 'EvidenceRefV1')
    if (typeof ref.artifact_type !== 'string' || ref.artifact_type === '' ||
        typeof ref.sha256 !== 'string' || !HEX64.test(ref.sha256)) throw new TypeError('EvidenceRefV1: value')
    const key = `${ref.artifact_type}\0${ref.sha256}`
    if (seenEvidence.has(key)) throw new TypeError('ReceiptV1: duplicate evidence_ref')
    seenEvidence.add(key)
    if (i > 0 && compareEvidence(receipt.evidence_refs[i - 1], ref) >= 0) throw new TypeError('ReceiptV1: evidence_refs not sorted')
  })
  const seenSigs = new Set<string>()
  receipt.signatures.forEach((proof, i) => {
    assertExactKeys(proof as unknown as Record<string, unknown>, ['signer', 'key_id', 'alg', 'value'], ['signer', 'key_id', 'alg', 'value'], 'ReceiptSignatureV1')
    if (typeof proof.signer !== 'string' || proof.signer === '' ||
        typeof proof.key_id !== 'string' || proof.key_id === '' ||
        proof.alg !== 'Ed25519' ||
        (requireValues && (typeof proof.value !== 'string' || !HEX128.test(proof.value)))) throw new TypeError('ReceiptSignatureV1: value')
    const key = `${proof.signer}\0${proof.key_id}`
    if (seenSigs.has(key)) throw new TypeError('ReceiptV1: duplicate signature')
    seenSigs.add(key)
    if (i > 0 && compareSignatures(receipt.signatures[i - 1], proof) >= 0) throw new TypeError('ReceiptV1: signatures not sorted')
  })
  if (requireValues && !receipt.signatures.some(s => s.signer === receipt.issuer)) throw new TypeError('ReceiptV1: issuer signature missing')
}

export function createReceiptV1(
  fields: Omit<ReceiptV1, 'receipt_id' | 'signatures'>,
  signers: ReceiptSignerV1[],
): ReceiptV1 {
  if (signers.length === 0) throw new TypeError('ReceiptV1: at least one signer')
  const copiedFields = structuredClone(fields)
  const evidence_refs = [...copiedFields.evidence_refs].sort(compareEvidence)
  const descriptors = signers.map(s => ({ signer: s.signer, key_id: s.key_id, alg: 'Ed25519' as const, private_key: s.private_key }))
    .sort(compareSignatures)
  const draft = { ...copiedFields, evidence_refs, receipt_id: '0'.repeat(64), signatures: [] } as ReceiptV1
  validateReceiptV1(draft, false)
  draft.receipt_id = computeReceiptIdV1(draft)
  draft.signatures = descriptors.map(({ private_key, ...descriptor }) => ({
    ...descriptor,
    value: sign(receiptSignaturePayloadV1(draft, descriptor), private_key),
  }))
  validateReceiptV1(draft)
  return draft
}

/** Section 3.3 line 588 and section 5.6 lines 1225-1228: one of four states, and a caller
 *  MUST NOT collapse indeterminate or unsupported into valid. */
export type ReceiptVerificationStatusV1 = 'valid' | 'invalid' | 'indeterminate' | 'unsupported'

export interface ReceiptVerificationV1 {
  /** True only when status is valid. Kept so existing callers are unaffected. */
  valid: boolean
  status: ReceiptVerificationStatusV1
  /** `not_checked` where the record never reached the recomputation. Reporting false
   *  there said the identifier did not match when it was never computed. */
  receipt_id_valid: boolean | 'not_checked'
  /** The signer-authority axis of section 5.6 line 1223, kept apart from artifact
   *  integrity. `not_established` means a key could not be resolved or the resolver
   *  failed: section 2.4 line 322 and section 2.5 lines 360-369 make that a resolution
   *  outcome, and section 5.6 line 1226 makes missing live state indeterminate. It is not
   *  evidence that a signature is wrong. */
  signer_authority: 'verified' | 'not_established' | 'invalid' | 'not_checked'
  /** The section 5.3 stage result for this record's own receipt_type. Section 5.6 line
   *  1214 has a verifier enforce the closed envelope AND the type-specific schema, so a
   *  result that reports the draft's own state word has to include it. `not_checked` is
   *  reported only where the record never reached the stage layer, which is when the
   *  envelope itself failed or the artifact is under another profile. */
  stage: ReceiptStageResultV1 | 'not_checked'
  /** Every signature the record carries, required or not, with the outcome of its own
   *  key resolution. `required` marks the ones the aggregate state depends on. */
  signature_results: {
    signer: string
    key_id: string
    valid: boolean
    required: boolean
    reason?: string
  }[]
  /** Signatures outside the required set, on their own axis. Draft line 1041 has a
   *  verifier verify every REQUIRED signature, and line 999 names one: the issuer's. A
   *  signature nobody required that does not verify says nothing about the record, and it
   *  must not move the aggregate state: signatures sit outside receipt_id by
   *  construction (lines 1003-1009), so anyone can append one to a published receipt
   *  without changing a digest, and letting that flip a conforming record to invalid
   *  puts the verification outcome in a third party's hands. */
  other_signatures: 'none' | 'all_verified' | 'not_all_verified'
  errors: string[]
}

/** Verifier input for the signature layer. */
export interface ReceiptSignatureRequirementsV1 {
  /** Signers the applicable profile or this verifier requires, beyond the issuer. A
   *  named signer that carries no descriptor at all is a missing required signature. */
  requiredSigners?: readonly string[]
}

/** The section 2.5 resolution outcomes a receipt key resolver may name, alongside the
 *  key itself. Draft lines 360-364 require a resolver to keep them apart; this SDK
 *  reported every one of them as the same answer. */
export interface KeyResolutionFailure {
  outcome: 'not_found' | 'ambiguous' | 'malformed' | 'unreachable' | 'unsupported_scheme'
}

const KEY_MATERIAL = /^[0-9a-fA-F]{64}$/

const KEY_OUTCOME_REASONS: Record<string, string> = {
  not_found: 'key_not_found',
  ambiguous: 'key_ambiguous',
  unreachable: 'key_unreachable',
  malformed: 'key_material_malformed',
  unsupported_scheme: 'key_scheme_unsupported',
}

/** The reason a resolver's answer is not usable key material, or undefined when it is.
 *
 *  Material that is not a 32-byte Ed25519 key never reaches the signature check: the
 *  check returns false on a length mismatch, so malformed material used to be reported
 *  as a failed signature, which says the bytes were checked when nothing was. */
function keyResolutionReason(resolved: string | undefined | KeyResolutionFailure): string | undefined {
  if (typeof resolved === 'string') {
    return KEY_MATERIAL.test(resolved) ? undefined : 'key_material_malformed'
  }
  if (resolved && typeof resolved === 'object' && typeof resolved.outcome === 'string') {
    return KEY_OUTCOME_REASONS[resolved.outcome] ?? 'key_unresolved'
  }
  return 'key_unresolved'
}

/** True when the artifact declares an envelope profile other than aps-receipt-v1. Such an
 *  artifact is unsupported (section 5.6 line 1226) rather than invalid, and is not judged
 *  against the aps-receipt-v1 schema, which is not its schema. */
function declaresForeignProfile(receipt: unknown): boolean {
  if (typeof receipt !== 'object' || receipt === null || Array.isArray(receipt)) return false
  const profile = (receipt as Record<string, unknown>).profile
  return typeof profile === 'string' && profile !== 'aps-receipt-v1'
}

/**
 * This entrypoint validates the standalone ReceiptV1 structure and the fields available
 * within the receipt. It does not establish cross-document constraints involving the
 * referenced decision, including the requirement that decision valid_until be later than
 * receipt issued_at. Use verifyReceiptWithDecisionV1 when both artifacts are available.
 *
 * This entrypoint operates on an already-parsed object and therefore cannot detect
 * duplicate members that may have existed in serialized JSON. For verification of
 * serialized artifacts, use the Serialized variant.
 */
export function verifyReceiptV1(
  receipt: ReceiptV1,
  resolveKey: (signer: string, keyId: string, issuedAt: string) => string | undefined | KeyResolutionFailure,
  stageOptions: ReceiptStageOptionsV1 = {},
  requirements: ReceiptSignatureRequirementsV1 = {},
): ReceiptVerificationV1 {
  const errors: string[] = []
  if (declaresForeignProfile(receipt)) {
    return {
      valid: false,
      status: 'unsupported',
      receipt_id_valid: 'not_checked',
      stage: 'not_checked',
      signer_authority: 'not_checked',
      signature_results: [],
      other_signatures: 'none',
      errors: ['unsupported_profile'],
    }
  }
  try { validateReceiptV1(receipt) } catch (err) {
    return {
      valid: false,
      status: 'invalid',
      receipt_id_valid: 'not_checked',
      stage: 'not_checked',
      signer_authority: 'not_checked',
      signature_results: [],
      other_signatures: 'none',
      errors: [err instanceof Error ? err.message : String(err)],
    }
  }
  const receipt_id_valid = computeReceiptIdV1(receipt) === receipt.receipt_id
  if (!receipt_id_valid) errors.push('receipt_id_mismatch')

  // The required set: the issuer, whom line 999 requires, plus whatever the applicable
  // profile or this verifier names. Everything else the record carries is checked and
  // reported, and decides nothing.
  const requiredSigners = new Set<string>([receipt.issuer, ...(requirements.requiredSigners ?? [])])
  const signature_results = receipt.signatures.map(proof => {
    const required = requiredSigners.has(proof.signer)
    let resolved: string | undefined | KeyResolutionFailure
    try {
      resolved = resolveKey(proof.signer, proof.key_id, receipt.issued_at)
    } catch {
      return { signer: proof.signer, key_id: proof.key_id, valid: false, required, reason: 'key_resolution_error' }
    }
    const reason = keyResolutionReason(resolved)
    if (reason) return { signer: proof.signer, key_id: proof.key_id, valid: false, required, reason }
    const { value, ...descriptor } = proof
    return {
      signer: proof.signer,
      key_id: proof.key_id,
      required,
      valid: verify(receiptSignaturePayloadV1(receipt, descriptor), value, resolved as string),
    }
  })
  for (const signer of requiredSigners) {
    if (!signature_results.some(item => item.signer === signer)) {
      errors.push('required_signature_missing')
    }
  }
  // A key that could not be resolved and a signature that does not verify are different
  // findings. Reporting both as signature_invalid said that the bytes were wrong when the
  // verifier had never checked them, which is exactly the collapse section 5.6 line 1227
  // forbids in the other direction. Unresolvable key material leaves signer authority
  // unestablished, which is indeterminate; only a resolved key whose signature fails is
  // invalid.
  const required = signature_results.filter(item => item.required)
  const others = signature_results.filter(item => !item.required)
  const unresolved = required.filter(r => r.reason !== undefined && r.reason !== 'key_scheme_unsupported')
  const unsupportedScheme = required.some(r => r.reason === 'key_scheme_unsupported')
  const badBytes = required.filter(r => !r.valid && r.reason === undefined)
  if (badBytes.length > 0) errors.push('signature_invalid')
  if (unsupportedScheme) errors.push('signer_key_scheme_unsupported')
  if (unresolved.length > 0) errors.push('signer_authority_indeterminate')
  const signerAuthority = badBytes.length > 0
    ? 'invalid' as const
    : unresolved.length > 0 || unsupportedScheme ? 'not_established' as const : 'verified' as const
  const other_signatures = others.length === 0
    ? 'none' as const
    : others.every(item => item.valid) ? 'all_verified' as const : 'not_all_verified' as const
  // Section 5.6 line 1214: a verifier enforces the closed ReceiptV1 schema AND the
  // type-specific schema. Reporting status "valid" for a record that breaks its own
  // section 5.3 stage would use the draft's word for something the draft does not call
  // valid, which is what let a gateway-issued action intent carrying a decision_ref and a
  // free-form result pass every check this SDK had. The stage rules live in their own
  // module and are called here rather than reimplemented.
  const stage = validateReceiptStageV1(receipt, stageOptions)
  if (stage.status !== 'valid') errors.push(`stage_${stage.status}`, ...stage.failures.map(f => f.code))

  const status: ReceiptVerificationStatusV1 =
    badBytes.length > 0 || receipt_id_valid !== true || stage.status === 'invalid' || errors.includes('required_signature_missing')
      ? 'invalid'
      : stage.status === 'unsupported' || unsupportedScheme
        ? 'unsupported'
        : unresolved.length > 0 || stage.status === 'indeterminate'
          ? 'indeterminate'
          : 'valid'
  return {
    valid: status === 'valid',
    status,
    receipt_id_valid,
    stage,
    signer_authority: signerAuthority,
    signature_results,
    other_signatures,
    errors,
  }
}

/**
 * Verify a receipt from its serialized bytes.
 *
 * The chain is raw -> strict duplicate-rejecting parse -> the existing structural
 * validation -> the existing cryptographic verification. Every stage after the parse is
 * verifyReceiptV1 itself, called once and unchanged, so this adds a parser in front of
 * the existing path rather than a second implementation of it.
 *
 * WHY A SERIALIZED ENTRY POINT IS NEEDED AT ALL. Rejecting a duplicate object member is
 * a property of parsing. Once bytes have become an object the later member has already
 * overwritten the earlier one and the evidence is gone, so verifyReceiptV1, which
 * receives an object, cannot detect it however carefully it validates. Exposing only the
 * object-taking form would leave JSON.parse plus verifyReceiptV1 as the easy and
 * superficially legitimate composition, which is exactly the shape this is meant to
 * remove.
 *
 * Parse failure is reported as the error code `parse_error` followed by the parser's own
 * message, so it is distinguishable from a structural failure, which surfaces the
 * validator's message with no code, and from a signature failure, which surfaces
 * `signature_invalid`. That uses the existing free-form `errors` array of
 * ReceiptVerificationV1; no shared enum or result contract was widened to carry it.
 */
export function verifyReceiptV1Serialized(
  raw: string,
  resolveKey: (signer: string, keyId: string, issuedAt: string) => string | undefined | KeyResolutionFailure,
  stageOptions: ReceiptStageOptionsV1 = {},
  requirements: ReceiptSignatureRequirementsV1 = {},
): ReceiptVerificationV1 {
  let parsed: JsonValue
  try {
    parsed = parseStrictIJson(raw)
  } catch (err) {
    // This parser's own nesting-depth and wire-size ceilings are properties of this
    // implementation, not validity conditions the draft states, so hitting one establishes
    // that this verifier stopped, never that the receipt is malformed. The same bytes can verify under a higher ceiling. It is reported on the
    // indeterminate axis under RESOURCE_LIMIT, as the authority-delegation surface already
    // reports its three ceilings. Every genuine parse failure below is unchanged.
    if (err instanceof IJsonResourceLimitError) {
      return {
        valid: false,
        status: 'indeterminate',
        receipt_id_valid: 'not_checked',
        stage: 'not_checked',
        signer_authority: 'not_checked',
        signature_results: [],
        other_signatures: 'none',
        errors: ['RESOURCE_LIMIT', err.message],
      }
    }
    return {
      valid: false,
      status: 'invalid',
      receipt_id_valid: 'not_checked',
      stage: 'not_checked',
      signer_authority: 'not_checked',
      signature_results: [],
      other_signatures: 'none',
      errors: ['parse_error', err instanceof Error ? err.message : String(err)],
    }
  }
  // The single narrowing point. It does NOT stand in for validation: verifyReceiptV1's
  // first action is validateReceiptV1, the full runtime structural check, and a value
  // that fails it returns invalid here rather than reaching any cryptographic step.
  // A cast-free form is not expressible against the current signatures. Passing the
  // parsed value directly is TS2345, and a single assertion is TS2352 because JsonValue
  // and ReceiptV1 do not overlap, so the type system itself requires the two-step form.
  // Removing the need for it would mean widening validateReceiptV1 to an assertion over
  // unknown, which its body's direct field accesses would force a rewrite of. That is a
  // public API decision, recorded in the handoff rather than taken here.
  return verifyReceiptV1(parsed as unknown as ReceiptV1, resolveKey, stageOptions, requirements)
}
