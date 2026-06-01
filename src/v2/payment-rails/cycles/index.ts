// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cycles — APS V2 ↔ Cycles reserve/commit/release budget-authority rail
// ══════════════════════════════════════════════════════════════════
// Public functions:
//   mapCyclesDenialToFoundation(evidence)            → FoundationDenialMapping | null
//
//   signCyclesPermitReceipt(input, privateKeyHex)    → CyclesPermitReceipt
//   verifyCyclesPermitReceipt(receipt, options)      → CyclesVerifyResult       (sync)
//   verifyCyclesPermitReceiptWithDID(receipt, options) → CyclesVerifyResult     (async)
//
//   signCyclesReleaseReceipt(input, privateKeyHex)   → CyclesReleaseReceipt
//   verifyCyclesReleaseReceipt(receipt, options)     → CyclesVerifyResult       (sync)
//   verifyCyclesReleaseReceiptWithDID(receipt, options) → CyclesVerifyResult    (async)
//
//   signCyclesDenial(input, privateKeyHex)           → CyclesDenial
//   verifyCyclesDenial(denial, options)              → CyclesVerifyResult       (sync)
//   verifyCyclesDenialWithDID(denial, options)       → CyclesVerifyResult       (async)
//
// Denial mapping (constants ported byte-for-byte from the merged spec):
//   - ErrorCode → APS Tier-1: 15 v0.1.25 base values
//   - DecisionReasonCode → APS Tier-1: 6 v0.1.25 base values
//   v0.1.26 extension codes are OUT OF SCOPE for v0.1 — see file header
//   of types.ts and the merged spec's v0.2 promotion criterion.
//
// Canonical-bytes scheme: receipts use field-omission via destructuring
// to match mpp/x402 convention within this codebase. receipt_id is a
// random UUID (mppr-style), not content-addressed. (The CyclesEvidence
// envelope this receipt binds to via `cycles_evidence.cycles_evidence_id_sha256`
// IS content-addressed; the APS receipt carries its own UUID identifier.)
//
// Join-integrity (the load-bearing offline-audit guarantee):
//   When the caller passes the fetched CyclesEvidence envelope via
//   VerifyCyclesOptions.evidence, verify recomputes its content hash
//   (cycles-evidence-v0.1 normative algorithm: evidence_id + signature
//   emptied, JCS-canonicalized, sha256) and confirms it matches BOTH the
//   envelope's own evidence_id AND the receipt's
//   cycles_evidence.cycles_evidence_id_sha256 → EVIDENCE_REF_HASH_MISMATCH
//   on either failure. Omit the envelope for signature-only verification.
//
// Out of scope for this commit (TODO follow-up):
//   - preAuthorizeCyclesReserve gateway hook into PaymentRail interface
//     (gateway-flow placement — held for the AEOESS gateway-flow ADR,
//     aeoess/agent-passport-system#25).
//
// Spec refs:
//   - runcycles/cycles-protocol drafts/cycles-evidence-v0.1.yaml (#90, 61186a2)
//   - runcycles/cycles-protocol drafts/cycles-aps-denial-mapping-v0.1.md (#93, 9b0fb5e)
//   - aeoess/agent-governance-vocabulary crosswalk/cycles.yaml (#92, 3ccc17f)
//   - aeoess/agent-governance-vocabulary crosswalk/budget_reservation.yaml (#91, 161b1d4)
//   - aeoess/agent-passport-system#27 (4abd9df) — SDK PR adding the three
//     rail.budget_reservation.*.v1 claim_type literals this adapter emits.
// ══════════════════════════════════════════════════════════════════

import { randomUUID } from 'node:crypto'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { sha256Hex } from '../canonicalize.js'
import { publicKeyFromPrivate, sign, verify as edVerify } from '../../../crypto/keys.js'
import {
  parseDidUri,
  publicKeyHexFromMethod,
  resolveVerificationMethod,
} from '../../../core/did-uri.js'
import type { DenialReason as FoundationDenialReason } from '../types.js'
import {
  CYCLES_PROTOCOL_VERSION,
  CYCLES_EVIDENCE_SCHEMA_VERSION,
  RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
} from './types.js'
export {
  CYCLES_PROTOCOL_VERSION,
  CYCLES_EVIDENCE_SCHEMA_VERSION,
  RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
  RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
} from './types.js'
import type {
  CyclesDenial,
  CyclesDenialDetail,
  CyclesEvidenceEnvelopeInput,
  CyclesEvidenceView,
  CyclesPermitReceipt,
  CyclesReleaseReceipt,
  CyclesResolveDidDocument,
  CyclesVerifyResult,
  ScopeOfClaim,
  SignCyclesDenialInput,
  SignCyclesPermitReceiptInput,
  SignCyclesReleaseReceiptInput,
  VerifyCyclesOptions,
} from './types.js'
import {
  resolveEvidenceRef,
  toEvidenceDescriptorInput,
} from './evidence-resolution.js'
import type {
  EvidenceDescriptorInput,
  EvidenceResolutionResult,
} from './evidence-resolution.js'

// ── Internal helpers ──────────────────────────────────────────────

function nowIso(): string {
  return new Date().toISOString()
}

/** Mirrors mpp's _mppSignerFor: either DID URI (when issuer_agent_id +
 *  issuer_key_ref both supplied) or raw hex pubkey. */
function _cyclesSignerFor(
  privateKeyHex: string,
  agentId: string | undefined,
  keyRef: string | undefined,
): string {
  if (agentId && keyRef) {
    if (!agentId.startsWith('did:')) {
      throw new Error(`signCycles*: issuer_agent_id must be a DID, got '${agentId}'`)
    }
    if (keyRef.includes('#')) {
      throw new Error("signCycles*: issuer_key_ref must not contain '#'")
    }
    return `${agentId}#${keyRef}`
  }
  return publicKeyFromPrivate(privateKeyHex)
}

// ── Default scope_of_claim assertions per artifact ─────────────────

function defaultCyclesPermitReceiptScope(): ScopeOfClaim {
  return {
    asserts:
      'aps:cycles.permit:emit — a budget reservation was authorized on the Cycles rail under the named delegation; reservation_id anchors the rail-side outcome and cycles_evidence binds to the signed CyclesEvidence envelope.',
    does_not_assert: [
      'the reservation was committed',
      'the action governed by the reservation completed',
      'live ledger state at any time after issuance',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

function defaultCyclesReleaseReceiptScope(): ScopeOfClaim {
  return {
    asserts:
      'aps:cycles.release:emit — a budget reservation was released without commit under the named delegation; reservation_id ties to the prior permit-receipt.',
    does_not_assert: [
      'the underlying action was cancelled (the reason field, when populated, is rail-reported)',
      'no separate commit occurred on a different reservation',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

function defaultCyclesDenialScope(): ScopeOfClaim {
  return {
    asserts:
      'aps:cycles.deny:emit — a Cycles budget-authority operation was refused with a closed-taxonomy Tier-1 denial reason; cycles.denial_detail preserves the canonical Cycles-side code Tier-2.',
    does_not_assert: [
      'the rail itself is unavailable',
      'the agent acted maliciously',
      'the underlying delegation is invalid (denial may flag a single missing constraint)',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}

// ── Denial mapping: Cycles ErrorCode → APS Tier-1 ─────────────────

const ERROR_CODE_TO_TIER1: Record<string, FoundationDenialReason> = {
  INVALID_REQUEST:          'rail_error',
  UNAUTHORIZED:             'rail_error',
  FORBIDDEN:                'no_commerce_scope',
  NOT_FOUND:                'rail_error',
  BUDGET_EXCEEDED:          'spend_limit_exceeded',
  BUDGET_FROZEN:            'wallet_revoked',
  BUDGET_CLOSED:            'wallet_revoked',
  RESERVATION_EXPIRED:      'time_window_violation',
  RESERVATION_FINALIZED:    'rail_error',
  IDEMPOTENCY_MISMATCH:     'rail_error',
  UNIT_MISMATCH:            'rail_error',
  OVERDRAFT_LIMIT_EXCEEDED: 'spend_limit_exceeded',
  DEBT_OUTSTANDING:         'wallet_revoked',
  MAX_EXTENSIONS_EXCEEDED:  'time_window_violation',
  INTERNAL_ERROR:           'rail_error',
}

// ── Denial mapping: Cycles DecisionReasonCode → APS Tier-1 ────────

const DECISION_REASON_TO_TIER1: Record<string, FoundationDenialReason> = {
  BUDGET_EXCEEDED:          'spend_limit_exceeded',
  BUDGET_FROZEN:            'wallet_revoked',
  BUDGET_CLOSED:            'wallet_revoked',
  BUDGET_NOT_FOUND:         'rail_error',
  OVERDRAFT_LIMIT_EXCEEDED: 'spend_limit_exceeded',
  DEBT_OUTSTANDING:         'wallet_revoked',
}

// ── mapCyclesDenialToFoundation ───────────────────────────────────

/**
 * Maps a Cycles denial signal (extracted from a CyclesEvidence view)
 * to an APS Tier-1 denial reason, preserving the full Cycles-side
 * detail Tier-2 in `cycles.denial_detail`.
 *
 * Returns `null` if the evidence view does not represent a denial
 * (artifact_type=decide-ALLOW, reserve-ALLOW, commit, release).
 *
 * Denial paths:
 *   (A) HTTP 4xx/5xx — artifact_type=error. ErrorCode source.
 *   (B) /v1/decide DENY — artifact_type=decide. DecisionReasonCode source.
 *   (C) dry_run=true reserve DENY — artifact_type=reserve.
 *       DecisionReasonCode source. (Non-dry reserve DENY is a wire-
 *       shape impossibility per cycles-protocol-v0.yaml:978 and is
 *       rejected at the CyclesEvidence schema layer.)
 */
export function mapCyclesDenialToFoundation(
  evidence: CyclesEvidenceView,
): { denial_reason: FoundationDenialReason; cycles: { denial_detail: CyclesDenialDetail } } | null {
  const p = evidence.payload

  if ('error' in p) {
    const e = p.error
    const code = e.response.error
    return {
      denial_reason: ERROR_CODE_TO_TIER1[code] ?? 'rail_error',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'ErrorCode',
          code,
          http_status: e.http_status,
          message: e.response.message,
          request_id: e.response.request_id,
          trace_id: e.response.trace_id ?? evidence.trace_id,
        },
      },
    }
  }

  if ('decide' in p && p.decide.response.decision === 'DENY') {
    const code = p.decide.response.reason_code ?? 'UNKNOWN'
    return {
      denial_reason: DECISION_REASON_TO_TIER1[code] ?? 'rail_error',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'DecisionReasonCode',
          code,
          trace_id: evidence.trace_id,
        },
      },
    }
  }

  if ('reserve' in p && p.reserve.response.decision === 'DENY') {
    const code = p.reserve.response.reason_code ?? 'UNKNOWN'
    return {
      denial_reason: DECISION_REASON_TO_TIER1[code] ?? 'rail_error',
      cycles: {
        denial_detail: {
          layer: 'cycles',
          source: 'DecisionReasonCode',
          code,
          trace_id: evidence.trace_id,
        },
      },
    }
  }

  return null
}

// ── Sign / verify: permit receipt ─────────────────────────────────

export function signCyclesPermitReceipt(
  input: SignCyclesPermitReceiptInput,
  signerPrivateKeyHex: string,
): CyclesPermitReceipt {
  const signerPub = _cyclesSignerFor(signerPrivateKeyHex, input.issuer_agent_id, input.issuer_key_ref)
  const issued_at = nowIso()
  const unsigned: Omit<CyclesPermitReceipt, 'signature'> = {
    claim_type: RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
    receipt_id: `cycles_permit_${randomUUID()}`,
    signer: signerPub,
    agent_id: input.agent_id,
    delegation_ref: input.delegation_ref,
    action_ref: input.action_ref,
    rail_name: 'cycles',
    reservation_id: input.reservation_id,
    reserved: input.reserved,
    decision: input.decision,
    cycles_evidence: input.cycles_evidence,
    issued_at,
    timestamp: issued_at,
    scope_of_claim: input.scope_of_claim ?? defaultCyclesPermitReceiptScope(),
  }
  if (input.expires_at_ms !== undefined) {
    unsigned.expires_at_ms = input.expires_at_ms
  }
  if (input.authority_state_at_admission !== undefined) {
    unsigned.authority_state_at_admission = input.authority_state_at_admission
  }
  if (input.trust_policy_ref !== undefined) {
    unsigned.trust_policy_ref = input.trust_policy_ref
  }
  const sigBytes = canonicalizeJCS(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

/** Verify a Cycles permit receipt (sync). With `options.evidence`, also
 *  checks the receipt↔envelope hash binding (see `_checkEvidenceJoin`).
 *  NOTE: `valid: true` does NOT assert the envelope's own Ed25519
 *  authenticity or signer authority — that is the v0.2 item (#43). Pin
 *  `expected_signer` for issuer trust until then. */
export function verifyCyclesPermitReceipt(
  receipt: CyclesPermitReceipt,
  options: VerifyCyclesOptions = {},
): CyclesVerifyResult {
  return _verifyReceiptCore(
    receipt,
    RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE,
    options,
  )
}

/** Verify a Cycles permit receipt (async, DID-URI signers). Join-integrity
 *  caveat as in `verifyCyclesPermitReceipt`: `valid: true` does NOT assert
 *  the envelope's own Ed25519 authenticity (v0.2 — #43). */
export async function verifyCyclesPermitReceiptWithDID(
  receipt: CyclesPermitReceipt,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyResult> {
  return _verifyReceiptWithDID(receipt, RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE, options)
}

// ── Sign / verify: release receipt ────────────────────────────────

export function signCyclesReleaseReceipt(
  input: SignCyclesReleaseReceiptInput,
  signerPrivateKeyHex: string,
): CyclesReleaseReceipt {
  const signerPub = _cyclesSignerFor(signerPrivateKeyHex, input.issuer_agent_id, input.issuer_key_ref)
  const issued_at = nowIso()
  const unsigned: Omit<CyclesReleaseReceipt, 'signature'> = {
    claim_type: RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
    receipt_id: `cycles_release_${randomUUID()}`,
    signer: signerPub,
    agent_id: input.agent_id,
    delegation_ref: input.delegation_ref,
    action_ref: input.action_ref,
    rail_name: 'cycles',
    reservation_id: input.reservation_id,
    released: input.released,
    cycles_evidence: input.cycles_evidence,
    issued_at,
    timestamp: issued_at,
    scope_of_claim: input.scope_of_claim ?? defaultCyclesReleaseReceiptScope(),
  }
  if (input.reason !== undefined) {
    unsigned.reason = input.reason
  }
  const sigBytes = canonicalizeJCS(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

/** Verify a Cycles release receipt (sync). With `options.evidence`, also
 *  checks the receipt↔envelope hash binding (see `_checkEvidenceJoin`).
 *  NOTE: `valid: true` does NOT assert the envelope's own Ed25519
 *  authenticity or signer authority — that is the v0.2 item (#43). Pin
 *  `expected_signer` for issuer trust until then. */
export function verifyCyclesReleaseReceipt(
  receipt: CyclesReleaseReceipt,
  options: VerifyCyclesOptions = {},
): CyclesVerifyResult {
  return _verifyReceiptCore(
    receipt,
    RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE,
    options,
  )
}

/** Verify a Cycles release receipt (async, DID-URI signers). Join-integrity
 *  caveat as in `verifyCyclesReleaseReceipt`: `valid: true` does NOT assert
 *  the envelope's own Ed25519 authenticity (v0.2 — #43). */
export async function verifyCyclesReleaseReceiptWithDID(
  receipt: CyclesReleaseReceipt,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyResult> {
  return _verifyReceiptWithDID(receipt, RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE, options)
}

// ── Sign / verify: denial ─────────────────────────────────────────

export function signCyclesDenial(
  input: SignCyclesDenialInput,
  signerPrivateKeyHex: string,
): CyclesDenial {
  const signerPub = _cyclesSignerFor(signerPrivateKeyHex, input.issuer_agent_id, input.issuer_key_ref)
  const issued_at = nowIso()
  const unsigned: Omit<CyclesDenial, 'signature'> = {
    claim_type: RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
    receipt_id: `cycles_denial_${randomUUID()}`,
    signer: signerPub,
    agent_id: input.agent_id,
    delegation_ref: input.delegation_ref,
    action_ref: input.action_ref,
    rail_name: 'cycles',
    denial_reason: input.denial_reason,
    cycles: input.cycles,
    cycles_evidence: input.cycles_evidence,
    issued_at,
    timestamp: issued_at,
    scope_of_claim: input.scope_of_claim ?? defaultCyclesDenialScope(),
  }
  const sigBytes = canonicalizeJCS(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

/** Verify a Cycles denial (sync). With `options.evidence`, also checks the
 *  receipt↔envelope hash binding (see `_checkEvidenceJoin`). NOTE:
 *  `valid: true` does NOT assert the envelope's own Ed25519 authenticity or
 *  signer authority — that is the v0.2 item (#43). Pin `expected_signer`
 *  for issuer trust until then. */
export function verifyCyclesDenial(
  denial: CyclesDenial,
  options: VerifyCyclesOptions = {},
): CyclesVerifyResult {
  return _verifyReceiptCore(
    denial,
    RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
    options,
  )
}

/** Verify a Cycles denial (async, DID-URI signers). Join-integrity caveat
 *  as in `verifyCyclesDenial`: `valid: true` does NOT assert the envelope's
 *  own Ed25519 authenticity (v0.2 — #43). */
export async function verifyCyclesDenialWithDID(
  denial: CyclesDenial,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyResult> {
  return _verifyReceiptWithDID(denial, RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE, options)
}

// ── Internal verifiers (shared by all three artifact types) ───────

type AnyCyclesSigned = CyclesPermitReceipt | CyclesReleaseReceipt | CyclesDenial

/**
 * Join-integrity check: bind the APS receipt to the Cycles-side evidence
 * it references. Recomputes the fetched envelope's content hash per the
 * cycles-evidence-v0.1 normative algorithm (evidence_id + signature both
 * emptied → JCS canonicalize → sha256) and confirms it matches:
 *   (a) the envelope's own `evidence_id`  — the envelope is internally
 *                                           consistent (its id is the true
 *                                           hash of its own content);
 *   (b) the receipt's `cycles_evidence.cycles_evidence_id_sha256`
 *                                          — the receipt binds to THIS envelope.
 *
 * Returns a failing result on mismatch, or `null` when the check passes
 * or is skipped (no envelope supplied → signature-only verification).
 *
 * Scope: verifies the receipt↔envelope HASH binding and envelope self-
 * consistency. It does NOT verify the envelope's OWN Ed25519 signature
 * against the Cycles signer key — cycles-evidence-v0.1 defers Cycles
 * signer-key resolution (did:cycles / JWKS) to v0.2, so envelope-
 * authenticity verification lands then. The APS receipt's own signature
 * (verified separately below) attests that APS vouched for this binding.
 *
 * Cross-system byte-match note: APS `canonicalizeJCS` reproduces the
 * `evidence_id` of every cycles-protocol reference fixture, so the empty-
 * string-sentinel rule here is the SAME canonicalization the Cycles server
 * used to derive the hash. Field omission would produce different bytes.
 */
function _checkEvidenceJoin(
  obj: AnyCyclesSigned,
  options: VerifyCyclesOptions,
): CyclesVerifyResult | null {
  const env: CyclesEvidenceEnvelopeInput | undefined = options.evidence
  if (!env) return null

  const recomputed = sha256Hex(
    canonicalizeJCS({ ...env, evidence_id: '', signature: '' }),
  )
  if (recomputed !== env.evidence_id) {
    return {
      valid: false,
      reason: 'EVIDENCE_REF_HASH_MISMATCH',
      detail: `envelope evidence_id ${String(env.evidence_id)} != recomputed ${recomputed}`,
    }
  }
  if (recomputed !== obj.cycles_evidence.cycles_evidence_id_sha256) {
    return {
      valid: false,
      reason: 'EVIDENCE_REF_HASH_MISMATCH',
      detail: `receipt cycles_evidence_id_sha256 ${obj.cycles_evidence.cycles_evidence_id_sha256} != envelope ${recomputed}`,
    }
  }
  return null
}

function _verifyReceiptCore(
  obj: AnyCyclesSigned,
  expectedClaimType:
    | typeof RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
  options: VerifyCyclesOptions,
): CyclesVerifyResult {
  const ttl = options.ttl_seconds ?? 24 * 60 * 60

  if (obj.claim_type !== expectedClaimType) {
    return { valid: false, reason: 'INVALID_CLAIM_TYPE', detail: `expected ${expectedClaimType} got ${obj.claim_type}` }
  }
  if (!obj.receipt_id || !obj.signer || !obj.agent_id || !obj.delegation_ref || !obj.action_ref) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD' }
  }
  if (obj.rail_name !== 'cycles') {
    return { valid: false, reason: 'INVALID_RAIL_NAME', detail: `expected 'cycles' got ${String(obj.rail_name)}` }
  }
  if (!obj.cycles_evidence?.cycles_evidence_url || !obj.cycles_evidence?.cycles_evidence_id_sha256) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'cycles_evidence' }
  }
  // Join-integrity: when the fetched envelope is supplied, bind it to the
  // receipt. Runs before signature/DID checks so a broken receipt↔envelope
  // join surfaces regardless of signer type (the DID path calls this core
  // first and propagates any non-DID_RESOLVER_MISSING failure unchanged).
  const joinFailure = _checkEvidenceJoin(obj, options)
  if (joinFailure) return joinFailure
  if (options.expected_signer && obj.signer !== options.expected_signer) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'signer mismatch' }
  }

  const issuedMs = Date.parse(obj.issued_at)
  if (!Number.isFinite(issuedMs)) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'issued_at' }
  }
  const nowMs = (options.now ?? new Date()).getTime()
  if (nowMs - issuedMs > ttl * 1000) {
    return { valid: false, reason: 'EXPIRED', detail: `older than ttl=${ttl}s` }
  }

  // Accountability-shape invariants (mpp convention). Cycles receipts
  // always carry the accountability fields (claim_type, timestamp,
  // scope_of_claim), so these are always checked.
  if (obj.timestamp !== obj.issued_at) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'timestamp != issued_at' }
  }
  if (
    !obj.scope_of_claim ||
    typeof obj.scope_of_claim.asserts !== 'string' ||
    obj.scope_of_claim.asserts.length === 0
  ) {
    return { valid: false, reason: 'MISSING_REQUIRED_FIELD', detail: 'scope_of_claim' }
  }

  // signature verify — strip sig, canonicalize, verify
  const { signature, ...rest } = obj
  const sigBytes = canonicalizeJCS(rest)
  if (typeof obj.signer === 'string' && obj.signer.startsWith('did:')) {
    return {
      valid: false,
      reason: 'DID_RESOLVER_MISSING',
      detail: 'use verify*WithDID for DID-URI signers',
    }
  }
  if (!edVerify(sigBytes, signature, obj.signer)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}

async function _verifyReceiptWithDID(
  obj: AnyCyclesSigned,
  expectedClaimType:
    | typeof RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
  options: VerifyCyclesOptions,
): Promise<CyclesVerifyResult> {
  const sync = _verifyReceiptCore(obj, expectedClaimType, options)
  if (sync.valid) return sync
  if (sync.reason !== 'DID_RESOLVER_MISSING') return sync
  if (!options.resolveDidDocument) {
    return { valid: false, reason: 'DID_RESOLVER_MISSING' }
  }
  const parsed = parseDidUri(obj.signer)
  if (!parsed) return { valid: false, reason: 'DID_URI_INVALID' }
  const didDoc = await options.resolveDidDocument(parsed.agentId)
  if (!didDoc) return { valid: false, reason: 'DID_DOC_NOT_FOUND' }
  const issuedMs = Date.parse(obj.issued_at)
  const result = resolveVerificationMethod(
    didDoc,
    obj.signer,
    options.now ? options.now.getTime() : undefined,
    Number.isFinite(issuedMs) ? issuedMs : undefined,
  )
  if (!result) return { valid: false, reason: 'DID_KEY_NOT_IN_DOC' }
  if (result.retired) return { valid: false, reason: 'DID_KEY_RETIRED' }
  const pubHex = publicKeyHexFromMethod(result.method)
  const { signature, ...rest } = obj
  const sigBytes = canonicalizeJCS(rest)
  if (!edVerify(sigBytes, signature, pubHex)) {
    return { valid: false, reason: 'SIGNATURE_INVALID', detail: 'Ed25519 verify failed' }
  }
  return { valid: true }
}

// ── External-evidence resolution: claimed vs resolved (W2-A2) ─────
// The sync/_WithDID paths above signature-check the receipt, which
// covers the CLAIMED cycles_evidence_id_sha256 but never fetches the
// envelope at cycles_evidence_url. These *WithEvidence paths COMPLETE
// the join-integrity check the file header flagged as a TODO: they run
// the full receipt verification first, then (when a caller-supplied
// resolver is present) fetch the envelope and recompute its content
// hash to test the claimed value. Egress lives entirely in the
// caller's resolver; the SDK reaches no global fetch.

/**
 * Combined verify + evidence-resolution result. `verify` is the existing
 * receipt verdict (signature, ttl, accountability shape - unchanged).
 * `evidence` is the claimed-vs-resolved verdict for the CyclesEvidence
 * envelope. `descriptor` is the mechanical input the W2-A1 verifier
 * descriptor consumes for the external-evidence axis.
 *
 * A green `verify` with a `signature_only` `descriptor.observation_basis`
 * is the explicit "claims an envelope at hash H, signature-checked only"
 * state. `counterparty_resolved` is "envelope at H fetched and matched".
 */
export interface CyclesVerifyWithEvidenceResult {
  verify: CyclesVerifyResult
  evidence: EvidenceResolutionResult
  descriptor: EvidenceDescriptorInput
}

async function _verifyWithEvidence(
  obj: AnyCyclesSigned,
  expectedClaimType:
    | typeof RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE
    | typeof RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE,
  options: VerifyCyclesOptions,
): Promise<CyclesVerifyWithEvidenceResult> {
  // Run the full receipt verification (DID-aware) first.
  const verify = await _verifyReceiptWithDID(obj, expectedClaimType, options)
  // Resolve the evidence ref regardless of the receipt verdict, so the
  // descriptor always reports the claimed-vs-resolved basis. Resolution
  // records failure, never throws.
  const evidence = await resolveEvidenceRef(
    obj.cycles_evidence,
    options.resolveEvidence,
    { failurePolicy: options.evidenceFailurePolicy },
  )
  return {
    verify,
    evidence,
    descriptor: toEvidenceDescriptorInput(evidence),
  }
}

export async function verifyCyclesPermitReceiptWithEvidence(
  receipt: CyclesPermitReceipt,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyWithEvidenceResult> {
  return _verifyWithEvidence(receipt, RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE, options)
}

export async function verifyCyclesReleaseReceiptWithEvidence(
  receipt: CyclesReleaseReceipt,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyWithEvidenceResult> {
  return _verifyWithEvidence(receipt, RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE, options)
}

export async function verifyCyclesDenialWithEvidence(
  denial: CyclesDenial,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyWithEvidenceResult> {
  return _verifyWithEvidence(denial, RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE, options)
}

/** Re-export the resolver type for callers wiring the async paths. */
export type { CyclesResolveDidDocument } from './types.js'

// ── External-evidence resolution surface (W2-A2) ──────────────────
export {
  resolveEvidenceRef,
  recomputeEvidenceContentHash,
  toEvidenceDescriptorInput,
} from './evidence-resolution.js'
export type {
  EvidenceResolver,
  EvidenceFetchResult,
  EvidenceResolutionResult,
  EvidenceResolutionStatus,
  EvidenceFailurePolicy,
  ResolveEvidenceConfig,
  FetchedCyclesEvidenceEnvelope,
  EvidenceDescriptorInput,
  EvidenceObservationBasis,
} from './evidence-resolution.js'
