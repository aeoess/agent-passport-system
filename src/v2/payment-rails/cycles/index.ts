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
// Out of scope for this commit (TODO follow-up):
//   - cycles_evidence_id_sha256 join-integrity check against a fetched
//     CyclesEvidence envelope (the load-bearing offline-audit guarantee).
//     Stub: VerifyCyclesOptions has no envelope field today; future
//     option add will pass the envelope in and recompute the sha256.
//   - preAuthorizeCyclesReserve gateway hook into PaymentRail interface.
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
  const sigBytes = canonicalizeJCS(unsigned)
  const signature = sign(sigBytes, signerPrivateKeyHex)
  return { ...unsigned, signature }
}

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

export async function verifyCyclesDenialWithDID(
  denial: CyclesDenial,
  options: VerifyCyclesOptions = {},
): Promise<CyclesVerifyResult> {
  return _verifyReceiptWithDID(denial, RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE, options)
}

// ── Internal verifiers (shared by all three artifact types) ───────

type AnyCyclesSigned = CyclesPermitReceipt | CyclesReleaseReceipt | CyclesDenial

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

/** Re-export the resolver type for callers wiring the async paths. */
export type { CyclesResolveDidDocument } from './types.js'
