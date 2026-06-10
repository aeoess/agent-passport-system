// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cycles — reserve/commit/release budget-authority rail
// ══════════════════════════════════════════════════════════════════
// Cycles (https://runcycles.io) is a pre-execution budget and action-
// authority protocol with a four-event lifecycle on the runtime plane:
//
//   decide  → stateless pre-check        (POST /v1/decide)
//   reserve → atomic authorization       (POST /v1/reservations)
//   commit  → settle at actual           (POST /v1/reservations/{id}/commit)
//   release → clear without debit        (POST /v1/reservations/{id}/release)
//
// Plus error responses (4xx/5xx) on any of the above.
//
// This adapter binds APS V2 governance to Cycles at the
// reserve / commit / release boundary, with the two-receipt emission
// model agreed in aeoess/agent-passport-system#25:
//
//   - Permit-receipt at reserve     (rail.budget_reservation.permit.v1)
//   - Release-receipt at release    (rail.budget_reservation.release.v1)
//   - Denial-receipt on live 4xx    (rail.budget_reservation.denial.v1)
//   - Denial-receipt on dry-run DENY or /v1/decide DENY (same literal)
//
// Signed denials carry an APS Tier-1 `denial_reason` (closed enum) plus
// the richer Cycles-specific detail Tier-2 in `cycles.denial_detail`.
// The full mapping spec lives at runcycles/cycles-protocol drafts/
// cycles-aps-denial-mapping-v0.1.md (merged commit 9b0fb5e).
//
// CyclesEvidence — the signed, content-addressed envelope wrapping the
// canonical Cycles wire body — is specified at runcycles/cycles-protocol
// drafts/cycles-evidence-v0.1.yaml (merged commit 61186a2). APS receipts
// reference it via the minimal `CyclesEvidenceRef` join shape below.
//
// SDK scope: type model + denial mapping + signed two-receipt emission.
// Out of scope (gateway product): live HTTP intercept, CyclesEvidence
// envelope construction (the Cycles server emits those), reservation
// lifecycle orchestration, multi-tenant routing.
// ══════════════════════════════════════════════════════════════════

import type { ScopeOfClaim } from '../../accountability/types/base.js'
export type { ScopeOfClaim } from '../../accountability/types/base.js'

/** Cycles protocol pin. Bump when the upstream protocol revision changes. */
export const CYCLES_PROTOCOL_VERSION = 'cycles-protocol-v0.1.25' as const

/** CyclesEvidence schema version this adapter consumes. */
export const CYCLES_EVIDENCE_SCHEMA_VERSION = 'cycles-evidence/v0.1' as const

// ── APS claim_type literals (rail.budget_reservation.*) ───────────
// These match the literals added to the payment-rails verifier in
// aeoess/agent-passport-system#27 (merged commit 4abd9df). The
// receipt-side literals (permit, release) ride the receipt-verify
// path; the denial literal rides the denial-verify path.

export const RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE =
  'rail.budget_reservation.permit.v1' as const
export const RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE =
  'rail.budget_reservation.release.v1' as const
export const RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE =
  'rail.budget_reservation.denial.v1' as const

// ── CyclesEvidenceRef (minimal join shape, APS ↔ Cycles boundary) ─
// Per issue #25 comment 4422627045: APS receipts reference Cycles-side
// CyclesEvidence envelopes by URL + content hash. The full
// envelope schema lives in cycles-protocol; APS only carries the join.

export interface CyclesEvidenceRef {
  /** Where to fetch the signed CyclesEvidence envelope. Opaque to APS. */
  cycles_evidence_url: string
  /** sha256 hex of the JCS-canonical envelope bytes with both
   *  evidence_id and signature emptied. The content-addressed id of
   *  the Cycles-side artifact this receipt binds to. */
  cycles_evidence_id_sha256: string
  /** APS-side action anchor (mirrors PaymentReceipt.action_ref). */
  action_ref: string
  /** APS-side delegation anchor (mirrors PaymentReceipt.delegation_ref). */
  delegation_ref: string
  /** For commit/release receipts: the prior permit-receipt's id, so
   *  the authorization → settlement chain is reconstructable from
   *  evidence alone. Omitted on permit-receipts and standalone denials. */
  prior_permit_receipt_id?: string
}

// ── Cycles wire-shape mirrors (minimal, read-only) ────────────────
// The adapter consumes CyclesEvidence envelopes to extract the
// denial signal. Defined here as a structural subset; full canonical
// schema lives at runcycles/cycles-protocol drafts/cycles-evidence-v0.1.yaml.

/** Cycles `Decision` enum — three-way decision on /decide and reserve. */
export type CyclesDecision = 'ALLOW' | 'ALLOW_WITH_CAPS' | 'DENY'

/** Cycles `ArtifactType` — the five CyclesEvidence lifecycle events. */
export type CyclesArtifactType =
  | 'decide'
  | 'reserve'
  | 'commit'
  | 'release'
  | 'error'

/** Minimal read-only view of a CyclesEvidence envelope's payload
 *  variants — only the fields the adapter actually reads. The full
 *  envelope schema (signed, content-addressed) lives at the canonical
 *  spec; this mirror exists so the denial-mapper can pattern-match
 *  without a full schema-validation dependency. */
export interface CyclesEvidenceView {
  artifact_type: CyclesArtifactType
  trace_id?: string
  payload:
    | {
        decide: { response: { decision: CyclesDecision; reason_code?: string } }
      }
    | {
        reserve: { response: { decision: CyclesDecision; reason_code?: string } }
      }
    | { commit: { reservation_id: string } }
    | { release: { reservation_id: string } }
    | {
        error: {
          endpoint: string
          http_status: number
          reservation_id?: string
          response: {
            error: string
            message: string
            request_id: string
            trace_id?: string
          }
        }
      }
}

// ── Authority-state-at-admission snapshot ─────────────────────────
// Optional Track B field (aeoess/agent-passport-system#25, amavashev
// catch): a snapshot of the authority/revocation/expiry state APS
// evaluated at admission, BEFORE calling Cycles. Carried inline on the
// permit-receipt (see `authority_state_at_admission` below), not as a
// content-hash ref. The delegation identity is not duplicated here — the
// receipt's own `delegation_ref` names the delegation this state is for.

/** Snapshot of the delegation-authority state APS saw at admission. */
export interface AuthorityStateSnapshot {
  /** Admission-time ISO 8601 — when APS evaluated this authority state. */
  checked_at: string
  /** Revocation state APS saw at admission. */
  delegation_revoked: boolean
  /** Delegation expiry APS saw at admission, when known. */
  delegation_expires_at?: string
  /** Origin of the snapshot. Fixed for the APS admission path. */
  source: 'aps_admission'
}

// ── Cycles permit-receipt ─────────────────────────────────────────

/** Signed receipt emitted at reserve-allow. Binds the APS delegation
 *  to a Cycles reservation; references the CyclesEvidence envelope
 *  for the underlying reserve event. */
export interface CyclesPermitReceipt {
  claim_type: typeof RAIL_BUDGET_RESERVATION_PERMIT_CLAIM_TYPE
  receipt_id: string
  signer: string
  agent_id: string
  delegation_ref: string
  action_ref: string
  rail_name: 'cycles'
  /** Cycles reservation_id from the reserve response. */
  reservation_id: string
  /** Reserved amount in canonical (unit, amount) form. Unit is the
   *  Cycles UnitEnum — USD_MICROCENTS, TOKENS, CREDITS, or RISK_POINTS. */
  reserved: { unit: string; amount: number }
  /** Cycles decision: ALLOW or ALLOW_WITH_CAPS (DENY rides denial). */
  decision: 'ALLOW' | 'ALLOW_WITH_CAPS'
  /** Reservation TTL deadline (Cycles `expires_at_ms`). */
  expires_at_ms?: number
  /** Bind to the signed Cycles-side artifact. */
  cycles_evidence: CyclesEvidenceRef
  issued_at: string
  /** Hex Ed25519 signature over the canonical receipt body, signature cleared. */
  signature: string

  /** Phase 4.1 / Q1 accountability fields. */
  timestamp?: string
  scope_of_claim?: ScopeOfClaim

  /** Optional (Track B): the authority/revocation/expiry state APS
   *  evaluated at admission, before calling Cycles, carried inline.
   *  Optional so existing fixtures and call sites that omit it stay
   *  valid. */
  authority_state_at_admission?: AuthorityStateSnapshot

  /** Optional (W2-B1): pointer to the trust-root-policy a producer
   *  evaluated this receipt's issuer against, of the form
   *  `${policy_id}@${policy_version}`. It is a REFERENCE, not an
   *  assurance: a relying party re-derives its own verdict against its
   *  own policy and never reads acceptance off this field. Optional so
   *  existing fixtures and call sites that omit it keep byte-identical
   *  canonical form. */
  trust_policy_ref?: string
}

// ── Cycles release-receipt ────────────────────────────────────────

/** Signed receipt emitted at release. Symmetric to permit; references
 *  the prior permit-receipt for chain completeness. */
export interface CyclesReleaseReceipt {
  claim_type: typeof RAIL_BUDGET_RESERVATION_RELEASE_CLAIM_TYPE
  receipt_id: string
  signer: string
  agent_id: string
  delegation_ref: string
  action_ref: string
  rail_name: 'cycles'
  reservation_id: string
  released: { unit: string; amount: number }
  /** Optional reason from the ReleaseRequest body. */
  reason?: string
  cycles_evidence: CyclesEvidenceRef
  issued_at: string
  signature: string

  timestamp?: string
  scope_of_claim?: ScopeOfClaim
}

// ── Cycles denial-receipt ─────────────────────────────────────────

/** Closed taxonomy of Cycles-sourced denial reasons (the source axis;
 *  the Tier-1 mapping happens via mapCyclesDenialToFoundation). */
export type CyclesDenialSource = 'ErrorCode' | 'DecisionReasonCode'

/** Cycles-specific denial detail. Lives Tier-2 in the APS denial-
 *  receipt under `cycles.denial_detail` so audit consumers retain the
 *  canonical denial identifier byte-for-byte. */
export interface CyclesDenialDetail {
  layer: 'cycles'
  /** Which Cycles axis surfaced the denial — see mapping doc. */
  source: CyclesDenialSource
  /** The canonical Cycles code (ErrorCode value OR DecisionReasonCode
   *  value, depending on `source`). Preserved byte-for-byte. */
  code: string
  /** HTTP status on the wire (only present when source=ErrorCode). */
  http_status?: number
  /** Server message (only present when source=ErrorCode). */
  message?: string
  /** Request correlation id (only present when source=ErrorCode). */
  request_id?: string
  /** W3C Trace Context trace-id (32-hex), when populated. */
  trace_id?: string
}

/** Signed denial — emitted on live 4xx, on /v1/decide DENY, or on
 *  dry-run reserve DENY. Carries the APS Tier-1 reason (closed enum
 *  via DenialReason from payment-rails/types.ts) plus the rich
 *  Cycles-side detail Tier-2. */
export interface CyclesDenial {
  claim_type: typeof RAIL_BUDGET_RESERVATION_DENIAL_CLAIM_TYPE
  receipt_id: string
  signer: string
  agent_id: string
  delegation_ref: string
  action_ref: string
  rail_name: 'cycles'
  /** APS Tier-1 reason from payment-rails/types.ts DenialReason. The
   *  string-typed import avoids a circular import; runtime validation
   *  via VALID_DENIAL_REASONS in hooks.ts. */
  denial_reason: string
  cycles: { denial_detail: CyclesDenialDetail }
  cycles_evidence: CyclesEvidenceRef
  issued_at: string
  signature: string

  timestamp?: string
  scope_of_claim?: ScopeOfClaim
}

// ── Verification result types ─────────────────────────────────────

export type CyclesVerifyReason =
  | 'INVALID_CLAIM_TYPE'
  | 'INVALID_SCHEMA_VERSION'
  | 'INVALID_RAIL_NAME'
  | 'MISSING_REQUIRED_FIELD'
  | 'SIGNATURE_INVALID'
  | 'EXPIRED'
  | 'EVIDENCE_REF_HASH_MISMATCH'
  /** The supplied CyclesEvidence envelope's OWN Ed25519 signature does not
   *  verify against the key in its `signer_did` (or `signer_did`/`signature`
   *  is absent). APS#43 (a): envelope signature validity. Distinct from
   *  EVIDENCE_REF_HASH_MISMATCH, which is the receipt↔envelope hash binding. */
  | 'EVIDENCE_SIGNATURE_INVALID'
  | 'DID_RESOLVER_MISSING'
  | 'DID_URI_INVALID'
  | 'DID_DOC_NOT_FOUND'
  | 'DID_KEY_NOT_IN_DOC'
  | 'DID_KEY_RETIRED'

/**
 * Which envelope-authenticity guarantee a passing verify actually checked,
 * surfaced when `options.evidence` is supplied (APS#43, the (a)/(b) split).
 * Present ONLY on a `valid: true` result that carried an envelope.
 *
 *  - 'signature_valid' : the envelope's own Ed25519 `signature` verifies
 *      against the key named in its `signer_did`. This is (a). It proves
 *      the bytes were signed by *that* key — NOT that the key is the
 *      legitimate Cycles signer. A forger can embed their own key and
 *      self-sign a consistent envelope, so signature_valid alone is not
 *      authenticity.
 *  - 'pinned_issuer'   : signature_valid AND the caller pinned the receipt
 *      issuer via `expected_signer` (enforced separately). NOTE the pin is on
 *      the APS *receipt* signer (`obj.signer`), not the envelope's
 *      `signer_did`. Envelope authenticity is therefore TRANSITIVE: it holds
 *      only insofar as you trust the pinned receipt issuer to have bound this
 *      receipt solely to a legitimate Cycles envelope. This is the manual
 *      form of (b) — a trust assumption about the pinned issuer, not a
 *      cryptographic proof of `signer_did`'s authority. Resolving that
 *      authority directly (so the unpinned case is also covered) is (b),
 *      gated on runcycles/cycles-protocol#103.
 */
export type EvidenceAuthenticity = 'signature_valid' | 'pinned_issuer'

export type CyclesVerifyResult =
  | { valid: true; evidence_authenticity?: EvidenceAuthenticity }
  | { valid: false; reason: CyclesVerifyReason; detail?: string }

// ── Sign-function input shapes (mirror the mpp/x402 pattern) ──────

export interface SignCyclesPermitReceiptInput {
  agent_id: string
  delegation_ref: string
  action_ref: string
  reservation_id: string
  reserved: { unit: string; amount: number }
  decision: 'ALLOW' | 'ALLOW_WITH_CAPS'
  expires_at_ms?: number
  cycles_evidence: CyclesEvidenceRef
  /** Optional (Track B): the authority-state snapshot APS evaluated at
   *  admission. When supplied, it is carried inline on the permit-receipt
   *  as authority_state_at_admission; when omitted, the field is left
   *  absent. */
  authority_state_at_admission?: AuthorityStateSnapshot
  /** Override the rail's default scope_of_claim. */
  scope_of_claim?: ScopeOfClaim
  /** When supplied alongside `issuer_key_ref`, signer becomes a DID URI
   *  of the form `${issuer_agent_id}#${issuer_key_ref}`. Otherwise the
   *  signer is the raw hex pubkey derived from the private key. */
  issuer_agent_id?: string
  issuer_key_ref?: string
  /** Optional (W2-B1): trust-root-policy reference, carried onto the
   *  permit-receipt as trust_policy_ref when supplied; absent otherwise
   *  (canonical bytes unchanged on omit). */
  trust_policy_ref?: string
}

export interface SignCyclesReleaseReceiptInput {
  agent_id: string
  delegation_ref: string
  action_ref: string
  reservation_id: string
  released: { unit: string; amount: number }
  /** Optional reason from the ReleaseRequest body. */
  reason?: string
  cycles_evidence: CyclesEvidenceRef
  scope_of_claim?: ScopeOfClaim
  issuer_agent_id?: string
  issuer_key_ref?: string
}

export interface SignCyclesDenialInput {
  agent_id: string
  delegation_ref: string
  action_ref: string
  /** APS Tier-1 reason — must be a member of `DenialReason` from
   *  payment-rails/types.ts. Runtime validation against
   *  VALID_DENIAL_REASONS at hooks.ts:87-94. */
  denial_reason: string
  cycles: { denial_detail: CyclesDenialDetail }
  cycles_evidence: CyclesEvidenceRef
  scope_of_claim?: ScopeOfClaim
  issuer_agent_id?: string
  issuer_key_ref?: string
}

// ── Fetched CyclesEvidence envelope (join-integrity input) ────────
// The full Cycles-side envelope a receipt's `cycles_evidence` references,
// as fetched from `cycles_evidence_url`. Unlike `CyclesEvidenceView`
// (the read-only denial-mapping subset), this carries `evidence_id` and
// `signature` so the verifier can recompute the content hash. APS treats
// the envelope as opaque beyond those two fields, hence the index
// signature — the recompute canonicalizes ALL fields, so every field the
// Cycles server emitted must survive the round-trip byte-for-byte.

/** A fetched CyclesEvidence envelope, for the join-integrity check. */
export interface CyclesEvidenceEnvelopeInput {
  /** Content-addressed id: sha256 of the JCS-canonical envelope bytes
   *  with `evidence_id` and `signature` both set to the empty string.
   *  Per runcycles/cycles-protocol drafts/cycles-evidence-v0.1.yaml. */
  evidence_id: string
  /** Ed25519 signature hex over the JCS-canonical envelope with `signature`
   *  emptied and `evidence_id` POPULATED (distinct from the content-hash
   *  recipe, which empties both). Emptied (not omitted) during the recompute;
   *  verified as-is against `signer_did` for the APS#43 (a) authenticity
   *  check. Per runcycles/cycles-protocol drafts/cycles-evidence-v0.1.yaml. */
  signature: string
  /** The Cycles signer key the envelope `signature` is verified against.
   *  v0.1 form is a bare Ed25519 hex pubkey (self-describing); a future
   *  `did:cycles` / JWKS resolvable form is the v0.2 (b) work tracked at
   *  runcycles/cycles-protocol#103. */
  signer_did: string
  [key: string]: unknown
}

// ── Verify-options shape ──────────────────────────────────────────

export interface VerifyCyclesOptions {
  now?: Date
  ttl_seconds?: number
  expected_signer?: string
  /** Required when signer is a DID URI. Sync verify paths return
   *  DID_RESOLVER_MISSING; pass this to the *WithDID async paths. */
  resolveDidDocument?: CyclesResolveDidDocument
  /** Optional (W2-A2): a caller-supplied resolver for the CyclesEvidence
   *  envelope at cycles_evidence_url. When supplied to the *WithEvidence
   *  async paths, the verifier fetches the envelope and recomputes its
   *  content hash to test the CLAIMED cycles_evidence_id_sha256. When
   *  omitted, the claimed hash is signature-checked only (claimed, not
   *  resolved). The SDK performs no network egress itself: the resolver
   *  owns the transport. Mirrors the resolveDidDocument seam. */
  resolveEvidence?: import('./evidence-resolution.js').EvidenceResolver
  /** Optional (W2-A2): failure posture for envelope resolution. Default
   *  'closed'. fail-open relaxes ONLY an unreachable endpoint to a
   *  degraded, still non-matching outcome; it never makes an unmatched
   *  envelope read as resolved. */
  evidenceFailurePolicy?: import('./evidence-resolution.js').EvidenceFailurePolicy
  /** The fetched CyclesEvidence envelope this receipt's `cycles_evidence`
   *  references (retrieved from `cycles_evidence_url`). When supplied,
   *  verify performs the join-integrity check: recompute the envelope's
   *  content hash and confirm it matches BOTH the envelope's own
   *  `evidence_id` (envelope untampered) AND the receipt's
   *  `cycles_evidence.cycles_evidence_id_sha256` (receipt binds to THIS
   *  envelope). When omitted, the check is skipped — signature-only
   *  verification, preserving prior behavior. APS does not own the fetch
   *  contract; the caller retrieves the envelope and passes it in. */
  evidence?: CyclesEvidenceEnvelopeInput
}

/** DID document resolver — mirrors MppResolveDidDocument. */
export type CyclesResolveDidDocument = (
  agentId: string,
) => Promise<import('../../../types/passport.js').RotatableDIDDocument | null>
