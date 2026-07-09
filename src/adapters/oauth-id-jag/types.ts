// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Types for the OAuth ID-JAG to APS delegation binding.
// Pinned to draft-ietf-oauth-identity-assertion-authz-grant-04 (2026-05-21).
// Stable APS semantics; draft-pinned external protocol semantics.

import type { Delegation } from '../../types/passport.js'
import type { DelegationRef } from '../../core/reanchor.js'
import type { AttestedSignal } from '../../types/attestation.js'

/** The pinned ID-JAG draft identifier. A version bump is a separate, deliberate change. */
export const IDJAG_DRAFT = 'draft-ietf-oauth-identity-assertion-authz-grant-04'

/** Domain-separation tag for the source-grant-ref commitment preimage. */
export const SOURCE_GRANT_REF_TAG = 'aps.id_jag.source_grant_ref.v1'

/**
 * The decoded ID-JAG claims (draft-04 field names). This is the decoded grant,
 * NOT proof that it was verified. The public path takes VerifiedIdJagGrant.
 */
export interface IdJagClaims {
  /** IdP Authorization Server issuer identifier. */
  iss: string
  /** Subject identifier (the authenticated End-User). */
  sub: string
  /** Resource Authorization Server identifier. */
  aud: string
  /** OAuth 2.0 client at the Resource Authorization Server. */
  client_id: string
  /** Unique JWT identifier. */
  jti: string
  /** Expiration time (JWT NumericDate, seconds since epoch). */
  exp: number
  /** Issued-at time (JWT NumericDate, seconds since epoch). */
  iat: number
  /** Subject identifier in an alternate namespace (optional). */
  sub_id?: string
  /** Resource Server identifier (optional). */
  resource?: string
  /** Space-separated scopes (optional). */
  scope?: string
  /** RAR authorization objects (optional). */
  authorization_details?: IdJagAuthorizationDetail[]
  /** Actor claim (optional). Advisory only. */
  act?: Record<string, unknown>
  /** Multi-tenant issuer tenant identifier (optional). Opaque context. */
  tenant?: string
  /** End-User authentication time (optional). Opaque context. */
  auth_time?: number
  /** Authentication Context Class Reference (optional). Opaque context. */
  acr?: string
  /** Authentication methods (optional). Opaque context. */
  amr?: string[]
  /** Resource AS tenant identifier (optional). Opaque context. */
  aud_tenant?: string
  /** Resource AS identifier for the End-User (optional). Opaque context, minimizable. */
  aud_sub?: string
  /** End-User email (optional). Opaque context, minimizable. */
  email?: string
}

/** A Rich Authorization Request object. RAR is open; only recognized fields are read. */
export interface IdJagAuthorizationDetail {
  type: string
  [key: string]: unknown
}

/** The caller's statement that it verified the grant. The grant signature itself is the caller's responsibility, never this module's. */
export interface IdJagVerification {
  /** Fixed: the caller asserts it verified the grant. */
  status: 'caller_verified'
  /** ISO 8601 time the caller performed verification. Required to form the signed attestation. */
  verifiedAt?: string
  /** Optional identifier of the verifier (DID or URI). */
  verifier?: string
  /** Optional kid the caller used to verify the grant. Recorded, never folded into a commitment as proof. */
  kid?: string
}

declare const VERIFIED_BRAND: unique symbol

/**
 * A grant the caller asserts it has verified, wrapped so an unverified grant is
 * unrepresentable on the public path. Construct only via verifiedIdJagGrant().
 */
export interface VerifiedIdJagGrant {
  readonly [VERIFIED_BRAND]: true
  readonly grant: IdJagClaims
  readonly verification: IdJagVerification
}

/** The committed preimage for sourceGrantRef. Provenance and binding target ONLY. Never scope, spend, chain, or receipt content. */
export interface SourceGrantRefPreimage {
  tag: typeof SOURCE_GRANT_REF_TAG
  draft: string
  iss: string
  sub: string
  jti: string
  client_id: string
  aud: string
  resource?: string
  exp: number
}

/** Marks the chain root as imported external trust, not an APS-native root. APS verification begins at the first APS-signed hop. */
export interface IdJagExternalRoot {
  type: 'external_identity_assertion'
  protocol: 'id-jag'
  verifiedBy: 'caller'
}

/** aud plus resource, carried but NOT enforced by the binding. The relying party MUST reject a mismatch. */
export interface IdJagCarriedAudience {
  enforcement: 'not_enforced_by_binding'
  recipients: string[]
}

/** Literal-only reconciliation of the ID-JAG act claim against the APS chain leaf. Advisory, never authoritative. */
export interface IdJagActReconciliation {
  status:
    | 'absent'
    | 'same_literal_identifier'
    | 'different_literal_identifier_not_enforced'
    | 'not_comparable'
  advisoryAct: Record<string, unknown> | null
}

/** The caller-signed verification attestation. Sound by accountability (a keyed party on the hook), not by construction. */
export interface IdJagCallerVerification {
  /** Existing-vocabulary signal record. provenance self_declared, verificationStatus declared (APS did not re-verify the grant). */
  signal: AttestedSignal
  /** The exact signed message: "verified grant <sourceGrantRef> at <verifiedAt>". */
  message: string
  /** The caller's signature over message, checkable under signerPublicKey. */
  signature: string
  /** The caller's APS public key (the party on the hook). */
  signerPublicKey: string
  /** ISO 8601 time the caller verified the grant. */
  verifiedAt: string
  /** Optional kid the caller used. Recorded only. */
  kid?: string
}

/** A non-fatal observation made during projection (for example a unitless RAR amount that was not stamped). */
export interface IdJagDiagnostic {
  code:
    | 'UNITLESS_AMOUNT_NOT_STAMPED'
    | 'RAR_SCOPE_CONFLICT_NOT_APPLIED'
    | 'OPAQUE_RAR_CARRIED_IMMUTABLE'
  detail: string
}

/** Claims carried by reference with no APS narrowing meaning. */
export interface IdJagOpaqueContext {
  tenant?: string
  aud_tenant?: string
  acr?: string
  amr?: string[]
  auth_time?: number
  aud_sub?: string
  email?: string
  sub_id?: string
}

/** Options for binding. Privacy minimization defaults OFF (public SDK; the draft asks to minimize sub_id). */
export interface IdJagBindOptions {
  /** When true, email, sub_id, and aud_sub are omitted from carried context. Default false. */
  minimizeSensitive?: boolean
}

/**
 * The binding descriptor. A pure projection of a verified ID-JAG grant onto the
 * APS envelope, plus the APS-signed chain built under it. Two anchors are kept
 * separate and never merged: delegationChainRoot is canonical chain content;
 * sourceGrantRef is grant provenance.
 */
export interface IdJagDescriptor {
  /** Pinned ID-JAG draft identifier. */
  draft: string
  /** Grant provenance hash over the committed preimage. NOT chain content. */
  sourceGrantRef: string
  /** The committed preimage, so a verifier can recompute sourceGrantRef. */
  sourceGrantRefPreimage: SourceGrantRefPreimage
  /** Canonical chain content hash over the APS-signed hops. NOT grant identity. */
  delegationChainRoot: string
  /** The APS-signed delegation hops built under the imported grant. */
  chain: Delegation[]
  /** Root authority by reference (the End-User sub). Keyless. */
  rootRef: DelegationRef
  /** Label marking the root as imported external trust. */
  externalRoot: IdJagExternalRoot
  /** First delegate: the requesting client at the Resource AS (a reference). */
  delegatedTo: string
  /** Projected APS scope baseline (from the scope claim). Lossy; see rawAuthorizationDetails. */
  scope: string[]
  /** The raw RAR objects, always preserved verbatim. */
  rawAuthorizationDetails: IdJagAuthorizationDetail[]
  /** True: the scope projection is lossy relative to authorization_details. */
  projectionLossy: boolean
  /** Non-fatal projection observations. */
  diagnostics: IdJagDiagnostic[]
  /** Spend cap, set ONLY when a recognized RAR amount carries a currency. Never invented. */
  spendLimit?: number
  /** Spend unit, set ONLY alongside a recognized spendLimit. Never invented, never 'unspecified'. */
  spendLimitUnit?: 'currency' | 'invocations'
  /** createdAt (ISO 8601) from iat. No notBefore: draft-04 has no nbf claim. */
  createdAt: string
  /** expiresAt (ISO 8601) from exp. */
  expiresAt: string
  /** aud plus resource, carried, not enforced by the binding. */
  carriedAudience: IdJagCarriedAudience
  /** External state the binding does not check. */
  externalState: { revocation: 'not_checked_by_binding' }
  /** Literal-only act reconciliation. Advisory. */
  actReconciliation: IdJagActReconciliation
  /** The caller-signed verification attestation. */
  callerVerification: IdJagCallerVerification
  /** Claims carried by reference with no APS narrowing meaning. */
  opaqueContext: IdJagOpaqueContext
  /** Honestly marks confirmation/sender-constraint material that is not carried. */
  notCarried: { cnf: 'not_carried'; dpop: 'not_carried' }
}

/** The result of the soundness verifier. */
export interface IdJagVerifyResult {
  /** Structural soundness: anchors recompute, attestation signature checks, no invented unit, draft pinned. */
  ok: boolean
  /**
   * Never a bare safe-for-execution boolean. When ok and external constraints
   * (audience, revocation) are carried but unchecked, this reports
   * structurally_valid_with_unchecked_external_constraints.
   */
  status:
    | 'structurally_valid_with_unchecked_external_constraints'
    | 'unsound'
  /** Per-check booleans. */
  checks: {
    draftPinned: boolean
    sourceGrantRefRecomputes: boolean
    sourceGrantRefPreimageScopeClean: boolean
    delegationChainRootRecomputes: boolean
    attestationSignatureValid: boolean
    audienceMarkedUnenforced: boolean
    noSilentSpendUnit: boolean
  }
  /** Human-readable failures (empty when ok). */
  failures: string[]
}

/** Error raised when a verified ID-JAG grant cannot be bound (missing required claim, missing verifiedAt). */
export class IdJagBindingError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message)
    this.name = 'IdJagBindingError'
  }
}
