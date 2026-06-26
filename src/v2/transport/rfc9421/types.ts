// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * @fileoverview Type definitions for the RFC 9421 + RFC 9530 request-binding
 * profile.
 *
 * This profile wraps a request-bound HTTP Message Signature (RFC 9421) as the
 * INNER proof and links it to an APS delegation receipt by content hash. The
 * HTTP signature shows "this exact request was the one authorized"; the APS
 * layer shows authority. These are two separate claims and must not be
 * conflated.
 *
 * IMPORTANT: action_ref does NOT bind the HTTP request. The binding between an
 * HTTP request and a delegation receipt here is the inner HTTP Message
 * Signature plus the explicit receipt content hash carried in the profile, not
 * the action_ref preimage.
 *
 * Strings below follow RFC 9421 (HTTP Message Signatures) and RFC 9530 (Digest
 * Fields) byte conventions. Byte-exactness is load-bearing: any difference in
 * case, the ": " separator, LF vs CRLF, parameter order, quoting, or
 * Structured-Fields serialization between the @signature-params base line and
 * the Signature-Input field value will cause verification failure.
 */

import type { ScopeOfClaim } from '../../accountability/types/base.js'

/**
 * A derived component identifier covered by this profile (RFC 9421 §2.2).
 * This profile covers the request-context derived components only; it does not
 * implement response-bound or query-param components, though @query MAY be
 * added by callers via rawCoveredComponents when query params are
 * security-relevant.
 */
export type DerivedComponent = '@method' | '@authority' | '@path'

/**
 * A field component identifier covered by this profile. content-digest binds
 * the body per RFC 9530.
 */
export type FieldComponent = 'content-digest'

/** Any component identifier this profile can place in the signature base. */
export type CoveredComponent = DerivedComponent | FieldComponent

/**
 * Supported content-digest algorithms (RFC 9530). Only sha-256 is implemented
 * as a reference; the dictionary key is the lowercase algorithm token.
 */
export type ContentDigestAlgorithm = 'sha-256'

/**
 * Signature algorithm. Ed25519 is the reference algorithm and is the one with a
 * deterministic, byte-matchable RFC vector (RFC 9421 Appendix B.2.6).
 */
export type SignatureAlgorithm = 'ed25519'

/**
 * The minimal request context needed to derive @method, @authority, @path and
 * to compute content-digest. Values are taken as-is from the request target.
 */
export interface RequestContext {
  /** HTTP method. Serialized uppercased per RFC 9421 §2.2.1. */
  method: string
  /**
   * Absolute target URI of the request, e.g.
   * 'https://example.com/foo?param=Value'. @authority and @path are derived
   * from this. Query is NOT part of @path.
   */
  url: string
  /**
   * Request body bytes, if any. When present and content-digest is covered, the
   * digest is computed over these exact bytes (content coding as transferred).
   */
  body?: Uint8Array
}

/**
 * Signing parameters that appear in the @signature-params line and the
 * Signature-Input field value, in declared order (RFC 9421 §2.3). Order is part
 * of the signed bytes.
 */
export interface SignatureParams {
  /** Unix seconds. Serialized UNQUOTED as a Structured-Fields Integer. */
  created: number
  /**
   * keyid is the DID verification method. Serialized QUOTED as a
   * Structured-Fields String. For the reference Ed25519 path this is a DID URL
   * fragment identifying the verification method, e.g.
   * 'did:key:z6Mk...#z6Mk...'.
   */
  keyid: string
  /**
   * Signer-chosen unique value. Serialized QUOTED. Replay defense; the verifier
   * MUST track seen nonces. nonce in Signature-Input is signer-asserted only.
   */
  nonce: string
  /**
   * Application/profile tag. Serialized QUOTED. Scopes a signature to a profile
   * to prevent cross-protocol reuse (RFC 9421 §7.2.x). Defaults to the APS
   * request-binding profile tag.
   */
  tag: string
  /**
   * Optional algorithm hint. Serialized QUOTED when present. OMITTED by default
   * to avoid alg-confusion; the verifier derives the algorithm from the key.
   */
  alg?: SignatureAlgorithm
  /** Optional expiry, Unix seconds. Serialized UNQUOTED when present. */
  expires?: number
}

/** The DID verification method material the signer holds. */
export interface SignerKey {
  /** Raw 32-byte Ed25519 private key, hex-encoded (64 hex chars). */
  privateKeyHex: string
  /**
   * DID verification method id placed in keyid, e.g.
   * 'did:key:z6Mk...#z6Mk...'. This is asserted, not resolved, by this
   * primitive; resolution is a separate concern.
   */
  verificationMethod: string
}

/** The verifying counterpart: the public key the verifier trusts for keyid. */
export interface VerifierKey {
  /** Raw 32-byte Ed25519 public key, hex-encoded (64 hex chars). */
  publicKeyHex: string
  /** DID verification method id this public key corresponds to. */
  verificationMethod: string
}

/**
 * The on-wire artifacts produced by signing a request, plus the bytes that were
 * actually signed. label is the Structured-Fields Dictionary key under which
 * Signature-Input and Signature carry this signature.
 */
export interface RequestSignature {
  /** Structured-Fields Dictionary key, e.g. 'aps'. */
  label: string
  /** Signature-Input field value for this label (no field name prefix). */
  signatureInput: string
  /** Signature field value for this label, sig-label=:BASE64:. */
  signature: string
  /**
   * Content-Digest field value, present when a body was covered, e.g.
   * 'sha-256=:...:'. The verifier recomputes this over received bytes.
   */
  contentDigest?: string
  /** The exact signature base string that was signed (ASCII, LF-joined). */
  signatureBase: string
}

/**
 * The request-binding profile object. The HTTP Message Signature is the inner
 * proof; receiptHash links it to an APS delegation receipt by content hash.
 *
 * This object is a transport envelope. It is NOT an APS accountability receipt
 * and is not signed with the APS receipt-signing path. scopeOfClaim is carried
 * to keep the evidentiary boundary explicit wherever this profile touches a
 * receipt.
 */
export interface RequestBindingProfile {
  /** Profile identifier, fixed for this version. */
  profile: 'aps:rfc9421-request-binding:v1'
  /** The covered components in signed order. */
  covered: CoveredComponent[]
  /** The inner HTTP Message Signature artifacts. */
  inner: RequestSignature
  /** The signer's DID verification method (same as keyid). */
  verificationMethod: string
  /** created from the signature params, surfaced for freshness checks. */
  created: number
  /** nonce from the signature params, surfaced for replay checks. */
  nonce: string
  /** tag from the signature params, surfaced for profile-scope checks. */
  tag: string
  /**
   * Content hash of the APS delegation receipt this request is bound to, hex
   * sha-256 over the receipt's canonical bytes. This is the link between the
   * HTTP request and APS authority. It is set by the caller; this profile does
   * not compute the receipt's own canonical form.
   */
  receiptHash?: string
  /**
   * Honest scope declaration. Reuses the shared ScopeOfClaim shape rather than
   * redefining it.
   */
  scopeOfClaim: ScopeOfClaim
}

/** Verifier acceptance policy. */
export interface VerifyPolicy {
  /** Expected profile tag. A mismatch is rejected (cross-protocol reuse). */
  expectedTag: string
  /**
   * Maximum allowed clock skew in seconds for created. A created value outside
   * [now - maxSkewSeconds, now + maxSkewSeconds] is rejected as stale or
   * future-dated.
   */
  maxSkewSeconds: number
  /**
   * Components that MUST be present in the covered set, else reject. Defaults to
   * @method, @authority, @path. An empty covered set is always rejected.
   */
  requiredComponents?: CoveredComponent[]
  /**
   * Reference time in Unix seconds. Defaults to Date.now()/1000. Injectable for
   * deterministic tests.
   */
  nowSeconds?: number
}

/** Reasons a verification can fail, for precise negative-path testing. */
export type VerifyFailureReason =
  | 'empty_covered_set'
  | 'missing_required_component'
  | 'tag_mismatch'
  | 'stale_created'
  | 'expired'
  | 'unknown_verification_method'
  | 'content_digest_missing'
  | 'content_digest_mismatch'
  | 'base_reconstruction_mismatch'
  | 'signature_invalid'
  | 'replayed_nonce'
  | 'malformed_input'

/** Result of verifying a request against a profile. */
export interface VerifyResult {
  valid: boolean
  reason?: VerifyFailureReason
  /** The verification method whose key validated the signature, when valid. */
  verificationMethod?: string
  /** Whether replay was checked. False when no nonceStore was supplied: the signature is valid but
   *  the request was NOT checked for nonce reuse, so it can be replayed. Require replayChecked when
   *  replay protection matters. */
  replayChecked?: boolean
}
