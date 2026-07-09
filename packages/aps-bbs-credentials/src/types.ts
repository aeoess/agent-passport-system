// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * @fileoverview EXPERIMENTAL, ISOLATED. Types for BBS selective-disclosure
 * scope credentials. This package is NOT imported by core and is NOT
 * core-reviewed crypto this round.
 *
 * A scope credential binds an ordered list of scope strings (for example
 * delegation scopes such as "read:repo" or "settle:usd:<=100") into a single
 * fixed-size BBS signature. The holder can later derive a zero-knowledge proof
 * that reveals only a chosen SUBSET of those scopes, without revealing the
 * undisclosed scopes or the original signature.
 *
 * Local mirror of ScopeOfClaim. The shape mirrors
 * src/v2/accountability/types/base.ts so callers can dogfood the honest-scope
 * convention without this isolated package importing core. Kept structurally
 * compatible on purpose; it is intentionally a copy, not an import, to preserve
 * isolation.
 */

export type CaptureMode =
  | 'gateway_observed'
  | 'runtime_attested'
  | 'self_attested'
  | 'partial'
  | 'unknown'

export type Completeness = 'complete' | 'partial' | 'best_effort'

/**
 * Structurally compatible with the core ScopeOfClaim
 * (src/v2/accountability/types/base.ts). Copied, not imported, to keep this
 * experimental package fully isolated from core.
 */
export interface ScopeOfClaim {
  /** 1-2 sentences: what this artifact claims cryptographically. */
  asserts: string
  /** Explicit list of what this artifact does NOT prove. */
  does_not_assert: string[]
  capture_mode: CaptureMode
  completeness: Completeness
  /** True when the holder itself produced the artifact without independent
   *  attestation. Self-attested artifacts have lower evidentiary weight. */
  self_attested: boolean
}

/** Selects the BBS ciphersuite hash function. */
export type Ciphersuite = 'SHA-256' | 'SHAKE-256'

/** A BBS key pair over BLS12-381. SK is a 32-byte scalar, PK is a 96-byte
 *  compressed G2 point. Both are raw bytes. */
export interface BbsKeyPair {
  /** Secret key, 32-byte scalar. */
  secretKey: Uint8Array
  /** Public key, 96-byte compressed G2 point. */
  publicKey: Uint8Array
}

/**
 * A scope credential issued by a signer over an ordered scope vector.
 * The signature is fixed-size (80 bytes) regardless of how many scopes it
 * covers.
 */
export interface ScopeCredential {
  /** Signer public key, 96-byte compressed G2 point. */
  publicKey: Uint8Array
  /** Domain-separation header bound into the signature at issue time. */
  header: Uint8Array
  /** Ordered scope strings, exactly as signed. Order is load-bearing:
   *  disclosure indexes refer to this order. */
  scopes: string[]
  /** BBS signature over the full scope vector, 80 bytes. */
  signature: Uint8Array
  /** Ciphersuite the credential was issued under. */
  ciphersuite: Ciphersuite
  /** Honest scope-of-claim for this credential. */
  scopeOfClaim: ScopeOfClaim
}

/**
 * A derived selective-disclosure presentation. Reveals only the disclosed
 * scopes; the undisclosed scopes and the original signature stay hidden.
 */
export interface ScopeDisclosureProof {
  /** Signer public key the proof verifies against, 96-byte G2 point. */
  publicKey: Uint8Array
  /** Header bound at issue time; required to verify. */
  header: Uint8Array
  /** Presentation header (verifier-supplied challenge) bound into the proof
   *  to prevent replay. */
  presentationHeader: Uint8Array
  /** The disclosed scope strings, in disclosure order. */
  disclosedScopes: string[]
  /** Zero-based indexes (into the original scope vector) of the disclosed
   *  scopes, sorted ascending. */
  disclosedIndexes: number[]
  /** The BBS proof bytes. Length grows with the number of HIDDEN scopes. */
  proof: Uint8Array
  /** Total number of scopes in the original credential. */
  totalScopes: number
  /** Ciphersuite the underlying credential was issued under. */
  ciphersuite: Ciphersuite
  /** Honest scope-of-claim for this presentation. */
  scopeOfClaim: ScopeOfClaim
}
