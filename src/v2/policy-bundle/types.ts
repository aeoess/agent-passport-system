// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Types for the signed, content-addressed policy-bundle primitive.
 *
 * A policy-bundle is three things together:
 *   1. a deterministic tar of policy files,
 *   2. a JCS-canonical manifest that pins each file by sha256 and pins the
 *      whole tar by sha256, plus governance changeType metadata,
 *   3. an Ed25519 detached signature over the canonical manifest.
 *
 * The format reuses existing protocol primitives: JCS canonicalization
 * (src/core/canonical-jcs.ts), the changeType governance vocabulary
 * (src/types/governance.ts), aps.txt for revocation (src/core/aps-txt.ts),
 * and ScopeOfClaim for honest scope declaration (accountability/types/base).
 */

import type { ScopeOfClaim } from '../accountability/types/base.js'
import type { GovernanceChangeType } from '../../types/governance.js'

/** One file pinned inside the bundle manifest. */
export interface PolicyBundleFileEntry {
  /** POSIX path inside the tar (forward slashes, no leading slash). */
  path: string
  /** Byte length of the file. */
  size: number
  /** Lowercase hex sha256 of the file bytes. */
  sha256: string
}

/** Governance classification of this bundle versus its predecessor. */
export interface PolicyBundleGovernance {
  /** How this bundle relates to the previous version of the same policy set. */
  changeType: GovernanceChangeType
  /** Manifest hash of the bundle this supersedes, or null for an initial bundle. */
  previousManifestHash: string | null
  /** Human-readable identifiers of added rules/principles. */
  additions: string[]
  /** Human-readable identifiers of changed rules/principles. */
  modifications: string[]
  /** Human-readable identifiers of removed rules/principles (weakening signal). */
  removals: string[]
}

/**
 * The JCS-canonical manifest. The Ed25519 signature is computed over
 * canonicalizeJCS(manifest) and stored OUTSIDE this object in the envelope.
 * The manifest itself never contains its own signature, so it stays
 * content-addressable.
 */
export interface PolicyBundleManifest {
  /** Format identifier. */
  format: 'aps-policy-bundle'
  /** Format version. */
  version: '1'
  /** Caller-chosen identifier for the policy set (stable across versions). */
  bundleId: string
  /** Lowercase hex sha256 of the deterministic tar bytes. */
  tarSha256: string
  /** Per-file pins, sorted by path. */
  files: PolicyBundleFileEntry[]
  /** Ed25519 hex public key of the signer. */
  signerPublicKey: string
  /** did:aps DID derived from signerPublicKey. */
  signerDid: string
  /** ISO 8601 UTC timestamp the bundle was created. */
  createdAt: string
  /** Governance change classification. */
  governance: PolicyBundleGovernance
  /** Honest scope declaration. Dogfoods ScopeOfClaim. */
  scopeOfClaim: ScopeOfClaim
}

/**
 * The on-disk / on-wire bundle envelope: the tar bytes (carried separately),
 * the manifest, and the detached signature over the canonical manifest.
 *
 * `tar` is kept as a hex string here so the envelope is a plain JSON object.
 * Callers that already hold the raw tar bytes can pass them to verify()
 * directly and skip re-decoding.
 */
export interface PolicyBundleEnvelope {
  manifest: PolicyBundleManifest
  /** Ed25519 detached signature (hex) over canonicalizeJCS(manifest). */
  signature: string
  /** Lowercase hex encoding of the deterministic tar bytes. */
  tarHex: string
}

/** Content-addressed identity: lowercase hex sha256 of the canonical manifest. */
export type ManifestHash = string

/** Per-check booleans plus an overall verdict and reasons. */
export interface PolicyBundleVerification {
  /** Overall verdict: every required check passed. */
  valid: boolean
  /** sha256(canonicalizeJCS(manifest)). Content-addressed bundle identity. */
  manifestHash: ManifestHash
  /** The Ed25519 signature over the canonical manifest verified. */
  signatureValid: boolean
  /** The tar bytes hash to manifest.tarSha256. */
  tarHashMatches: boolean
  /** Every file in the tar matches its manifest pin, and counts agree. */
  fileHashesMatch: boolean
  /** signerDid is consistent with signerPublicKey. */
  signerDidConsistent: boolean
  /** True when governance.changeType indicates weakening or mixed. */
  weakeningFlagged: boolean
  /** True when an aps.txt revocation check marked this bundle revoked. */
  revoked: boolean
  /** Machine-readable failure/flag codes. */
  reasons: string[]
}
