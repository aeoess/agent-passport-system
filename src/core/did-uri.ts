// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// DID URI helpers for rail receipts (Phase 4.1 / P12)
// ══════════════════════════════════════════════════════════════════
// Receipts historically carried `signer_did = <raw hex Ed25519 pubkey>`.
// That binds receipt verification to a specific key forever — rotation
// gives no security benefit because the verifier cannot tell whether
// the embedded pubkey is currently retired in the issuer's DID document.
//
// Phase 4.1 / P12 switches signer_did to a DID URI of the form
// `did:<method>:<id>#<keyRef>` (e.g. `did:aps:zABC#key-2`). The verifier
// resolves the DID document via a caller-supplied resolver, walks
// verificationMethod[] to find the matching key, and respects retiredAt:
//
//   - Key not in doc                                → reject
//   - Key retired BEFORE the receipt was signed     → reject (compromise)
//   - Key retired, retiredAt unreadable             → reject (nothing places
//                                                     the retirement after
//                                                     signing)
//   - Key retired AFTER the receipt was signed      → accept (legitimate
//                                                     post-rotation
//                                                     verification)
//   - Key currently active                          → accept
//
// Receipts continue to carry raw hex pubkeys when issuers don't supply
// agentId/keyRef inputs — that is the legacy compatible-superset path.
// ══════════════════════════════════════════════════════════════════

import { multibaseToHex } from './did.js'
import { parseRfc3339 } from './rfc3339.js'
import type {
  RotatableDIDDocument,
  RotatableVerificationMethod,
} from '../types/passport.js'

/**
 * Parse a DID URI of the form `<agentId>#<keyRef>` into its parts. The
 * agentId is the full DID (e.g. `did:aps:zABC`), keyRef is the fragment
 * after the first `#` (e.g. `key-2`). Returns null when the input is
 * not a valid DID URI with a fragment.
 */
export function parseDidUri(s: string): { agentId: string; keyRef: string } | null {
  if (typeof s !== 'string' || !s.startsWith('did:')) return null
  const hashIdx = s.indexOf('#')
  if (hashIdx <= 4) return null
  const agentId = s.slice(0, hashIdx)
  const keyRef = s.slice(hashIdx + 1)
  if (agentId.length === 0 || keyRef.length === 0) return null
  // Guard against multiple '#' characters which are not valid in DID URIs.
  if (keyRef.includes('#')) return null
  return { agentId, keyRef }
}

/**
 * Build a DID URI from agentId and keyRef. agentId must already be a
 * `did:<method>:<id>` form; keyRef is the fragment without the '#'.
 */
export function buildDidUri(agentId: string, keyRef: string): string {
  if (!agentId.startsWith('did:')) {
    throw new Error(`buildDidUri: agentId must be a DID, got '${agentId}'`)
  }
  if (keyRef.length === 0) {
    throw new Error('buildDidUri: keyRef must be non-empty')
  }
  if (keyRef.includes('#')) {
    throw new Error("buildDidUri: keyRef must not contain '#'")
  }
  if (agentId.includes('#')) {
    throw new Error("buildDidUri: agentId must not contain '#'")
  }
  return `${agentId}#${keyRef}`
}

export interface ResolveVerificationMethodResult {
  method: RotatableVerificationMethod
  /** True when the key was retired BEFORE the receipt was signed
   *  (compromise mode — verifier MUST reject), and also when the document
   *  carries a `retiredAt` that cannot be read as an instant. False when the
   *  key is active OR was retired AFTER the receipt was signed (legitimate
   *  post-rotation verification). */
  retired: boolean
}

/**
 * Resolve a DID URI against a RotatableDIDDocument and return the
 * verificationMethod entry plus a `retired` flag that takes signing
 * time into account.
 *
 * Returns:
 *   - `null` if the keyRef does not exist in the document, or if the
 *     URI's agentId does not match the document's id (caller passed
 *     the wrong document).
 *   - `{ method, retired: false }` when the key is currently active OR
 *     was retired after `issuedAtMs` (the receipt was signed while the
 *     key was still active — acceptable to verify post-rotation).
 *   - `{ method, retired: true }` when the key was retired before
 *     `issuedAtMs` (compromise mode — verifier MUST reject the
 *     signature regardless of mathematical validity).
 *
 * @param didDoc      The agent's RotatableDIDDocument.
 * @param didUri      The DID URI carried in the receipt's signer_did.
 * @param nowMs       Wall-clock at verification time. Defaults to Date.now().
 * @param issuedAtMs  Wall-clock when the receipt was signed. Defaults to
 *                    nowMs (which collapses to "key must be currently
 *                    active") when omitted.
 */
export function resolveVerificationMethod(
  didDoc: RotatableDIDDocument,
  didUri: string,
  nowMs?: number,
  issuedAtMs?: number,
): ResolveVerificationMethodResult | null {
  const parsed = parseDidUri(didUri)
  if (!parsed) return null
  if (didDoc.id !== parsed.agentId) return null

  const method = didDoc.verificationMethod.find((vm) => vm.id === didUri)
  if (!method) return null

  const _now = nowMs ?? Date.now()
  const _issued = issuedAtMs ?? _now

  if (method.retiredAt) {
    const retiredAt = parseRfc3339(method.retiredAt)
    if (!retiredAt.ok) {
      // The document asserts this key was retired but gives no readable
      // instant, so nothing here places the retirement after signing. A
      // retirement this resolver cannot read is not one it can clear.
      return { method, retired: true }
    }
    if (retiredAt.ms <= _issued) {
      // Retired before (or at exactly) the signing instant — reject.
      // The "<= " is deliberate: a key retired at the same millisecond
      // as the signature is treated as compromised.
      return { method, retired: true }
    }
    // retiredAt > issuedAtMs: accept the signature as a legitimate
    // pre-rotation issuance verifying post-rotation.
    return { method, retired: false }
  }
  return { method, retired: false }
}

/**
 * Convenience: extract the raw hex Ed25519 pubkey from a resolved
 * verificationMethod entry. Wraps `multibaseToHex(method.publicKeyMultibase)`
 * so callers don't need to import from did.js.
 */
export function publicKeyHexFromMethod(method: RotatableVerificationMethod): string {
  return multibaseToHex(method.publicKeyMultibase)
}

/** Reasons an Ed25519 verification can fail BEFORE the cryptographic
 *  step. Surfaced by rail verifiers under their own reason unions. */
export type DidUriVerifyFailure =
  | 'did_resolver_missing'
  | 'did_uri_invalid'
  | 'did_doc_not_found'
  | 'did_key_not_in_doc'
  | 'did_key_retired'
