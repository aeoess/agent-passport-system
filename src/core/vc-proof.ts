// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Proof binding and proof-signing input for the credential surfaces
// ══════════════════════════════════════════════════════════════════
// Two rules that vc.ts, vc-wrapper.ts and credential-request.ts all need and
// each used to get wrong in the same way.
//
// 1. WHOSE KEY. A proof carries `verificationMethod`, and all three modules
//    derived the verification key from it and verified under that key. But the
//    proof is part of the document the attacker wrote. Deriving the key from
//    it establishes only that whoever assembled the document held one private
//    key, which is true of every document anyone can make. The relying party's
//    question is whether the key belongs to the identity the document CLAIMS
//    to speak for: `issuer` on a credential, `holder` on a presentation.
//    bindVerificationMethod answers that, and returns a state rather than a
//    boolean, because "this key is not the issuer's" and "this DID method
//    cannot be resolved offline" are different answers and only one of them is
//    an accusation.
//
// 2. WHAT IS SIGNED. All three signed the document body and then attached a
//    proof block that was not covered by the signature, so `created`,
//    `proofPurpose`, `challenge` and `domain` could be rewritten without
//    invalidating `proofValue`. A presentation minted for one verifier could
//    be readdressed to another. proofSigningInput puts the proof
//    configuration (everything except `proofValue`) inside the signed bytes,
//    reusing the repo's existing canonicalization and the same
//    body-plus-partial-proof shape verifyDecisionArtifact already uses. This
//    is not W3C Data Integrity and does not implement RDF canonicalization.
//
// The vocabulary is the repo's own: `keyAuthority` mirrors `key_authority` in
// src/v2/identity-binding/types.ts, three-valued for the same reason, and
// `unresolved` there likewise means the verifier could not establish the
// binding rather than that it disproved one.
// ══════════════════════════════════════════════════════════════════

import { selfCertifyingPublicKey } from '../v2/identity-binding/did-aps.js'

/** Whether the signing key was shown to belong to the claimed identity.
 *   - 'verified'   : the DID commits to this key.
 *   - 'rejected'   : the DID commits to a different key, or names a different
 *                    identity than the document claims.
 *   - 'unresolved' : the DID method is not self-certifying, so the binding
 *                    cannot be established without resolving a DID document.
 *                    NOT an acceptance. */
export type KeyAuthority = 'verified' | 'unresolved' | 'rejected'

export type ProofBinding =
  | { keyAuthority: 'verified'; publicKey: string }
  | { keyAuthority: 'unresolved' | 'rejected'; reason: string }

/**
 * Bind a proof's `verificationMethod` to the identity the document claims.
 *
 * Both halves are checked, because either alone is insufficient. The DID
 * before the fragment must be the claimed DID, or the proof is a proof by
 * somebody else. And the key must derive from that DID, or the DID string and
 * the key material are unrelated assertions sitting next to each other.
 *
 * Only self-certifying methods can be bound offline: did:key and the legacy
 * did:aps, both of which encode the Ed25519 key in the identifier itself.
 * Every other method needs a resolved DID document, and this SDK has no
 * resolver on these surfaces, so it reports 'unresolved' and the caller
 * refuses. That is a compatibility break for any did:web credential that used
 * to verify here, and it is the intended one: it never established anything.
 *
 * The FRAGMENT is deliberately not constrained. A self-certifying DID commits
 * to exactly one key, so the fragment selects nothing and cannot be used to
 * substitute key material. A fragment the controller does not list is a
 * document-conformance defect, not an authority one, and catching it needs the
 * DID document this function does not fetch.
 */
export function bindVerificationMethod(
  claimedDid: unknown,
  verificationMethod: unknown,
): ProofBinding {
  if (typeof claimedDid !== 'string' || claimedDid.length === 0) {
    return { keyAuthority: 'rejected', reason: 'document claims no issuer or holder DID' }
  }
  if (typeof verificationMethod !== 'string' || verificationMethod.length === 0) {
    return { keyAuthority: 'rejected', reason: 'proof carries no verificationMethod' }
  }

  const methodDid = verificationMethod.split('#')[0]
  if (methodDid !== claimedDid) {
    return {
      keyAuthority: 'rejected',
      reason: `proof verificationMethod names ${methodDid}, which is not the claimed ${claimedDid}`,
    }
  }

  let derived: string | null
  try {
    derived = selfCertifyingPublicKey(methodDid)
  } catch (err) {
    // A malformed or non-canonical self-certifying identifier. The method
    // claims to encode its own key and does not, which is a rejection rather
    // than an unresolved binding.
    return {
      keyAuthority: 'rejected',
      reason: `not a canonical self-certifying identifier: ${err instanceof Error ? err.message : String(err)}`,
    }
  }

  if (derived === null) {
    return {
      keyAuthority: 'unresolved',
      reason: `${methodDid.split(':').slice(0, 2).join(':')} is not self-certifying and this verifier resolves no DID documents`,
    }
  }

  return { keyAuthority: 'verified', publicKey: derived }
}

/**
 * The bytes a proof is made over: the document with its `proof` member
 * replaced by the proof configuration, which is the proof minus `proofValue`.
 *
 * Signing and verification MUST both go through this, or every credential in
 * existence stops verifying against half a change. The canonicalizer is
 * supplied by the caller so the repo's write-boundary rule survives:
 * canonicalizeForWrite when signing, canonicalize when rebuilding the preimage
 * of an artifact that already exists.
 */
export function proofSigningInput(
  document: Record<string, unknown>,
  proof: Record<string, unknown>,
  canon: (value: unknown) => string,
): string {
  const { proof: _existing, ...body } = document
  const { proofValue: _value, ...proofConfig } = proof
  return canon({ ...body, proof: proofConfig })
}
