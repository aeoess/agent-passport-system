// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// revocation_artifact_digest: the one new pure function in v0
// ══════════════════════════════════════════════════════════════════
// A publication proof commits to THIS digest and answers exactly one
// question: "was this exact artifact included". Discovery (was there some
// other artifact I was never shown) is a separate problem and is NOT
// answered here.
//
// Preimage, as explicit bytes:
//   UTF8("APS-REVOCATION-ARTIFACT-V0") || 0x00 || UTF8(JCS(artifact))
//
// The 0x00 is a BYTE, assembled with Buffer.concat. It is never written as
// a JavaScript "\0" string concatenation: the older V1 records in
// identity-binding do write their domain that way, and the byte form is the
// contract that a second implementation can reproduce without knowing how
// one language spells a NUL inside a string literal.
//
// canonicalizeJCSForWrite, not canonicalizeJCS: this is a NEW hashing
// boundary with no history behind it, so the APS unsafe-integer write rule
// applies from the first byte. A verifier rebuilding a preimage signed
// before that rule exists must keep using canonicalizeJCS; this digest has
// no such preimages.
//
// The argument is the FULL validated artifact, signature included. Digesting
// an unsigned form would let one signed artifact and a re-signed variant of
// it collide.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { canonicalizeJCSForWrite } from '../../core/canonical-jcs.js'

/** Domain separator for the artifact digest. Distinct from every signature
 *  domain in the SDK, so a digest preimage can never be mistaken for a
 *  signing preimage and vice versa. */
export const REVOCATION_ARTIFACT_DOMAIN = 'APS-REVOCATION-ARTIFACT-V0'

/** Digest of a revocation artifact, as "sha256:" + 64 lowercase hex.
 *
 *  Invariants:
 *  - preimage is UTF8(REVOCATION_ARTIFACT_DOMAIN) || 0x00 || UTF8(JCS(artifact)),
 *    assembled as bytes, never as a JavaScript string carrying a NUL;
 *  - canonicalization is canonicalizeJCSForWrite, so an integer outside the
 *    interoperable IEEE 754 range is refused rather than hashed;
 *  - the argument is the FULL artifact including its signature, so re-signing
 *    the same facts yields a different digest;
 *  - it commits to nothing about publication. Inclusion is answered by
 *    verifyPublicationCommitment, discovery by nothing in this module.
 *
 *  Throws whatever canonicalizeJCSForWrite throws for a value with no canonical
 *  form; it never returns a digest for input it could not canonicalize. */
export function revocationArtifactDigest(artifact: unknown): string {
  const preimage = Buffer.concat([
    Buffer.from(REVOCATION_ARTIFACT_DOMAIN, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonicalizeJCSForWrite(artifact), 'utf8'),
  ])
  return 'sha256:' + createHash('sha256').update(preimage).digest('hex')
}
