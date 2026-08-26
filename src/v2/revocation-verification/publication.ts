// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Publication boundary
// ══════════════════════════════════════════════════════════════════
// This is the BOUNDARY, not a transparency-log integration. There is no
// log client and no network call anywhere in this module. A caller that
// has obtained a proof from whatever log it uses reduces that proof to one
// committed digest and asks this function whether the digest is the one
// this exact artifact produces.
//
// What a true answer means: the committed digest is the digest of this
// artifact. What it does NOT mean: that the commitment was published, that
// the log is honest, that the log is complete, or that no other revocation
// artifact exists. Those are the log's properties, not this function's.
// ══════════════════════════════════════════════════════════════════

import { revocationArtifactDigest } from './digest.js'
import type { PublicationCommitmentProof, PublicationCommitmentResult } from './types.js'

/** Answers one question: is `proof.committed_digest` the digest this exact
 *  artifact produces.
 *
 *  Invariants:
 *  - true ONLY on an exact string match against the recomputed digest;
 *  - total and fail-closed: a proof with no string committed_digest, and an
 *    artifact with no canonical form, both return false rather than throw;
 *  - no log client and no network call, here or anywhere in this module. A
 *    true answer says nothing about whether the commitment was published,
 *    whether the log is honest, or whether some other artifact exists. */
export function verifyPublicationCommitment(
  proof: PublicationCommitmentProof,
  artifact: unknown,
): PublicationCommitmentResult {
  const committed = (proof as { committed_digest?: unknown } | null | undefined)?.committed_digest
  if (typeof committed !== 'string') return { publication_verified: false }

  let recomputed: string
  try {
    recomputed = revocationArtifactDigest(artifact)
  } catch {
    // An artifact with no canonical form has no digest, so no commitment can
    // equal it. Fail closed rather than propagate: the caller asked a yes/no
    // question about a commitment, and the honest answer is no.
    return { publication_verified: false }
  }
  return { publication_verified: committed === recomputed }
}
