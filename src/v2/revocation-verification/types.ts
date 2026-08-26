// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Revocation verification v0: cross-object result shape
// ══════════════════════════════════════════════════════════════════
// There is NO new signed record type here. The authority-bearing objects
// stay the ones that already exist:
//   RevocationRecord               (delegation revocation, core/delegation.ts)
//   PrincipalBindingRevocationV1   (v2/identity-binding/revocation.ts)
//
// What is new is a verifier that reads a revocation artifact AGAINST the
// object it claims to revoke. verifyRevocation() alone checks a record's
// signature under the record's OWN revokedBy field, so a forged record
// self-verifies; the cross-object check is the security property.
//
// Outcome vocabulary is deliberately narrow:
//   REVOKED                          at least one artifact survived for the subject
//   no_revocation_evidence_observed  none did. NEVER read this as "not revoked":
//                                    this verifier answers about the artifacts it
//                                    was handed, not about completeness of the set.
// ══════════════════════════════════════════════════════════════════

import type { Delegation } from '../../types/passport.js'
import type { HistoricalKeyResolver, PrincipalBindingV1 } from '../identity-binding/types.js'

/** The two kinds of object this module can be asked about. Closed set. */
export type RevocationSubjectKind = 'delegation' | 'principal_binding'

/** Per-subject verdict. There is no not_revoked member and there will not be
 *  one: absence of evidence here is absence of evidence, not a negative claim. */
export type RevocationSubjectOutcome = 'REVOKED' | 'no_revocation_evidence_observed'

/** Per-artifact rejection reasons. The first three are the delegation path
 *  (S2 of the fold); 'invalid' carries a binding-path failure through with the
 *  existing verifier's own code string, unaltered. */
export type RevocationDiscardOutcome =
  | 'invalid_reference'
  | 'unauthorized_revoker'
  | 'invalid_signature'
  | 'invalid'

/** One surviving artifact, identified by digest and by its own record id. */
export interface RevocationArtifactEntry {
  /** "sha256:" + 64 lowercase hex, over the full validated artifact. */
  revocation_artifact_digest: string
  /** The artifact's own identifier: revocationId (delegation) or revocation_id (binding). */
  ref_id: string
}

/** One rejected artifact, attributed to the subject it named. */
export interface RevocationDiscard {
  /** Position in the input artifacts array. Order-dependent by construction. */
  index: number
  outcome: RevocationDiscardOutcome
  reason: string
}

/** Everything this module concluded about one (subject_kind, subject_id). */
export interface RevocationSubjectResult {
  subject_kind: RevocationSubjectKind
  subject_id: string
  outcome: RevocationSubjectOutcome
  /** Surviving artifacts, deduped by digest, sorted by digest. */
  artifacts: RevocationArtifactEntry[]
  /** Surviving artifacts dropped as exact repeats of one already counted. */
  duplicate_count: number
  discards: RevocationDiscard[]
}

/** An input with no readable subject. It cannot be attributed to any
 *  (subject_kind, subject_id), so it is reported at the top level. */
export interface UnclassifiableArtifact {
  index: number
  outcome: 'malformed'
  reason: string
}

/** The full result. subjects is sorted and total over the supplied subjects;
 *  unclassifiable holds only what could not be attributed to any of them. */
export interface RevocationVerificationResult {
  /** Sorted by (subject_kind, subject_id). Carries one row for every supplied
   *  delegation and binding, plus one for every subject named by a classifiable
   *  artifact, so a subject with no evidence is stated rather than absent. */
  subjects: RevocationSubjectResult[]
  unclassifiable: UnclassifiableArtifact[]
}

/** Everything the verifier reads. It opens no connection and consults no
 *  registry: the caller supplies the objects and the historical key resolver. */
export interface RevocationVerificationInput {
  artifacts: unknown[]
  /** Keyed by Delegation.delegationId. */
  delegations: Map<string, Delegation>
  /** Keyed by PrincipalBindingV1.binding_id. */
  bindings: Map<string, PrincipalBindingV1>
  /** Passed straight through to verifyPrincipalBindingRevocationV1. */
  resolver: HistoricalKeyResolver
}

/** A publication proof reduced to the one thing this module can check: the
 *  digest the log was told to commit to. Everything else about the proof is
 *  the log's business and is deliberately not modelled here. */
export interface PublicationCommitmentProof {
  committed_digest: string
}

/** Inclusion of one exact artifact, and nothing else. */
export interface PublicationCommitmentResult {
  publication_verified: boolean
}
