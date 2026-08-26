// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Cross-object revocation verification
// ══════════════════════════════════════════════════════════════════
// INVARIANT for both kinds: verify the artifact INTRINSICALLY first, then
// verify it against the supplied subject and authority context. A record whose
// own signature does not hold is not evidence of anything, so nothing is
// reported about what it names or who signed it.
//
// DELEGATION PATH, first failure wins:
//   1. verifyRevocation(record)               false -> invalid_signature
//   2. delegation lookup by delegationId      miss  -> invalid_reference
//   3. revocation.revokedBy == delegation.delegatedBy
//                                             else  -> unauthorized_revoker
// Step 3 is still the whole point. verifyRevocation checks the signature under
// revocation.revokedBy, a field of the record itself, so anyone can mint a
// record that verifies. Only the delegation says who was allowed to revoke.
//
// BINDING PATH, same invariant, first failure wins:
//   1. verifyPrincipalBindingRevocationV1(record, resolver)
//      any non-valid state -> 'invalid', reason = that verifier's own code,
//      verbatim. It already resolves verification_method historically at
//      revoked_at and recomputes revocation_id; nothing is re-implemented
//      here and nothing is re-worded.
//   2. binding_id must match a supplied binding   else -> invalid_reference
//
// REVOKED is absorbing. N surviving artifacts for one subject is REVOKED
// with N, never equivocation: revocation_id hashes a draft carrying a
// nonce, so one subject can honestly carry more than one revocation record,
// and with a single state there is nothing for two of them to contradict.
//
// Subjects are seeded from the supplied delegations and bindings before any
// artifact is read, so a subject that was asked about and has no evidence
// says no_revocation_evidence_observed instead of being missing from the
// result. An artifact naming a subject that was not supplied still gets its
// own row, carrying the discard that explains it.
// ══════════════════════════════════════════════════════════════════

import { verifyRevocation } from '../../core/delegation.js'
import type { Delegation, RevocationRecord } from '../../types/passport.js'
import { verifyPrincipalBindingRevocationV1 } from '../identity-binding/revocation.js'
import type { HistoricalKeyResolver, PrincipalBindingV1 } from '../identity-binding/types.js'
import { revocationArtifactDigest } from './digest.js'
import type {
  RevocationArtifactEntry,
  RevocationDiscard,
  RevocationDiscardOutcome,
  RevocationSubjectKind,
  RevocationSubjectResult,
  RevocationVerificationInput,
  RevocationVerificationResult,
  UnclassifiableArtifact,
} from './types.js'

// ── shape reading ──

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0
}

type Classified =
  | { kind: 'delegation'; subject_id: string; record: RevocationRecord }
  | { kind: 'principal_binding'; subject_id: string; record: Record<string, unknown> }
  | { kind: 'unclassifiable'; reason: string }

/** Shape classification only. Reason strings are fixed text and never echo
 *  attacker-supplied values back into the result. */
function classify(artifact: unknown): Classified {
  if (!isPlainObject(artifact)) {
    return { kind: 'unclassifiable', reason: 'artifact is not a JSON object' }
  }
  if (Object.hasOwn(artifact, 'record_type')) {
    if (artifact.record_type !== 'aps.principal-binding-revocation') {
      return { kind: 'unclassifiable', reason: 'unknown record_type for a revocation artifact' }
    }
    if (!isNonEmptyString(artifact.binding_id)) {
      return { kind: 'unclassifiable', reason: 'binding revocation carries no readable binding_id' }
    }
    return { kind: 'principal_binding', subject_id: artifact.binding_id, record: artifact }
  }
  if (
    isNonEmptyString(artifact.delegationId) &&
    isNonEmptyString(artifact.revocationId) &&
    isNonEmptyString(artifact.revokedBy) &&
    isNonEmptyString(artifact.signature)
  ) {
    return {
      kind: 'delegation',
      subject_id: artifact.delegationId,
      record: artifact as unknown as RevocationRecord,
    }
  }
  return { kind: 'unclassifiable', reason: 'artifact matches no known revocation record shape' }
}

// ── per-path checks ──

interface Failure {
  outcome: RevocationDiscardOutcome
  reason: string
}

function checkDelegationArtifact(
  record: RevocationRecord,
  delegations: Map<string, Delegation>,
): Failure | null {
  if (!verifyRevocation(record)) {
    return { outcome: 'invalid_signature', reason: 'verifyRevocation rejected the record signature' }
  }
  const delegation = delegations.get(record.delegationId)
  if (!delegation || delegation.delegationId !== record.delegationId) {
    return { outcome: 'invalid_reference', reason: 'no supplied delegation matches delegationId' }
  }
  if (record.revokedBy !== delegation.delegatedBy) {
    return { outcome: 'unauthorized_revoker', reason: 'revokedBy is not the delegation delegatedBy key' }
  }
  return null
}

async function checkBindingArtifact(
  record: Record<string, unknown>,
  bindings: Map<string, PrincipalBindingV1>,
  resolver: HistoricalKeyResolver,
): Promise<Failure | null> {
  const verified = await verifyPrincipalBindingRevocationV1(record, resolver)
  if (verified.state !== 'valid') {
    return { outcome: 'invalid', reason: verified.code }
  }
  const bindingId = record.binding_id as string
  const binding = bindings.get(bindingId)
  if (!binding || binding.binding_id !== bindingId) {
    return { outcome: 'invalid_reference', reason: 'no supplied binding matches binding_id' }
  }
  return null
}

// ── accumulation ──

interface MutableSubject {
  subject_kind: RevocationSubjectKind
  subject_id: string
  /** Insertion-ordered by first sighting; re-sorted by digest on output. */
  artifacts: Map<string, RevocationArtifactEntry>
  duplicate_count: number
  discards: RevocationDiscard[]
}

function subjectKey(kind: RevocationSubjectKind, id: string): string {
  // The kind is a fixed two-member enum and neither member contains a space,
  // so a space keeps the composite key injective for any subject_id.
  return `${kind} ${id}`
}

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

/** Reads revocation artifacts AGAINST the objects they claim to revoke.
 *
 *  Invariants:
 *  - deterministic: same input, same output, byte for byte. subjects are
 *    sorted by (subject_kind, subject_id) and artifacts by digest;
 *  - one row per supplied delegation and binding, plus one per subject named
 *    by a classifiable artifact, so an absence of evidence is stated;
 *  - REVOKED is absorbing and counts artifacts; it is never equivocation;
 *  - no_revocation_evidence_observed is NOT a claim that the subject is
 *    unrevoked. It reports on the artifacts supplied, and says nothing about
 *    whether that set was complete;
 *  - a binding-path failure carries the existing verifier's own code string
 *    through unaltered, so this module never re-words another verifier;
 *  - discards[].index names a position in the input array and is therefore
 *    the only order-dependent field in the result. */
export async function verifyRevocationEvidence(
  input: RevocationVerificationInput,
): Promise<RevocationVerificationResult> {
  const subjects = new Map<string, MutableSubject>()
  const unclassifiable: UnclassifiableArtifact[] = []

  const ensureSubject = (kind: RevocationSubjectKind, id: string): MutableSubject => {
    const key = subjectKey(kind, id)
    let subject = subjects.get(key)
    if (!subject) {
      subject = {
        subject_kind: kind,
        subject_id: id,
        artifacts: new Map(),
        duplicate_count: 0,
        discards: [],
      }
      subjects.set(key, subject)
    }
    return subject
  }

  for (const delegation of input.delegations.values()) {
    ensureSubject('delegation', delegation.delegationId)
  }
  for (const binding of input.bindings.values()) {
    ensureSubject('principal_binding', binding.binding_id)
  }

  for (let index = 0; index < input.artifacts.length; index++) {
    const artifact = input.artifacts[index]
    const classified = classify(artifact)
    if (classified.kind === 'unclassifiable') {
      unclassifiable.push({ index, outcome: 'malformed', reason: classified.reason })
      continue
    }

    const subject = ensureSubject(classified.kind, classified.subject_id)
    const failure = classified.kind === 'delegation'
      ? checkDelegationArtifact(classified.record, input.delegations)
      : await checkBindingArtifact(classified.record, input.bindings, input.resolver)
    if (failure) {
      subject.discards.push({ index, outcome: failure.outcome, reason: failure.reason })
      continue
    }

    let digest: string
    try {
      digest = revocationArtifactDigest(artifact)
    } catch {
      // The artifact passed its own verifier but has no canonical form at the
      // write boundary, so it cannot be committed to or deduped. Both existing
      // verifiers reject the values that reach this branch today; it is here so
      // that a future relaxation upstream cannot turn into a silent admission.
      subject.discards.push({
        index,
        outcome: 'invalid',
        reason: 'artifact has no canonical form at the write boundary',
      })
      continue
    }

    if (subject.artifacts.has(digest)) {
      subject.duplicate_count += 1
      continue
    }
    const refId = classified.kind === 'delegation'
      ? classified.record.revocationId
      : (classified.record.revocation_id as string)
    subject.artifacts.set(digest, { revocation_artifact_digest: digest, ref_id: refId })
  }

  const rows: RevocationSubjectResult[] = [...subjects.values()].map(subject => ({
    subject_kind: subject.subject_kind,
    subject_id: subject.subject_id,
    outcome: subject.artifacts.size > 0
      ? ('REVOKED' as const)
      : ('no_revocation_evidence_observed' as const),
    artifacts: [...subject.artifacts.values()].sort((a, b) =>
      compare(a.revocation_artifact_digest, b.revocation_artifact_digest)),
    duplicate_count: subject.duplicate_count,
    discards: subject.discards,
  }))
  rows.sort((a, b) =>
    compare(a.subject_kind, b.subject_kind) || compare(a.subject_id, b.subject_id))

  return { subjects: rows, unclassifiable }
}
