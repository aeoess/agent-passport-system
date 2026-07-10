// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════════
// proof_ref. Name an external soundness proof by content hash.
// ══════════════════════════════════════════════════════════════════════
//
// PROOF BOX
//   Proves:   A proof_ref names an external proof artifact by its content
//             hash. Attaching one to a receipt proves only that the receipt
//             points at that artifact.
//   Does NOT
//   prove:    that the referenced proof is valid, sound, or even retrievable.
//             Validation of the artifact is out of band and out of scope this
//             round. The reference is format agnostic on purpose: no
//             cross-system proof object schema is committed here. That work is
//             tracked separately (A2A#1463).
//
// scope_of_claim discipline: when a receipt carries a proof_ref, the receipt's
// scope_of_claim.does_not_assert SHOULD include a line stating that the
// referenced proof was not validated by this system. helperScopeNote() returns
// that line so emitters can dogfood the honest-scope convention.
// ══════════════════════════════════════════════════════════════════════

import { createHash } from 'crypto'
import type { ProofRef, ProofRefHashAlgorithm } from '../../types/policy.js'

export type { ProofRef, ProofRefHashAlgorithm } from '../../types/policy.js'

/** Only algorithm specified this round. */
export const PROOF_REF_ALGORITHM: ProofRefHashAlgorithm = 'sha256'

/** A 64-char lowercase hex sha256 digest. */
const SHA256_HEX = /^[0-9a-f]{64}$/

/** Parameters for {@link buildProofRef}. */
export interface BuildProofRefParams {
  /** The external proof artifact, as bytes or a UTF-8 string. */
  artifact: string | Uint8Array
  /** Advisory label for the producing proof system (e.g. 'smtlib2', 'lean4'). */
  proofSystem?: string
  /** Advisory fetch hint. The reference is the hash, not the locator. */
  locator?: string
}

/** Construct a {@link ProofRef} by hashing the proof artifact's bytes.
 *  Deterministic: identical artifact bytes always yield the same hash. */
export function buildProofRef(params: BuildProofRefParams): ProofRef {
  const bytes =
    typeof params.artifact === 'string'
      ? Buffer.from(params.artifact, 'utf-8')
      : Buffer.from(params.artifact)
  const hash = createHash('sha256').update(bytes).digest('hex')
  const ref: ProofRef = { algorithm: PROOF_REF_ALGORITHM, hash }
  if (params.proofSystem !== undefined) ref.proofSystem = params.proofSystem
  if (params.locator !== undefined) ref.locator = params.locator
  return ref
}

/** Reasons a {@link ProofRef} can fail structural validation. */
export type ProofRefValidationError =
  | 'MISSING_REF'
  | 'UNSUPPORTED_ALGORITHM'
  | 'MALFORMED_HASH'

export interface ProofRefValidationResult {
  /** True when the reference is structurally well formed. This says NOTHING
   *  about whether the referenced artifact is a valid or sound proof. */
  wellFormed: boolean
  errors: ProofRefValidationError[]
}

/** Structural validation only. A well-formed result asserts the reference has a
 *  supported algorithm and a syntactically valid hash. It does not fetch, hash,
 *  or check the referenced artifact. */
export function validateProofRef(ref: ProofRef | undefined | null): ProofRefValidationResult {
  const errors: ProofRefValidationError[] = []
  if (ref === undefined || ref === null) {
    return { wellFormed: false, errors: ['MISSING_REF'] }
  }
  if (ref.algorithm !== PROOF_REF_ALGORITHM) {
    errors.push('UNSUPPORTED_ALGORITHM')
  }
  if (typeof ref.hash !== 'string' || !SHA256_HEX.test(ref.hash)) {
    errors.push('MALFORMED_HASH')
  }
  return { wellFormed: errors.length === 0, errors }
}

/** Check whether an artifact's bytes hash to the reference's recorded hash.
 *  This is the only sense in which a proof_ref is "checkable" this round: it
 *  confirms the bytes match the named hash. It does NOT establish that those
 *  bytes constitute a valid or sound proof. */
export function proofRefMatchesArtifact(
  ref: ProofRef,
  artifact: string | Uint8Array,
): boolean {
  if (!validateProofRef(ref).wellFormed) return false
  const recomputed = buildProofRef({ artifact }).hash
  return recomputed === ref.hash
}

/** The honest-scope line an emitter SHOULD add to a receipt's
 *  scope_of_claim.does_not_assert when attaching a proof_ref. Dogfoods the
 *  ScopeOfClaim convention from src/v2/accountability/types/base.ts. */
export function proofRefScopeNote(): string {
  return 'The referenced external proof was named by hash but not validated by this system.'
}
