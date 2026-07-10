// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Human-oversight descriptor (verifier-derived)
// ══════════════════════════════════════════════════════════════════
// The descriptor is the verifier OUTPUT computed over the human-oversight
// slots. It is a SET of mechanical facts consistent with the four-valued
// Belnap ConstraintStatus (src/types/gateway.ts), never a scalar ladder
// and never read from the receipt. It records:
//   - which co-signer signatures over the body checked out (per signer),
//   - whether a human oversight signature is present and valid,
//   - which signers are independent in the key and DID graph (the sharp
//     metric: signers that share a root of trust are NOT independent),
//   - whether an approval reference is recorded and which scheme it uses,
//   - whether a break_glass declaration is present, well formed, in force,
//     and over an allowed class.
//
// At most ONE verifier-derived advisory scalar sits on top of the set:
// `advisory_independent_human_oversight`. It is labeled a relying-party
// -policy output, computed here, and is NEVER an issuer-set field on any
// receipt. Relying parties MAY ignore it and read the set directly.
// ══════════════════════════════════════════════════════════════════

import type { ConstraintStatus } from '../../types/gateway.js'
import type {
  CoSignerEntry,
  CoSignerRole,
  SharesRoot,
} from './types.js'

// ── Per-signature mechanical fact ──
// One entry per recorded co_signer signature. `status` is the Belnap
// four-valued result: 'pass' when the signature verified, 'fail' when it
// did not, 'unknown' when no key was available to check, 'not_applicable'
// when the entry is structurally absent of a signature to check.
export interface CoSignatureFact {
  publicKey: string
  role: CoSignerRole
  keyClass: string
  did?: string
  status: ConstraintStatus
}

// ── Independence edge ──
// A verifier-computed relation between two recorded signers. `sharesRoot`
// true means the two signers are NOT independent (they share a root of
// trust in the key and DID graph); two such signers are self-attestation
// even when there are two signatures.
export interface IndependenceEdge {
  a: string
  b: string
  sharesRoot: boolean
}

// ── Approval-reference fact ──
export type ApprovalScheme = 'commerce_hex' | 'charter_uuid' | 'unrecognized'

export interface ApprovalReferenceFact {
  present: boolean
  requestId?: string
  scheme: ApprovalScheme
  /** Whether a hash commitment to the signed approval was recorded. */
  commitmentPresent: boolean
}

// ── Break-glass fact ──
export interface BreakGlassFact {
  present: boolean
  /** Structurally complete (all required fields present and typed). */
  wellFormed: boolean
  /** Not past its expires_at at evaluation time. */
  inForce: boolean
  /** Over an allowed class (true when no forbidden class was matched). */
  classAllowed: boolean
  /** Whether the declaration owes a post-hoc review. */
  postReviewRequired: boolean
  /** Reasons the declaration is rejected, if any. */
  rejections: string[]
}

// ── The descriptor: a SET of mechanical facts ──
export interface HumanOversightDescriptor {
  /** Per-signature Belnap results. */
  coSignatures: CoSignatureFact[]
  /** At least one co_signer entry with role 'human' verified ('pass'). */
  humanSignaturePresent: boolean
  /** Independence edges across all signer pairs. */
  independence: IndependenceEdge[]
  /** True when no recorded signer pair shares a root of trust. With a
   *  single signer, there are no pairs, so this is vacuously true; read
   *  it together with coSignatures and humanSignaturePresent. */
  allSignersIndependent: boolean
  approvalReference: ApprovalReferenceFact
  breakGlass: BreakGlassFact
  /** ───────── verifier-derived advisory scalar ─────────
   *  Relying-party-policy OUTPUT, computed by this verifier. NOT a field
   *  on any receipt and NOT issuer-set. True only when a human signature
   *  verified AND that human signer is independent of every other signer
   *  in the key and DID graph AND no break_glass declaration is rejected.
   *  A relying party MAY override this with its own policy over the set. */
  advisory_independent_human_oversight: boolean
}

// ══════════════════════════════════════════════════════════════════
// Independence over the key and DID graph
// ══════════════════════════════════════════════════════════════════

/**
 * Build the independence edge set for the recorded signers. The caller
 * supplies `sharesRoot`, derived from the key and DID graph (M3 key
 * resolution, trust anchors). This module does not infer roots of trust;
 * it consumes the relation and records which pairs share one.
 *
 * Default when `sharesRoot` is omitted: two signers share a root only
 * when they present the identical public key or identical DID. That is
 * the minimal, conservative graph: same key is the same party, same DID
 * is the same controller. A richer graph (shared gateway anchor, shared
 * controller document) is the caller's to supply.
 */
export function computeIndependence(
  signers: CoSignerEntry[],
  sharesRoot?: SharesRoot
): { edges: IndependenceEdge[]; allIndependent: boolean } {
  const rel: SharesRoot =
    sharesRoot ??
    ((a, b) =>
      a.publicKey === b.publicKey ||
      (a.did !== undefined && a.did === b.did))

  const edges: IndependenceEdge[] = []
  let allIndependent = true
  for (let i = 0; i < signers.length; i++) {
    for (let j = i + 1; j < signers.length; j++) {
      const shares = rel(signers[i], signers[j])
      if (shares) allIndependent = false
      edges.push({
        a: signers[i].publicKey,
        b: signers[j].publicKey,
        sharesRoot: shares,
      })
    }
  }
  return { edges, allIndependent }
}

/**
 * Is a single signer independent of every OTHER recorded signer? Used to
 * decide whether a verified human signature stands on its own in the key
 * and DID graph. A signer with no peers is vacuously independent.
 */
export function isSignerIndependent(
  target: CoSignerEntry,
  signers: CoSignerEntry[],
  sharesRoot?: SharesRoot
): boolean {
  const rel: SharesRoot =
    sharesRoot ??
    ((a, b) =>
      a.publicKey === b.publicKey ||
      (a.did !== undefined && a.did === b.did))

  for (const other of signers) {
    // Skip only the literal same object reference (an entry is not its own
    // peer). A DISTINCT entry that happens to share a public key or DID is
    // the same party and so is NOT independent: let `rel` decide.
    if (other === target) continue
    if (rel(target, other)) return false
  }
  return true
}
