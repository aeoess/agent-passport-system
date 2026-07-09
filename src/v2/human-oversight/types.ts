// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Human oversight as evidence (W2-B5): slot + descriptor type shapes
// ══════════════════════════════════════════════════════════════════
// Additive, optional, versioned slots that record human oversight on a
// general (NON-bilateral) signed receipt as evidence, plus the shapes a
// verifier derives from them. The slots carry mechanical facts only:
// which DID signed which body, the recorded approval reference, and the
// break_glass declaration. Nothing here is an issuer-set assurance
// value. Assurance is computed by the verifier as a relying-party-policy
// output (see descriptor.ts), never read from the receipt.
//
// For the BILATERAL case (two interacting agents co-sign one outcome)
// use the existing src/core/bilateral-receipt.ts co-sign. These slots
// cover the general path: a human and an agent (or a gateway) co-signing
// one canonical body that is NOT a bilateral interaction outcome.
// ══════════════════════════════════════════════════════════════════

import type { ApprovalSubjectType } from '../../types/approval.js'
import type { EvidenceCommitment } from '../../types/bilateral-receipt.js'

// ── Co-signer role ──
// The party class a co-signature represents. 'human' is the oversight
// signature this module exists to record; 'agent' and 'gateway' let a
// general body carry the same destructure-then-canonicalize multi-sig
// discipline as a bilateral receipt without being a bilateral receipt.
export type CoSignerRole = 'human' | 'agent' | 'gateway'

// ── Co-signer entry ──
// One signature over the SAME canonical body as every sibling entry.
// Modeled on ApprovalSignature (src/types/approval.ts) so a co_signer
// slot and a charter ApprovalSignature stay structurally aligned. The
// signed bytes are canonicalize(receipt-minus-the-co_signer-slot), the
// same discipline as bilateral-receipt.ts:101-102.
export interface CoSignerEntry {
  /** Ed25519 public key (hex) of the signer. */
  publicKey: string
  /** Party class this signature represents. */
  role: CoSignerRole
  /** Key class label (e.g. 'human', 'operations'), mirrors
   *  ApprovalSignature.keyClass. Free of policy meaning here; the
   *  verifier reads it as a mechanical fact, not as an assurance grade. */
  keyClass: string
  /** Optional DID the signer asserts. Used by the descriptor to derive
   *  signer independence from the key and DID graph. */
  did?: string
  /** ISO 8601 timestamp the signature was produced. */
  signedAt: string
  /** Ed25519 signature over canonical(receipt-minus-co_signer-slot), hex. */
  signature: string
}

// ── Approval reference ──
// A pointer to an approval request that lives outside this receipt.
// Matches the two existing request-id schemes: 'approval-<hex>'
// (commerce.ts:221) or 'approval_<uuid12>' (charter.ts:542). No third
// scheme is coined. Optionally binds the signed approval by hash via the
// existing EvidenceCommitment pattern rather than embedding it.
export interface ApprovalReference {
  /** Existing request id: 'approval-<hex>' or 'approval_<uuid12>'. */
  requestId: string
  /** Optional subject-type classification, reusing the approval union. */
  subjectType?: ApprovalSubjectType
  /** Optional hash commitment to the signed approval artifact. The full
   *  approval is fetched out of band and checked against the hash; it is
   *  NOT embedded here (bilateral-receipt.ts:149-174 pattern). */
  commitment?: EvidenceCommitment
}

// ── Break-glass declaration ──
// A FORMAT recording that an emergency override was declared, who
// declared it, when it expires, and whether a post-hoc review is owed.
// This is not machinery: no workflow runs here, no notification fires,
// no escalation executes. Those are gateway operations and out of scope.
// The verifier checks the declaration is well formed, unexpired, and not
// asserted over a forbidden class.
export interface BreakGlass {
  /** Why the override was declared. Free text, recorded verbatim. */
  reason: string
  /** Public key (hex) or DID of the human who approved the override. */
  approved_by: string
  /** ISO 8601 instant after which the override is no longer in force. */
  expires_at: string
  /** Whether a post-hoc human review is owed for this override. */
  post_review_required: boolean
  /** Optional action class the override applies to. The verifier rejects
   *  the declaration when this names a class the relying party forbids
   *  from break-glass override. */
  action_class?: string
}

// ── The three additive slots, as a versioned mix-in ──
// A receipt that omits all three is byte-identical to its pre-slot form:
// the slots are optional and live under a single versioned container so
// canonicalization of a receipt without them is unchanged.
export interface HumanOversightSlots {
  /** Co-signatures over the receipt body for the NON-bilateral case. */
  co_signer?: CoSignerEntry[]
  /** Pointer to an out-of-band approval request. */
  approval_reference?: ApprovalReference
  /** Emergency-override declaration (format only). */
  break_glass?: BreakGlass
  /** Slot-format version. Present only when any slot is present. */
  human_oversight_version?: '1.0'
}

// ── Public-key resolver for a co-signer ──
// The verifier needs the public key for each recorded signer. A co_signer
// entry carries its own publicKey, but a caller may also supply a DID-to
// -key resolution. This is the minimal hook; full DID resolution is M3
// (src/v2/key-resolution), reused by the caller, not re-implemented here.
export interface CoSignerKeyResolution {
  /** The public key (hex) to verify this entry's signature against. */
  publicKey: string
  /** Optional DID the key was resolved from, for the descriptor graph. */
  did?: string
}

// ── sharesRoot relation ──
// Verifier-supplied predicate: do two signers share a root of trust in
// the key and DID graph? Two signers that share the gateway root are
// still self-attestation; independence is derived from this relation,
// not asserted by the issuer. Returns true when the two signers are NOT
// independent (they share a root). The caller computes this from the key
// and DID graph (M3 resolution, trust anchors); this module consumes it.
export type SharesRoot = (a: CoSignerEntry, b: CoSignerEntry) => boolean
