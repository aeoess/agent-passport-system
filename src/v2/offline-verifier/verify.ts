// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Offline verifier - a zero-network verify path that emits the descriptor
// ══════════════════════════════════════════════════════════════════
// This is a standalone APS verify path with NO network dependency. It
// composes three pieces the SDK already ships, in a fixed order, and
// returns both the verdict and the W2-A1 Evidence Descriptor:
//
//   1. CRYPTO layer  - verifyActionReceipt: claim_type, receipt_id
//      re-derivation, Ed25519 signature. Pure, offline. (existing)
//   2. CONTEXT layer - verifyReceiptContext: the relying-party
//      responsibility checks (expiry, revocation, budget, principal,
//      policy freshness, replay, claim match, execution attestation),
//      against the caller's own ground truth. Pure, offline. (promoted)
//   3. DESCRIPTOR    - the verifier OUTPUT: which signer signed which
//      claim, the witness observation bases, witness conflict presence,
//      multi-party signature validity, and signer independence from the
//      key/DID graph. The lattice point is the Belnap ConstraintStatus.
//      Built by the W2-A1 builder (interim builder here until A1 merges).
//
// Why no network: every input the verifier needs is supplied by the
// caller. Key resolution is done UPSTREAM (the caller hands in the
// signature-check facts and the anchor edges); this module never fetches
// a JWKS, a CRL, a DID document, or a transparency log. That is what
// makes it air-gappable and what the offline test pins.
//
// ABSOLUTE RULE: assurance is a verifier-derived OUTPUT. Nothing here
// reads an issuer-written assurance/evidence field. There is no such
// field on the receipt.
//
// SCOPE OF CLAIM (dogfooded):
//   Proves: a receipt that returns verdict 'accept' is a well-formed,
//     correctly-signed aps:action:v1 receipt presented inside the
//     envelope the caller's context describes, and the descriptor reports
//     exactly the mechanical evidence facts the verifier recomputed,
//     with no network access.
//   Does NOT prove: that the off-protocol effect the receipt names
//     occurred, that the signer's key was honestly held, that the
//     caller's context is itself accurate, or any truth assertion about
//     the underlying outcome. A receipt is a signed declaration.
// ══════════════════════════════════════════════════════════════════

import { verifyActionReceipt } from '../accountability/verify/action.js'
import type { ActionReceipt } from '../accountability/types/action.js'
import type { WitnessConflict } from '../../types/gateway.js'
import {
  verifyReceiptContext,
  type ReceiptContext,
  type RejectReason,
} from './context.js'
import { buildDescriptor } from './descriptor.js'
import type {
  CheckedSignature,
  EvidenceDescriptor,
  WitnessObservationFact,
} from './descriptor-interface.js'

/** Evidence the caller supplies for the descriptor. The verifier does NOT
 *  fetch any of this; it is the caller's already-resolved view. */
export interface OfflineDescriptorInputs {
  /** Pre-checked signature facts beyond the receipt's own signer. When
   *  omitted, the verifier seeds the descriptor with the single fact it
   *  can recompute itself: the receipt's signer_did over its 'outcome'
   *  claim, with `valid` set to the crypto-layer result. */
  signatures?: CheckedSignature[]
  /** Witness observation facts (observationBasis + optional divergence). */
  witnessObservations?: WitnessObservationFact[]
  /** Witness conflict events the verifier holds for this receipt. */
  witnessConflicts?: WitnessConflict[]
  /** Anchor equivalences for the independence graph. */
  anchorEdges?: Array<[string, string]>
}

/** Options for the offline verify path. All optional; the verifier reads
 *  no defaults from any network source. */
export interface OfflineVerifyOptions {
  /** Relying-party context for the context layer. When omitted, ONLY the
   *  crypto layer runs and `contextChecked` is false in the result. A
   *  caller that wants the full envelope check MUST supply this. */
  context?: ReceiptContext
  /** Descriptor evidence inputs (signatures, witnesses, conflicts, anchors). */
  descriptor?: OfflineDescriptorInputs
}

export type OfflineVerifyVerdict = 'accept' | 'reject'

export interface OfflineVerifyResult {
  /** Headline: did the receipt pass every layer that ran? */
  verdict: OfflineVerifyVerdict
  /** True iff the crypto layer (signature, receipt_id, claim_type) passed. */
  cryptoValid: boolean
  /** True iff the context layer ran. False when no context was supplied. */
  contextChecked: boolean
  /** True iff the context layer ran AND passed. Always false when it did
   *  not run. */
  contextValid: boolean
  /** The first rejecting reason, if any. Undefined on accept. */
  reason?: RejectReason
  /** Which layer surfaced the rejection, if any. */
  rejectedAtLayer?: 'crypto' | 'context'
  /** The verifier OUTPUT descriptor. Always present: even a rejected
   *  receipt yields a descriptor reporting the mechanical facts (e.g. a
   *  failed signature shows up as a 'fail' corroboration status). */
  descriptor: EvidenceDescriptor
}

/**
 * Verify an ActionReceipt fully offline and return the verdict plus the
 * W2-A1 Evidence Descriptor.
 *
 * Layer order is fixed and matches the conformance corpus: crypto first,
 * then context. A tampered or unsigned receipt is rejected before any
 * context is consulted. The descriptor is built from the signature facts
 * regardless of verdict, so a relying party always has the mechanical
 * evidence view even on rejection.
 *
 * Pure and zero-network: no fetch, no DID resolution, no CRL, no clock
 * read beyond what the caller supplies in {@link ReceiptContext}.
 */
export function verifyOffline(
  receipt: ActionReceipt,
  opts: OfflineVerifyOptions = {},
): OfflineVerifyResult {
  // ── 1. crypto layer ──
  const crypto = verifyActionReceipt(receipt)
  const cryptoValid = crypto.valid

  // ── descriptor seed: the one signature fact the verifier itself can
  //    recompute is the receipt's signer over its outcome claim. The
  //    crypto-layer result IS the signature-valid fact for that signer.
  //    Callers can add further pre-checked signatures (co-signers,
  //    gateway countersignature, witnesses) via opts.descriptor.signatures. ──
  const seedSignature: CheckedSignature = {
    signerId: receipt.signer_did,
    role: 'action_signer',
    claim: 'outcome',
    valid: cryptoValid,
  }
  const extraSignatures = opts.descriptor?.signatures ?? []
  const signatures: CheckedSignature[] = [seedSignature, ...extraSignatures]

  const descriptor = buildDescriptor({
    receiptId: receipt.receipt_id,
    signatures,
    witnessObservations: opts.descriptor?.witnessObservations,
    witnessConflicts: opts.descriptor?.witnessConflicts,
    anchorEdges: opts.descriptor?.anchorEdges,
  })

  // Crypto rejection short-circuits: context is never consulted for a
  // receipt that is not even well-formed and signed.
  if (!cryptoValid) {
    return {
      verdict: 'reject',
      cryptoValid: false,
      contextChecked: false,
      contextValid: false,
      reason: crypto.reason as RejectReason,
      rejectedAtLayer: 'crypto',
      descriptor,
    }
  }

  // ── 2. context layer (only when the caller supplies ground truth) ──
  if (opts.context === undefined) {
    // No context supplied: crypto-only acceptance. The result is honest
    // about this - contextChecked is false, so a relying party knows the
    // envelope checks were not run.
    return {
      verdict: 'accept',
      cryptoValid: true,
      contextChecked: false,
      contextValid: false,
      descriptor,
    }
  }

  const ctx = verifyReceiptContext(receipt, opts.context)
  if (!ctx.valid) {
    return {
      verdict: 'reject',
      cryptoValid: true,
      contextChecked: true,
      contextValid: false,
      reason: ctx.reason,
      rejectedAtLayer: 'context',
      descriptor,
    }
  }

  return {
    verdict: 'accept',
    cryptoValid: true,
    contextChecked: true,
    contextValid: true,
    descriptor,
  }
}
