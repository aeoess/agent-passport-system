// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// W2-A1 Evidence Descriptor interface - consumed, not owned
// ══════════════════════════════════════════════════════════════════
// The Evidence Descriptor and its structural types are owned by the W2-A1
// module (src/v2/assurance/descriptor.ts). This file re-exports them
// verbatim so the offline verifier shares A1's canonical types as a single
// source of truth, and adds only the builder-shape contract the verifier
// is typed against.
//
// THE ABSOLUTE RULE these types preserve: assurance is a verifier-derived
// OUTPUT, never an issuer-set INPUT. No field is read from a receipt body
// as a grade. Every field is a mechanical fact the verifier recomputes
// from the receipt, the signatures it already checked, the witness
// attestations, and the key/DID graph. The lattice point is the
// four-valued Belnap ConstraintStatus, never a scalar ladder.
// ══════════════════════════════════════════════════════════════════

export type {
  IndependenceRelation,
  SignerNode,
  SignerGraph,
  SignerClaim,
  WitnessObservationFact,
  CheckedSignature,
  BuildDescriptorInput,
  EvidenceDescriptor,
} from '../assurance/descriptor.js'

import type {
  BuildDescriptorInput,
  EvidenceDescriptor,
} from '../assurance/descriptor.js'

/** The builder function shape. The offline verifier is typed against this,
 *  so A1's buildEvidenceDescriptor is a drop-in. */
export type DescriptorBuilder = (input: BuildDescriptorInput) => EvidenceDescriptor
