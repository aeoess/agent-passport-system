// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Evidence Descriptor builder - re-export of the canonical W2-A1 builder
// ══════════════════════════════════════════════════════════════════
// The canonical Evidence Descriptor builder is owned by W2-A1
// (src/v2/assurance/descriptor.ts: buildEvidenceDescriptor). The offline
// verifier is typed against the DescriptorBuilder contract in
// ./descriptor-interface (which re-exports A1's types), so this is a
// drop-in: buildDescriptor IS A1's buildEvidenceDescriptor. The interim
// standalone builder that shipped on the C2 branch before A1 merged has
// been removed in favour of the single canonical source.
//
// ABSOLUTE RULE preserved: assurance is a verifier-derived OUTPUT.
// Independence is computed from the key/DID graph; the lattice point is
// the Belnap ConstraintStatus, never a scalar ladder.
// ══════════════════════════════════════════════════════════════════

export { buildEvidenceDescriptor as buildDescriptor } from '../assurance/descriptor.js'
