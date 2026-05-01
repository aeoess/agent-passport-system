// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Accountability MVP — Wave 1 attribution-grade receipt surface
// ══════════════════════════════════════════════════════════════════
// Spec: specs/full-accountability-mvp.md
//
// Five primitives:
//   ActionReceipt              — what was emitted, by whom, under what authority
//   AuthorityBoundaryReceipt   — was the action inside or outside delegation
//   CustodyReceipt             — provenance trail of receipt-handling events
//   ContestabilityReceipt      — affected-party challenge with controller response
//   APSBundle                  — signed aggregation envelope with Merkle commitment
//
// Every receipt extends AccountabilityReceiptBase and MUST declare its
// scope_of_claim. Verbal confessions, not brain scans.
//
// SDK scope: receipt construction, JCS canonicalization, Ed25519 signing,
//            cryptographic verification, Merkle aggregation.
//
// Out of scope (private gateway): replay engines, drift detection, compliance
// dashboards, cross-tenant correlation, decision-equivalence reports.
// ══════════════════════════════════════════════════════════════════

// Types
export * from './types/index.js'

// Constructors
export { createActionReceipt } from './construct/action.js'
export { createAuthorityBoundaryReceipt } from './construct/authority-boundary.js'
export { createCustodyReceipt } from './construct/custody.js'
export { createContestabilityReceipt, attachControllerResponse } from './construct/contestability.js'
export { createAPSBundle, computeMerkleRoot } from './construct/bundle.js'

// Verifiers
export { verifyActionReceipt } from './verify/action.js'
export { verifyAuthorityBoundaryReceipt } from './verify/authority-boundary.js'
export { verifyCustodyReceipt } from './verify/custody.js'
export { verifyContestabilityReceipt } from './verify/contestability.js'
export { verifyAPSBundle } from './verify/bundle.js'
