// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Audience binding: module surface
//
// A versioned, additive `aud` slot on delegation and receipt proofs so a
// passport issued for recipient A is rejected when presented to recipient B.
// Reuses the OAuth array-normalize + membership-check pattern, reconciles with
// the cross_chain confused-deputy constraint, and composes with the M1
// RFC 9421 request-binding profile via @authority without changing signed
// bytes. The `aud` slot is optional-until-profile-required; omitting it leaves
// a proof byte-identical to before this module existed.
//
// PROOF BOX
//   Proves: the issuer named this relying party among the proof's recipients;
//           a proof minted for A is rejected at B.
//   Does NOT prove: that a NAMED recipient will not misuse what it
//           legitimately received; audience restricts WHO may present a proof,
//           not what a legitimate holder does next.
// ══════════════════════════════════════════════════════════════════

export type {
  AudienceBinding,
  AudiencePolicy,
  AudienceStatus,
  AudienceReason,
  AudienceCheckResult,
} from './types.js'

export { AUDIENCE_BINDING_PROFILE } from './types.js'

export type { AudienceBearer } from './verify.js'

export {
  normalizeRecipients,
  matchAudience,
  checkAudience,
  bindAudience,
} from './verify.js'

export type { AudienceCrossChainReconciliation } from './reconcile.js'

export {
  audienceToConstraintStatus,
  audienceFailure,
  reconcileAudienceWithCrossChain,
} from './reconcile.js'

export type {
  RequestAudiencePolicy,
  RequestAudienceResult,
} from './request-binding.js'

export { verifyRequestWithAudience } from './request-binding.js'
