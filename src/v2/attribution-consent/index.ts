// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Attribution Consent — public surface

export type {
  AttributionReceipt,
  AttributionConsentResult,
  ArtifactCitation,
  CitingArtifact,
  AgentDID,
  PrincipalDID,
  ContextID,
  Ed25519Signature,
} from './types.js'

export { createAttributionReceipt, receiptCore } from './create.js'
export type { CreateAttributionReceiptParams } from './create.js'
export { signAttributionConsent } from './sign.js'
export { verifyAttributionConsent, checkArtifactCitations } from './verify.js'
