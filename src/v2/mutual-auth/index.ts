// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Mutual Authentication v1 — module surface
// ══════════════════════════════════════════════════════════════════

export type {
  MutualAuthRole,
  MutualAuthCertificate,
  MutualAuthHello,
  MutualAuthAttest,
  MutualAuthSession,
  MutualAuthResult,
  MutualAuthPolicy,
  MutualAuthFailureReason,
  TrustAnchor,
  TrustAnchorBundle,
  AgentCertBinding,
} from './types.js'

export {
  buildCertificate,
  signCertificate,
  certificateId,
  verifyCertificateSignature,
  isCertificateTemporallyValid,
  checkAnchor,
} from './certificate.js'

export type {
  BuildCertificateInput,
  VerifyCertificateOutcome,
  AnchorCheckOutcome,
} from './certificate.js'

export {
  buildBundle,
  signBundle,
  verifyBundle,
} from './trust-bundle.js'

export type {
  BuildBundleInput,
  BundleVerifyOutcome,
  BundleVerifyReason,
} from './trust-bundle.js'

export {
  newNonce,
  buildHello,
  chooseVersion,
  buildAttest,
  verifyAttest,
  deriveSession,
  isSessionActive,
} from './handshake.js'

export type {
  BuildAttestInput,
  VerifyAttestInput,
  VerifyAttestOutcome,
} from './handshake.js'
