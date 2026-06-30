// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// APS Composition Check Receipt v0 public barrel. Carrier + anchor verifier only;
// detection of composition hazards is private gateway intelligence, not in this repo.
export {
  COMPOSITION_CHECK_PROFILE,
  COMPOSITION_CHECK_TAG,
  COMPOSITION_CHECK_RESULTS,
  ATTESTOR_INDEPENDENCE_CLASSES,
} from './types.js'
export type {
  CompositionCheckResult,
  AttestorIndependenceClass,
  CompositionCheckReceipt,
  RegisteredAttestorKey,
  CompositionCheckVerificationContext,
  CompositionCheckVerifyResult,
} from './types.js'
export { verifyCompositionCheck, compositionCheckSigningPayload } from './verify.js'
