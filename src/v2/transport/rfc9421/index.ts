// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// RFC 9421 + RFC 9530 request-binding profile: module surface
//
// Wraps a request-bound HTTP Message Signature (RFC 9421) as the INNER proof
// and links it to an APS delegation receipt by content hash. The HTTP
// signature shows "this exact request was the one authorized"; the APS layer
// shows authority. See the proof box in profile.ts.
// ══════════════════════════════════════════════════════════════════

export type {
  DerivedComponent,
  FieldComponent,
  CoveredComponent,
  ContentDigestAlgorithm,
  SignatureAlgorithm,
  RequestContext,
  SignatureParams,
  SignerKey,
  VerifierKey,
  RequestSignature,
  RequestBindingProfile,
  VerifyPolicy,
  VerifyFailureReason,
  VerifyResult,
} from './types.js'

export {
  deriveAuthority,
  derivePath,
  computeContentDigest,
  buildSignatureParamsValue,
  resolveComponentValue,
  buildSignatureBase,
} from './signature-base.js'

export {
  APS_REQUEST_BINDING_TAG,
  APS_REQUEST_BINDING_PROFILE,
  DEFAULT_COVERED,
  defaultScopeOfClaim,
  signRequest,
  verifyRequest,
  InMemoryNonceStore,
} from './profile.js'

export type {
  NonceStore,
  SignRequestInput,
  VerifyRequestInput,
} from './profile.js'
