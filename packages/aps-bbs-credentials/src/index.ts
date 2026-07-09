// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * @fileoverview EXPERIMENTAL, ISOLATED entry point for BBS selective-disclosure
 * scope credentials. NOT imported by core. NOT core-reviewed crypto this round.
 * The crypto-review burden is outstanding. See README.md and the proof box in
 * credential.ts before relying on anything here.
 */

export {
  defaultCredentialScope,
  defaultDisclosureScope,
  deriveDisclosureProof,
  generateKeyPair,
  issueScopeCredential,
  verifyDisclosureProof,
  verifyScopeCredential,
} from './credential.js'

export type {
  BbsKeyPair,
  CaptureMode,
  Ciphersuite,
  Completeness,
  ScopeCredential,
  ScopeDisclosureProof,
  ScopeOfClaim,
} from './types.js'
