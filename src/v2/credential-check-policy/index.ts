// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Credential Check Policy — public surface

export type {
  CredentialCheckMode,
  CredentialCheckPolicy,
  CredentialCheckResult,
  CredentialCheckDenialCode,
  AcceptanceStamp,
} from './types.js'

export {
  verifyOnAccept,
  evaluateCredentialCheck,
  resolveCheckMode,
} from './check.js'
