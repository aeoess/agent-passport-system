// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
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
