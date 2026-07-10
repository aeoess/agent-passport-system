// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Wallet Binding — public surface

export type {
  BoundWallet,
  WalletChain,
  WalletVerificationChallenge,
  UnbindEvent,
} from './types.js'

export {
  bindWallet,
  unbindWallet,
  verifyBoundWallet,
  verifyUnbindEvent,
} from './bind.js'
