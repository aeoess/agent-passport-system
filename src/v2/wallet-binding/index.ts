// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
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
