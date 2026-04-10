// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Wallet Binding — agent-native (structural) wallet attestation
// ══════════════════════════════════════════════════════════════════
// Composes with issuer-attested (behavioral) wallet binding from the
// insumer-examples ecosystem (skyemeta/skyeprofile and friends).
//
// APS provides the structural layer: the agent's own passport private
// key signs a binding statement attaching an external chain address to
// its identity. Verifiable offline with just the passport public key.
// ══════════════════════════════════════════════════════════════════

/** Canonical chain identifiers. The string union is open-ended on purpose. */
export type WalletChain =
  | 'nano'
  | 'solana'
  | 'ethereum'
  | 'base'
  | 'bitcoin'
  | string

/** A signed binding between a passport and an external wallet address. */
export interface BoundWallet {
  chain: WalletChain
  address: string
  /** ISO 8601 timestamp when the binding was created. */
  bound_at: string
  /**
   * Ed25519 signature over canonicalize({ passport_id, chain, address, bound_at }),
   * signed by the passport's private key. Verifiable with the passport public key
   * alone — no passport object required.
   */
  binding_signature: string
  /**
   * Optional proof that the holder of the external wallet's private key
   * authorized the binding. Format depends on chain. For chains without
   * a native signing scheme on the SDK side, this is left undefined and
   * the binding rests on the passport signature alone.
   */
  verification_challenge?: WalletVerificationChallenge
}

/**
 * Optional cross-key proof. The external wallet signs a challenge string
 * (typically the same canonical payload that produced binding_signature)
 * with its own private key, in whatever signature scheme the chain uses.
 */
export interface WalletVerificationChallenge {
  /** What the external wallet signed. SDK does not interpret. */
  challenge: string
  /** External-wallet signature over `challenge`, encoded per chain convention. */
  signature: string
  /** Signature scheme hint (e.g. 'ed25519', 'secp256k1', 'nano-block'). */
  scheme?: string
}

/**
 * Signed unbind event. Produced by unbindWallet(). The unbind history is
 * preserved separately from the passport's current bound_wallets list so
 * verifiers can reconstruct the bind/unbind timeline if needed.
 */
export interface UnbindEvent {
  passport_id: string
  chain: WalletChain
  address: string
  /** ISO 8601 timestamp when the unbind was created. */
  unbound_at: string
  /**
   * Ed25519 signature over canonicalize({ passport_id, chain, address, unbound_at, event: 'unbind' }),
   * signed by the passport's private key.
   */
  unbind_signature: string
}
