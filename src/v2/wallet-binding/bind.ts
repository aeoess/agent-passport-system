// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Wallet Binding — bind / unbind / verify functions
// ══════════════════════════════════════════════════════════════════

import { sign, verify } from '../../crypto/keys.js'
import { canonicalize } from '../../core/canonical.js'
import type { SignedPassport } from '../../types/passport.js'
import type {
  BoundWallet,
  WalletChain,
  WalletVerificationChallenge,
  UnbindEvent,
} from './types.js'

/**
 * Build the canonical payload that the passport private key signs to
 * attest a binding. Verifiers reconstruct this exact payload to check
 * the binding_signature against the passport's public key.
 */
function bindingPayload(opts: {
  passport_id: string
  chain: WalletChain
  address: string
  bound_at: string
}): string {
  return canonicalize({
    passport_id: opts.passport_id,
    chain: opts.chain,
    address: opts.address,
    bound_at: opts.bound_at,
  })
}

function unbindPayload(opts: {
  passport_id: string
  chain: WalletChain
  address: string
  unbound_at: string
}): string {
  return canonicalize({
    passport_id: opts.passport_id,
    chain: opts.chain,
    address: opts.address,
    unbound_at: opts.unbound_at,
    event: 'unbind',
  })
}

/**
 * Bind an external wallet to a passport. Produces a new SignedPassport with
 * the BoundWallet appended to bound_wallets and the entire passport re-signed
 * by the agent's private key.
 *
 * The binding_signature on the BoundWallet is independently verifiable: a
 * third party with only the passport's public key can call verify(payload,
 * binding_signature, publicKey) without holding the passport object itself.
 */
export function bindWallet(opts: {
  passport: SignedPassport
  privateKey: string
  chain: WalletChain
  address: string
  verificationChallenge?: WalletVerificationChallenge
  /** Override the bind timestamp (for deterministic test fixtures). */
  boundAt?: string
}): SignedPassport {
  if (!opts.address || typeof opts.address !== 'string') {
    throw new Error('bindWallet: address must be a non-empty string')
  }
  if (!opts.chain || typeof opts.chain !== 'string') {
    throw new Error('bindWallet: chain must be a non-empty string')
  }

  const bound_at = opts.boundAt ?? new Date().toISOString()
  const payload = bindingPayload({
    passport_id: opts.passport.passport.agentId,
    chain: opts.chain,
    address: opts.address,
    bound_at,
  })

  let binding_signature: string
  try {
    binding_signature = sign(payload, opts.privateKey)
  } catch (e: any) {
    throw new Error(`bindWallet: failed to sign binding payload — ${e?.message || String(e)}`)
  }

  // Sanity check: the produced signature must verify against the passport's
  // public key. If the caller passed a wrong private key, surface that here
  // rather than producing a passport with an unverifiable binding.
  if (!verify(payload, binding_signature, opts.passport.passport.publicKey)) {
    throw new Error(
      'bindWallet: binding signature does not verify against passport public key — wrong private key?'
    )
  }

  const bound: BoundWallet = {
    chain: opts.chain,
    address: opts.address,
    bound_at,
    binding_signature,
    ...(opts.verificationChallenge ? { verification_challenge: opts.verificationChallenge } : {}),
  }

  const existing = opts.passport.passport.bound_wallets ?? []
  const updatedPassport = {
    ...opts.passport.passport,
    bound_wallets: [...existing, bound],
  }

  // Re-sign the entire passport so verifyPassport() still passes for the new
  // shape. The binding_signature alone is enough to prove the binding to an
  // external verifier; the re-sign keeps the passport itself self-consistent.
  const passportSignature = sign(canonicalize(updatedPassport), opts.privateKey)

  return {
    ...opts.passport,
    passport: updatedPassport,
    signature: passportSignature,
    signedAt: new Date().toISOString(),
  }
}

/**
 * Unbind a wallet from a passport. Returns:
 *  - passport: a new SignedPassport with the wallet removed from bound_wallets
 *  - unbindEvent: a separately signed UnbindEvent that callers can persist
 *    to preserve the bind/unbind history outside the passport itself.
 *
 * Throws if the (chain, address) is not currently bound.
 */
export function unbindWallet(opts: {
  passport: SignedPassport
  privateKey: string
  chain: WalletChain
  address: string
  /** Override the unbind timestamp (for deterministic test fixtures). */
  unboundAt?: string
}): { passport: SignedPassport; unbindEvent: UnbindEvent } {
  const existing = opts.passport.passport.bound_wallets ?? []
  const idx = existing.findIndex(
    (w) => w.chain === opts.chain && w.address === opts.address
  )
  if (idx === -1) {
    throw new Error(
      `unbindWallet: no bound wallet matches chain="${opts.chain}" address="${opts.address}"`
    )
  }

  const unbound_at = opts.unboundAt ?? new Date().toISOString()
  const payload = unbindPayload({
    passport_id: opts.passport.passport.agentId,
    chain: opts.chain,
    address: opts.address,
    unbound_at,
  })

  let unbind_signature: string
  try {
    unbind_signature = sign(payload, opts.privateKey)
  } catch (e: any) {
    throw new Error(`unbindWallet: failed to sign unbind payload — ${e?.message || String(e)}`)
  }

  if (!verify(payload, unbind_signature, opts.passport.passport.publicKey)) {
    throw new Error(
      'unbindWallet: unbind signature does not verify against passport public key — wrong private key?'
    )
  }

  const updatedWallets = existing.slice()
  updatedWallets.splice(idx, 1)

  const updatedPassport = {
    ...opts.passport.passport,
    bound_wallets: updatedWallets,
  }
  const passportSignature = sign(canonicalize(updatedPassport), opts.privateKey)

  const unbindEvent: UnbindEvent = {
    passport_id: opts.passport.passport.agentId,
    chain: opts.chain,
    address: opts.address,
    unbound_at,
    unbind_signature,
  }

  return {
    passport: {
      ...opts.passport,
      passport: updatedPassport,
      signature: passportSignature,
      signedAt: new Date().toISOString(),
    },
    unbindEvent,
  }
}

/**
 * Verify that (chain, address) is currently bound to the passport AND that
 * the binding_signature is valid against the passport's public key.
 *
 * Returns false if the wallet is not in bound_wallets, the signature is
 * invalid, or the bound record has been tampered with.
 */
export function verifyBoundWallet(
  passport: SignedPassport,
  chain: WalletChain,
  address: string
): boolean {
  const wallets = passport.passport.bound_wallets
  if (!wallets || wallets.length === 0) return false

  const bound = wallets.find((w) => w.chain === chain && w.address === address)
  if (!bound) return false

  const payload = bindingPayload({
    passport_id: passport.passport.agentId,
    chain: bound.chain,
    address: bound.address,
    bound_at: bound.bound_at,
  })

  try {
    return verify(payload, bound.binding_signature, passport.passport.publicKey)
  } catch {
    return false
  }
}

/**
 * Verify a previously issued unbind event against a passport's public key.
 * Useful when reconstructing wallet history from a stored unbind log.
 */
export function verifyUnbindEvent(event: UnbindEvent, passportPublicKey: string): boolean {
  const payload = unbindPayload({
    passport_id: event.passport_id,
    chain: event.chain,
    address: event.address,
    unbound_at: event.unbound_at,
  })
  try {
    return verify(payload, event.unbind_signature, passportPublicKey)
  } catch {
    return false
  }
}
