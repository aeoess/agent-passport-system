// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Signer-produced signature verification (W2-B2)
// ══════════════════════════════════════════════════════════════════
// Thin convenience over the unchanged `verify()` from src/crypto/keys.ts. A
// signature produced by ANY Signer implementation (local or remote) verifies
// through the exact same path; this helper just resolves the signer's public
// key first. There is no remote verification: verification is always local and
// algorithm-equal to the Ed25519 default.
// ══════════════════════════════════════════════════════════════════

import { verify } from '../../crypto/keys.js'
import type { Signer } from './types.js'

/**
 * Verify a `signature` over `message` against a Signer's public key using the
 * unchanged `verify()`. Returns true iff the signature is the raw 64-byte
 * Ed25519 signature of the UTF-8 bytes of `message` under the signer's key.
 *
 * Proves: the signature relation holds for the bytes the signer was given.
 * Does NOT prove: anything about where the private key lives, nor that the
 * backend that produced the signature is uncompromised.
 */
export async function verifyWithSigner(
  message: string,
  signature: string,
  signer: Signer,
): Promise<boolean> {
  const publicKeyHex = await signer.publicKeyHex()
  return verify(message, signature, publicKeyHex)
}
