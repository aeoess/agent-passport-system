// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// LocalEd25519Signer - the default Signer (W2-B2)
// ══════════════════════════════════════════════════════════════════
// Wraps the unchanged free function `sign()` from src/crypto/keys.ts so the
// pluggable Signer abstraction has an in-core default that is byte-identical to
// the direct callsites. This DOES NOT replace `sign()` and DOES NOT touch any
// existing builder; it is opt-in. A receipt signed through this signer carries
// the same 64-byte raw Ed25519 signature the direct call would have produced.
//
// Unlike a remote signer, this default necessarily holds the raw private key in
// process (that is what "local" means). Callers who need the key to stay in an
// HSM/KMS use a remote adapter from packages/aps-remote-signer instead.
// ══════════════════════════════════════════════════════════════════

import { sign, publicKeyFromPrivate } from '../../crypto/keys.js'
import {
  type Signer,
  type SignerHandle,
  RemoteSignerError,
  defaultKeyId,
  assertRawEd25519SignatureHex,
} from './types.js'

export interface LocalSignerOptions {
  /** Raw 32-byte Ed25519 private key, hex-encoded (64 hex chars). */
  privateKeyHex: string
  /** Override the default `ed25519:<first-16-hex>` key id. */
  keyId?: string
}

/**
 * The default Signer. Delegates signing to the canonical `sign()` so output is
 * interchangeable with the direct-callsite path and verifies under the
 * unchanged `verify()`. Use a remote adapter instead when the raw key must
 * never live in this process.
 */
export class LocalEd25519Signer implements Signer {
  readonly handle: SignerHandle = { kind: 'local', keyRef: 'in-process' }
  #privateKeyHex: string
  #publicKeyHex: string
  #keyId: string

  constructor(opts: LocalSignerOptions) {
    if (
      typeof opts.privateKeyHex !== 'string' ||
      opts.privateKeyHex.length !== 64 ||
      !/^[0-9a-f]+$/i.test(opts.privateKeyHex)
    ) {
      throw new RemoteSignerError(
        `LocalEd25519Signer requires a 64-hex-char raw Ed25519 private key (got ${
          typeof opts.privateKeyHex === 'string'
            ? `length ${opts.privateKeyHex.length}`
            : typeof opts.privateKeyHex
        })`,
      )
    }
    this.#privateKeyHex = opts.privateKeyHex
    this.#publicKeyHex = publicKeyFromPrivate(opts.privateKeyHex)
    this.#keyId = opts.keyId ?? defaultKeyId(this.#publicKeyHex)
  }

  async sign(message: string): Promise<string> {
    // Same UTF-8 message bytes, same DER handling, same output as the direct
    // callsites. Re-validate the shape so this path enforces the identical raw
    // 64-byte contract that remote adapters are held to.
    return assertRawEd25519SignatureHex(sign(message, this.#privateKeyHex))
  }

  async publicKeyHex(): Promise<string> {
    return this.#publicKeyHex
  }

  async keyId(): Promise<string> {
    return this.#keyId
  }
}

/** Convenience constructor matching the existing `from*` adapter ergonomics. */
export function createLocalSigner(opts: LocalSignerOptions): Signer {
  return new LocalEd25519Signer(opts)
}
