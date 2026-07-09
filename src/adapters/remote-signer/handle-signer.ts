// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// HandleSigner - the remote-signer reference shape (W2-B2)
// ══════════════════════════════════════════════════════════════════
// The in-core, cloud-SDK-free Signer that every remote adapter (AWS KMS, Azure
// Key Vault, Vault Transit, PKCS#11) reduces to. It is constructed from two
// backend callbacks and a handle; it NEVER receives or holds a raw private key.
//
//   - `signRemote(messageUtf8)` asks the backend to sign the UTF-8 message bytes
//     and return a raw 64-byte Ed25519 signature hex. The key stays in the
//     HSM/KMS; only the signature crosses the boundary.
//   - `getPublicKeyHex()` fetches the raw 32-byte Ed25519 public key hex.
//
// The cloud adapters in packages/aps-remote-signer build these two callbacks
// over a vendor SDK and pass them here. Core ships only this shape, so core
// imports no cloud SDK. Tests construct a HandleSigner over a backend stub to
// prove a KMS-signed receipt verifies identically to the Ed25519 path and that
// the raw key never materializes in the consuming process.
// ══════════════════════════════════════════════════════════════════

import {
  type Signer,
  type SignerHandle,
  RemoteSignerError,
  defaultKeyId,
  assertRawEd25519SignatureHex,
} from './types.js'

/**
 * Backend callback: sign the UTF-8 bytes of `messageUtf8` with key material the
 * backend holds, returning raw 64-byte Ed25519 signature hex (128 chars). The
 * raw private key MUST NOT cross this boundary.
 */
export type RemoteSignFn = (messageUtf8: string) => Promise<string>

/** Backend callback: return the raw 32-byte Ed25519 public key hex (64 chars). */
export type RemotePublicKeyFn = () => Promise<string>

export interface HandleSignerOptions {
  handle: SignerHandle
  signRemote: RemoteSignFn
  getPublicKeyHex: RemotePublicKeyFn
  /** Override the default `ed25519:<first-16-hex>` key id (e.g. a KMS key id). */
  keyId?: string
}

/**
 * Remote Signer over two backend callbacks and a handle. Holds no raw key.
 * Caches the public key on first fetch (it is not secret and is stable for the
 * key's lifetime). The signature returned by the backend is validated at the
 * boundary so a DER-wrapped or wrong-algorithm response is rejected here rather
 * than failing an opaque verify() later.
 */
export class HandleSigner implements Signer {
  readonly handle: SignerHandle
  #signRemote: RemoteSignFn
  #getPublicKeyHex: RemotePublicKeyFn
  #keyIdOverride?: string
  #cachedPublicKeyHex?: string

  constructor(opts: HandleSignerOptions) {
    if (typeof opts.signRemote !== 'function' || typeof opts.getPublicKeyHex !== 'function') {
      throw new RemoteSignerError('HandleSigner requires signRemote and getPublicKeyHex callbacks')
    }
    if (!opts.handle || typeof opts.handle.kind !== 'string' || typeof opts.handle.keyRef !== 'string') {
      throw new RemoteSignerError('HandleSigner requires a { kind, keyRef } handle')
    }
    this.handle = opts.handle
    this.#signRemote = opts.signRemote
    this.#getPublicKeyHex = opts.getPublicKeyHex
    this.#keyIdOverride = opts.keyId
  }

  async sign(message: string): Promise<string> {
    const sigHex = await this.#signRemote(message)
    return assertRawEd25519SignatureHex(sigHex)
  }

  async publicKeyHex(): Promise<string> {
    if (this.#cachedPublicKeyHex === undefined) {
      const pub = await this.#getPublicKeyHex()
      if (typeof pub !== 'string' || pub.length !== 64 || !/^[0-9a-f]+$/i.test(pub)) {
        throw new RemoteSignerError(
          `remote backend returned a non-raw-Ed25519 public key (expected 64 hex chars, got ${
            typeof pub === 'string' ? `length ${pub.length}` : typeof pub
          })`,
        )
      }
      this.#cachedPublicKeyHex = pub
    }
    return this.#cachedPublicKeyHex
  }

  async keyId(): Promise<string> {
    if (this.#keyIdOverride !== undefined) return this.#keyIdOverride
    return defaultKeyId(await this.publicKeyHex())
  }
}

/** Convenience constructor matching the existing `from*` adapter ergonomics. */
export function createHandleSigner(opts: HandleSignerOptions): Signer {
  return new HandleSigner(opts)
}
