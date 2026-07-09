// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Remote Signer abstraction (W2-B2, additive, EXTENDS the Ed25519 default)
// ══════════════════════════════════════════════════════════════════
// The repo has no Signer interface: every builder calls the free function
// `sign(message, privateKeyHex)` from src/crypto/keys.ts directly with a raw
// hex private key on its options object. This module introduces a pluggable,
// async `Signer` abstraction WITHOUT changing that default function or any of
// its ~40 callsites. The default implementation (LocalEd25519Signer) defers to
// the unchanged `sign()`, so a receipt produced through the abstraction is
// byte-identical to one produced by the direct call and verifies under the
// unchanged `verify()`.
//
// A remote signer (AWS KMS, Azure Key Vault, Vault Transit, PKCS#11) holds only
// a HANDLE to key material that lives in the HSM/KMS. The raw private key never
// materializes in process. The cloud SDK adapters live in the isolated optional
// package packages/aps-remote-signer (own package.json) and are NEVER imported
// by core, so core stays light and ships no cloud SDK dependency.
//
// The signed-bytes boundary is fixed: a Signer receives the SAME canonicalized
// UTF-8 string the direct callsite would pass to sign(), and returns raw
// 64-byte Ed25519 signature hex (128 chars). Output is interchangeable.
// ══════════════════════════════════════════════════════════════════

/**
 * Opaque reference to remote key material. A remote signer holds one of these
 * instead of a raw private key; the bytes of the key never enter this process.
 *
 *  - `kind` names the custody backend (`'local'`, `'aws-kms'`, `'azure-kv'`,
 *    `'vault-transit'`, `'pkcs11'`, or any string an adapter chooses).
 *  - `keyRef` is the backend-native locator: a KMS key ARN/id, a Key Vault key
 *    identifier URL, a Vault Transit key name, a PKCS#11 object label, etc.
 *    It is an identifier, never secret key material.
 */
export interface SignerHandle {
  /** Custody backend identifier. */
  readonly kind: string
  /** Backend-native locator for the key. NOT secret key material. */
  readonly keyRef: string
}

/**
 * Pluggable signer. Async by contract so a network/HSM round-trip composes
 * cleanly; the default local implementation resolves synchronously-derived
 * bytes inside a resolved promise.
 *
 * Contract (every implementation MUST hold):
 *  1. `sign(message)` signs the UTF-8 bytes of `message` exactly as the
 *     canonical free function `sign()` does, and returns raw 64-byte Ed25519
 *     signature hex (128 chars). No DER wrapping at this boundary.
 *  2. `publicKeyHex()` returns the raw 32-byte Ed25519 public key hex
 *     (64 chars) that `verify()` checks the signature against.
 *  3. `keyId()` returns a stable identifier for the key, following the
 *     existing `ed25519:<first-16-hex>` convention unless the backend supplies
 *     its own (e.g. a KMS key id).
 *  4. The raw private key is NEVER returned, logged, or stored by the signer.
 */
export interface Signer {
  /** Sign the UTF-8 bytes of `message`; returns raw 64-byte Ed25519 sig hex. */
  sign(message: string): Promise<string>
  /** Raw 32-byte Ed25519 public key hex (64 chars) for verification. */
  publicKeyHex(): Promise<string>
  /** Stable key identifier (default convention `ed25519:<first-16-hex>`). */
  keyId(): Promise<string>
  /** Custody handle describing where the key lives. */
  readonly handle: SignerHandle
}

/**
 * Raised when a remote signer is asked for material it must never expose, or
 * when a backend returns a signature that is not a wire-compatible raw Ed25519
 * signature. Adapters throw this rather than silently returning a value that
 * would fail verification downstream.
 */
export class RemoteSignerError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'RemoteSignerError'
  }
}

/** Default key-id convention shared with decisionReceipt.ts. */
export function defaultKeyId(publicKeyHex: string): string {
  return `ed25519:${publicKeyHex.slice(0, 16)}`
}

/**
 * Validate that a backend-returned signature is wire-compatible: a raw 64-byte
 * Ed25519 signature, hex-encoded (128 chars). Adapters call this on every value
 * coming back from a KMS/HSM so a mis-encoded (e.g. DER-wrapped) signature is
 * rejected at the boundary instead of failing an opaque verify() later.
 */
export function assertRawEd25519SignatureHex(sigHex: unknown): string {
  if (typeof sigHex !== 'string' || sigHex.length !== 128 || !/^[0-9a-f]+$/i.test(sigHex)) {
    throw new RemoteSignerError(
      `remote signer returned a non-raw-Ed25519 signature (expected 128 hex chars, got ${
        typeof sigHex === 'string' ? `length ${sigHex.length}` : typeof sigHex
      }); the backend may be returning a DER-wrapped or wrong-algorithm signature`,
    )
  }
  return sigHex
}
