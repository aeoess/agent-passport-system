// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Remote Signer adapters - public surface (W2-B2, EXTENDS)
// ══════════════════════════════════════════════════════════════════
// A pluggable async Signer abstraction over the existing Ed25519 default. The
// default function `sign(message, privateKeyHex)` in src/crypto/keys.ts and its
// ~40 callsites are UNCHANGED. The abstraction is opt-in.
//
//   Signer                  the interface (sign / publicKeyHex / keyId / handle)
//   LocalEd25519Signer      default, delegates to the unchanged sign()
//   HandleSigner            remote reference: two backend callbacks + a handle,
//                           holds NO raw key (the cloud-SDK-free shape every
//                           remote adapter reduces to)
//   verifyWithSigner        verify a signer signature via the unchanged verify()
//
// Cloud adapters (AWS KMS, Azure Key Vault, Vault Transit, PKCS#11) live in the
// isolated optional package packages/aps-remote-signer with their own
// package.json and are NEVER imported here, so core ships no cloud SDK.
//
// PROOF BOX (dogfooded as a ScopeOfClaim via buildRemoteSignerScopeOfClaim):
//   Proves:        a remote-signer receipt carries the SAME signature relation
//                  as the local-signer path (same UTF-8 message bytes, same raw
//                  64-byte Ed25519 signature, verifies under the unchanged
//                  verify()), and the signing key stayed in the HSM/KMS (only a
//                  handle and the returned signature ever crossed into process).
//   Does NOT prove: that the KMS/HSM itself is uncompromised, that the operator
//                  custody policy on the key is correct, or anything about key
//                  provenance beyond the public key the verifier trusts.
// ══════════════════════════════════════════════════════════════════

import type { ScopeOfClaim } from '../../v2/accountability/types/base.js'

export {
  type Signer,
  type SignerHandle,
  RemoteSignerError,
  defaultKeyId,
  assertRawEd25519SignatureHex,
} from './types.js'

export {
  LocalEd25519Signer,
  createLocalSigner,
  type LocalSignerOptions,
} from './local-signer.js'

export {
  HandleSigner,
  createHandleSigner,
  type HandleSignerOptions,
  type RemoteSignFn,
  type RemotePublicKeyFn,
} from './handle-signer.js'

export { verifyWithSigner } from './verify.js'

/**
 * The remote-signer proof box rendered as a ScopeOfClaim, for callers that emit
 * an accountability receipt covering a signature produced through a remote
 * signer. Mirrors the PROOF BOX above. The signature relation is what is tested;
 * key custody is reported as a mechanical fact (a handle, not the raw key), not
 * as an assurance the backend is trustworthy.
 */
export function buildRemoteSignerScopeOfClaim(backendKind: string): ScopeOfClaim {
  return {
    asserts:
      `A signature was produced by a remote signer (custody backend '${backendKind}') over the ` +
      'same UTF-8 message bytes the local Ed25519 path would sign, and it verifies under the ' +
      'unchanged verify(); only a key handle and the returned signature crossed into process.',
    does_not_assert: [
      'That the HSM/KMS backend itself is uncompromised.',
      'That the operator custody policy on the key is correct.',
      'Anything about key provenance beyond the public key the verifier trusts.',
    ],
    capture_mode: 'gateway_observed',
    completeness: 'complete',
    self_attested: false,
  }
}
