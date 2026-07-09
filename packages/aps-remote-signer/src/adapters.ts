// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Cloud remote-signer adapters (AWS KMS, Azure Key Vault, Vault Transit, PKCS#11)
// ══════════════════════════════════════════════════════════════════
// Each adapter reduces to a core HandleSigner over an injected backend port.
// The raw private key never enters this process: the adapter holds only the
// client handle and the key reference, and forwards the UTF-8 message bytes to
// the backend, which returns a raw 64-byte Ed25519 signature. A receipt signed
// through any of these verifies IDENTICALLY to one signed by the Ed25519 default
// (same message bytes, same raw signature, same unchanged verify()).
//
// PROOF BOX:
//   Proves:        a remote-signer receipt carries the same signature relation
//                  as the local path, and the signing key stayed in the HSM/KMS.
//   Does NOT prove: that the HSM/KMS itself is uncompromised.
// ══════════════════════════════════════════════════════════════════

import { HandleSigner, type Signer } from 'agent-passport-system'
import type {
  AwsKmsPort,
  AzureKeyVaultPort,
  VaultTransitPort,
  Pkcs11Port,
} from './ports.js'

/** AWS KMS adapter. `client` is an injected, configured AwsKmsPort. */
export function createAwsKmsSigner(opts: {
  client: AwsKmsPort
  keyId: string
  /** Override the default ed25519:<first-16-hex> key id (e.g. the KMS ARN). */
  signerKeyId?: string
}): Signer {
  return new HandleSigner({
    handle: { kind: 'aws-kms', keyRef: opts.keyId },
    signRemote: (messageUtf8) => opts.client.signRaw(opts.keyId, messageUtf8),
    getPublicKeyHex: () => opts.client.getRawPublicKeyHex(opts.keyId),
    keyId: opts.signerKeyId,
  })
}

/** Azure Key Vault adapter. `client` is an injected, configured AzureKeyVaultPort. */
export function createAzureKeyVaultSigner(opts: {
  client: AzureKeyVaultPort
  keyName: string
  signerKeyId?: string
}): Signer {
  return new HandleSigner({
    handle: { kind: 'azure-kv', keyRef: opts.keyName },
    signRemote: (messageUtf8) => opts.client.signRaw(opts.keyName, messageUtf8),
    getPublicKeyHex: () => opts.client.getRawPublicKeyHex(opts.keyName),
    keyId: opts.signerKeyId,
  })
}

/** HashiCorp Vault Transit adapter. `client` is an injected, configured VaultTransitPort. */
export function createVaultTransitSigner(opts: {
  client: VaultTransitPort
  keyName: string
  signerKeyId?: string
}): Signer {
  return new HandleSigner({
    handle: { kind: 'vault-transit', keyRef: opts.keyName },
    signRemote: (messageUtf8) => opts.client.signRaw(opts.keyName, messageUtf8),
    getPublicKeyHex: () => opts.client.getRawPublicKeyHex(opts.keyName),
    keyId: opts.signerKeyId,
  })
}

/** PKCS#11 adapter. `client` is an injected, configured Pkcs11Port. */
export function createPkcs11Signer(opts: {
  client: Pkcs11Port
  objectLabel: string
  signerKeyId?: string
}): Signer {
  return new HandleSigner({
    handle: { kind: 'pkcs11', keyRef: opts.objectLabel },
    signRemote: (messageUtf8) => opts.client.signRaw(opts.objectLabel, messageUtf8),
    getPublicKeyHex: () => opts.client.getRawPublicKeyHex(opts.objectLabel),
    keyId: opts.signerKeyId,
  })
}
