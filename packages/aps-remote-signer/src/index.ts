// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * @fileoverview OPTIONAL, ISOLATED entry point for remote signer adapters.
 * NOT imported by core. Cloud SDKs are NOT bundled: each adapter takes an
 * injected, already-configured backend client (a structural port). The raw
 * private key never materializes in process; each adapter reduces to a core
 * HandleSigner holding only a key handle and backend callbacks.
 *
 * A receipt signed through any adapter here verifies IDENTICALLY to one signed
 * by the Ed25519 default in the core SDK.
 */

export {
  createAwsKmsSigner,
  createAzureKeyVaultSigner,
  createVaultTransitSigner,
  createPkcs11Signer,
} from './adapters.js'

export type {
  AwsKmsPort,
  AzureKeyVaultPort,
  VaultTransitPort,
  Pkcs11Port,
} from './ports.js'
