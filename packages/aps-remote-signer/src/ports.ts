// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Backend ports (structural client contracts)
// ══════════════════════════════════════════════════════════════════
// Each cloud adapter takes an ALREADY-CONSTRUCTED vendor client conforming to
// the minimal structural port below. This package therefore imports NO cloud
// SDK: the caller constructs the AWS/Azure/Vault/PKCS#11 client, configures its
// credentials and region/endpoint, and injects it. The raw private key lives in
// the HSM/KMS behind the client and never enters this process - the adapter
// only ever holds the client handle and the key reference.
//
// Ports describe what the adapter NEEDS, not the full vendor SDK. A thin shim
// around the real SDK (or a test double) satisfies them. Each port returns the
// material the APS Signer abstraction requires: a raw 64-byte Ed25519 signature
// over the given UTF-8 message bytes, and the raw 32-byte Ed25519 public key.
// ══════════════════════════════════════════════════════════════════

/**
 * AWS KMS port. The key is an asymmetric Ed25519 KMS key with usage
 * SIGN_VERIFY. `keyId` is the KMS key id, ARN, or alias.
 *
 * The real client wraps @aws-sdk/client-kms: `Sign` with
 * SigningAlgorithm 'EDDSA' and MessageType 'RAW', and `GetPublicKey`. The shim
 * is responsible for unwrapping the SubjectPublicKeyInfo DER from GetPublicKey
 * down to the raw 32 bytes, and for ensuring the Sign response is the raw
 * 64-byte Ed25519 signature (KMS returns raw for EdDSA).
 */
export interface AwsKmsPort {
  signRaw(keyId: string, messageUtf8: string): Promise<string>
  getRawPublicKeyHex(keyId: string): Promise<string>
}

/**
 * Azure Key Vault port. The key is an EdDSA (Ed25519/OKP) key in a Key Vault or
 * Managed HSM. `keyName` (optionally with version) identifies it.
 *
 * The real client wraps @azure/keyvault-keys CryptographyClient.signData with
 * algorithm 'EdDSA' plus a keys-client get for the public key (the OKP `x`
 * parameter is the raw 32-byte public key).
 */
export interface AzureKeyVaultPort {
  signRaw(keyName: string, messageUtf8: string): Promise<string>
  getRawPublicKeyHex(keyName: string): Promise<string>
}

/**
 * HashiCorp Vault Transit port. The key is an `ed25519` Transit key. `keyName`
 * is the Transit key name.
 *
 * The real client wraps the Transit `sign/:name` and `keys/:name` HTTP API. The
 * shim decodes Vault's `vault:v1:<base64sig>` envelope to raw 64-byte hex and
 * the base64 public key to raw 32-byte hex.
 */
export interface VaultTransitPort {
  signRaw(keyName: string, messageUtf8: string): Promise<string>
  getRawPublicKeyHex(keyName: string): Promise<string>
}

/**
 * PKCS#11 port. The key is an Ed25519 private object on a hardware token,
 * referenced by `objectLabel` (or handle). The real client wraps a PKCS#11
 * binding (e.g. graphene-pk11) doing C_Sign with CKM_EDDSA and reading the
 * public EC point.
 */
export interface Pkcs11Port {
  signRaw(objectLabel: string, messageUtf8: string): Promise<string>
  getRawPublicKeyHex(objectLabel: string): Promise<string>
}
