// Agent Passport System — W3C DID Method (did:aps)
// DID Method Specification: did:aps:<hex-encoded-ed25519-public-key>
//
// Maps Agent Passports to W3C DID Documents without
// changing the core protocol. Pure translation layer.

import { canonicalize } from './canonical.js'
import { sign, verify } from '../crypto/keys.js'
import type { AgentPassport, Delegation } from '../types/passport.js'
import type {
  DIDDocument, VerificationMethod, ServiceEndpoint,
  DIDResolutionResult
} from '../types/did.js'

// ── Constants ──

const DID_METHOD = 'aps'
const DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1'
]

// ── DID Creation & Resolution ──

/**
 * Create a DID from an Ed25519 public key.
 * Format: did:aps:<hex-public-key>
 */
export function createDID(publicKey: string): string {
  if (!publicKey || publicKey.length !== 64) {
    throw new Error('Invalid Ed25519 public key: expected 64-char hex string')
  }
  return `did:${DID_METHOD}:${publicKey}`
}

/**
 * Extract the public key from a did:aps DID.
 */
export function publicKeyFromDID(did: string): string {
  const parts = did.split(':')
  if (parts.length !== 3 || parts[0] !== 'did' || parts[1] !== DID_METHOD) {
    throw new Error(`Invalid did:aps DID: ${did}`)
  }
  return parts[2]
}

/**
 * Check if a string is a valid did:aps DID.
 */
export function isValidDID(did: string): boolean {
  try {
    const key = publicKeyFromDID(did)
    return /^[0-9a-f]{64}$/i.test(key)
  } catch {
    return false
  }
}

/**
 * Generate a W3C DID Document from an Agent Passport.
 */
export function passportToDIDDocument(
  passport: AgentPassport,
  options?: {
    serviceEndpoints?: ServiceEndpoint[]
    controllers?: string[]
  }
): DIDDocument {
  const did = createDID(passport.publicKey)
  const keyId = `${did}#key-1`

  // Convert hex public key to multibase (z-prefix + base58btc)
  // For Ed25519, multicodec prefix is 0xed01
  const publicKeyMultibase = hexToMultibase(passport.publicKey)

  const verificationMethod: VerificationMethod = {
    id: keyId,
    type: 'Ed25519VerificationKey2020',
    controller: did,
    publicKeyMultibase
  }

  const controllers = options?.controllers
    ? options.controllers.map(c => c.startsWith('did:') ? c : createDID(c))
    : [did]

  const doc: DIDDocument = {
    '@context': DID_CONTEXT,
    id: did,
    controller: controllers.length === 1 ? controllers[0] : controllers,
    verificationMethod: [verificationMethod],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    service: options?.serviceEndpoints || [],
    created: passport.createdAt,
    updated: passport.createdAt
  }

  return doc
}

/**
 * Resolve a did:aps DID. For now, returns a minimal document
 * from just the public key. In future, could query a registry.
 */
export function resolveDID(did: string): DIDResolutionResult {
  if (!isValidDID(did)) {
    return {
      didDocument: null,
      didDocumentMetadata: { created: '', updated: '' },
      didResolutionMetadata: {
        contentType: 'application/did+ld+json',
        error: 'invalidDid'
      }
    }
  }

  const publicKey = publicKeyFromDID(did)
  const keyId = `${did}#key-1`
  const publicKeyMultibase = hexToMultibase(publicKey)
  const now = new Date().toISOString()

  return {
    didDocument: {
      '@context': DID_CONTEXT,
      id: did,
      controller: did,
      verificationMethod: [{
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase
      }],
      authentication: [keyId],
      assertionMethod: [keyId],
      created: now,
      updated: now
    },
    didDocumentMetadata: { created: now, updated: now },
    didResolutionMetadata: { contentType: 'application/did+ld+json' }
  }
}

/**
 * Sign arbitrary data using the DID's verification method.
 * Returns a base64url-encoded signature.
 */
export async function signWithDID(
  data: Record<string, unknown>,
  privateKey: string,
  did: string
): Promise<string> {
  const canonical = canonicalize(data)
  const sig = await sign(canonical, privateKey)
  return hexToBase64url(sig)
}

/**
 * Verify a signature against a DID's public key.
 */
export async function verifyWithDID(
  data: Record<string, unknown>,
  signatureBase64url: string,
  did: string
): Promise<boolean> {
  const publicKey = publicKeyFromDID(did)
  const sig = base64urlToHex(signatureBase64url)
  const canonical = canonicalize(data)
  return verify(canonical, sig, publicKey)
}

// ── Encoding Helpers ──

// Base58btc alphabet (Bitcoin)
const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

/**
 * Convert hex-encoded Ed25519 public key to multibase (z-prefix + base58btc).
 * Prepends the Ed25519 multicodec prefix (0xed, 0x01) before encoding.
 */
export function hexToMultibase(hexKey: string): string {
  // Ed25519 multicodec prefix
  const prefix = [0xed, 0x01]
  const keyBytes = hexToBytes(hexKey)
  const bytes = new Uint8Array([...prefix, ...keyBytes])
  return 'z' + base58btcEncode(bytes)
}

/**
 * Convert multibase back to hex-encoded public key.
 */
export function multibaseToHex(multibase: string): string {
  if (!multibase.startsWith('z')) {
    throw new Error('Only z-prefix (base58btc) multibase supported')
  }
  const bytes = base58btcDecode(multibase.slice(1))
  // Strip the 2-byte Ed25519 multicodec prefix
  if (bytes[0] !== 0xed || bytes[1] !== 0x01) {
    throw new Error('Invalid Ed25519 multicodec prefix')
  }
  return bytesToHex(bytes.slice(2))
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16)
  }
  return bytes
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('')
}

function base58btcEncode(bytes: Uint8Array): string {
  // Convert bytes to a big integer
  let num = 0n
  for (const b of bytes) {
    num = num * 256n + BigInt(b)
  }
  // Encode
  let encoded = ''
  while (num > 0n) {
    const rem = Number(num % 58n)
    num = num / 58n
    encoded = BASE58_ALPHABET[rem] + encoded
  }
  // Leading zeros
  for (const b of bytes) {
    if (b === 0) encoded = '1' + encoded
    else break
  }
  return encoded || '1'
}

function base58btcDecode(str: string): Uint8Array {
  let num = 0n
  for (const c of str) {
    const idx = BASE58_ALPHABET.indexOf(c)
    if (idx === -1) throw new Error(`Invalid base58 character: ${c}`)
    num = num * 58n + BigInt(idx)
  }
  // Convert back to bytes
  const hex = num.toString(16).padStart(2, '0')
  const padded = hex.length % 2 ? '0' + hex : hex
  const bytes = hexToBytes(padded)
  // Leading zeros
  let leadingZeros = 0
  for (const c of str) {
    if (c === '1') leadingZeros++
    else break
  }
  const result = new Uint8Array(leadingZeros + bytes.length)
  result.set(bytes, leadingZeros)
  return result
}

function hexToBase64url(hex: string): string {
  const bytes = hexToBytes(hex)
  const base64 = Buffer.from(bytes).toString('base64')
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64urlToHex(b64url: string): string {
  const base64 = b64url.replace(/-/g, '+').replace(/_/g, '/')
  const buf = Buffer.from(base64, 'base64')
  return bytesToHex(new Uint8Array(buf))
}
