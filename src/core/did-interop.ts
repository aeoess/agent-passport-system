// Agent Passport System — DID Interop (did:key + did:web)
// Translation layer between APS passports and W3C DID methods.
// did:key for self-certifying identifiers, did:web for domain-linked.

import { hexToMultibase, multibaseToHex } from './did.js'

// ── did:key ──

/**
 * Convert an Ed25519 public key (hex) to did:key format.
 * Format: did:key:z6Mk... (multicodec 0xed01 + base58btc)
 *
 * The multibase value is the same encoding used in did:aps multibase
 * identifiers — Ed25519 multicodec prefix (0xed, 0x01) + raw key bytes,
 * base58btc encoded with z-prefix.
 */
export function toDIDKey(ed25519PublicKeyHex: string): string {
  if (!ed25519PublicKeyHex || !/^[0-9a-f]{64}$/i.test(ed25519PublicKeyHex)) {
    throw new Error('Invalid Ed25519 public key: expected 64-char hex string')
  }
  const multibase = hexToMultibase(ed25519PublicKeyHex)
  return `did:key:${multibase}`
}

/**
 * Parse a did:key back to a raw Ed25519 public key (hex).
 * Validates the did:key prefix and multicodec bytes.
 */
export function fromDIDKey(didKey: string): string {
  if (typeof didKey !== 'string') {
    throw new Error('did:key must be a string')
  }
  const parts = didKey.split(':')
  if (parts.length !== 3 || parts[0] !== 'did' || parts[1] !== 'key') {
    throw new Error(`Invalid did:key format: ${didKey}`)
  }
  const multibase = parts[2]
  if (!multibase.startsWith('z')) {
    throw new Error('did:key identifier must use z-prefix (base58btc) multibase')
  }
  return multibaseToHex(multibase)
}

// ── did:web ──

/**
 * Construct the HTTPS URL for a did:web DID document.
 *
 * did:web:example.com         → https://example.com/.well-known/did.json
 * did:web:example.com:users:1 → https://example.com/users/1/did.json
 * did:web:example.com%3A8443  → https://example.com:8443/.well-known/did.json
 */
export function didWebToUrl(didWeb: string): string {
  if (typeof didWeb !== 'string') {
    throw new Error('did:web must be a string')
  }
  const parts = didWeb.split(':')
  if (parts.length < 3 || parts[0] !== 'did' || parts[1] !== 'web') {
    throw new Error(`Invalid did:web format: ${didWeb}`)
  }
  // Everything after "did:web:" is the domain-and-path, colon-separated
  const segments = parts.slice(2).map(s => decodeURIComponent(s))
  const domain = segments[0]
  if (!domain) {
    throw new Error('did:web must include a domain')
  }
  if (segments.length === 1) {
    return `https://${domain}/.well-known/did.json`
  }
  const path = segments.slice(1).join('/')
  return `https://${domain}/${path}/did.json`
}

/**
 * Resolve a did:web DID by fetching the DID document over HTTPS.
 * Returns the parsed DID Document object.
 *
 * Throws on network errors, non-200 responses, and invalid JSON.
 */
export async function resolveDIDWeb(didWeb: string): Promise<object> {
  const url = didWebToUrl(didWeb)
  const response = await fetch(url, {
    headers: { 'Accept': 'application/did+ld+json, application/json' },
    signal: AbortSignal.timeout(10_000),
  })
  if (!response.ok) {
    throw new Error(`did:web resolution failed: HTTP ${response.status} from ${url}`)
  }
  const doc = await response.json()
  if (!doc || typeof doc !== 'object' || !('id' in doc)) {
    throw new Error(`did:web resolution returned invalid DID Document from ${url}`)
  }
  return doc as object
}

// ── Passport ↔ DID Document ──

const DID_CONTEXT = [
  'https://www.w3.org/ns/did/v1',
  'https://w3id.org/security/suites/ed25519-2020/v1',
]

/**
 * Convert an APS passport to a W3C DID Document.
 * Produces a document with did:key as the subject identifier
 * and a single Ed25519VerificationKey2020 verification method.
 *
 * Accepts a minimal passport shape: { agent_id, public_key }.
 * Optionally accepts created_at for the document timestamps.
 */
export function passportToDIDDocument(passport: {
  agent_id: string
  public_key: string
  created_at?: string
}): object {
  if (!passport.public_key || !/^[0-9a-f]{64}$/i.test(passport.public_key)) {
    throw new Error('Invalid passport: public_key must be 64-char hex')
  }
  if (!passport.agent_id) {
    throw new Error('Invalid passport: agent_id is required')
  }

  const did = toDIDKey(passport.public_key)
  const keyId = `${did}#key-1`
  const publicKeyMultibase = hexToMultibase(passport.public_key)
  const now = passport.created_at || new Date().toISOString()

  return {
    '@context': DID_CONTEXT,
    id: did,
    controller: did,
    alsoKnownAs: [`did:aps:${publicKeyMultibase}`],
    verificationMethod: [{
      id: keyId,
      type: 'Ed25519VerificationKey2020',
      controller: did,
      publicKeyMultibase,
    }],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    service: [{
      id: `${did}#aps`,
      type: 'AgentPassportService',
      serviceEndpoint: {
        agentId: passport.agent_id,
        protocol: 'aps',
        version: '1.0.0',
      },
    }],
    created: now,
    updated: now,
  }
}
