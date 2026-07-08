// Agent Passport System — DID Interop (did:key + did:web)
// Translation layer between APS passports and W3C DID methods.
// did:key for self-certifying identifiers, did:web for domain-linked.

import { isIP, BlockList } from 'node:net'
import { lookup as dnsLookup } from 'node:dns/promises'
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

/** SSRF guard (D-SSRF1): the domain segment of a did:web identifier is
 *  attacker/remote-peer suppliable in real callers (tool-registry trust
 *  roots, trust-policy key locators). Block the classic SSRF targets:
 *  loopback, link-local (including the 169.254.169.254 cloud metadata
 *  address), and RFC1918/ULA private ranges, before the outbound fetch. */
const SSRF_BLOCKLIST = new BlockList()
SSRF_BLOCKLIST.addSubnet('127.0.0.0', 8, 'ipv4')   // loopback
SSRF_BLOCKLIST.addSubnet('169.254.0.0', 16, 'ipv4') // link-local incl. cloud metadata
SSRF_BLOCKLIST.addSubnet('10.0.0.0', 8, 'ipv4')     // RFC1918
SSRF_BLOCKLIST.addSubnet('172.16.0.0', 12, 'ipv4')  // RFC1918
SSRF_BLOCKLIST.addSubnet('192.168.0.0', 16, 'ipv4') // RFC1918
SSRF_BLOCKLIST.addSubnet('0.0.0.0', 8, 'ipv4')      // "this network"
SSRF_BLOCKLIST.addSubnet('::1', 128, 'ipv6')        // loopback
SSRF_BLOCKLIST.addSubnet('fe80::', 10, 'ipv6')      // link-local
SSRF_BLOCKLIST.addSubnet('fc00::', 7, 'ipv6')       // unique-local

const DNS_SAFETY_TIMEOUT_MS = 3_000

function isBlockedAddress(address: string, family: 4 | 6): boolean {
  return SSRF_BLOCKLIST.check(address, family === 4 ? 'ipv4' : 'ipv6')
}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('dns safety lookup timed out')), ms)
    p.then(v => { clearTimeout(t); resolve(v) }, e => { clearTimeout(t); reject(e) })
  })
}

/**
 * Reject did:web targets that resolve to a private/internal address before
 * any fetch is made. Fails OPEN on DNS lookup errors/timeouts for an
 * unresolvable or unreachable hostname: that failure mode is identical to
 * (and surfaced by) the subsequent fetch, so legitimate "domain doesn't
 * exist" error paths are unaffected. Fails CLOSED (throws) only when a
 * concrete address is confirmed to be in a blocked range.
 */
async function assertSafeDidWebTarget(url: string): Promise<void> {
  const { hostname } = new URL(url)
  const literalFamily = isIP(hostname)
  if (literalFamily === 4 || literalFamily === 6) {
    if (isBlockedAddress(hostname, literalFamily)) {
      throw new Error(`did:web resolution blocked: ${hostname} is a private/internal address`)
    }
    return
  }
  if (hostname === 'localhost') {
    throw new Error(`did:web resolution blocked: ${hostname} is a private/internal address`)
  }
  let addresses: { address: string; family: number }[]
  try {
    addresses = await withTimeout(dnsLookup(hostname, { all: true }), DNS_SAFETY_TIMEOUT_MS)
  } catch {
    // DNS failure/timeout here is not a security decision; let the
    // subsequent fetch() surface the real network error as before.
    return
  }
  for (const { address, family } of addresses) {
    if ((family === 4 || family === 6) && isBlockedAddress(address, family)) {
      throw new Error(
        `did:web resolution blocked: ${hostname} resolves to a private/internal address (${address})`,
      )
    }
  }
}

/**
 * Resolve a did:web DID by fetching the DID document over HTTPS.
 * Returns the parsed DID Document object.
 *
 * Throws on network errors, non-200 responses, and invalid JSON.
 */
export async function resolveDIDWeb(didWeb: string): Promise<object> {
  const url = didWebToUrl(didWeb)
  await assertSafeDidWebTarget(url)
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
