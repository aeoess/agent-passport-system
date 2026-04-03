// Agent Passport System — Identity Bridge
// Import external identity credentials (SPIFFE SVID, OAuth tokens)
// into APS attestations and delegation parameters.

import crypto from 'node:crypto'
import type { ProviderAttestation } from '../types/attestation.js'

// ── SPIFFE SVID Import ──

export interface SPIFFESVIDInput {
  /** SPIFFE ID (spiffe://trust-domain/workload-path) */
  spiffeId: string
  /** Optional X.509 certificate (PEM or base64 DER) */
  x509Cert?: string
  /** Expiration timestamp (ISO 8601) */
  expiresAt: string
}

export interface ParsedSPIFFEID {
  trustDomain: string
  workloadPath: string
}

/**
 * Parse a SPIFFE ID into trust domain and workload path.
 * Format: spiffe://trust-domain/workload/path/segments
 */
export function parseSPIFFEID(spiffeId: string): ParsedSPIFFEID {
  if (!spiffeId || !spiffeId.startsWith('spiffe://')) {
    throw new Error(`Invalid SPIFFE ID: must start with spiffe:// — got: ${spiffeId}`)
  }
  const withoutScheme = spiffeId.slice('spiffe://'.length)
  const slashIndex = withoutScheme.indexOf('/')
  if (slashIndex === -1 || slashIndex === 0) {
    throw new Error(`Invalid SPIFFE ID: missing trust domain or workload path — got: ${spiffeId}`)
  }
  const trustDomain = withoutScheme.slice(0, slashIndex)
  const workloadPath = withoutScheme.slice(slashIndex)
  if (!workloadPath || workloadPath === '/') {
    throw new Error(`Invalid SPIFFE ID: workload path must not be empty — got: ${spiffeId}`)
  }
  return { trustDomain, workloadPath }
}

/**
 * Import a SPIFFE SVID into an APS ProviderAttestation.
 *
 * SPIFFE SVIDs are infrastructure-level identity (Tier 1 in APS attestation model).
 * An agent presenting a valid SVID qualifies for Grade 2 (runtime_bound) because
 * the SVID proves the workload identity was attested by the trust domain's CA.
 *
 * The attestation uses:
 * - provider: trust domain (e.g., "cluster.example.com")
 * - subjectClass: "workload"
 * - subjectIdHash: SHA-256 of the full SPIFFE ID
 * - verificationMethod: "x509" if cert provided, "spiffe_bundle" otherwise
 */
export function importSPIFFESVID(svid: SPIFFESVIDInput): ProviderAttestation {
  const { trustDomain, workloadPath } = parseSPIFFEID(svid.spiffeId)

  if (!svid.expiresAt) {
    throw new Error('SVID expiresAt is required')
  }

  const subjectIdHash = crypto
    .createHash('sha256')
    .update(svid.spiffeId)
    .digest('hex')

  return {
    provider: trustDomain,
    subjectClass: 'workload',
    subjectIdHash,
    verificationMethod: svid.x509Cert ? 'x509' : 'spiffe_bundle',
    issuedAt: new Date().toISOString(),
    expiresAt: svid.expiresAt,
  }
}

// ── OAuth Scope Mapper ──

/** Default OAuth → APS scope mapping */
const DEFAULT_SCOPE_MAP: Record<string, string> = {
  'read:*': 'data_read',
  'write:*': 'data_write',
  'admin:*': 'governance',
  'pay:*': 'commerce',
}

/**
 * Convert OAuth scopes to APS delegation scopes.
 *
 * Matching rules:
 * 1. Exact match checked first (e.g., "read:users" against mapping key "read:users")
 * 2. Wildcard match: "read:users" matches "read:*" pattern
 * 3. Unmatched scopes are passed through as-is (preserves information)
 *
 * Custom mapping overrides defaults for overlapping keys.
 */
export function mapOAuthScopes(
  oauthScopes: string[],
  scopeMapping?: Record<string, string>,
): string[] {
  const mapping = { ...DEFAULT_SCOPE_MAP, ...scopeMapping }
  const result: string[] = []
  const seen = new Set<string>()

  for (const scope of oauthScopes) {
    let mapped: string | undefined

    // Exact match first
    if (mapping[scope]) {
      mapped = mapping[scope]
    } else {
      // Wildcard match: "read:users" matches "read:*"
      const prefix = scope.split(':')[0]
      const wildcardKey = `${prefix}:*`
      if (mapping[wildcardKey]) {
        mapped = mapping[wildcardKey]
      }
    }

    const value = mapped || scope
    if (!seen.has(value)) {
      seen.add(value)
      result.push(value)
    }
  }

  return result
}

// ── OAuth Token Import ──

export interface OAuthTokenInput {
  /** Subject identifier (user or client ID) */
  sub: string
  /** Space-separated scope string */
  scope: string
  /** Issuer URL */
  iss: string
  /** Expiration (Unix timestamp, seconds) */
  exp: number
}

export interface OAuthImportResult {
  /** APS agent ID derived from OAuth subject + issuer */
  agentId: string
  /** Delegation scope ceiling derived from OAuth scopes */
  delegationScope: string[]
  /** Expiration as ISO 8601 */
  expiresAt: string
}

/**
 * Convert an OAuth token's claims into APS delegation parameters.
 *
 * The OAuth scope becomes the delegation ceiling: the agent can never
 * exceed the authority granted by the OAuth token. This preserves
 * monotonic narrowing — the OAuth grant is the root of the delegation chain.
 *
 * Agent ID is deterministic: sha256(iss + sub) truncated, so the same
 * OAuth subject always maps to the same APS agent.
 */
export function importOAuthToken(
  token: OAuthTokenInput,
  scopeMapping?: Record<string, string>,
): OAuthImportResult {
  if (!token.sub) throw new Error('OAuth token must have a sub claim')
  if (!token.iss) throw new Error('OAuth token must have an iss claim')
  if (!token.exp || token.exp <= 0) throw new Error('OAuth token must have a valid exp claim')

  const scopes = token.scope ? token.scope.split(' ').filter(Boolean) : []
  const delegationScope = mapOAuthScopes(scopes, scopeMapping)

  const idHash = crypto
    .createHash('sha256')
    .update(`${token.iss}:${token.sub}`)
    .digest('hex')
    .slice(0, 16)

  const agentId = `agent-oauth-${idHash}`
  const expiresAt = new Date(token.exp * 1000).toISOString()

  return { agentId, delegationScope, expiresAt }
}
