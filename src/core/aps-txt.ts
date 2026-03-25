// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * aps.txt — Site-Wide Governance Declaration
 *
 * Like robots.txt but for AI governance. A file at yourdomain.com/aps.txt
 * declares site-wide governance: publisher identity, default terms,
 * revocation endpoint, and MCP upgrade path.
 *
 * Any agent visiting any page on the domain checks aps.txt first.
 * One file governs the entire site.
 *
 * Format: JSON, signed with Ed25519, served at /.well-known/aps.txt or /aps.txt
 */

import { createHash } from 'node:crypto'
import { sign, verify, canonicalize, createDID } from '../index.js'
import type { GovernanceTerms, RevocationPolicy } from './governance-block.js'
import { DEFAULT_REVOCATION_POLICY } from './governance-block.js'

// ═══════════════════════════════════════
// Types
// ═══════════════════════════════════════

export interface ApsTxt {
  /** APS protocol identifier */
  '@context': 'https://aeoess.com/governance/v1'
  '@type': 'ApsTxt'
  /** Domain this declaration covers */
  domain: string
  /** Publisher's DID */
  publisher_did: string
  /** Publisher name (human-readable) */
  publisher_name: string
  /** Default terms for all content on this domain */
  default_terms: GovernanceTerms
  /** Default revocation policy */
  default_revocation_policy: RevocationPolicy
  /** URL for revocation status checks */
  revocation_endpoint?: string
  /** MCP endpoint for full enforcement channel */
  mcp_endpoint?: string
  /** Per-path overrides (e.g. /api/* has different terms than /blog/*) */
  path_overrides?: PathOverride[]
  /** When this declaration was generated */
  generated_at: string
  /** Ed25519 signature */
  signature: string
}

export interface PathOverride {
  /** Glob pattern (e.g. "/api/*", "/blog/*", "/data/**") */
  pattern: string
  /** Terms override for this path */
  terms: GovernanceTerms
  /** Optional revocation policy override */
  revocation_policy?: RevocationPolicy
}

// ═══════════════════════════════════════
// Generate
// ═══════════════════════════════════════

export interface GenerateApsTxtInput {
  domain: string
  publisherName: string
  publicKey: string
  privateKey: string
  defaultTerms: GovernanceTerms
  defaultRevocationPolicy?: RevocationPolicy
  revocationEndpoint?: string
  mcpEndpoint?: string
  pathOverrides?: PathOverride[]
}

export function generateApsTxt(input: GenerateApsTxtInput): ApsTxt {
  const publisherDid = createDID(input.publicKey)
  const now = new Date().toISOString()

  const doc: Omit<ApsTxt, 'signature'> = {
    '@context': 'https://aeoess.com/governance/v1',
    '@type': 'ApsTxt',
    domain: input.domain,
    publisher_did: publisherDid,
    publisher_name: input.publisherName,
    default_terms: input.defaultTerms,
    default_revocation_policy: input.defaultRevocationPolicy || DEFAULT_REVOCATION_POLICY,
    generated_at: now,
    ...(input.revocationEndpoint && { revocation_endpoint: input.revocationEndpoint }),
    ...(input.mcpEndpoint && { mcp_endpoint: input.mcpEndpoint }),
    ...(input.pathOverrides?.length && { path_overrides: input.pathOverrides }),
  }

  const payload = canonicalize(doc)
  const signature = sign(payload, input.privateKey)
  return { ...doc, signature }
}

export function verifyApsTxt(doc: ApsTxt, publicKey: string): { valid: boolean; errors: string[] } {
  const errors: string[] = []
  const { signature, ...rest } = doc
  const payload = canonicalize(rest)
  const sigValid = verify(payload, signature, publicKey)
  if (!sigValid) errors.push('Signature verification failed')

  const expectedDid = createDID(publicKey)
  if (doc.publisher_did !== expectedDid) errors.push(`DID mismatch: expected ${expectedDid}`)

  return { valid: errors.length === 0, errors }
}

/**
 * Resolve terms for a specific path using aps.txt path overrides.
 * Falls back to default_terms if no override matches.
 */
export function resolveTermsForPath(doc: ApsTxt, path: string): GovernanceTerms {
  if (doc.path_overrides) {
    for (const override of doc.path_overrides) {
      if (matchGlob(override.pattern, path)) {
        return { ...doc.default_terms, ...override.terms }
      }
    }
  }
  return doc.default_terms
}

function matchGlob(pattern: string, path: string): boolean {
  // Simple glob: * matches one segment, ** matches multiple segments
  const regex = pattern
    .replace(/\*\*/g, '§DOUBLESTAR§')
    .replace(/\*/g, '[^/]*')
    .replace(/§DOUBLESTAR§/g, '.*')
  return new RegExp(`^${regex}$`).test(path)
}

/**
 * Serialize aps.txt to a JSON string ready to serve as a file.
 */
export function serializeApsTxt(doc: ApsTxt): string {
  return JSON.stringify(doc, null, 2)
}

/**
 * Parse an aps.txt JSON string back to an object.
 */
export function parseApsTxt(content: string): ApsTxt | null {
  try {
    const parsed = JSON.parse(content)
    if (parsed['@type'] !== 'ApsTxt') return null
    return parsed as ApsTxt
  } catch { return null }
}

// ═══════════════════════════════════════
// Governance HTTP Headers
// ═══════════════════════════════════════

import type { GovernanceBlock } from './governance-block.js'

/**
 * Generate HTTP response headers for governance.
 * Works for ANY response type — HTML, JSON, images, PDFs.
 */
export function governanceHeaders(block: GovernanceBlock): Record<string, string> {
  const compact = JSON.stringify(block)
  const b64 = Buffer.from(compact).toString('base64')
  return {
    'X-APS-Governance': b64,
    'X-APS-DID': block.source_did,
    'X-APS-Content-Hash': block.content_hash,
    'X-APS-Terms-Training': block.terms.training || 'not_specified',
    'X-APS-Terms-Inference': block.terms.inference || 'not_specified',
  }
}

/**
 * Parse governance from HTTP response headers.
 */
export function parseGovernanceHeaders(headers: Record<string, string>): GovernanceBlock | null {
  const b64 = headers['x-aps-governance'] || headers['X-APS-Governance']
  if (!b64) return null
  try {
    return JSON.parse(Buffer.from(b64, 'base64').toString('utf-8')) as GovernanceBlock
  } catch { return null }
}

// ═══════════════════════════════════════
// Chained Governance Blocks
// ═══════════════════════════════════════

export interface ChainedGovernanceBlock extends GovernanceBlock {
  /** Reference to the parent governance block this is derived from */
  parent_block_hash: string
  /** What type of derivation (summary, embedding, rag_chunk, etc.) */
  derivation_type: string
  /** The derivative agent's DID (different from original publisher) */
  derivative_agent_did: string
}

/**
 * Create a chained governance block for derivative content.
 * The derivative carries its own governance AND the chain back to the source.
 */
export function createChainedGovernanceBlock(input: {
  /** The derivative content */
  content: string
  /** The derivative agent's keys */
  publicKey: string
  privateKey: string
  /** Terms the derivative is published under */
  terms: GovernanceTerms
  /** The original governance block this derives from */
  parentBlock: GovernanceBlock
  /** Type of derivation */
  derivationType: string
  revocationPolicy?: RevocationPolicy
}): ChainedGovernanceBlock {
  const contentHash = `sha256:${createHash('sha256').update(input.content).digest('hex')}`
  const derivativeDid = createDID(input.publicKey)
  const parentBlockHash = `sha256:${createHash('sha256').update(canonicalize(input.parentBlock)).digest('hex')}`
  const now = new Date().toISOString()

  const block: Omit<ChainedGovernanceBlock, 'signature'> = {
    '@context': 'https://aeoess.com/governance/v1',
    '@type': 'GovernanceBlock',
    source_did: input.parentBlock.source_did,
    content_hash: contentHash,
    published_at: now,
    governance_generated_at: now,
    terms: input.terms,
    revocation_policy: input.revocationPolicy || input.parentBlock.revocation_policy,
    parent_block_hash: parentBlockHash,
    derivation_type: input.derivationType,
    derivative_agent_did: derivativeDid,
  }

  const payload = canonicalize(block)
  const signature = sign(payload, input.privateKey)
  return { ...block, signature }
}

/**
 * Verify a chained governance block, including parent hash consistency.
 */
export function verifyChainedBlock(
  chain: ChainedGovernanceBlock,
  content: string,
  derivativePublicKey: string,
  parentBlock?: GovernanceBlock,
): { valid: boolean; chainValid: boolean; errors: string[] } {
  const errors: string[] = []

  // Verify derivative signature
  const { signature, ...rest } = chain
  const payload = canonicalize(rest)
  const sigValid = verify(payload, signature, derivativePublicKey)
  if (!sigValid) errors.push('Derivative signature verification failed')

  // Verify content hash
  const expectedHash = `sha256:${createHash('sha256').update(content).digest('hex')}`
  if (chain.content_hash !== expectedHash) errors.push('Content hash mismatch')

  // Verify parent chain if parent provided
  let chainValid = true
  if (parentBlock) {
    const expectedParentHash = `sha256:${createHash('sha256').update(canonicalize(parentBlock)).digest('hex')}`
    if (chain.parent_block_hash !== expectedParentHash) {
      errors.push('Parent block hash mismatch — chain broken')
      chainValid = false
    }
  }

  return { valid: sigValid && errors.length === 0, chainValid, errors }
}
