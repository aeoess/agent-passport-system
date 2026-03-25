// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Governance Block — Cryptographic governance metadata for HTML embedding.
 *
 * Embeds signed provenance, terms, and revocation primitives directly into
 * web pages so ANY crawler (not just MCP clients) ingests governance metadata
 * alongside content.
 *
 * Two channels, same primitives:
 *   HTML: governance block embedded in page — evidence layer (proof terms were served)
 *   MCP:  full enforcement — terms must be accepted before content is served
 *
 * Compatible with: C2PA (provenance), RSL (licensing), W3C JSON-LD Signatures
 * Novel contribution: revocation propagation + per-artifact-type obligations
 */

import { createHash } from 'node:crypto'
import { sign, verify, canonicalize, createDID } from '../index.js'

// ═══════════════════════════════════════
// Types
// ═══════════════════════════════════════

export type UsagePermission = 'permitted' | 'prohibited' | 'compensation_required' | 'attribution_required'

export interface GovernanceTerms {
  /** Can agents use this for real-time inference/RAG? */
  inference?: UsagePermission
  /** Can agents use this to train/fine-tune models? */
  training?: UsagePermission
  /** Can agents redistribute or republish this content? */
  redistribution?: UsagePermission
  /** Can agents create derivative works? */
  derivative?: UsagePermission
  /** Can agents cache this content locally? */
  caching?: UsagePermission
  /** Custom terms (key-value) */
  custom?: Record<string, UsagePermission>
  /** Human-readable license reference */
  license_url?: string
  /** Terms version (for settlement pinning) */
  version?: string
}

export interface RevocationPolicy {
  /** What happens to cached copies when this content is revoked? */
  cached_copy: 'delete' | 'retain_with_notice' | 'no_obligation'
  /** What happens to RAG chunks derived from this content? */
  rag_chunk: 'delete' | 'quarantine' | 'no_obligation'
  /** What happens to embeddings derived from this content? */
  embedding: 'quarantine' | 'flag_for_review' | 'no_obligation'
  /** What happens to models fine-tuned on this content? */
  fine_tune: 'no_future_use' | 'retraining_required' | 'no_obligation'
  /** What happens to synthetic derivatives? */
  synthetic: 'compensation_only' | 'delete' | 'no_obligation'
}

export interface GovernanceBlock {
  /** APS protocol identifier */
  '@context': 'https://aeoess.com/governance/v1'
  '@type': 'GovernanceBlock'
  /** DID of the content publisher */
  source_did: string
  /** SHA-256 hash of the content body */
  content_hash: string
  /** When the content was published */
  published_at: string
  /** When the governance block was generated */
  governance_generated_at: string
  /** Machine-readable licensing terms */
  terms: GovernanceTerms
  /** What happens when content is revoked */
  revocation_policy: RevocationPolicy
  /** Ed25519 signature over canonical(everything except signature) */
  signature: string
}

// ═══════════════════════════════════════
// Default revocation policy
// ═══════════════════════════════════════

export const DEFAULT_REVOCATION_POLICY: RevocationPolicy = {
  cached_copy: 'delete',
  rag_chunk: 'delete',
  embedding: 'quarantine',
  fine_tune: 'no_future_use',
  synthetic: 'compensation_only',
}

// ═══════════════════════════════════════
// Generate
// ═══════════════════════════════════════

export interface GenerateGovernanceBlockInput {
  /** Content body to hash (the article text, not the full HTML) */
  content: string
  /** Publisher's public key (hex) */
  publicKey: string
  /** Publisher's private key (hex) for signing */
  privateKey: string
  /** Licensing terms */
  terms: GovernanceTerms
  /** Revocation policy (defaults to strict) */
  revocationPolicy?: RevocationPolicy
  /** Publication timestamp (defaults to now) */
  publishedAt?: string
}

export function generateGovernanceBlock(input: GenerateGovernanceBlockInput): GovernanceBlock {
  const contentHash = createHash('sha256').update(input.content).digest('hex')
  const sourceDid = createDID(input.publicKey)
  const now = new Date().toISOString()

  const block: Omit<GovernanceBlock, 'signature'> = {
    '@context': 'https://aeoess.com/governance/v1',
    '@type': 'GovernanceBlock',
    source_did: sourceDid,
    content_hash: `sha256:${contentHash}`,
    published_at: input.publishedAt || now,
    governance_generated_at: now,
    terms: input.terms,
    revocation_policy: input.revocationPolicy || DEFAULT_REVOCATION_POLICY,
  }

  const payload = canonicalize(block)
  const signature = sign(payload, input.privateKey)

  return { ...block, signature }
}

// ═══════════════════════════════════════
// Verify
// ═══════════════════════════════════════

export interface GovernanceBlockVerification {
  /** Is the Ed25519 signature valid? */
  signatureValid: boolean
  /** Does the content hash match the provided content? */
  contentHashValid: boolean
  /** Does the DID resolve to the signing key? */
  didConsistent: boolean
  /** Overall: all checks pass */
  valid: boolean
  /** Human-readable errors */
  errors: string[]
}

export function verifyGovernanceBlock(
  block: GovernanceBlock,
  content: string,
  publicKey: string,
): GovernanceBlockVerification {
  const errors: string[] = []

  // 1. Verify signature
  const { signature, ...rest } = block
  const payload = canonicalize(rest)
  const signatureValid = verify(payload, signature, publicKey)
  if (!signatureValid) errors.push('Signature verification failed')

  // 2. Verify content hash
  const expectedHash = `sha256:${createHash('sha256').update(content).digest('hex')}`
  const contentHashValid = block.content_hash === expectedHash
  if (!contentHashValid) errors.push(`Content hash mismatch: expected ${expectedHash}, got ${block.content_hash}`)

  // 3. Verify DID consistency
  const expectedDid = createDID(publicKey)
  const didConsistent = block.source_did === expectedDid
  if (!didConsistent) errors.push(`DID mismatch: expected ${expectedDid}, got ${block.source_did}`)

  return {
    signatureValid,
    contentHashValid,
    didConsistent,
    valid: signatureValid && contentHashValid && didConsistent,
    errors,
  }
}

// ═══════════════════════════════════════
// HTML rendering
// ═══════════════════════════════════════

/**
 * Render a governance block as an HTML script tag for embedding in any web page.
 *
 * Usage: Insert the returned string anywhere in your HTML <head> or <body>.
 * Every crawler that reads the page ingests this block alongside the content.
 *
 * Example output:
 * <script type="application/aps-governance+json">{"@context":"https://aeoess.com/governance/v1",...}</script>
 */
export function renderGovernanceHTML(block: GovernanceBlock): string {
  const json = JSON.stringify(block, null, 2)
  return `<script type="application/aps-governance+json">\n${json}\n</script>`
}

/**
 * Render as a meta tag alternative (for strict CSP environments).
 * The full block is base64-encoded in the content attribute.
 */
export function renderGovernanceMeta(block: GovernanceBlock): string {
  const b64 = Buffer.from(JSON.stringify(block)).toString('base64')
  return `<meta name="aps-governance" content="${b64}" />`
}

/**
 * Parse a governance block from HTML content.
 * Looks for <script type="application/aps-governance+json"> or
 * <meta name="aps-governance" content="..."> tags.
 */
export function parseGovernanceBlockFromHTML(html: string): GovernanceBlock | null {
  // Try script tag first
  const scriptMatch = html.match(
    /<script\s+type\s*=\s*"application\/aps-governance\+json"\s*>([\s\S]*?)<\/script>/i
  )
  if (scriptMatch) {
    try { return JSON.parse(scriptMatch[1].trim()) as GovernanceBlock } catch { return null }
  }

  // Try meta tag
  const metaMatch = html.match(
    /<meta\s+name\s*=\s*"aps-governance"\s+content\s*=\s*"([^"]+)"\s*\/?>/i
  )
  if (metaMatch) {
    try {
      const decoded = Buffer.from(metaMatch[1], 'base64').toString('utf-8')
      return JSON.parse(decoded) as GovernanceBlock
    } catch { return null }
  }

  return null
}

/**
 * Convenience: generate + render in one call.
 * Returns both the block (for storage/MCP) and the HTML tag (for embedding).
 */
export function embedGovernance(input: GenerateGovernanceBlockInput): {
  block: GovernanceBlock
  html: string
  meta: string
} {
  const block = generateGovernanceBlock(input)
  return {
    block,
    html: renderGovernanceHTML(block),
    meta: renderGovernanceMeta(block),
  }
}

/**
 * Check if a specific usage is permitted under the governance block's terms.
 */
export function isUsagePermitted(
  block: GovernanceBlock,
  usage: keyof Omit<GovernanceTerms, 'custom' | 'license_url' | 'version'>,
): { permitted: boolean; condition: UsagePermission | 'not_specified' } {
  const permission = block.terms[usage]
  if (!permission) return { permitted: true, condition: 'not_specified' }
  return {
    permitted: permission === 'permitted' || permission === 'attribution_required',
    condition: permission,
  }
}
