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
  /** Optional DID pattern for agent-specific terms (e.g. "did:meeet:*", "did:aps:*", "did:*")
   *  Source: alxvasilevvv on openclaw#49971 — 1,020 MEEET agents need method-level matching */
  user_agent?: string
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

export interface VerifyApsTxtOptions {
  /** When true, unsigned or unverifiable aps.txt returns { valid: false, reason: 'UNSIGNED' } */
  strict?: boolean
}

export interface VerifyApsTxtResult {
  valid: boolean
  errors: string[]
  /** Set when strict mode rejects an unsigned/unverifiable document */
  reason?: 'UNSIGNED'
}

export function verifyApsTxt(
  doc: ApsTxt,
  publicKey?: string,
  options?: VerifyApsTxtOptions,
): VerifyApsTxtResult {
  const strict = options?.strict ?? false

  // Strict mode: if no public key provided, reject as unsigned
  if (!publicKey) {
    if (strict) {
      return { valid: false, errors: ['No public key provided for signature verification'], reason: 'UNSIGNED' }
    }
    return { valid: true, errors: [] }
  }

  const errors: string[] = []
  const { signature, ...rest } = doc
  const payload = canonicalize(rest)
  const sigValid = verify(payload, signature, publicKey)
  if (!sigValid) {
    if (strict) {
      return { valid: false, errors: ['Signature verification failed'], reason: 'UNSIGNED' }
    }
    errors.push('Signature verification failed')
  }

  const expectedDid = createDID(publicKey)
  if (doc.publisher_did !== expectedDid) errors.push(`DID mismatch: expected ${expectedDid}`)

  return { valid: errors.length === 0, errors }
}

/**
 * Resolve terms for a specific path using aps.txt path overrides.
 * Falls back to default_terms if no override matches.
 */
export function resolveTermsForPath(doc: ApsTxt, path: string, agentDid?: string): GovernanceTerms {
  if (doc.path_overrides) {
    for (const override of doc.path_overrides) {
      const pathMatch = matchGlob(override.pattern, path)
      // If override has a user_agent pattern, both path AND agent must match
      if (override.user_agent) {
        if (pathMatch && agentDid && matchDidPattern(override.user_agent, agentDid)) {
          return { ...doc.default_terms, ...override.terms }
        }
      } else if (pathMatch) {
        return { ...doc.default_terms, ...override.terms }
      }
    }
  }
  return doc.default_terms
}

function matchGlob(pattern: string, path: string): boolean {
  // Iterative glob match — no regex, no ReDoS risk.
  // * matches one path segment, ** matches zero or more segments.
  const patParts = pattern.split('/')
  const pathParts = path.split('/')
  return globPartsMatch(patParts, 0, pathParts, 0)
}

function globPartsMatch(pat: string[], pi: number, path: string[], xi: number): boolean {
  while (pi < pat.length && xi < path.length) {
    if (pat[pi] === '**') {
      // ** matches zero or more segments — try each possible skip
      // Bounded: at most path.length - xi iterations (linear, not exponential)
      for (let skip = 0; skip <= path.length - xi; skip++) {
        if (globPartsMatch(pat, pi + 1, path, xi + skip)) return true
      }
      return false
    }
    if (pat[pi] === '*') {
      // * matches exactly one segment (any content)
      pi++; xi++; continue
    }
    if (pat[pi] !== path[xi]) return false
    pi++; xi++
  }
  // Consume trailing ** patterns (they can match zero segments)
  while (pi < pat.length && pat[pi] === '**') pi++
  return pi === pat.length && xi === path.length
}

/** Match a DID pattern against an agent's DID.
 *  `did:meeet:*` matches `did:meeet:agent_abc`
 *  `did:*` matches any DID
 *  `did:aps:agent_123` matches exact DID
 *  Source: alxvasilevvv on openclaw#49971
 */
function matchDidPattern(pattern: string, did: string): boolean {
  if (pattern === '*' || pattern === 'did:*') return true
  // Simple wildcard match without regex — split on * and check segments
  const parts = pattern.split('*')
  if (parts.length === 1) return pattern === did  // no wildcard, exact match
  // Check: did starts with first part and ends with last part,
  // with all intermediate parts appearing in order
  let pos = 0
  for (let i = 0; i < parts.length; i++) {
    const part = parts[i]
    if (i === 0) {
      if (!did.startsWith(part)) return false
      pos = part.length
    } else if (i === parts.length - 1) {
      if (!did.slice(pos).endsWith(part)) return false
    } else {
      const idx = did.indexOf(part, pos)
      if (idx === -1) return false
      pos = idx + part.length
    }
  }
  return true
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
    ...(input.parentBlock.expires_at ? { expires_at: input.parentBlock.expires_at } : {}),
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


// ══════════════════════════════════════════════════════════════════
// Security Fixes — MoltyCel AV-2, AV-4, AV-5 (qntm#7)
// ══════════════════════════════════════════════════════════════════

/**
 * AV-2 Fix: Strict aps.txt enforcement.
 * Verifies signature before resolving path terms.
 * unsigned aps.txt → warning or block depending on mode.
 *
 * Source: MoltyCel on qntm#7 — unsigned aps.txt can be replaced
 * by a compromised repo. DID-signed aps.txt prevents this.
 */
export type ApsTxtEnforcementMode = 'permissive' | 'warn' | 'strict'

export interface ApsTxtEnforcementResult {
  /** Whether the agent should proceed */
  allowed: boolean
  /** Resolved governance terms for the requested path */
  terms: GovernanceTerms | null
  /** Warning if aps.txt is unsigned or unverifiable */
  warning?: string
  /** Error if strict mode blocks access */
  error?: string
  /** Whether the aps.txt signature was verified */
  signatureVerified: boolean
}

export function enforceApsTxt(
  doc: ApsTxt,
  path: string,
  opts: {
    /** Publisher's public key for signature verification */
    publisherPublicKey?: string
    /** Enforcement mode: permissive (allow unsigned), warn (allow with warning), strict (block unsigned) */
    mode?: ApsTxtEnforcementMode
    /** Trust threshold (0-1). Below this, restrictive aps.txt produces warning instead of block (AV-4 DoS fix) */
    trustThreshold?: number
    /** Publisher's trust score (0-1). If below trustThreshold, warn instead of block */
    publisherTrustScore?: number
  } = {}
): ApsTxtEnforcementResult {
  const mode = opts.mode ?? 'warn'
  const trustThreshold = opts.trustThreshold ?? 0.3
  const publisherTrust = opts.publisherTrustScore ?? 0

  // Step 1: Verify signature if public key provided
  let signatureVerified = false
  if (opts.publisherPublicKey) {
    const verification = verifyApsTxt(doc, opts.publisherPublicKey)
    signatureVerified = verification.valid
  }

  // Step 2: Check enforcement mode for unsigned aps.txt
  if (!signatureVerified) {
    if (mode === 'strict') {
      return {
        allowed: false,
        terms: null,
        error: 'aps.txt signature verification failed (strict mode)',
        signatureVerified: false,
      }
    }
    if (mode === 'warn') {
      // Continue but with warning
    }
  }

  // Step 3: Resolve terms for the path
  const terms = resolveTermsForPath(doc, path)

  // Step 4: AV-4 DoS protection — restrictive aps.txt from unknown publishers
  // If publisher trust is below threshold and aps.txt blocks all agents,
  // produce warning instead of block
  if (isAllDenied(terms) || isFullBlock(doc, path)) {
    if (publisherTrust < trustThreshold && !signatureVerified) {
      return {
        allowed: true,
        terms,
        warning: `Low-trust publisher (${publisherTrust}) with restrictive aps.txt — proceeding with caution (AV-4 protection)`,
        signatureVerified,
      }
    }
  }

  return {
    allowed: true,
    terms,
    warning: signatureVerified ? undefined : 'aps.txt signature not verified — proceeding in permissive mode',
    signatureVerified,
  }
}

// ══════════════════════════════════════════════════════════════════
// AV-4 Fix: aps.txt DoS Risk Evaluation
// Source: MoltyCel on qntm#7 — malicious `Disallow: /` for `did:*`
// blocks all DID-verified agents. Risk evaluation helps agents
// decide whether to trust restrictive aps.txt declarations.
// ══════════════════════════════════════════════════════════════════

export type ApsTxtRiskLevel = 'low' | 'medium' | 'high'

export interface ApsTxtRiskResult {
  risk: ApsTxtRiskLevel
  warnings: string[]
}

/**
 * Evaluate the risk level of an aps.txt document.
 * Flags suspicious patterns that may indicate DoS or manipulation.
 *
 * - Blanket block (all usage prohibited for wildcard agents) → high risk
 * - Unsigned restrictive rules → medium risk
 * - Unknown author with restrictive rules → medium risk
 * - Signed, non-restrictive → low risk
 */
export function evaluateApsTxtRisk(
  doc: ApsTxt,
  opts?: {
    /** Publisher's public key for signature verification */
    publisherPublicKey?: string
  },
): ApsTxtRiskResult {
  const warnings: string[] = []
  let risk: ApsTxtRiskLevel = 'low'

  // Check signature status
  let signed = false
  if (opts?.publisherPublicKey) {
    const verification = verifyApsTxt(doc, opts.publisherPublicKey)
    signed = verification.valid
  }

  // Check for blanket block on default terms
  const defaultAllDenied = isAllDenied(doc.default_terms)
  if (defaultAllDenied) {
    risk = 'high'
    warnings.push('blanket_block')
  }

  // Check path overrides for wildcard agent blocks
  if (doc.path_overrides) {
    for (const override of doc.path_overrides) {
      const isWildcard = override.user_agent === '*' || override.user_agent === 'did:*'
      const isFullPath = override.pattern === '/*' || override.pattern === '/**' || override.pattern === '/'
      if (isWildcard && isFullPath && isAllDenied(override.terms)) {
        risk = 'high'
        warnings.push('blanket_block')
        break
      }
    }
  }

  // Unsigned restrictive rules
  if (!signed && (defaultAllDenied || hasRestrictiveOverrides(doc))) {
    if (risk !== 'high') risk = 'medium'
    warnings.push('unsigned_restrictive')
  }

  // Unknown author (no publisher name or generic) with restrictive rules
  if ((!doc.publisher_name || doc.publisher_name.trim() === '') && hasAnyRestriction(doc)) {
    if (risk !== 'high') risk = 'medium'
    warnings.push('new_author_restrictive')
  }

  return { risk, warnings: [...new Set(warnings)] }
}

/** Check if any path override has restrictive terms */
function hasRestrictiveOverrides(doc: ApsTxt): boolean {
  if (!doc.path_overrides) return false
  return doc.path_overrides.some(o => isAllDenied(o.terms))
}

/** Check if any terms have at least one prohibited field */
function hasAnyRestriction(doc: ApsTxt): boolean {
  const fields = ['inference', 'training', 'redistribution', 'derivative', 'caching'] as const
  if (fields.some(f => doc.default_terms[f] === 'prohibited')) return true
  if (doc.path_overrides) {
    return doc.path_overrides.some(o => fields.some(f => o.terms[f] === 'prohibited'))
  }
  return false
}

/** Check if governance terms deny all usage types */
function isAllDenied(terms: GovernanceTerms): boolean {
  const fields = ['inference', 'training', 'redistribution', 'derivative', 'caching'] as const
  return fields.every(f => terms[f] === 'prohibited')
}

/** Check if aps.txt effectively blocks all agents for a path */
function isFullBlock(doc: ApsTxt, path: string): boolean {
  if (!doc.path_overrides) return false
  for (const override of doc.path_overrides) {
    if (override.pattern === '/*' || override.pattern === '/**') {
      if (isAllDenied(override.terms)) return true
    }
  }
  return false
}
