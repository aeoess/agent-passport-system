// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Governance Consumer — Agent-side primitives for reading governed content.
 *
 * Completes the 360 loop:
 *   Publisher: embedGovernance() → HTML with signed block
 *   Agent:     fetchGovernedContent() → verify → check terms → create access receipt
 *
 * The access receipt is cryptographic proof that the agent accessed
 * this content under these terms at this time. This is the evidence
 * trail for compliance monitoring and settlement.
 */

import { createHash } from 'node:crypto'
import { sign, verify, canonicalize, createDID } from '../index.js'
import { parseGovernanceBlockFromHTML, verifyGovernanceBlock, isUsagePermitted } from './governance-block.js'
import type { GovernanceBlock, UsagePermission } from './governance-block.js'
import { parseApsTxt, resolveTermsForPath } from './aps-txt.js'
import { parseGovernanceHeaders } from './aps-txt.js'
import type { ApsTxt } from './aps-txt.js'

// ═══════════════════════════════════════
// Access Receipt — proof agent consumed content under terms
// ═══════════════════════════════════════

export interface AccessReceipt {
  receiptId: string
  /** Agent's DID */
  agent_did: string
  /** Publisher's DID (from governance block) */
  publisher_did: string
  /** Content hash (from governance block) */
  content_hash: string
  /** URL where content was accessed */
  source_url: string
  /** The terms that were in effect at access time */
  terms_at_access: GovernanceBlock['terms']
  /** The revocation policy in effect */
  revocation_policy_at_access: GovernanceBlock['revocation_policy']
  /** How the agent intends to use this content */
  intended_usage: string
  /** Whether the governance block was valid at access time */
  governance_verified: boolean
  /** Timestamp */
  accessed_at: string
  /** Ed25519 signature by the consuming agent */
  signature: string
}

export interface GovernanceCheckResult {
  /** Was a governance block found? */
  found: boolean
  /** Source: 'html_script' | 'html_meta' | 'http_header' | 'aps_txt' | 'none' */
  source: string
  /** The governance block (if found) */
  block: GovernanceBlock | null
  /** Verification result */
  verified: boolean
  /** Terms for the requested usage */
  usageCheck: { permitted: boolean; condition: UsagePermission | 'not_specified' } | null
  /** Errors */
  errors: string[]
}

/**
 * Check governance for HTML content — extracts block from HTML,
 * verifies signature and content hash, checks usage permission.
 */
export function checkHTMLGovernance(
  html: string,
  contentBody: string,
  publisherPublicKey: string,
  intendedUsage: 'inference' | 'training' | 'redistribution' | 'derivative' | 'caching',
): GovernanceCheckResult {
  const block = parseGovernanceBlockFromHTML(html)

  if (!block) {
    return { found: false, source: 'none', block: null, verified: false, usageCheck: null, errors: ['No governance block found in HTML'] }
  }

  const source = html.includes('application/aps-governance+json') ? 'html_script' : 'html_meta'
  const verification = verifyGovernanceBlock(block, contentBody, publisherPublicKey)
  const usageCheck = isUsagePermitted(block, intendedUsage)

  return {
    found: true,
    source,
    block,
    verified: verification.valid,
    usageCheck,
    errors: verification.errors,
  }
}

/**
 * Check governance from HTTP response headers.
 */
export function checkHeaderGovernance(
  headers: Record<string, string>,
  contentBody: string,
  publisherPublicKey: string,
  intendedUsage: 'inference' | 'training' | 'redistribution' | 'derivative' | 'caching',
): GovernanceCheckResult {
  const block = parseGovernanceHeaders(headers)

  if (!block) {
    return { found: false, source: 'none', block: null, verified: false, usageCheck: null, errors: ['No X-APS-Governance header found'] }
  }

  const verification = verifyGovernanceBlock(block, contentBody, publisherPublicKey)
  const usageCheck = isUsagePermitted(block, intendedUsage)

  return { found: true, source: 'http_header', block, verified: verification.valid, usageCheck, errors: verification.errors }
}

// ═══════════════════════════════════════
// Access Receipt — create proof of consumption
// ═══════════════════════════════════════

export function createAccessReceipt(input: {
  /** Agent's keys */
  agentPublicKey: string
  agentPrivateKey: string
  /** Governance block from the content */
  block: GovernanceBlock
  /** URL where content was accessed */
  sourceUrl: string
  /** How the agent intends to use this */
  intendedUsage: string
  /** Was the governance block valid? */
  governanceVerified: boolean
}): AccessReceipt {
  const agentDid = createDID(input.agentPublicKey)

  const receiptId = `gar_${createHash('sha256').update(`${agentDid}:${input.block.content_hash}:${Date.now()}`).digest('hex').slice(0, 24)}`
  const now = new Date().toISOString()

  const receipt: Omit<AccessReceipt, 'signature'> = {
    receiptId,
    agent_did: agentDid,
    publisher_did: input.block.source_did,
    content_hash: input.block.content_hash,
    source_url: input.sourceUrl,
    terms_at_access: input.block.terms,
    revocation_policy_at_access: input.block.revocation_policy,
    intended_usage: input.intendedUsage,
    governance_verified: input.governanceVerified,
    accessed_at: now,
  }

  const payload = canonicalize(receipt)
  const signature = sign(payload, input.agentPrivateKey)
  return { ...receipt, signature }
}

export function verifyAccessReceipt(receipt: AccessReceipt, agentPublicKey: string): boolean {
  const { signature, ...rest } = receipt
  const payload = canonicalize(rest)
  return verify(payload, signature, agentPublicKey)
}

// ═══════════════════════════════════════
// Full 360 Flow — the complete loop
// ═══════════════════════════════════════

export interface Full360Result {
  /** Governance check result */
  governance: GovernanceCheckResult
  /** Access receipt (if governance found and agent keys provided) */
  receipt: AccessReceipt | null
  /** Is the intended usage permitted? */
  permitted: boolean
  /** Human-readable summary */
  summary: string
}

/**
 * Execute the full 360 governance loop:
 *
 * 1. Extract governance block from HTML (script tag, meta tag, or headers)
 * 2. Verify signature + content hash + DID consistency
 * 3. Check if intended usage is permitted
 * 4. Create signed access receipt (proof of consumption under terms)
 *
 * This is the function an agent calls on every page it reads.
 */
export function governanceLoop360(input: {
  /** Full HTML of the page */
  html: string
  /** Article content body (text only, for hash verification) */
  contentBody: string
  /** Publisher's public key (for verification) */
  publisherPublicKey: string
  /** Agent's keys (for receipt signing) */
  agentPublicKey: string
  agentPrivateKey: string
  /** How the agent intends to use this content */
  intendedUsage: 'inference' | 'training' | 'redistribution' | 'derivative' | 'caching'
  /** URL of the page */
  sourceUrl: string
  /** Optional HTTP response headers */
  responseHeaders?: Record<string, string>
}): Full360Result {

  // Step 1+2: Try HTML first, then headers
  let governance = checkHTMLGovernance(input.html, input.contentBody, input.publisherPublicKey, input.intendedUsage)

  if (!governance.found && input.responseHeaders) {
    governance = checkHeaderGovernance(input.responseHeaders, input.contentBody, input.publisherPublicKey, input.intendedUsage)
  }

  // No governance found — ungoverned content
  if (!governance.found || !governance.block) {
    return {
      governance,
      receipt: null,
      permitted: true, // ungoverned = no restrictions
      summary: `No governance block found at ${input.sourceUrl}. Content is ungoverned.`,
    }
  }

  // Step 3: Check usage
  const permitted = governance.usageCheck?.permitted ?? true

  // Step 4: Create access receipt
  const receipt = createAccessReceipt({
    agentPublicKey: input.agentPublicKey,
    agentPrivateKey: input.agentPrivateKey,
    block: governance.block,
    sourceUrl: input.sourceUrl,
    intendedUsage: input.intendedUsage,
    governanceVerified: governance.verified,
  })

  const condition = governance.usageCheck?.condition || 'not_specified'
  const summary = [
    `Governance: ${governance.verified ? 'VERIFIED' : 'INVALID'} (${governance.source})`,
    `Publisher: ${governance.block.source_did}`,
    `Usage "${input.intendedUsage}": ${permitted ? 'PERMITTED' : 'RESTRICTED'} (${condition})`,
    `Receipt: ${receipt.receiptId}`,
    governance.verified ? '' : `Errors: ${governance.errors.join('; ')}`,
  ].filter(Boolean).join('\n')

  return { governance, receipt, permitted, summary }
}
