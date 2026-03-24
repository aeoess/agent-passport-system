// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * agent.json Bridge — APS ↔ agent.json Commerce Integration
 *
 * Maps agent.json capability manifests (FransDevelopment/agent-json spec v1.3)
 * to APS 4-gate commerce preflight and signed receipt generation.
 *
 * agent.json declares WHAT a service offers + economics.
 * APS enforces WHO can spend, HOW MUCH, and traces it back to the human principal.
 *
 * Composition: agent.json (capability discovery + pricing) + APS (identity + delegation + enforcement)
 *
 * @module interop/agent-json-bridge
 */

import { randomBytes } from 'node:crypto'
import { sign } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import { scopeAuthorizes } from '../core/delegation.js'
import type { CommerceDelegation, CommercePreflightResult, CommercePreflightCheck } from '../types/commerce.js'

// ═══════════════════════════════════════
// agent.json Types (per spec v1.3)
// ═══════════════════════════════════════

export interface AgentJsonManifest {
  version: string
  origin: string
  payout_address: string
  display_name?: string
  description?: string
  identity?: AgentJsonIdentity
  intents?: AgentJsonIntent[]
  bounty?: AgentJsonBounty
  incentive?: AgentJsonIncentive
  payments?: Record<string, unknown>
  x402?: Record<string, unknown>
  extensions?: Record<string, unknown>
}

export interface AgentJsonIdentity {
  did?: string
  public_key?: string
}

export interface AgentJsonIntent {
  name: string
  description: string
  endpoint?: string
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE'
  parameters?: Record<string, AgentJsonParameter>
  returns?: AgentJsonReturns
  price?: AgentJsonPrice
  bounty?: AgentJsonBounty
  incentive?: AgentJsonIncentive
  payments?: Record<string, unknown>
  x402?: Record<string, unknown>
  extensions?: Record<string, unknown>
}

export interface AgentJsonParameter {
  type: 'string' | 'integer' | 'number' | 'boolean' | 'array' | 'object'
  required?: boolean
  description?: string
  enum?: unknown[]
  default?: unknown
}

export interface AgentJsonReturns {
  type: 'object' | 'array' | 'string'
  description?: string
  properties?: Record<string, { type: string; description?: string }>
}

export interface AgentJsonPrice {
  amount: number
  currency: string
  model?: 'per_call' | 'per_unit' | 'flat'
  unit_param?: string
  free_tier?: number
  network?: string | string[]
}

export interface AgentJsonBounty {
  type: 'cpa'
  rate: number
  currency: string
  splits?: { orchestrator?: number; platform?: number; referrer?: number }
}

export interface AgentJsonIncentive {
  type: 'cpa'
  rate: number
  currency: string
}

// ═══════════════════════════════════════
// Commerce Receipt linking agent.json service to APS delegation
// ═══════════════════════════════════════

export interface AgentJsonCommerceReceipt {
  receiptId: string
  version: string
  timestamp: string
  // APS side
  agentId: string
  delegationId: string
  delegationChain: string[]
  beneficiary: string
  // agent.json side
  service: {
    origin: string
    displayName?: string
    did?: string
    publicKey?: string
  }
  intent: {
    name: string
    description: string
    endpoint?: string
  }
  spend: {
    amount: number
    currency: string
    pricingModel: string
  }
  bountyEarned?: {
    amount: number
    currency: string
  }
  signature: string
}

// ═══════════════════════════════════════
// Parse & Validate
// ═══════════════════════════════════════

/**
 * Parse and validate an agent.json manifest.
 * Accepts either a JSON string or an already-parsed object.
 * Validates required fields per spec: version, origin, payout_address.
 */
export function parseAgentJson(input: string | object): AgentJsonManifest {
  let manifest: AgentJsonManifest

  if (typeof input === 'string') {
    try {
      manifest = JSON.parse(input) as AgentJsonManifest
    } catch {
      throw new Error('Invalid agent.json: not valid JSON')
    }
  } else {
    manifest = input as AgentJsonManifest
  }

  // Required fields (spec §4.1)
  if (!manifest.version) throw new Error('Invalid agent.json: missing required field "version"')
  if (!manifest.origin) throw new Error('Invalid agent.json: missing required field "origin"')
  if (!manifest.payout_address) throw new Error('Invalid agent.json: missing required field "payout_address"')

  // Version check
  const validVersions = ['1.0', '1.1', '1.2', '1.3']
  if (!validVersions.includes(manifest.version)) {
    throw new Error(`Invalid agent.json: unsupported version "${manifest.version}"`)
  }

  // Validate intents if present
  if (manifest.intents) {
    if (!Array.isArray(manifest.intents)) throw new Error('Invalid agent.json: "intents" must be an array')
    for (const intent of manifest.intents) {
      if (!intent.name) throw new Error('Invalid agent.json: intent missing required field "name"')
      if (!intent.description) throw new Error('Invalid agent.json: intent missing required field "description"')
    }
  }

  return manifest
}

/**
 * Resolve the effective price for an intent.
 * Returns amount in the smallest currency unit (cents for USD/USDC)
 * or the raw amount if no conversion needed.
 */
export function resolveIntentPrice(manifest: AgentJsonManifest, intentName: string): {
  amount: number
  currency: string
  model: string
} | null {
  const intent = manifest.intents?.find(i => i.name === intentName)
  if (!intent?.price) return null
  return {
    amount: intent.price.amount,
    currency: intent.price.currency,
    model: intent.price.model || 'per_call',
  }
}

/**
 * Resolve effective bounty for an intent.
 * Intent-level bounty overrides manifest-level bounty (spec §4.4).
 */
export function resolveIntentBounty(manifest: AgentJsonManifest, intentName: string): AgentJsonBounty | null {
  const intent = manifest.intents?.find(i => i.name === intentName)
  return intent?.bounty ?? manifest.bounty ?? null
}

// ═══════════════════════════════════════
// Commerce Preflight: agent.json → APS 4-gate pipeline
// ═══════════════════════════════════════

/**
 * Run APS 4-gate commerce preflight against an agent.json intent.
 *
 * Gates:
 *   1. Scope check — is the intent's scope covered by delegation?
 *   2. Spend limit — is the price within remaining budget?
 *   3. Merchant whitelist — is the service origin in allowed merchants?
 *   4. Human approval threshold — does price exceed approval threshold?
 *
 * Maps agent.json's `price` field to APS's `CommerceDelegation` constraints.
 */
export function commercePreflightFromManifest(opts: {
  manifest: AgentJsonManifest
  intentName: string
  delegation: CommerceDelegation
}): CommercePreflightResult {
  const { manifest, intentName, delegation } = opts
  const checks: CommercePreflightCheck[] = []
  const warnings: string[] = []

  const intent = manifest.intents?.find(i => i.name === intentName)
  if (!intent) {
    return {
      permitted: false,
      checks: [{ check: 'intent_exists', passed: false, detail: `Intent "${intentName}" not found in manifest for ${manifest.origin}` }],
      warnings: [],
      blockedReason: `Intent "${intentName}" not declared in agent.json`,
    }
  }

  // Gate 1: Scope check — map intent name to commerce scope
  const requiredScope = `commerce:${intentName}`
  const hasScope = scopeAuthorizes(delegation.scope, 'commerce:checkout') ||
    scopeAuthorizes(delegation.scope, requiredScope)
  checks.push({
    check: 'delegation_scope',
    passed: hasScope,
    detail: hasScope
      ? `Delegation covers scope for intent "${intentName}"`
      : `Delegation lacks scope for "${intentName}". Has: [${delegation.scope.join(', ')}]`,
  })

  // Gate 2: Spend limit — check price against remaining budget
  const price = resolveIntentPrice(manifest, intentName)
  let withinBudget = true
  if (price) {
    const remaining = delegation.spendLimit - delegation.spentAmount
    withinBudget = price.amount <= remaining
    checks.push({
      check: 'spend_limit',
      passed: withinBudget,
      detail: withinBudget
        ? `Price ${price.amount} ${price.currency} within remaining budget ${remaining} ${delegation.currency}`
        : `Price ${price.amount} ${price.currency} exceeds remaining budget ${remaining} ${delegation.currency}`,
    })
  } else {
    // No price = free intent
    checks.push({
      check: 'spend_limit',
      passed: true,
      detail: 'Intent has no price (free tier or unpriced)',
    })
  }

  // Gate 3: Merchant whitelist — is this service origin allowed?
  let merchantAllowed = true
  if (delegation.approvedMerchants && delegation.approvedMerchants.length > 0) {
    merchantAllowed = delegation.approvedMerchants.includes(manifest.origin)
    checks.push({
      check: 'merchant_whitelist',
      passed: merchantAllowed,
      detail: merchantAllowed
        ? `Service "${manifest.origin}" is in approved merchants list`
        : `Service "${manifest.origin}" not in approved merchants: [${delegation.approvedMerchants.join(', ')}]`,
    })
  } else {
    checks.push({
      check: 'merchant_whitelist',
      passed: true,
      detail: 'No merchant whitelist configured (all merchants allowed)',
    })
  }

  // Gate 4: Human approval threshold
  let needsApproval = false
  if (price && delegation.humanApprovalThreshold !== undefined) {
    needsApproval = price.amount > delegation.humanApprovalThreshold
    if (needsApproval) {
      warnings.push(`Price ${price.amount} ${price.currency} exceeds human approval threshold ${delegation.humanApprovalThreshold}`)
    }
  }
  checks.push({
    check: 'human_approval',
    passed: !needsApproval,
    detail: needsApproval
      ? `Human approval required: price ${price!.amount} exceeds threshold ${delegation.humanApprovalThreshold}`
      : 'No human approval required',
  })

  const allPassed = checks.every(c => c.passed)

  return {
    permitted: allPassed,
    checks,
    delegation: allPassed ? delegation : undefined,
    warnings,
    blockedReason: allPassed ? undefined : checks.filter(c => !c.passed).map(c => c.detail).join('; '),
  }
}

// ═══════════════════════════════════════
// Receipt Generation: signed proof linking agent.json + APS
// ═══════════════════════════════════════

/**
 * Generate a signed commerce receipt linking an agent.json intent
 * to an APS delegation chain.
 *
 * Call this AFTER successful preflight + execution.
 * The receipt proves: who authorized (delegation chain), what was called
 * (intent from manifest), how much was spent (price from manifest),
 * who benefits (principal from delegation), and which service provided it
 * (identity from manifest).
 */
export function generateCommerceReceiptFromManifest(opts: {
  manifest: AgentJsonManifest
  intentName: string
  delegation: CommerceDelegation
  beneficiary: string
  privateKey: string
}): AgentJsonCommerceReceipt {
  const { manifest, intentName, delegation, beneficiary, privateKey } = opts

  const intent = manifest.intents?.find(i => i.name === intentName)
  if (!intent) {
    throw new Error(`Intent "${intentName}" not found in manifest for ${manifest.origin}`)
  }

  const price = resolveIntentPrice(manifest, intentName)
  const bounty = resolveIntentBounty(manifest, intentName)

  const receipt: Omit<AgentJsonCommerceReceipt, 'signature'> = {
    receiptId: 'ajr_' + randomBytes(12).toString('hex'),
    version: '1.0',
    timestamp: new Date().toISOString(),
    agentId: delegation.agentId,
    delegationId: delegation.delegationId,
    delegationChain: [delegation.delegationId],
    beneficiary,
    service: {
      origin: manifest.origin,
      displayName: manifest.display_name,
      did: manifest.identity?.did,
      publicKey: manifest.identity?.public_key,
    },
    intent: {
      name: intent.name,
      description: intent.description,
      endpoint: intent.endpoint,
    },
    spend: {
      amount: price?.amount ?? 0,
      currency: price?.currency ?? delegation.currency,
      pricingModel: price?.model ?? 'free',
    },
    bountyEarned: bounty ? { amount: bounty.rate, currency: bounty.currency } : undefined,
  }

  const sig = sign(canonicalize(receipt), privateKey)
  return { ...receipt, signature: sig }
}
