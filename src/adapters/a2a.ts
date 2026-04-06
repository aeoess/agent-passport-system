// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Google A2A Adapter — maps A2A Agent Cards to APS passports
 * and A2A Tasks to APS coordination.
 *
 * A2A pattern: Agent Card (discovery) → Task (work) → Artifact (output)
 * APS pattern: Passport (identity) → Intent/Decision (governance) → Receipt (proof)
 */

import { GovernanceHook } from './governance-hook.js'
import type { GovernanceHookConfig, ActionDescriptor, GovernanceReceipt, GovernanceResult } from './governance-hook.js'
import type { A2AAgentCard } from '../types/a2a.js'

export interface A2AGovernance {
  /** Map an A2A Agent Card to APS-compatible scopes */
  deriveScopes: (card: A2AAgentCard) => string[]
  /** Govern an A2A task send */
  governTaskSend: (
    targetCard: A2AAgentCard,
    taskDescription: string,
    execute: () => Promise<unknown>,
  ) => Promise<{ result: unknown; receipt: GovernanceReceipt; governance: GovernanceResult }>
  /** Govern receiving a task */
  governTaskReceive: (
    senderUrl: string,
    taskDescription: string,
    execute: () => Promise<unknown>,
  ) => Promise<{ result: unknown; receipt: GovernanceReceipt; governance: GovernanceResult }>
  get_audit_trail: () => GovernanceReceipt[]
  hook: GovernanceHook
}

export function createA2AGovernance(config: GovernanceHookConfig): A2AGovernance {
  const hook = new GovernanceHook(config)

  const deriveScopes = (card: A2AAgentCard): string[] => {
    const scopes: string[] = []
    if (card.skills) {
      for (const skill of card.skills) {
        scopes.push(`a2a:skill:${skill.id}`)
      }
    }
    if (card.capabilities?.streaming) scopes.push('a2a:streaming')
    if (card.capabilities?.pushNotifications) scopes.push('a2a:push')
    if (scopes.length === 0) scopes.push('a2a:task:execute')
    return scopes
  }

  const governTaskSend = async (
    targetCard: A2AAgentCard,
    taskDescription: string,
    execute: () => Promise<unknown>,
  ) => {
    const action: ActionDescriptor = {
      type: 'a2a:task:send',
      target: targetCard.url,
      scopeRequired: 'a2a:task:execute',
      metadata: { targetName: targetCard.name, task: taskDescription.slice(0, 200) },
    }
    return hook.wrap(action, execute)
  }

  const governTaskReceive = async (
    senderUrl: string,
    taskDescription: string,
    execute: () => Promise<unknown>,
  ) => {
    const action: ActionDescriptor = {
      type: 'a2a:task:receive',
      target: senderUrl,
      scopeRequired: 'a2a:task:execute',
      metadata: { sender: senderUrl, task: taskDescription.slice(0, 200) },
    }
    return hook.wrap(action, execute)
  }

  return {
    deriveScopes,
    governTaskSend,
    governTaskReceive,
    get_audit_trail: () => hook.getReceipts(),
    hook,
  }
}


// ══════════════════════════════════════
// v2: Direct passport ↔ Agent Card bridge (IBAC pattern)
// ══════════════════════════════════════

import { verifyPassport } from '../verification/verify.js'
import type { Delegation, SignedPassport } from '../types/passport.js'

export interface A2AAgentCardV2 {
  name: string
  description?: string
  url?: string
  provider?: { organization: string; url?: string }
  version?: string
  capabilities?: {
    streaming?: boolean
    pushNotifications?: boolean
    stateTransitionHistory?: boolean
  }
  skills?: Array<{
    id: string
    name: string
    description?: string
    inputModes?: string[]
    outputModes?: string[]
  }>
  securitySchemes?: Record<string, unknown>
  security?: unknown[]
  defaultInputModes?: string[]
  defaultOutputModes?: string[]
  extensions?: { aps_trust?: unknown; [k: string]: unknown }
}

/** Convert APS passport to A2A Agent Card */
export function passportToA2ACard(
  passport: SignedPassport,
  opts?: {
    delegation?: Delegation
    url?: string
    skills?: A2AAgentCardV2['skills']
    capabilities?: A2AAgentCardV2['capabilities']
  },
): A2AAgentCardV2 {
  const p = passport.passport
  const card: A2AAgentCardV2 = {
    name: p.agentName || p.agentId,
    description: p.mission,
    url: opts?.url,
    version: '1.0',
    capabilities: opts?.capabilities || {},
    securitySchemes: {
      aps_ed25519: {
        type: 'ed25519',
        publicKey: p.publicKey,
        agentId: p.agentId,
      },
    },
  }

  // Map delegation scope to skills
  if (opts?.skills) {
    card.skills = opts.skills
  } else if (opts?.delegation) {
    card.skills = opts.delegation.scope.map(s => ({
      id: s,
      name: s.replace(/:/g, ' ').replace(/\b\w/g, c => c.toUpperCase()),
    }))
  }

  if (p.ownerAlias) {
    card.provider = { organization: p.ownerAlias }
  }

  return card
}

/** Convert A2A Agent Card to APS passport metadata */
export function a2aCardToPassportMeta(
  card: A2AAgentCardV2,
): { agentId: string; metadata: Record<string, unknown> } {
  return {
    agentId: card.name.toLowerCase().replace(/[^a-z0-9-]/g, '-'),
    metadata: {
      a2a_name: card.name,
      a2a_description: card.description,
      a2a_url: card.url,
      a2a_provider: card.provider,
      a2a_version: card.version,
      a2a_capabilities: card.capabilities,
      a2a_skill_count: card.skills?.length || 0,
    },
  }
}

/** Verify an A2A agent has valid APS identity */
export function verifyA2AIdentity(
  card: A2AAgentCardV2,
  passport: SignedPassport,
): { valid: boolean; errors: string[] } {
  const errors: string[] = []

  const pc = verifyPassport(passport)
  if (!pc.valid) errors.push(...pc.errors)

  const p = passport.passport
  if (card.name !== p.agentName && card.name !== p.agentId) {
    errors.push(`Card name "${card.name}" does not match passport agentName "${p.agentName}" or agentId "${p.agentId}"`)
  }

  const schemePubKey = (card.securitySchemes?.aps_ed25519 as Record<string, unknown>)?.publicKey
  if (schemePubKey && schemePubKey !== p.publicKey) {
    errors.push('Card security scheme publicKey does not match passport publicKey')
  }

  return { valid: errors.length === 0, errors }
}

/** Extract delegation scope from A2A skills */
export function a2aSkillsToScope(
  skills?: A2AAgentCardV2['skills'],
): string[] {
  if (!skills || skills.length === 0) return []
  return skills.map(s => `a2a:${s.id}`)
}

/** Embed APS trust signal in Agent Card extensions */
export function embedA2ATrustSignal(
  card: A2AAgentCardV2,
  passport: SignedPassport,
  trustEndpoint?: string,
): A2AAgentCardV2 {
  return {
    ...card,
    extensions: {
      ...card.extensions,
      aps_trust: {
        agentId: passport.passport.agentId,
        publicKey: passport.passport.publicKey,
        trustEndpoint: trustEndpoint || `https://gateway.aeoess.com/api/v1/public/trust/${passport.passport.agentId}`,
        protocol: 'agent-passport-system',
      },
    },
  }
}
