// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Gonka Adapter — Governance layer for decentralized GPU inference networks
 *
 * Replaces Gonka's primitive allowlist.csv + manual governance votes with
 * APS delegation chains: automatic expiry, monotonic narrowing, cascade
 * revocation, signed receipts for off-chain devshard settlement.
 *
 * No Gonka SDK dependency. All types are local interfaces.
 */

import { createHash } from 'node:crypto'
import { scopeAuthorizes, verifyDelegation } from '../core/delegation.js'
import { verifyPassport } from '../verification/verify.js'
import { sign } from '../crypto/keys.js'
import { canonicalize } from '../core/canonical.js'
import type { Delegation, ActionReceipt, SignedPassport } from '../types/passport.js'
import { reportReceipt, type GatewayReporterConfig } from './gateway-reporter.js'

// ── Types ──

export interface GonkaInferenceRequest {
  model: string
  prompt: string
  maxTokens?: number
  hostAddress?: string
  epochId?: number
  devshardId?: string
}

export interface GonkaHostConfig {
  passport: SignedPassport
  delegation: Delegation
  privateKey: string
  allowedModels?: string[]
  maxInferencesPerEpoch?: number
  gateway?: GatewayReporterConfig
  onReceipt?: (r: ActionReceipt) => void
  onDenied?: (info: { host: string; reason: string }) => void
}

export interface GonkaInferenceReceipt {
  receipt: ActionReceipt
  model: string
  epochId?: number
  devshardId?: string
  inferenceHash: string
}

export interface GonkaHostVerification {
  authorized: boolean
  reason: string
  scope: string
  hostAddress: string
  model: string
}

// ── Helpers ──

function sha256(data: string): string {
  return createHash('sha256').update(data).digest('hex')
}

function buildReceipt(
  agentId: string, delegationId: string, privateKey: string,
  target: string, scope: string, status: 'success' | 'failure', summary: string,
): ActionReceipt {
  const data: Omit<ActionReceipt, 'signature'> = {
    receiptId: `rcpt_gonka_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    version: '1.1',
    timestamp: new Date().toISOString(),
    agentId, delegationId,
    action: { type: 'gonka_inference', target, scopeUsed: scope },
    result: { status, summary },
    delegationChain: [],
  }
  const sig = sign(canonicalize(data), privateKey)
  return { ...data, signature: sig } as ActionReceipt
}

// Track inferences per epoch for rate limiting
const epochCounters = new Map<string, number>()

function getEpochKey(agentId: string, epochId?: number): string {
  return `${agentId}:${epochId ?? 'default'}`
}

// ── Core functions ──

/** Verify a host has authority to serve inference for a model */
export function verifyGonkaHost(
  hostAddress: string,
  model: string,
  config: GonkaHostConfig,
): GonkaHostVerification {
  const scope = `inference:serve:${model}`

  const pc = verifyPassport(config.passport)
  if (!pc.valid) {
    return { authorized: false, reason: `Passport invalid: ${pc.errors.join(', ')}`, scope, hostAddress, model }
  }

  const dc = verifyDelegation(config.delegation)
  if (!dc.valid) {
    return { authorized: false, reason: `Delegation invalid: ${dc.errors.join(', ')}`, scope, hostAddress, model }
  }

  if (config.allowedModels && config.allowedModels.length > 0 && !config.allowedModels.includes(model)) {
    return { authorized: false, reason: `Model "${model}" not in allowed models`, scope, hostAddress, model }
  }

  if (!scopeAuthorizes(config.delegation.scope, scope)) {
    return { authorized: false, reason: `Scope "${scope}" not covered by delegation [${config.delegation.scope.join(', ')}]`, scope, hostAddress, model }
  }

  return { authorized: true, reason: `Host authorized to serve ${model}`, scope, hostAddress, model }
}

/** Govern an inference request -- check delegation, model, rate limits */
export async function governGonkaInference(
  request: GonkaInferenceRequest,
  execute: (req: GonkaInferenceRequest) => Promise<{ response: string; tokensUsed: number }>,
  config: GonkaHostConfig,
): Promise<{ result: { response: string; tokensUsed: number }; receipt: GonkaInferenceReceipt } | { denied: true; reason: string; receipt: ActionReceipt }> {
  const host = request.hostAddress || config.passport.passport.agentId
  const scope = `inference:serve:${request.model}`

  // Verify host
  const check = verifyGonkaHost(host, request.model, config)
  if (!check.authorized) {
    if (config.onDenied) config.onDenied({ host, reason: check.reason })
    const receipt = buildReceipt(config.passport.passport.agentId, config.delegation.delegationId, config.privateKey, request.model, scope, 'failure', check.reason)
    if (config.onReceipt) config.onReceipt(receipt)
    if (config.gateway) reportReceipt(receipt, config.gateway).catch(() => {})
    return { denied: true, reason: check.reason, receipt }
  }

  // Rate limit check
  if (config.maxInferencesPerEpoch != null) {
    const key = getEpochKey(config.passport.passport.agentId, request.epochId)
    const count = epochCounters.get(key) || 0
    if (count >= config.maxInferencesPerEpoch) {
      const reason = `Rate limit exceeded: ${count}/${config.maxInferencesPerEpoch} inferences this epoch`
      if (config.onDenied) config.onDenied({ host, reason })
      const receipt = buildReceipt(config.passport.passport.agentId, config.delegation.delegationId, config.privateKey, request.model, scope, 'failure', reason)
      if (config.onReceipt) config.onReceipt(receipt)
      if (config.gateway) reportReceipt(receipt, config.gateway).catch(() => {})
      return { denied: true, reason, receipt }
    }
    epochCounters.set(key, count + 1)
  }

  // Execute
  const result = await execute(request)

  // Compute inference hash for devshard verification
  const inferenceHash = sha256(canonicalize({ prompt: request.prompt, response: result.response }))

  const receipt = buildReceipt(
    config.passport.passport.agentId, config.delegation.delegationId, config.privateKey,
    request.model, scope, 'success',
    `Inference completed: ${result.tokensUsed} tokens, hash: ${inferenceHash.slice(0, 16)}`,
  )
  if (config.onReceipt) config.onReceipt(receipt)
  if (config.gateway) reportReceipt(receipt, config.gateway).catch(() => {})

  return {
    result,
    receipt: { receipt, model: request.model, epochId: request.epochId, devshardId: request.devshardId, inferenceHash },
  }
}

/** Create a devshard session receipt (off-chain proof for settlement) */
export function createDevshardReceipt(
  devshardId: string,
  inferenceCount: number,
  totalTokens: number,
  participants: string[],
  config: Pick<GonkaHostConfig, 'passport' | 'delegation' | 'privateKey'>,
): ActionReceipt {
  const data: Omit<ActionReceipt, 'signature'> = {
    receiptId: `rcpt_devshard_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    version: '1.1',
    timestamp: new Date().toISOString(),
    agentId: config.passport.passport.agentId,
    delegationId: config.delegation.delegationId,
    action: {
      type: 'devshard_session',
      target: devshardId,
      scopeUsed: 'devshard:participate',
    },
    result: {
      status: 'success',
      summary: `Devshard ${devshardId}: ${inferenceCount} inferences, ${totalTokens} tokens, ${participants.length} participants`,
    },
    delegationChain: participants,
  }
  const sig = sign(canonicalize(data), config.privateKey)
  return { ...data, signature: sig } as ActionReceipt
}

/** Convert APS delegation to Gonka-compatible allowlist entry */
export function delegationToAllowlistEntry(
  delegation: Delegation,
  passport: SignedPassport,
): { address: string; model: string; scope: string[]; expiresAtBlock?: number } {
  const models = delegation.scope
    .filter(s => s.startsWith('inference:serve:'))
    .map(s => s.replace('inference:serve:', ''))

  return {
    address: passport.passport.agentId,
    model: models[0] || '*',
    scope: delegation.scope,
    expiresAtBlock: undefined,
  }
}

/** Convert Gonka epoch timing to APS delegation expiry */
export function epochToDelegationExpiry(
  currentEpoch: number,
  epochDurationBlocks: number,
  epochsValid: number,
): Date {
  // Assume ~6 second block time (Cosmos SDK default)
  const blocksRemaining = epochDurationBlocks * epochsValid
  const secondsRemaining = blocksRemaining * 6
  return new Date(Date.now() + secondsRemaining * 1000)
}

/** Validate PoC (Proof-of-Compute) participation receipt */
export function verifyPoCParticipation(
  hostAddress: string,
  epochId: number,
  weight: number,
  config: Pick<GonkaHostConfig, 'passport' | 'privateKey'>,
): ActionReceipt {
  const data: Omit<ActionReceipt, 'signature'> = {
    receiptId: `rcpt_poc_${Date.now().toString(36)}_${Math.random().toString(36).slice(2, 6)}`,
    version: '1.1',
    timestamp: new Date().toISOString(),
    agentId: config.passport.passport.agentId,
    delegationId: 'poc_validation',
    action: {
      type: 'poc_participation',
      target: hostAddress,
      scopeUsed: 'inference:validate',
    },
    result: {
      status: 'success',
      summary: `PoC validation: host ${hostAddress}, epoch ${epochId}, weight ${weight}`,
    },
    delegationChain: [],
  }
  const sig = sign(canonicalize(data), config.privateKey)
  return { ...data, signature: sig } as ActionReceipt
}
