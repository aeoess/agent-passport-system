// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Federation — Cross-Gateway Portability Functions (WS-2, WS-3)
// ══════════════════════════════════════════════════════════════════

import { sign, verify } from '../crypto/keys.js'
import { canonicalize } from './canonical.js'
import { createHash } from 'crypto'
import type { ForeignReceiptEnvelope, VouchedReputation } from '../types/federation.js'
import type { GatewayImportPolicy } from '../types/gateway.js'

// ══════════════════════════════════════
// WS-2: RECEIPT PORTABILITY
// ══════════════════════════════════════

export interface ImportReceiptOptions {
  receiptId: string
  receiptContent: string          // canonical receipt content for hashing
  originGatewayId: string
  originGatewaySignature: string
  agentId: string
  agentSignature: string
  importerPrivateKey: string
  importerGatewayId: string
  importPolicy: GatewayImportPolicy
}

/** Import a foreign receipt. Evaluates against the import policy and
 *  signs the import decision. Returns a ForeignReceiptEnvelope. */
export function importReceipt(opts: ImportReceiptOptions): ForeignReceiptEnvelope {
  const receiptHash = createHash('sha256').update(opts.receiptContent).digest('hex')

  // Check import policy
  const accepted = opts.importPolicy.receipts.acceptFrom.includes(opts.originGatewayId)
    || opts.importPolicy.receipts.acceptFrom.includes('*')

  const now = new Date().toISOString()
  const envelope: Omit<ForeignReceiptEnvelope, 'importingGatewaySignature'> = {
    receiptId: opts.receiptId,
    originGatewayId: opts.originGatewayId,
    originGatewaySignature: opts.originGatewaySignature,
    agentId: opts.agentId,
    agentSignature: opts.agentSignature,
    receiptHash,
    importDecision: accepted ? 'accepted' : 'rejected',
    importedAt: now,
  }

  const canonical = canonicalize(envelope)
  const importingGatewaySignature = sign(canonical, opts.importerPrivateKey)
  return { ...envelope, importingGatewaySignature }
}

/** Verify a foreign receipt envelope's importing gateway signature. */
export function verifyReceiptEnvelope(envelope: ForeignReceiptEnvelope, importerPublicKey: string): boolean {
  const { importingGatewaySignature, ...body } = envelope
  const canonical = canonicalize(body)
  try {
    return verify(canonical, importingGatewaySignature, importerPublicKey)
  } catch { return false }
}

// ══════════════════════════════════════
// WS-3: REPUTATION PORTABILITY
// ══════════════════════════════════════

export interface VouchReputationOptions {
  agentId: string
  tier: number
  diversityScore: number
  gatewayPrivateKey: string
  gatewayId: string
  ttlSeconds?: number             // defaults to 30 days
}

/** Create a vouched reputation attestation for cross-gateway portability.
 *  Only summary metrics (tier + diversity score) — no receipt history. */
export function vouchReputation(opts: VouchReputationOptions): VouchedReputation {
  const now = new Date().toISOString()
  const ttl = opts.ttlSeconds ?? 86400 * 30
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString()

  const rep: Omit<VouchedReputation, 'originGatewaySignature'> = {
    agentId: opts.agentId,
    originGatewayId: opts.gatewayId,
    attestedTier: opts.tier,
    attestedDiversityScore: opts.diversityScore,
    attestedAt: now,
    expiresAt,
  }

  const canonical = canonicalize(rep)
  const originGatewaySignature = sign(canonical, opts.gatewayPrivateKey)
  return { ...rep, originGatewaySignature }
}

/** Verify a vouched reputation's gateway signature. */
export function verifyVouchedReputation(rep: VouchedReputation, gatewayPublicKey: string): boolean {
  const { originGatewaySignature, ...body } = rep
  const canonical = canonicalize(body)
  try {
    return verify(canonical, originGatewaySignature, gatewayPublicKey)
  } catch { return false }
}

/** Apply a gateway's import policy downgrade to a foreign reputation.
 *  Returns the effective tier after downgrade. */
export function applyReputationDowngrade(
  rep: VouchedReputation,
  importPolicy: GatewayImportPolicy,
): { effectiveTier: number; effectiveDiversity: number; accepted: boolean } {
  const accepted = importPolicy.reputation.acceptFrom.includes(rep.originGatewayId)
    || importPolicy.reputation.acceptFrom.includes('*')

  if (!accepted) {
    return { effectiveTier: importPolicy.foreignAgentDefaultTier, effectiveDiversity: 0, accepted: false }
  }

  const ratio = importPolicy.reputation.downgradeRatio
  return {
    effectiveTier: Math.floor(rep.attestedTier * ratio),
    effectiveDiversity: rep.attestedDiversityScore * ratio,
    accepted: true,
  }
}
