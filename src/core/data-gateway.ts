// ══════════════════════════════════════════════════════════════════════
// Data Gateway — Composable Gateway + Data Enforcement
// ══════════════════════════════════════════════════════════════════════
// Wraps ProxyGateway + DataEnforcementGate into a single call.
// One gateway call: identity → delegation → policy → data terms → execute.
//
// Also adds real-time compensation enforcement: agent must accept
// DataTerms before accessing data. No acceptance = no access.
// ══════════════════════════════════════════════════════════════════════

import {
  DataEnforcementGate, DataAccessRequest, DataAccessDecision,
  DataEnforcementConfig,
} from './data-enforcement.js'
import { ContributionLedger, createContributionLedger } from './data-contribution.js'
import { SourceReceipt, DataPurpose, AccessMethod } from '../types/data-source.js'

// ── Terms Acceptance Registry ──
// Agents must explicitly accept DataTerms before accessing data.
// No acceptance = no access, even in audit mode.

export interface TermsAcceptance {
  agentId: string
  agentPublicKey: string
  sourceReceiptId: string
  acceptedAt: string
  compensationAcknowledged: boolean  // agent confirms it will honor compensation terms
  signature?: string
}

export interface DataGatewayConfig {
  gatewayId: string
  gatewayPublicKey: string
  gatewayPrivateKey: string
  enforcementMode: 'enforce' | 'audit' | 'off'
  requireTermsAcceptance: boolean     // if true, agents must call acceptTerms() before access
  onAccessBlocked?: (agentId: string, source: string, reason: string) => void
  onAccessGranted?: (agentId: string, source: string, receiptId: string) => void
  onTermsAccepted?: (acceptance: TermsAcceptance) => void
}

// ── Data Gateway ──

export class DataGateway {
  private config: DataGatewayConfig
  private enforcementGate: DataEnforcementGate
  private acceptances: Map<string, TermsAcceptance> = new Map() // key: agentId:sourceReceiptId

  constructor(config: DataGatewayConfig, ledger?: ContributionLedger) {
    this.config = config
    this.enforcementGate = new DataEnforcementGate({
      gatewayId: config.gatewayId,
      gatewayPublicKey: config.gatewayPublicKey,
      gatewayPrivateKey: config.gatewayPrivateKey,
      mode: config.enforcementMode,
      onAccessBlocked: (agentId, src, violations) => {
        config.onAccessBlocked?.(agentId, src, violations.join('; '))
      },
      onAccessRecorded: (receipt) => {
        config.onAccessGranted?.(receipt.agentId, receipt.sourceReceiptId, receipt.accessReceiptId)
      },
    }, ledger || createContributionLedger())
  }

  /** Register a data source with the gateway */
  registerSource(receipt: SourceReceipt, descriptor: string): void {
    this.enforcementGate.registerSource(receipt, descriptor)
  }

  /**
   * Agent accepts terms for a data source.
   * Must be called before access if requireTermsAcceptance is true.
   */
  acceptTerms(opts: {
    agentId: string
    agentPublicKey: string
    sourceReceiptId: string
    signature?: string
  }): TermsAcceptance {
    const acceptance: TermsAcceptance = {
      agentId: opts.agentId,
      agentPublicKey: opts.agentPublicKey,
      sourceReceiptId: opts.sourceReceiptId,
      acceptedAt: new Date().toISOString(),
      compensationAcknowledged: true,
      signature: opts.signature,
    }
    const key = `${opts.agentId}:${opts.sourceReceiptId}`
    this.acceptances.set(key, acceptance)
    this.config.onTermsAccepted?.(acceptance)
    return acceptance
  }

  /** Check if an agent has accepted terms for a source */
  hasAcceptedTerms(agentId: string, sourceReceiptId: string): boolean {
    return this.acceptances.has(`${agentId}:${sourceReceiptId}`)
  }

  /**
   * Request data access through the gateway.
   * Single call: terms acceptance check → data terms compliance → receipt generation → contribution ledger.
   */
  requestAccess(request: DataAccessRequest): DataAccessDecision {
    // Step 1: Check terms acceptance (if required)
    if (this.config.requireTermsAcceptance) {
      if (!this.hasAcceptedTerms(request.agentId, request.sourceReceiptId)) {
        this.config.onAccessBlocked?.(request.agentId, request.sourceReceiptId, 'Terms not accepted')
        return {
          allowed: false,
          sourceReceiptId: request.sourceReceiptId,
          hardViolations: ['Agent has not accepted DataTerms for this source. Call acceptTerms() first.'],
          advisoryWarnings: [],
        }
      }
    }

    // Step 2: Delegate to enforcement gate (terms compliance + receipt + contribution ledger)
    return this.enforcementGate.checkAccess(request)
  }

  /**
   * Preflight: check multiple sources at once.
   * Validates terms acceptance + compliance for all sources.
   */
  preflightAccess(requests: DataAccessRequest[]): { allAllowed: boolean; decisions: DataAccessDecision[] } {
    if (this.config.requireTermsAcceptance) {
      const decisions: DataAccessDecision[] = requests.map(r => {
        if (!this.hasAcceptedTerms(r.agentId, r.sourceReceiptId)) {
          return {
            allowed: false,
            sourceReceiptId: r.sourceReceiptId,
            hardViolations: ['Terms not accepted'],
            advisoryWarnings: [],
          }
        }
        return this.enforcementGate.checkAccess(r)
      })
      return { allAllowed: decisions.every(d => d.allowed), decisions }
    }
    return this.enforcementGate.preflightCheck(requests)
  }

  /** Get the underlying enforcement gate (for ledger/receipt access) */
  getEnforcementGate(): DataEnforcementGate { return this.enforcementGate }

  /** Get the contribution ledger */
  getLedger(): ContributionLedger { return this.enforcementGate.getLedger() }

  /** Get all terms acceptances */
  getAcceptances(): TermsAcceptance[] { return Array.from(this.acceptances.values()) }

  /** Revoke terms acceptance (e.g., source updated terms) */
  revokeAcceptance(agentId: string, sourceReceiptId: string): boolean {
    return this.acceptances.delete(`${agentId}:${sourceReceiptId}`)
  }

  /** Revoke all acceptances for a source (terms changed, all agents must re-accept) */
  revokeAllAcceptancesForSource(sourceReceiptId: string): number {
    let count = 0
    for (const [key] of this.acceptances) {
      if (key.endsWith(`:${sourceReceiptId}`)) {
        this.acceptances.delete(key)
        count++
      }
    }
    return count
  }
}
