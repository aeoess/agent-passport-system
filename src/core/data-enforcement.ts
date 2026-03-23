// ══════════════════════════════════════════════════════════════════════
// Data Enforcement Gate
// ══════════════════════════════════════════════════════════════════════
// Sits alongside the ProxyGateway. Before an agent accesses data,
// the enforcement gate checks DataTerms, blocks if non-compliant,
// and automatically generates access receipts + contribution records.
//
// Key principle: the agent cannot skip this check. The gateway calls
// the enforcement gate before executing any data-accessing tool.
// ══════════════════════════════════════════════════════════════════════

import crypto from 'crypto'
import {
  DataAccessReceipt, DataTerms, SourceReceipt, DataPurpose, AccessMethod,
} from '../types/data-source.js'
import {
  checkTermsCompliance, recordDataAccess, buildDataAccessMerkleRoot,
} from './data-source.js'
import {
  ContributionLedger, createContributionLedger, recordContribution,
} from './data-contribution.js'

// ── Data Enforcement Config ──

export interface DataEnforcementConfig {
  gatewayId: string
  gatewayPublicKey: string
  gatewayPrivateKey: string
  mode: 'enforce' | 'audit' | 'off'
  // If enforce: block non-compliant access. If audit: log but allow. If off: skip entirely.
  onAccessBlocked?: (agentId: string, sourceId: string, violations: string[]) => void
  onAccessRecorded?: (receipt: DataAccessReceipt) => void
  onTermsWarning?: (agentId: string, sourceId: string, warnings: string[]) => void
}

// ── Registered Data Source ──

interface RegisteredSource {
  receipt: SourceReceipt
  descriptor: string
  accessCount: number
}

// ── Access Request ──

export interface DataAccessRequest {
  agentId: string
  agentPublicKey: string
  principalId: string
  delegationId?: string
  sourceReceiptId: string
  declaredPurpose: DataPurpose
  accessMethod: AccessMethod
  accessScope: string
  executionFrameId: string
  dataHash?: string
}

// ── Access Decision ──

export interface DataAccessDecision {
  allowed: boolean
  sourceReceiptId: string
  hardViolations: string[]
  advisoryWarnings: string[]
  receipt?: DataAccessReceipt
  accessesRemaining?: number
}

// ── Data Enforcement Gate ──

export class DataEnforcementGate {
  private config: DataEnforcementConfig
  private sources: Map<string, RegisteredSource> = new Map()
  private ledger: ContributionLedger
  private receipts: DataAccessReceipt[] = []

  constructor(config: DataEnforcementConfig, ledger?: ContributionLedger) {
    this.config = config
    this.ledger = ledger || createContributionLedger()
  }

  /** Register a data source with the gate. Only registered sources are enforced. */
  registerSource(receipt: SourceReceipt, descriptor: string): void {
    this.sources.set(receipt.sourceReceiptId, { receipt, descriptor, accessCount: 0 })
  }

  /** Get the contribution ledger for settlement/reporting */
  getLedger(): ContributionLedger { return this.ledger }

  /** Get all access receipts */
  getReceipts(): DataAccessReceipt[] { return [...this.receipts] }

  /** Get Merkle root of all receipts */
  getMerkleRoot(): string { return buildDataAccessMerkleRoot(this.receipts) }

  /**
   * Check whether an agent can access a data source.
   * In 'enforce' mode, blocks non-compliant access.
   * In 'audit' mode, logs but allows.
   * Always generates a receipt and feeds the contribution ledger.
   */
  checkAccess(request: DataAccessRequest): DataAccessDecision {
    if (this.config.mode === 'off') {
      return { allowed: true, sourceReceiptId: request.sourceReceiptId, hardViolations: [], advisoryWarnings: [] }
    }

    const source = this.sources.get(request.sourceReceiptId)
    if (!source) {
      return {
        allowed: false,
        sourceReceiptId: request.sourceReceiptId,
        hardViolations: ['Source not registered with enforcement gate'],
        advisoryWarnings: [],
      }
    }

    // Check terms compliance
    const compliance = checkTermsCompliance({
      sourceReceipt: source.receipt,
      agentId: request.agentId,
      principalId: request.principalId,
      declaredPurpose: request.declaredPurpose,
      currentAccessCount: source.accessCount,
    })

    // In enforce mode, block if hard violations exist
    if (this.config.mode === 'enforce' && !compliance.compliant) {
      this.config.onAccessBlocked?.(request.agentId, request.sourceReceiptId, compliance.hardViolations)
      return {
        allowed: false,
        sourceReceiptId: request.sourceReceiptId,
        hardViolations: compliance.hardViolations,
        advisoryWarnings: compliance.advisoryWarnings,
        accessesRemaining: compliance.accessesRemaining,
      }
    }

    // Advisory warnings (both modes)
    if (compliance.advisoryWarnings.length > 0) {
      this.config.onTermsWarning?.(request.agentId, request.sourceReceiptId, compliance.advisoryWarnings)
    }

    // Generate access receipt (gateway-signed, third-party attestation)
    const receipt = recordDataAccess({
      sourceReceipt: source.receipt,
      dataHash: request.dataHash || crypto.createHash('sha256').update(request.executionFrameId + request.sourceReceiptId).digest('hex'),
      agentId: request.agentId,
      agentPublicKey: request.agentPublicKey,
      delegationId: request.delegationId,
      principalId: request.principalId,
      executionFrameId: request.executionFrameId,
      accessScope: request.accessScope,
      accessMethod: request.accessMethod,
      declaredPurpose: request.declaredPurpose,
      gatewayId: this.config.gatewayId,
      gatewayPublicKey: this.config.gatewayPublicKey,
      gatewayPrivateKey: this.config.gatewayPrivateKey,
    })

    // Update tracking
    source.accessCount++
    this.receipts.push(receipt)
    this.config.onAccessRecorded?.(receipt)

    // Feed the contribution ledger
    recordContribution(this.ledger, receipt, source.descriptor)

    return {
      allowed: true,
      sourceReceiptId: request.sourceReceiptId,
      hardViolations: compliance.hardViolations, // empty in enforce mode if we got here
      advisoryWarnings: compliance.advisoryWarnings,
      receipt,
      accessesRemaining: compliance.accessesRemaining,
    }
  }

  /** Bulk check: verify an agent can access all required sources before starting execution */
  preflightCheck(requests: DataAccessRequest[]): { allAllowed: boolean; decisions: DataAccessDecision[] } {
    const decisions = requests.map(r => {
      // Dry run — don't generate receipts, just check compliance
      const source = this.sources.get(r.sourceReceiptId)
      if (!source) return { allowed: false, sourceReceiptId: r.sourceReceiptId, hardViolations: ['Source not registered'], advisoryWarnings: [] }
      const compliance = checkTermsCompliance({
        sourceReceipt: source.receipt,
        agentId: r.agentId,
        principalId: r.principalId,
        declaredPurpose: r.declaredPurpose,
        currentAccessCount: source.accessCount,
      })
      return {
        allowed: this.config.mode === 'enforce' ? compliance.compliant : true,
        sourceReceiptId: r.sourceReceiptId,
        hardViolations: compliance.hardViolations,
        advisoryWarnings: compliance.advisoryWarnings,
        accessesRemaining: compliance.accessesRemaining,
      }
    })
    return { allAllowed: decisions.every(d => d.allowed), decisions }
  }
}
