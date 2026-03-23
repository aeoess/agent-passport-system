// ══════════════════════════════════════
// Module 38: Data Contribution Ledger
// ══════════════════════════════════════
// Aggregation layer on top of Module 36A receipts.
// Tracks who accessed what data, how many times, and what's owed.
// Enables: "Show me every agent that used our dataset in March"

// ── Contribution Record ──
// One record per source-agent-principal triple.
// Aggregates access receipts over time.

export interface ContributionRecord {
  contributionId: string              // 'dcr_' + uuid
  sourceReceiptId: string
  sourceDescriptor: string            // human-readable source name
  agentId: string
  agentPublicKey: string
  principalId: string                 // human at root of chain
  accessCount: number
  firstAccessAt: string
  lastAccessAt: string
  purposes: string[]                  // unique declared purposes
  accessMethods: string[]             // unique access methods
  totalDataBytes?: number             // estimated data volume
  compensationAccrued: CompensationAccrual
  receiptIds: string[]                // all DataAccessReceipt IDs
}

// ── Compensation Accrual ──
// Running tally of what's owed based on DataTerms.compensation

export interface CompensationAccrual {
  model: 'none' | 'attribution_only' | 'per_access' | 'revenue_share' | 'pool' | 'negotiate'
  totalOwed: number                    // computed from model + access count
  currency: string                     // from CompensationModel
  accessesBilled: number               // receipts included in computation
  lastComputedAt: string
}

// ── Contribution Query ──

export interface ContributionQuery {
  sourceReceiptId?: string
  agentId?: string
  principalId?: string
  purpose?: string
  after?: string                       // ISO timestamp
  before?: string                      // ISO timestamp
  minAccessCount?: number
}

// ── Source Metrics ──
// Aggregate view for a data source owner.

export interface SourceMetrics {
  sourceReceiptId: string
  sourceDescriptor: string
  totalAccesses: number
  uniqueAgents: number
  uniquePrincipals: number
  purposeBreakdown: Record<string, number>
  compensationOwed: CompensationAccrual
  firstAccess: string
  lastAccess: string
  topAgents: Array<{ agentId: string; accessCount: number }>
}

// ── Agent Data Footprint ──
// Which data sources an agent has touched.

export interface AgentDataFootprint {
  agentId: string
  agentPublicKey: string
  principalId: string
  sourcesAccessed: Array<{
    sourceReceiptId: string
    sourceDescriptor: string
    accessCount: number
    purposes: string[]
    lastAccess: string
    compensationStatus: 'none' | 'attribution_only' | 'accruing' | 'settled'
  }>
  totalSources: number
  totalAccesses: number
  totalCompensationAccrued: number
  currency: string
}

// ══════════════════════════════════════
// Module 39: Data Settlement Protocol
// ══════════════════════════════════════
// Takes access receipts + DataTerms → generates settlement records.
// Cryptographically signed, Merkle-committed, auditable.

// ── Settlement Period ──

export interface SettlementPeriod {
  startDate: string                    // ISO date
  endDate: string                      // ISO date
  periodLabel: string                  // e.g., "2026-03" or "2026-Q1"
}

// ── Settlement Line Item ──
// One source-to-principal payment line.

export interface SettlementLineItem {
  sourceReceiptId: string
  sourceDescriptor: string
  sourcePrincipalId: string | null     // who gets paid (null = unknown for gateway-observed)
  payerPrincipalId: string             // who owes (principal who authorized the accessing agent)
  accessCount: number
  compensationModel: 'none' | 'attribution_only' | 'per_access' | 'revenue_share' | 'pool' | 'negotiate'
  amount: number
  currency: string
  receiptIds: string[]                 // backing evidence
  period: SettlementPeriod
}

// ── Settlement Record ──
// Cryptographically signed aggregate of what's owed.

export interface SettlementRecord {
  settlementId: string                 // 'stlr_' + uuid
  period: SettlementPeriod
  generatedAt: string
  generatedBy: string                  // gateway or operator public key
  lineItems: SettlementLineItem[]
  totalAmount: number
  currency: string
  totalAccesses: number
  uniqueSources: number
  uniquePayers: number
  merkleRoot: string                   // Merkle root of all backing receipt IDs
  signature: string                    // Ed25519 by generatedBy
}

// ── Settlement Verification ──

export interface SettlementVerification {
  valid: boolean
  errors: string[]
  signatureValid: boolean
  merkleValid: boolean
  lineItemsConsistent: boolean         // amounts match model * count
  totalConsistent: boolean             // sum of line items matches total
}

// ── Compliance Report ──
// GDPR Article 30, EU AI Act Article 10, SOC 2 data handling.

export interface DataComplianceReport {
  reportId: string                     // 'dcpr_' + uuid
  reportType: 'gdpr_article30' | 'euai_article10' | 'soc2_data' | 'general'
  period: SettlementPeriod
  generatedAt: string
  agentId?: string                     // filter by agent
  principalId?: string                 // filter by principal
  summary: {
    totalDataAccesses: number
    uniqueDataSources: number
    purposeBreakdown: Record<string, number>
    compensationSummary: { total: number; currency: string; settled: number; pending: number }
    termsViolations: number
    advisoryWarnings: number
  }
  accessDetails: Array<{
    sourceDescriptor: string
    accessCount: number
    purposes: string[]
    compensationModel: string
    termsCompliant: boolean
  }>
  signature: string
}
