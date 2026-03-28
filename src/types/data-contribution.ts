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


// ══════════════════════════════════════
// Module 40: Data Source Attribution
// ══════════════════════════════════════
// The inverse of Module 37's agent attribution.
// Agent attribution: "Agent A did 60% of the work"
// Data source attribution: "Data Source X contributed 60% to this output"
// This is the AppsFlyer for AI data — which source caused which value.

// ── Attribution Weight Model ──
// Configurable, not hardcoded. "Attribution weights are configurable,
// not hardcoded gospel." Multiple models, customer picks.

export type DataAttributionModel =
  | 'equal'           // equal split across all sources
  | 'access_weighted' // weighted by access count
  | 'recency_weighted'// more recent access = higher weight
  | 'custom'          // caller provides explicit weights

// ── Per-Source Attribution Entry ──

export interface DataSourceAttributionEntry {
  sourceReceiptId: string
  sourceDescriptor: string
  accessReceiptIds: string[]
  accessCount: number
  weight: number               // raw computed weight
  percentage: number           // normalized 0-100
  compensationOwed: number
  currency: string
  compensationModel: string
}

// ── Data Source Attribution Report ──
// Signed, Merkle-committed proof of which data sources
// contributed to a specific output or decision.

export interface DataSourceAttributionReport {
  reportId: string              // 'dsar_' + uuid
  // What output this attribution is for
  outputArtifactId: string
  outputType: string            // 'decision' | 'content' | 'model' | 'action'
  // Attribution entries per source
  sources: DataSourceAttributionEntry[]
  // Model used
  attributionModel: DataAttributionModel
  // Totals
  totalSources: number
  totalAccessEvents: number
  totalCompensation: number
  currency: string
  // Cryptographic commitment
  merkleRoot: string            // Merkle root of all backing access receipt IDs
  entriesHash: string           // SHA-256 of canonical entries
  // Metadata
  generatedAt: string
  generatedBy: string           // public key of generator
  signature: string
}
