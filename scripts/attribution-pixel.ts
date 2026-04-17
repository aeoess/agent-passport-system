#!/usr/bin/env npx tsx
// ══════════════════════════════════════════════════════════════════════
// Attribution Pixel — End-to-End Demo
// ══════════════════════════════════════════════════════════════════════
// "AppsFlyer for AI agent data"
//
// This script demonstrates the complete attribution loop:
// 1. Register 3 data sources with different compensation terms
// 2. Agent accesses all 3 through the gateway
// 3. Agent produces an output
// 4. Compute fractional data source attribution
// 5. Generate settlement (who's owed what)
// 6. Generate compliance report
// 7. Verify everything cryptographically
// ══════════════════════════════════════════════════════════════════════

import { generateKeyPair } from '../src/crypto/keys.js'
import { registerSelfAttestedSource } from '../src/core/data-source.js'
import { createContributionLedger, recordContribution,
  getSourceMetrics, getAgentDataFootprint } from '../src/core/data-contribution.js'
import { generateSettlement, verifySettlement,
  generateDataComplianceReport } from '../src/core/data-settlement.js'
import { computeDataSourceAttribution,
  verifyDataSourceAttribution } from '../src/core/data-source-attribution.js'
import type { DataAccessReceipt } from '../src/types/data-source.js'

// ── Setup: Generate keys for all participants ──
const gateway = generateKeyPair()
const publisher = generateKeyPair()
const agent = generateKeyPair()

console.log('═══════════════════════════════════════════')
console.log('  ATTRIBUTION PIXEL — Full Loop Demo')
console.log('═══════════════════════════════════════════\n')

// ── Step 1: Register 3 data sources ──
console.log('STEP 1: Register data sources\n')

const sources = [
  registerSelfAttestedSource({
    ownerPrincipalId: 'principal_nyt',
    ownerPublicKey: publisher.publicKey,
    ownerPrivateKey: publisher.privateKey,
    contentCommitment: 'sha256_nyt_archive_2026',
    contentType: 'structured_data',
    contentDescriptor: 'NYT News Archive',
    dataTerms: {
      allowedPurposes: ['inference:decision_support', 'analytics:internal'],
      requireAttribution: true,
      requireNotification: false,
      compensation: { type: 'per_access', amount: 0.10, currency: 'usd' },
      derivativePolicy: 'attribution_required',
      auditVisibility: 'source_and_principal',
      revocable: true,
    },
  }),
  registerSelfAttestedSource({
    ownerPrincipalId: 'principal_reuters',
    ownerPublicKey: publisher.publicKey,
    ownerPrivateKey: publisher.privateKey,
    contentCommitment: 'sha256_reuters_feed_2026',
    contentType: 'structured_data',
    contentDescriptor: 'Reuters Financial Feed',
    dataTerms: {
      allowedPurposes: ['inference:decision_support'],
      requireAttribution: true,
      requireNotification: true,
      compensation: { type: 'per_access', amount: 0.25, currency: 'usd' },
      derivativePolicy: 'same_terms',
      auditVisibility: 'source_and_principal',
      revocable: true,
    },
  }),
  registerSelfAttestedSource({
    ownerPrincipalId: 'principal_openresearch',
    ownerPublicKey: publisher.publicKey,
    ownerPrivateKey: publisher.privateKey,
    contentCommitment: 'sha256_open_research_2026',
    contentType: 'structured_data',
    contentDescriptor: 'Open Research Papers (CC-BY)',
    dataTerms: {
      allowedPurposes: ['inference:decision_support', 'research:academic'],
      requireAttribution: true,
      requireNotification: false,
      compensation: { type: 'attribution_only' },
      derivativePolicy: 'unrestricted',
      auditVisibility: 'public',
      revocable: false,
    },
  }),
]

for (const s of sources) {
  console.log(`  ✓ ${s.contentDescriptor} [${s.sourceReceiptId.slice(0, 12)}...] — ${s.dataTerms.compensation.type}`)
}

// ── Step 2: Agent accesses data through the gateway ──
console.log('\nSTEP 2: Agent accesses data through gateway\n')

function createAccessReceipt(sourceReceipt: any, accessCount: number): DataAccessReceipt[] {
  const receipts: DataAccessReceipt[] = []
  for (let i = 0; i < accessCount; i++) {
    receipts.push({
      accessReceiptId: 'dacr_' + Math.random().toString(36).slice(2, 14),
      sourceReceiptId: sourceReceipt.sourceReceiptId,
      sourceMode: sourceReceipt.sourceMode,
      dataHash: 'sha256_' + Math.random().toString(36).slice(2, 14),
      agentId: 'agent_research_bot',
      agentPublicKey: agent.publicKey,
      principalId: 'principal_acme_corp',
      executionFrameId: 'frame_' + Math.random().toString(36).slice(2, 8),
      accessScope: 'read',
      accessMethod: 'api_call',
      declaredPurpose: 'inference:decision_support',
      termsAtAccessTime: sourceReceipt.dataTerms,
      timestamp: new Date().toISOString(),
      gatewayId: 'gateway_main',
      gatewayPublicKey: gateway.publicKey,
      gatewaySignature: 'gw_sig_' + Math.random().toString(36).slice(2, 8),
    })
  }
  return receipts
}

// Simulate: NYT accessed 5 times, Reuters 2 times, Open Research 3 times
const nytReceipts = createAccessReceipt(sources[0], 5)
const reutersReceipts = createAccessReceipt(sources[1], 2)
const openReceipts = createAccessReceipt(sources[2], 3)
const allReceipts = [...nytReceipts, ...reutersReceipts, ...openReceipts]

console.log(`  ✓ NYT News Archive: ${nytReceipts.length} accesses @ $0.10/access`)
console.log(`  ✓ Reuters Financial Feed: ${reutersReceipts.length} accesses @ $0.25/access`)
console.log(`  ✓ Open Research Papers: ${openReceipts.length} accesses (attribution only)`)
console.log(`  Total: ${allReceipts.length} access receipts generated`)

// ── Step 3: Record contributions in the ledger ──
console.log('\nSTEP 3: Record contributions in ledger\n')

const ledger = createContributionLedger()
for (const r of nytReceipts) recordContribution(ledger, r, 'NYT News Archive')
for (const r of reutersReceipts) recordContribution(ledger, r, 'Reuters Financial Feed')
for (const r of openReceipts) recordContribution(ledger, r, 'Open Research Papers (CC-BY)')

console.log(`  ✓ Ledger has ${ledger.records.size} contribution records`)


// ── Step 4: Compute Data Source Attribution ──
console.log('\nSTEP 4: Compute data source attribution\n')

const descriptors = new Map([
  [sources[0].sourceReceiptId, 'NYT News Archive'],
  [sources[1].sourceReceiptId, 'Reuters Financial Feed'],
  [sources[2].sourceReceiptId, 'Open Research Papers (CC-BY)'],
])

// Note: 'access_weighted' policy lives in @aeoess/gateway
// (src/sdk-migrated/core/attribution-models.ts) — the SDK demo here
// uses model='equal' to keep the script self-contained and free of
// gateway product policy.
const attribution = computeDataSourceAttribution({
  outputArtifactId: 'decision_market_analysis_q1_2026',
  outputType: 'decision',
  accessReceipts: allReceipts,
  sourceDescriptors: descriptors,
  model: 'equal',
  generatorPublicKey: gateway.publicKey,
  generatorPrivateKey: gateway.privateKey,
})

console.log(`  Report: ${attribution.reportId}`)
console.log(`  Model: ${attribution.attributionModel}`)
console.log(`  Output: ${attribution.outputArtifactId}`)
console.log('')
console.log('  ┌─────────────────────────────────┬────────┬──────────┬───────────┐')
console.log('  │ Data Source                      │ Access │ Share    │ Owed      │')
console.log('  ├─────────────────────────────────┼────────┼──────────┼───────────┤')
for (const s of attribution.sources) {
  const name = (s.sourceDescriptor || s.sourceReceiptId).padEnd(33)
  const count = String(s.accessCount).padStart(6)
  const pct = (s.percentage.toFixed(1) + '%').padStart(8)
  const owed = ('$' + s.compensationOwed.toFixed(2)).padStart(9)
  console.log(`  │ ${name}│${count} │${pct} │${owed} │`)
}
console.log('  └─────────────────────────────────┴────────┴──────────┴───────────┘')
console.log(`\n  Total compensation: $${attribution.totalCompensation.toFixed(2)}`)
console.log(`  Merkle root: ${attribution.merkleRoot.slice(0, 16)}...`)

// ── Step 5: Verify attribution cryptographically ──
console.log('\nSTEP 5: Verify attribution report\n')

const verification = verifyDataSourceAttribution(attribution, gateway.publicKey)
console.log(`  Signature valid: ${verification.valid ? '✓' : '✗'}`)
if (verification.errors.length > 0) {
  for (const e of verification.errors) console.log(`  ✗ ${e}`)
} else {
  console.log('  ✓ Entries hash verified')
  console.log('  ✓ Merkle root verified')
  console.log('  ✓ Percentages sum to 100%')
  console.log('  ✓ All counts consistent')
}

// ── Step 6: Generate Settlement ──
console.log('\nSTEP 6: Generate settlement record\n')

const period = {
  startDate: '2026-03-01T00:00:00Z',
  endDate: '2026-03-31T23:59:59Z',
  periodLabel: '2026-03',
}
const settlement = generateSettlement(ledger, period, gateway.publicKey, gateway.privateKey)
const settlementVerification = verifySettlement(settlement)

console.log(`  Settlement: ${settlement.settlementId}`)
console.log(`  Period: ${settlement.period.periodLabel}`)
console.log(`  Line items: ${settlement.lineItems.length}`)
console.log(`  Total owed: $${settlement.totalAmount.toFixed(2)}`)
console.log(`  Total accesses: ${settlement.totalAccesses}`)
console.log(`  Unique sources: ${settlement.uniqueSources}`)
console.log(`  Merkle root: ${settlement.merkleRoot.slice(0, 16)}...`)
console.log(`  Verified: ${settlementVerification.valid ? '✓' : '✗'}`)

// ── Step 7: Generate Compliance Report ──
console.log('\nSTEP 7: Generate EU AI Act compliance report\n')

const compliance = generateDataComplianceReport(
  ledger, period, 'euai_article10', gateway.privateKey,
)

console.log(`  Report: ${compliance.reportId}`)
console.log(`  Type: ${compliance.reportType}`)
console.log(`  Total data accesses: ${compliance.summary.totalDataAccesses}`)
console.log(`  Unique data sources: ${compliance.summary.uniqueDataSources}`)
console.log(`  Compensation owed: $${compliance.summary.compensationSummary.total.toFixed(2)}`)
console.log(`  Terms violations: ${compliance.summary.termsViolations}`)

// ── Source Metrics (data owner's dashboard view) ──
console.log('\n─── DATA OWNER DASHBOARD ───\n')

for (const source of sources) {
  const metrics = getSourceMetrics(ledger, source.sourceReceiptId)
  if (!metrics) continue
  console.log(`  📊 ${metrics.sourceDescriptor || source.contentDescriptor}`)
  console.log(`     Accesses: ${metrics.totalAccesses}`)
  console.log(`     Unique agents: ${metrics.uniqueAgents}`)
  console.log(`     Owed: $${metrics.compensationOwed.totalOwed.toFixed(2)}`)
  console.log('')
}

// ── Agent Footprint (agent operator's compliance view) ──
console.log('─── AGENT OPERATOR COMPLIANCE VIEW ───\n')

const footprint = getAgentDataFootprint(ledger, 'agent_research_bot')
if (footprint) {
  console.log(`  Agent: ${footprint.agentId}`)
  console.log(`  Sources accessed: ${footprint.totalSources}`)
  console.log(`  Total accesses: ${footprint.totalAccesses}`)
  console.log(`  Total compensation accrued: $${footprint.totalCompensationAccrued.toFixed(2)}`)
}

console.log('\n═══════════════════════════════════════════')
console.log('  ATTRIBUTION PIXEL — Complete')
console.log('  Every step cryptographically signed.')
console.log('  Every receipt Merkle-committed.')
console.log('  Every claim independently verifiable.')
console.log('═══════════════════════════════════════════\n')
