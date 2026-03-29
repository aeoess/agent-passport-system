// examples/crewai-governance.ts
// ─────────────────────────────────────────────────────────────────
// CrewAI + Agent Passport System — Governance in 5 minutes
//
// This example shows how to add cryptographic governance to a CrewAI
// crew. Every task gets scoped delegation, spend controls, and
// a signed audit receipt. Takes 10 lines of APS code.
//
// Prerequisites:
//   npm install agent-passport-system crewai-js  (or use Python)
//
// Run: npx tsx examples/crewai-governance.ts
// ─────────────────────────────────────────────────────────────────

import {
  generateKeyPair,
  createCrewAIGovernance,
} from 'agent-passport-system'

// ═══════════════════════════════════════════════════════════════
// STEP 1: Create identity + delegation (one-time setup)
// ═══════════════════════════════════════════════════════════════

// In production: load from persistent storage. Here we generate fresh.
const principal = generateKeyPair()  // The human (you)
const agent = generateKeyPair()      // The CrewAI agent

// What this agent is allowed to do:
const gov = createCrewAIGovernance({
  agentId: 'crewai-research-agent',
  agentPublicKey: agent.publicKey,
  agentPrivateKey: agent.privateKey,
  delegationId: 'del_research_2026',
  allowedScopes: [
    'tool:web_search',       // Can search the web
    'tool:read_file',        // Can read files
    'task:execute',          // Can complete tasks
  ],
  spendLimitPerAction: 5.00, // Max $5 per action
})

console.log('Agent passport created.')
console.log(`  Agent ID: crewai-research-agent`)
console.log(`  Public key: ${agent.publicKey.slice(0, 24)}...`)
console.log(`  Allowed scopes: web_search, read_file, task:execute`)
console.log(`  Spend limit: $5.00 per action\n`)

// ═══════════════════════════════════════════════════════════════
// STEP 2: Wrap tool calls with governance
// ═══════════════════════════════════════════════════════════════

// Simulated tool functions (replace with real CrewAI tools)
async function webSearch(query: string): Promise<string> {
  return `Results for "${query}": [3 articles found]`
}

async function sendEmail(to: string, body: string): Promise<string> {
  return `Email sent to ${to}`
}

// ── Permitted tool call ──
console.log('── Attempting web_search (permitted) ──')
const searchResult = await gov.governedToolCall(
  'web_search',
  { query: 'AI agent governance standards 2026' },
  () => webSearch('AI agent governance standards 2026'),
  0.01  // $0.01 estimated cost
)
console.log(`  Verdict: ${searchResult.governance.verdict}`)
console.log(`  Result: ${searchResult.result}`)
console.log(`  Receipt ID: ${searchResult.receipt.receiptId}`)
console.log(`  Signed: ${searchResult.receipt.signature.slice(0, 24)}...\n`)

// ── Denied tool call (not in allowed scopes) ──
console.log('── Attempting send_email (NOT in allowed scopes) ──')
const emailResult = await gov.governedToolCall(
  'send_email',
  { to: 'ceo@company.com', body: 'Quarterly report attached' },
  () => sendEmail('ceo@company.com', 'Quarterly report attached'),
)
console.log(`  Verdict: ${emailResult.governance.verdict}`)
console.log(`  Result: ${emailResult.result}`)  // null — action blocked
console.log(`  Reason: ${emailResult.governance.reason}`)
console.log(`  Receipt ID: ${emailResult.receipt.receiptId}`)
console.log(`  (Denial is also receipted — full audit trail)\n`)

// ── Over-budget tool call ──
console.log('── Attempting expensive action ($50, limit is $5) ──')
const expensiveResult = await gov.governedToolCall(
  'web_search',
  { query: 'premium data source' },
  () => webSearch('premium data source'),
  50.00  // $50 — over the $5 limit
)
console.log(`  Verdict: ${expensiveResult.governance.verdict}`)
console.log(`  Reason: ${expensiveResult.governance.reason}\n`)

// ═══════════════════════════════════════════════════════════════
// STEP 3: Task completion callback (use in CrewAI task config)
// ═══════════════════════════════════════════════════════════════

console.log('── Task completion callback ──')
const taskReceipt = gov.taskCallback({
  description: 'Research AI governance standards and summarize findings',
  result: 'Found 3 key standards: APS, AIP, DAAP. APS has the most complete implementation.',
  agent: 'research-agent',
})
console.log(`  Task receipted: ${taskReceipt.receiptId}`)
console.log(`  Verdict: ${taskReceipt.verdict}`)
console.log(`  Duration: ${taskReceipt.durationMs}ms\n`)

// ═══════════════════════════════════════════════════════════════
// STEP 4: Audit trail — all receipts from this session
// ═══════════════════════════════════════════════════════════════

console.log('── Session audit trail ──')
const receipts = gov.getReceipts()
console.log(`  Total receipts: ${receipts.length}`)
receipts.forEach((r, i) => {
  console.log(`  ${i + 1}. ${r.action.type} → ${r.verdict} (${r.executionResult})`)
})

// Verify any receipt
const verified = gov.hook.verifyReceipt(receipts[0])
console.log(`\n  Receipt #1 signature valid: ${verified}`)
console.log(`  Total spend: $${gov.hook.getTotalSpend().toFixed(2)}`)

console.log('\n═══════════════════════════════════════════════════════════════')
console.log(' What just happened:')
console.log('═══════════════════════════════════════════════════════════════')
console.log(' 1. Agent got a cryptographic identity (Ed25519 keypair)')
console.log(' 2. Delegation scoped to: web_search, read_file, task:execute')
console.log(' 3. Spend limit set at $5 per action')
console.log(' 4. web_search → PERMITTED (in scope, under budget)')
console.log(' 5. send_email → DENIED (not in allowed scopes)')
console.log(' 6. expensive search → DENIED (over spend limit)')
console.log(' 7. Task completion → receipted with signed proof')
console.log(' 8. Every action — permitted or denied — has a signed receipt')
console.log(' 9. Receipts are cryptographically verifiable')
console.log('')
console.log(' This is governance for the agent economy.')
console.log(' npm install agent-passport-system')
console.log(' https://aeoess.com')
