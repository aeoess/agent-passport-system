/**
 * Demo: APS Governance + Composio Tool Execution
 * Run: npx tsx examples/composio-governance/demo.ts
 */

import {
  createPassport,
  createDelegation,
  generateKeyPair,
} from 'agent-passport-system'

import {
  governComposioToolkit,
  type ComposioAction,
} from './composio-governance-adapter.js'

async function main() {
  // Set up principal (human) and agent keys
  const principalKeys = generateKeyPair()
  const agentKeys = generateKeyPair()

  const { signedPassport } = createPassport({
    agentId: 'agent-crm-assistant',
    agentName: 'CRM Assistant',
    ownerAlias: 'tima',
    mission: 'Manage CRM records and post team updates',
    capabilities: ['crm', 'messaging'],
    runtime: { platform: 'node', version: process.version },
  })

  const delegation = createDelegation({
    delegatedTo: agentKeys.publicKey,
    delegatedBy: principalKeys.publicKey,
    scope: ['salesforce:read', 'salesforce:update', 'slack:post', 'github:create'],
    privateKey: principalKeys.privateKey,
    spendLimit: 0,
  })

  // Mock Composio tools (any object with name, description, execute)
  const tools: ComposioAction[] = [
    {
      name: 'SALESFORCE_READ_ACCOUNT',
      description: 'Read a Salesforce account record',
      execute: async (params) => ({ id: 'acc_001', name: 'Acme Corp', ...params }),
    },
    {
      name: 'SALESFORCE_DELETE_RECORD',
      description: 'Delete a Salesforce record',
      execute: async (params) => ({ deleted: true, ...params }),
    },
    {
      name: 'SLACK_POST_MESSAGE',
      description: 'Post a message to a Slack channel',
      execute: async (params) => ({ ok: true, ts: '1234567890.123456', ...params }),
    },
    {
      name: 'GITHUB_CREATE_PR',
      description: 'Create a GitHub pull request',
      execute: async (params) => ({ number: 42, url: 'https://github.com/org/repo/pull/42', ...params }),
    },
    {
      name: 'GITHUB_DELETE_REPO',
      description: 'Delete a GitHub repository',
      execute: async (params) => ({ deleted: true, ...params }),
    },
  ]

  // Wrap all tools with APS governance
  const governed = governComposioToolkit({
    passport: signedPassport,
    delegation,
    privateKey: agentKeys.privateKey,
    tools,
    onDenied: (event) => {
      console.log(`  [DENIED] ${event.tool}: ${event.reason}`)
    },
    onReceipt: (receipt) => {
      console.log(`  [RECEIPT] ${receipt.receiptId}`)
    },
  })

  console.log('=== APS + Composio Governance Demo ===\n')

  // Scenario 1: Salesforce read (permitted)
  console.log('1. Salesforce read account (scope: salesforce:read)')
  const r1 = await governed[0].execute({ accountId: 'acc_001' })
  console.log(`   -> ${'result' in r1 ? 'Permitted' : 'Denied: ' + r1.reason}\n`)

  // Scenario 2: Salesforce delete (blocked: destructive, no delete scope)
  console.log('2. Salesforce delete record (scope: salesforce:delete, destructive)')
  const r2 = await governed[1].execute({ recordId: 'rec_001' })
  console.log(`   -> ${'result' in r2 ? 'Permitted' : 'Denied: ' + r2.reason}\n`)

  // Scenario 3: Slack post (permitted)
  console.log('3. Slack post message (scope: slack:post)')
  const r3 = await governed[2].execute({ channel: '#team', text: 'Deploy complete' })
  console.log(`   -> ${'result' in r3 ? 'Permitted' : 'Denied: ' + r3.reason}\n`)

  // Scenario 4: GitHub create PR (permitted)
  console.log('4. GitHub create PR (scope: github:create)')
  const r4 = await governed[3].execute({ title: 'Fix bug', base: 'main' })
  console.log(`   -> ${'result' in r4 ? 'Permitted' : 'Denied: ' + r4.reason}\n`)

  // Scenario 5: GitHub delete repo (blocked: destructive, no delete scope)
  console.log('5. GitHub delete repo (destructive, outside delegation)')
  const r5 = await governed[4].execute({ repo: 'org/repo' })
  console.log(`   -> ${'result' in r5 ? 'Permitted' : 'Denied: ' + r5.reason}\n`)

  console.log(`Total governed tools: ${governed.length}`)
}

main().catch(console.error)
