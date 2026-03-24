// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  GovernanceHook,
  createCrewAIGovernance,
  createADKGovernancePlugin,
  createLangChainGovernanceHandler,
  createA2AGovernance,
} from '../src/index.js'
import type { GovernanceHookConfig, ActionDescriptor, A2AAgentCard } from '../src/index.js'

const keys = generateKeyPair()

function makeConfig(overrides?: Partial<GovernanceHookConfig>): GovernanceHookConfig {
  return {
    agentId: 'test-agent',
    agentPublicKey: keys.publicKey,
    agentPrivateKey: keys.privateKey,
    delegationId: 'del-001',
    allowedScopes: ['data:read', 'tool:search', 'commerce:checkout'],
    ...overrides,
  }
}

// ═══════════════════════════════════════
// GovernanceHook — Core
// ═══════════════════════════════════════

describe('GovernanceHook — Core', () => {
  it('permits action within scope', () => {
    const hook = new GovernanceHook(makeConfig())
    const result = hook.beforeAction({ type: 'read', target: 'db', scopeRequired: 'data:read' })
    assert.equal(result.verdict, 'permit')
    assert.ok(result.intentId.startsWith('intent_'))
    assert.ok(result.reason.includes('authorized'))
  })

  it('denies action outside scope', () => {
    const hook = new GovernanceHook(makeConfig())
    const result = hook.beforeAction({ type: 'delete', target: 'db', scopeRequired: 'admin:delete' })
    assert.equal(result.verdict, 'deny')
    assert.ok(result.violations!.length > 0)
    assert.ok(result.violations![0].includes('admin:delete'))
  })

  it('supports wildcard scopes', () => {
    const hook = new GovernanceHook(makeConfig({ allowedScopes: ['data:*'] }))
    const result = hook.beforeAction({ type: 'read', target: 'db', scopeRequired: 'data:read' })
    assert.equal(result.verdict, 'permit')
  })

  it('denies when spend exceeds limit', () => {
    const hook = new GovernanceHook(makeConfig({ spendLimitPerAction: 100 }))
    const result = hook.beforeAction({
      type: 'purchase', target: 'store', scopeRequired: 'commerce:checkout', estimatedCost: 150,
    })
    assert.equal(result.verdict, 'deny')
    assert.ok(result.violations![0].includes('150'))
  })

  it('generates signed receipt after action', () => {
    const hook = new GovernanceHook(makeConfig())
    const action: ActionDescriptor = { type: 'read', target: 'db', scopeRequired: 'data:read' }
    const gov = hook.beforeAction(action)
    const receipt = hook.afterAction(gov, action, 'success', new Date().toISOString())
    assert.ok(receipt.receiptId.startsWith('rcpt_'))
    assert.equal(receipt.verdict, 'permit')
    assert.equal(receipt.executionResult, 'success')
    assert.ok(receipt.signature)
    assert.ok(receipt.durationMs >= 0)
  })

  it('receipt signature is verifiable', () => {
    const hook = new GovernanceHook(makeConfig())
    const action: ActionDescriptor = { type: 'read', target: 'db', scopeRequired: 'data:read' }
    const gov = hook.beforeAction(action)
    const receipt = hook.afterAction(gov, action, 'success', new Date().toISOString())
    assert.equal(hook.verifyReceipt(receipt), true)
  })

  it('wrap() governs async action end-to-end', async () => {
    const hook = new GovernanceHook(makeConfig())
    const action: ActionDescriptor = { type: 'search', target: 'api', scopeRequired: 'tool:search' }
    const { result, receipt, governance } = await hook.wrap(action, async () => 'search results')
    assert.equal(governance.verdict, 'permit')
    assert.equal(result, 'search results')
    assert.equal(receipt.executionResult, 'success')
  })

  it('wrap() blocks denied action without executing', async () => {
    const hook = new GovernanceHook(makeConfig())
    let executed = false
    const action: ActionDescriptor = { type: 'delete', target: 'db', scopeRequired: 'admin:nuke' }
    const { result, governance } = await hook.wrap(action, async () => { executed = true; return 'bad' })
    assert.equal(governance.verdict, 'deny')
    assert.equal(result, null)
    assert.equal(executed, false)
  })

  it('tracks cumulative spend', async () => {
    const hook = new GovernanceHook(makeConfig())
    const action: ActionDescriptor = { type: 'buy', target: 'store', scopeRequired: 'commerce:checkout', estimatedCost: 25 }
    await hook.wrap(action, async () => 'purchased')
    await hook.wrap(action, async () => 'purchased')
    assert.equal(hook.getTotalSpend(), 50)
    assert.equal(hook.getReceipts().length, 2)
  })
})

// ═══════════════════════════════════════
// CrewAI Adapter
// ═══════════════════════════════════════

describe('CrewAI Adapter', () => {
  it('taskCallback produces receipt', () => {
    const gov = createCrewAIGovernance(makeConfig({ allowedScopes: ['task:execute'] }))
    const receipt = gov.taskCallback({
      description: 'Research market trends', result: 'Report generated', agent: 'researcher',
    })
    assert.ok(receipt.receiptId)
    assert.equal(receipt.executionResult, 'success')
  })

  it('governedToolCall permits authorized tool', async () => {
    const gov = createCrewAIGovernance(makeConfig({ allowedScopes: ['tool:search'] }))
    const { result, governance } = await gov.governedToolCall(
      'search', { query: 'AI trends' }, async () => ['result1', 'result2'],
    )
    assert.equal(governance.verdict, 'permit')
    assert.deepEqual(result, ['result1', 'result2'])
  })

  it('governedToolCall blocks unauthorized tool', async () => {
    const gov = createCrewAIGovernance(makeConfig({ allowedScopes: ['tool:search'] }))
    const { result, governance } = await gov.governedToolCall(
      'database_delete', {}, async () => 'should not execute',
    )
    assert.equal(governance.verdict, 'deny')
    assert.equal(result, null)
  })

  it('accumulates receipts across calls', async () => {
    const gov = createCrewAIGovernance(makeConfig({ allowedScopes: ['tool:*'] }))
    await gov.governedToolCall('search', {}, async () => 'ok')
    await gov.governedToolCall('fetch', {}, async () => 'ok')
    gov.taskCallback({ description: 'done', result: 'complete', agent: 'a' })
    assert.equal(gov.getReceipts().length, 3)
  })
})

// ═══════════════════════════════════════
// ADK Adapter
// ═══════════════════════════════════════

describe('ADK GovernancePlugin Adapter', () => {
  it('before_action permits authorized tool', () => {
    const plugin = createADKGovernancePlugin(makeConfig({ allowedScopes: ['tool:*'] }))
    const result = plugin.before_action({
      tool_name: 'web_search', tool_input: { query: 'test' },
      agent_name: 'researcher', session_id: 'sess-1',
    })
    assert.equal(result.allowed, true)
  })

  it('before_action blocks unauthorized tool', () => {
    const plugin = createADKGovernancePlugin(makeConfig({ allowedScopes: ['tool:search'] }))
    const result = plugin.before_action({
      tool_name: 'delete_account', tool_input: {},
      agent_name: 'attacker', session_id: 'sess-2',
    })
    assert.equal(result.allowed, false)
  })

  it('after_action produces receipt linked to before_action', () => {
    const plugin = createADKGovernancePlugin(makeConfig({ allowedScopes: ['tool:*'] }))
    const ctx = { tool_name: 'search', tool_input: { q: 'test' }, agent_name: 'a' }
    plugin.before_action(ctx)
    const receipt = plugin.after_action(ctx, { results: ['a', 'b'] })
    assert.ok(receipt.receiptId)
    assert.equal(receipt.executionResult, 'success')
  })

  it('audit trail tracks all actions', () => {
    const plugin = createADKGovernancePlugin(makeConfig({ allowedScopes: ['tool:*'] }))
    const ctx1 = { tool_name: 'search', tool_input: {}, agent_name: 'a' }
    const ctx2 = { tool_name: 'fetch', tool_input: {}, agent_name: 'a' }
    plugin.before_action(ctx1)
    plugin.after_action(ctx1, 'ok')
    plugin.before_action(ctx2)
    plugin.after_action(ctx2, 'ok')
    assert.equal(plugin.get_audit_trail().length, 2)
  })
})

// ═══════════════════════════════════════
// LangChain Adapter
// ═══════════════════════════════════════

describe('LangChain GovernanceHandler Adapter', () => {
  it('on_tool_start → on_tool_end produces receipt', () => {
    const handler = createLangChainGovernanceHandler(makeConfig({ allowedScopes: ['tool:*'] }))
    const { allowed, intentId } = handler.on_tool_start('serpapi', '{"query":"test"}', 'run-1')
    assert.equal(allowed, true)
    assert.ok(intentId)
    const receipt = handler.on_tool_end('search results', 'run-1')
    assert.ok(receipt)
    assert.equal(receipt!.executionResult, 'success')
  })

  it('on_tool_error records failure', () => {
    const handler = createLangChainGovernanceHandler(makeConfig({ allowedScopes: ['tool:*'] }))
    handler.on_tool_start('flaky_api', '{}', 'run-2')
    const receipt = handler.on_tool_error('timeout', 'run-2')
    assert.ok(receipt)
    assert.equal(receipt!.executionResult, 'failure')
  })

  it('on_chain_start → on_chain_end produces receipt', () => {
    const handler = createLangChainGovernanceHandler(makeConfig({ allowedScopes: ['chain:*'] }))
    const { allowed } = handler.on_chain_start('RetrievalQA', { query: 'test' }, 'run-3')
    assert.equal(allowed, true)
    const receipt = handler.on_chain_end({ answer: 'response' }, 'run-3')
    assert.ok(receipt)
    assert.equal(receipt!.executionResult, 'success')
  })

  it('blocks unauthorized tool at on_tool_start', () => {
    const handler = createLangChainGovernanceHandler(makeConfig({ allowedScopes: ['tool:search'] }))
    const { allowed } = handler.on_tool_start('rm_rf', '{}', 'run-4')
    assert.equal(allowed, false)
    // No pending intent — on_tool_end returns null
    const receipt = handler.on_tool_end('', 'run-4')
    assert.equal(receipt, null)
  })
})

// ═══════════════════════════════════════
// A2A Adapter
// ═══════════════════════════════════════

describe('A2A Adapter', () => {
  const mockCard: A2AAgentCard = {
    name: 'Research Agent', description: 'Finds things', url: 'https://agent.example.com',
    version: '1.0',
    capabilities: { streaming: true, pushNotifications: false },
    defaultInputModes: ['text/plain'], defaultOutputModes: ['text/plain'],
    skills: [
      { id: 'web_search', name: 'Web Search', description: 'Search the web' },
      { id: 'summarize', name: 'Summarize', description: 'Summarize text' },
    ],
  }

  it('deriveScopes maps skills to scopes', () => {
    const gov = createA2AGovernance(makeConfig({ allowedScopes: ['a2a:*'] }))
    const scopes = gov.deriveScopes(mockCard)
    assert.ok(scopes.includes('a2a:skill:web_search'))
    assert.ok(scopes.includes('a2a:skill:summarize'))
    assert.ok(scopes.includes('a2a:streaming'))
    assert.ok(!scopes.includes('a2a:push'))
  })

  it('governTaskSend permits authorized task', async () => {
    const gov = createA2AGovernance(makeConfig({ allowedScopes: ['a2a:*'] }))
    const { result, governance } = await gov.governTaskSend(
      mockCard, 'Find recent AI papers', async () => ({ papers: ['paper1', 'paper2'] }),
    )
    assert.equal(governance.verdict, 'permit')
    assert.deepEqual(result, { papers: ['paper1', 'paper2'] })
  })

  it('governTaskReceive permits authorized receive', async () => {
    const gov = createA2AGovernance(makeConfig({ allowedScopes: ['a2a:*'] }))
    const { result, governance } = await gov.governTaskReceive(
      'https://sender.example.com', 'Process this data', async () => 'processed',
    )
    assert.equal(governance.verdict, 'permit')
    assert.equal(result, 'processed')
  })

  it('blocks task when scope insufficient', async () => {
    const gov = createA2AGovernance(makeConfig({ allowedScopes: ['data:read'] }))
    const { result, governance } = await gov.governTaskSend(
      mockCard, 'Do something', async () => 'should not run',
    )
    assert.equal(governance.verdict, 'deny')
    assert.equal(result, null)
  })
})
