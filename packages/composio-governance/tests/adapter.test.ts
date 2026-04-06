// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for @aeoess/composio-governance

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  createPassport,
  createDelegation,
  generateKeyPair,
  createDefaultRecoveryPolicy,
  verify,
  canonicalize,
} from 'agent-passport-system'
import type { ActionReceipt } from 'agent-passport-system'

import {
  governComposioAction,
  governComposioToolkit,
  type ComposioAction,
  type DenialEvent,
} from '../src/index.js'

// ── Helpers ──

function setup(scopes: string[] = ['salesforce:read', 'salesforce:update', 'slack:post', 'github:create']) {
  const principalKeys = generateKeyPair()
  const agentKeys = generateKeyPair()

  const { signedPassport } = createPassport({
    agentId: 'agent-test-composio-pkg',
    agentName: 'Test Agent',
    ownerAlias: 'tima',
    mission: 'Test composio governance package',
    capabilities: ['tools'],
    runtime: { platform: 'node', version: process.version },
  })

  const delegation = createDelegation({
    delegatedTo: agentKeys.publicKey,
    delegatedBy: principalKeys.publicKey,
    scope: scopes,
    privateKey: principalKeys.privateKey,
    spendLimit: 0,
  })

  return { signedPassport, delegation, agentKeys, principalKeys }
}

function mockTool(name: string, result: unknown = { ok: true }): ComposioAction {
  return { name, description: `Mock ${name}`, execute: async () => result }
}

function failingTool(name: string, error: string): ComposioAction {
  return { name, description: `Failing ${name}`, execute: async () => { throw new Error(error) } }
}

describe('@aeoess/composio-governance', () => {
  describe('Permitted actions', () => {
    it('produces receipt with correct scope for permitted action', async () => {
      const { signedPassport, delegation, agentKeys } = setup()
      const receipts: ActionReceipt[] = []

      const governed = governComposioAction({
        passport: signedPassport,
        delegation,
        privateKey: agentKeys.privateKey,
        action: mockTool('SALESFORCE_READ_ACCOUNT', { id: 'acc_001' }),
        onReceipt: (r) => receipts.push(r),
      })

      const result = await governed.execute({ accountId: 'acc_001' })
      assert.ok('result' in result && !('denied' in result))
      assert.deepStrictEqual(result.result, { id: 'acc_001' })
      assert.equal(receipts.length, 1)
      assert.equal(receipts[0].action.scopeUsed, 'salesforce:read')
      assert.ok(receipts[0].signature)

      // Verify signature
      const { signature, ...rest } = receipts[0]
      const valid = verify(canonicalize(rest), signature, agentKeys.publicKey)
      assert.ok(valid)
    })
  })

  describe('Denied actions', () => {
    it('produces denial receipt with reason when scope not covered', async () => {
      const { signedPassport, delegation, agentKeys } = setup(['salesforce:read'])
      const denials: DenialEvent[] = []

      const governed = governComposioAction({
        passport: signedPassport,
        delegation,
        privateKey: agentKeys.privateKey,
        action: mockTool('SLACK_POST_MESSAGE'),
        onDenied: (e) => denials.push(e),
      })

      const result = await governed.execute({ channel: '#general' })
      assert.ok('denied' in result && result.denied === true)
      assert.ok(result.reason.includes('slack:post'))
      assert.ok(result.reason.includes('not covered'))
      assert.ok(result.denialReceipt.receiptId)
      assert.equal(denials.length, 1)
    })
  })

  describe('Batch governance', () => {
    it('wraps all tools', () => {
      const { signedPassport, delegation, agentKeys } = setup()

      const governed = governComposioToolkit({
        passport: signedPassport,
        delegation,
        privateKey: agentKeys.privateKey,
        tools: [
          mockTool('SALESFORCE_READ_ACCOUNT'),
          mockTool('SLACK_POST_MESSAGE'),
          mockTool('GITHUB_CREATE_PR'),
        ],
      })

      assert.equal(governed.length, 3)
      assert.ok(governed[0].description.startsWith('[APS Governed]'))
      assert.ok(governed[1].description.startsWith('[APS Governed]'))
      assert.ok(governed[2].description.startsWith('[APS Governed]'))
    })
  })

  describe('Destructive action gating', () => {
    it('permits destructive with explicit delete scope, blocks without', async () => {
      const { signedPassport, delegation, agentKeys } = setup(['salesforce:delete'])
      const governed = governComposioAction({
        passport: signedPassport, delegation, privateKey: agentKeys.privateKey,
        action: mockTool('SALESFORCE_DELETE_RECORD'),
      })
      const result = await governed.execute({ recordId: 'rec_001' })
      assert.ok('result' in result && !('denied' in result))

      // Without delete scope
      const { signedPassport: p2, delegation: d2, agentKeys: k2 } = setup(['salesforce:read'])
      const governed2 = governComposioAction({
        passport: p2, delegation: d2, privateKey: k2.privateKey,
        action: mockTool('SALESFORCE_DELETE_RECORD'),
      })
      const result2 = await governed2.execute({})
      assert.ok('denied' in result2 && result2.denied === true)
    })

    it('permits destructive action with explicit admin scope', async () => {
      const { signedPassport, delegation, agentKeys } = setup(['salesforce:read', 'salesforce:delete'])
      const governed = governComposioAction({
        passport: signedPassport, delegation, privateKey: agentKeys.privateKey,
        action: mockTool('SALESFORCE_DELETE_RECORD'),
      })
      const result = await governed.execute({})
      assert.ok('result' in result && !('denied' in result))
    })

    it('flags all destructive verbs', async () => {
      const { signedPassport, delegation, agentKeys } = setup(['db:read'])
      for (const name of ['DB_DESTROY_TABLE', 'DB_DROP_INDEX', 'DB_REMOVE_ROW', 'DB_PURGE_CACHE', 'DB_WIPE_DATA', 'DB_TRUNCATE_TABLE']) {
        const governed = governComposioAction({
          passport: signedPassport, delegation, privateKey: agentKeys.privateKey,
          action: mockTool(name),
        })
        const result = await governed.execute({})
        assert.ok('denied' in result, `${name} should be denied`)
      }
    })
  })

  describe('Recovery policy on tool_error', () => {
    it('consults recovery policy when tool execution fails', async () => {
      const { signedPassport, delegation, agentKeys } = setup()
      const denials: DenialEvent[] = []

      const governed = governComposioAction({
        passport: signedPassport,
        delegation,
        privateKey: agentKeys.privateKey,
        action: failingTool('SALESFORCE_READ_ACCOUNT', 'Connection timeout'),
        recoveryPolicy: createDefaultRecoveryPolicy(),
        onDenied: (e) => denials.push(e),
      })

      const result = await governed.execute({ accountId: 'acc_001' })
      assert.ok('result' in result)
      assert.ok('receipt' in result)
      assert.equal(denials.length, 1)
      assert.ok(denials[0].reason.includes('Recovery strategy'))
    })
  })
})
