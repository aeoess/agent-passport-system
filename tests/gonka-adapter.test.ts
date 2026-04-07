// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createPassport, createDelegation, verify, canonicalize,
  verifyGonkaHost, governGonkaInference, createDevshardReceipt,
  delegationToAllowlistEntry, epochToDelegationExpiry, verifyPoCParticipation,
} from '../src/index.js'
import type { ActionReceipt, GonkaInferenceRequest } from '../src/index.js'

const pk = generateKeyPair()
const ak = generateKeyPair()
const { signedPassport } = createPassport({
  agentId: 'gonka1-host-test', agentName: 'Gonka Test Host', ownerAlias: 'tima',
  mission: 'GPU inference host', capabilities: ['inference'], runtime: { platform: 'node', version: process.version },
})
function mkDel(scopes: string[]) {
  return createDelegation({ delegatedTo: ak.publicKey, delegatedBy: pk.publicKey, scope: scopes, privateKey: pk.privateKey })
}
const mockInfer = async (_req: GonkaInferenceRequest) => ({ response: 'Hello world', tokensUsed: 42 })

describe('Gonka Adapter', () => {
  describe('verifyGonkaHost', () => {
    it('host authorized for model', () => {
      const r = verifyGonkaHost('gonka1-host-1', 'Qwen/Qwen3-235B', {
        passport: signedPassport, delegation: mkDel(['inference:serve:Qwen/Qwen3-235B']), privateKey: ak.privateKey,
      })
      assert.equal(r.authorized, true)
      assert.equal(r.model, 'Qwen/Qwen3-235B')
    })

    it('host denied (wrong model)', () => {
      const r = verifyGonkaHost('gonka1-host-1', 'llama-405b', {
        passport: signedPassport, delegation: mkDel(['inference:serve:Qwen/Qwen3-235B']), privateKey: ak.privateKey,
      })
      assert.equal(r.authorized, false)
      assert.ok(r.reason.includes('not covered'))
    })

    it('host denied (expired delegation)', () => {
      const del = { ...mkDel(['inference:serve:Qwen/Qwen3-235B']), expiresAt: new Date(Date.now() - 1000).toISOString() }
      const r = verifyGonkaHost('gonka1-host-1', 'Qwen/Qwen3-235B', {
        passport: signedPassport, delegation: del, privateKey: ak.privateKey,
      })
      assert.equal(r.authorized, false)
    })

    it('host denied (model not in allowlist)', () => {
      const r = verifyGonkaHost('gonka1-host-1', 'llama-405b', {
        passport: signedPassport, delegation: mkDel(['inference:serve:llama-405b']), privateKey: ak.privateKey,
        allowedModels: ['Qwen/Qwen3-235B'],
      })
      assert.equal(r.authorized, false)
      assert.ok(r.reason.includes('not in allowed models'))
    })

    it('empty model allowlist permits all models', () => {
      const r = verifyGonkaHost('gonka1-host-1', 'any-model', {
        passport: signedPassport, delegation: mkDel(['inference:serve:any-model']), privateKey: ak.privateKey,
        allowedModels: [],
      })
      assert.equal(r.authorized, true)
    })

    it('multiple models in scope', () => {
      const del = mkDel(['inference:serve:model-a', 'inference:serve:model-b'])
      const r1 = verifyGonkaHost('h1', 'model-a', { passport: signedPassport, delegation: del, privateKey: ak.privateKey })
      const r2 = verifyGonkaHost('h1', 'model-b', { passport: signedPassport, delegation: del, privateKey: ak.privateKey })
      const r3 = verifyGonkaHost('h1', 'model-c', { passport: signedPassport, delegation: del, privateKey: ak.privateKey })
      assert.ok(r1.authorized)
      assert.ok(r2.authorized)
      assert.ok(!r3.authorized)
    })
  })

  describe('governGonkaInference', () => {
    it('authorized inference produces receipt with inferenceHash', async () => {
      const receipts: ActionReceipt[] = []
      const r = await governGonkaInference(
        { model: 'Qwen/Qwen3-235B', prompt: 'What is APS?', epochId: 155 },
        mockInfer,
        { passport: signedPassport, delegation: mkDel(['inference:serve:Qwen/Qwen3-235B']), privateKey: ak.privateKey, onReceipt: r => receipts.push(r) },
      )
      assert.ok('result' in r && !('denied' in r))
      assert.equal(r.result.tokensUsed, 42)
      assert.equal(r.receipt.model, 'Qwen/Qwen3-235B')
      assert.equal(r.receipt.epochId, 155)
      assert.ok(r.receipt.inferenceHash.length === 64)
      assert.equal(receipts.length, 1)
    })

    it('denied inference (scope violation)', async () => {
      const r = await governGonkaInference(
        { model: 'forbidden-model', prompt: 'test' },
        mockInfer,
        { passport: signedPassport, delegation: mkDel(['inference:serve:Qwen/Qwen3-235B']), privateKey: ak.privateKey },
      )
      assert.ok('denied' in r && r.denied === true)
      assert.ok(r.reason.includes('not covered'))
    })

    it('denied inference (model not in allowlist)', async () => {
      const r = await governGonkaInference(
        { model: 'Qwen/Qwen3-235B', prompt: 'test' },
        mockInfer,
        { passport: signedPassport, delegation: mkDel(['inference:serve:Qwen/Qwen3-235B']), privateKey: ak.privateKey, allowedModels: ['other-model'] },
      )
      assert.ok('denied' in r && r.denied === true)
    })

    it('rate limit enforcement (maxInferencesPerEpoch)', async () => {
      const cfg = {
        passport: signedPassport,
        delegation: mkDel(['inference:serve:rate-test']),
        privateKey: ak.privateKey,
        maxInferencesPerEpoch: 2,
      }
      const req = { model: 'rate-test', prompt: 'test', epochId: 9999 }

      const r1 = await governGonkaInference(req, mockInfer, cfg)
      assert.ok('result' in r1 && !('denied' in r1))
      const r2 = await governGonkaInference(req, mockInfer, cfg)
      assert.ok('result' in r2 && !('denied' in r2))
      const r3 = await governGonkaInference(req, mockInfer, cfg)
      assert.ok('denied' in r3 && r3.denied === true)
      assert.ok(r3.reason.includes('Rate limit'))
    })

    it('onDenied callback fires', async () => {
      let fired = false
      await governGonkaInference(
        { model: 'nope', prompt: 'test' }, mockInfer,
        { passport: signedPassport, delegation: mkDel(['inference:serve:other']), privateKey: ak.privateKey, onDenied: () => { fired = true } },
      )
      assert.ok(fired)
    })

    it('onReceipt callback fires', async () => {
      let fired = false
      await governGonkaInference(
        { model: 'cb-test', prompt: 'test' }, mockInfer,
        { passport: signedPassport, delegation: mkDel(['inference:serve:cb-test']), privateKey: ak.privateKey, onReceipt: () => { fired = true } },
      )
      assert.ok(fired)
    })
  })

  describe('createDevshardReceipt', () => {
    it('creates receipt with participants', () => {
      const r = createDevshardReceipt('shard-001', 50, 12000, ['host-a', 'host-b', 'host-c'], {
        passport: signedPassport, delegation: mkDel(['devshard:participate']), privateKey: ak.privateKey,
      })
      assert.ok(r.receiptId.startsWith('rcpt_devshard_'))
      assert.equal(r.action.target, 'shard-001')
      assert.equal(r.delegationChain.length, 3)
      assert.ok(r.result.summary.includes('50 inferences'))
      assert.ok(r.result.summary.includes('12000 tokens'))
    })

    it('signature verifies', () => {
      const r = createDevshardReceipt('shard-002', 10, 5000, ['host-x'], {
        passport: signedPassport, delegation: mkDel(['devshard:participate']), privateKey: ak.privateKey,
      })
      const { signature, ...rest } = r
      assert.ok(verify(canonicalize(rest), signature, ak.publicKey))
    })
  })

  describe('delegationToAllowlistEntry', () => {
    it('converts delegation to allowlist entry', () => {
      const del = mkDel(['inference:serve:Qwen/Qwen3-235B', 'inference:validate'])
      const entry = delegationToAllowlistEntry(del, signedPassport)
      assert.equal(entry.address, 'gonka1-host-test')
      assert.equal(entry.model, 'Qwen/Qwen3-235B')
      assert.ok(entry.scope.includes('inference:serve:Qwen/Qwen3-235B'))
    })
  })

  describe('epochToDelegationExpiry', () => {
    it('calculates expiry from epoch timing', () => {
      const expiry = epochToDelegationExpiry(155, 100, 3)
      const now = new Date()
      // 100 blocks * 3 epochs * 6 seconds = 1800 seconds
      const diff = (expiry.getTime() - now.getTime()) / 1000
      assert.ok(diff > 1790 && diff < 1810, `Expected ~1800s, got ${diff}s`)
    })
  })

  describe('verifyPoCParticipation', () => {
    it('produces receipt', () => {
      const r = verifyPoCParticipation('gonka1-validator-1', 155, 0.85, {
        passport: signedPassport, privateKey: ak.privateKey,
      })
      assert.ok(r.receiptId.startsWith('rcpt_poc_'))
      assert.equal(r.action.type, 'poc_participation')
      assert.equal(r.action.target, 'gonka1-validator-1')
      assert.ok(r.result.summary.includes('epoch 155'))
      assert.ok(r.result.summary.includes('weight 0.85'))
    })

    it('signature verifies', () => {
      const r = verifyPoCParticipation('gonka1-val-2', 156, 0.9, {
        passport: signedPassport, privateKey: ak.privateKey,
      })
      const { signature, ...rest } = r
      assert.ok(verify(canonicalize(rest), signature, ak.publicKey))
    })
  })
})
