// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createPassport, createDelegation, verify, canonicalize,
  verifyCrewMember, governCrewTask, crewTaskToScopes,
} from '../src/index.js'
import type { ActionReceipt, CrewTask } from '../src/index.js'

const pk = generateKeyPair()
const ak = generateKeyPair()
const { signedPassport } = createPassport({
  agentId: 'agent-crew-test', agentName: 'Crew Test', ownerAlias: 'tima',
  mission: 'test', capabilities: ['crew'], runtime: { platform: 'node', version: process.version },
})
function mkDel(scopes: string[]) {
  return createDelegation({ delegatedTo: ak.publicKey, delegatedBy: pk.publicKey, scope: scopes, privateKey: pk.privateKey })
}
const mockExec = async (_task: CrewTask) => ({ result: 'done' })

describe('CrewAI Adapter v2', () => {
  it('crew member authorized for task', () => {
    const task: CrewTask = { description: 'Research', agent: 'researcher', tools: ['search'] }
    const r = verifyCrewMember('researcher', task, {
      passport: signedPassport, delegation: mkDel(['crew:execute:researcher', 'tools:search']), privateKey: ak.privateKey,
    })
    assert.equal(r.authorized, true)
  })

  it('crew member denied (scope mismatch)', () => {
    const task: CrewTask = { description: 'Delete', agent: 'admin', tools: ['rm'] }
    const r = verifyCrewMember('admin', task, {
      passport: signedPassport, delegation: mkDel(['crew:execute:researcher']), privateKey: ak.privateKey,
    })
    assert.equal(r.authorized, false)
  })

  it('crew member denied (expired delegation)', () => {
    const del = mkDel(['crew:execute:researcher'])
    del.expiresAt = new Date(Date.now() - 1000).toISOString()
    const task: CrewTask = { description: 'Research', agent: 'researcher' }
    const r = verifyCrewMember('researcher', task, {
      passport: signedPassport, delegation: del, privateKey: ak.privateKey,
    })
    assert.equal(r.authorized, false)
  })

  it('task with tools includes tool scopes', () => {
    const scopes = crewTaskToScopes({ description: 'X', agent: 'a', tools: ['search', 'browse'] })
    assert.deepStrictEqual(scopes, ['crew:execute:a', 'tools:search', 'tools:browse'])
  })

  it('task without tools has crew:execute only', () => {
    const scopes = crewTaskToScopes({ description: 'X', agent: 'a' })
    assert.deepStrictEqual(scopes, ['crew:execute:a'])
  })

  it('governed task execution with receipt', async () => {
    const receipts: ActionReceipt[] = []
    const r = await governCrewTask(
      { description: 'Research AI', agent: 'researcher', tools: ['search'] },
      mockExec,
      { passport: signedPassport, delegation: mkDel(['crew:execute:researcher', 'tools:search']), privateKey: ak.privateKey, onReceipt: r => receipts.push(r) },
    )
    assert.ok('output' in r && !('denied' in r))
    assert.ok(r.receipt.receiptId.startsWith('rcpt_crew_'))
    assert.ok(receipts.length >= 1)
  })

  it('governed task denial with receipt', async () => {
    const r = await governCrewTask(
      { description: 'Hack stuff', agent: 'hacker' },
      mockExec,
      { passport: signedPassport, delegation: mkDel(['crew:execute:researcher']), privateKey: ak.privateKey },
    )
    assert.ok('denied' in r && r.denied === true)
    assert.ok(r.receipt.receiptId)
  })

  it('tool receipts collected', async () => {
    const r = await governCrewTask(
      { description: 'Research', agent: 'researcher', tools: ['search', 'browse'] },
      mockExec,
      { passport: signedPassport, delegation: mkDel(['crew:execute:researcher', 'tools:search', 'tools:browse']), privateKey: ak.privateKey },
    )
    assert.ok('toolReceipts' in r)
    assert.equal(r.toolReceipts.length, 2)
  })

  it('onDenied callback fires', async () => {
    let info: { task: string; agent: string; reason: string } | null = null
    await governCrewTask(
      { description: 'X', agent: 'bad' }, mockExec,
      { passport: signedPassport, delegation: mkDel(['crew:execute:good']), privateKey: ak.privateKey, onDenied: i => { info = i } },
    )
    assert.ok(info)
    assert.equal(info!.agent, 'bad')
  })

  it('receipt signature verifies', async () => {
    const r = await governCrewTask(
      { description: 'Work', agent: 'worker' }, mockExec,
      { passport: signedPassport, delegation: mkDel(['crew:execute:worker']), privateKey: ak.privateKey },
    )
    const { signature, ...rest } = r.receipt
    assert.ok(verify(canonicalize(rest), signature, ak.publicKey))
  })

  it('empty task description handling', () => {
    const scopes = crewTaskToScopes({ description: '', agent: 'a' })
    assert.deepStrictEqual(scopes, ['crew:execute:a'])
  })

  it('multiple crew members different scopes', () => {
    const del = mkDel(['crew:execute:researcher', 'crew:execute:writer', 'tools:search'])
    const r1 = verifyCrewMember('researcher', { description: 'R', agent: 'researcher', tools: ['search'] }, { passport: signedPassport, delegation: del, privateKey: ak.privateKey })
    const r2 = verifyCrewMember('writer', { description: 'W', agent: 'writer' }, { passport: signedPassport, delegation: del, privateKey: ak.privateKey })
    const r3 = verifyCrewMember('hacker', { description: 'H', agent: 'hacker' }, { passport: signedPassport, delegation: del, privateKey: ak.privateKey })
    assert.ok(r1.authorized)
    assert.ok(r2.authorized)
    assert.ok(!r3.authorized)
  })
})
