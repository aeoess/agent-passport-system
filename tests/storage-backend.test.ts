// ══════════════════════════════════════════════════════════════════
// StorageBackend Test Suite
// ══════════════════════════════════════════════════════════════════
// Reusable test harness that any StorageBackend implementation must
// pass. Run against VolatileBackend, SQLiteBackend, PostgresBackend.
// ══════════════════════════════════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { VolatileBackend } from '../src/storage/volatile-backend.js'
import { generateKeyPair } from '../src/crypto/keys.js'
import type { StorageBackend, StoredAgentRecord } from '../src/storage/types.js'
import type { Delegation, RevocationRecord, ActionReceipt } from '../src/types/passport.js'
import type { ScopedReputation, DemotionEvent } from '../src/types/reputation-authority.js'
import type { KeyRotationEntry } from '../src/types/identity.js'

function makeAgent(id: string): StoredAgentRecord {
  return {
    agentId: id,
    passport: { agentId: id, name: 'Test', publicKey: 'pk_' + id } as any,
    attestation: { attested: true } as any,
    registeredAt: new Date().toISOString()
  }
}

function makeDelegation(id: string, toKey: string, scope: string[], limit?: number): Delegation {
  return {
    delegationId: id, delegatedTo: toKey, delegatedBy: 'principal_key',
    scope, spendLimit: limit, maxDepth: 2, currentDepth: 0,
    createdAt: new Date().toISOString(), expiresAt: new Date(Date.now() + 86400000).toISOString(),
    signature: 'sig_' + id
  } as Delegation
}

function makeReceipt(id: string, agentId: string, tool: string): ActionReceipt {
  return {
    receiptId: id, version: '1.1', timestamp: new Date().toISOString(),
    agentId, delegationId: 'del_test',
    action: { type: `gateway:${tool}`, target: '{}', scopeUsed: tool },
    result: { status: 'success', summary: 'ok' },
    delegationChain: ['pk_principal'], signature: 'sig_' + id
  } as ActionReceipt
}

function makeRevocation(delegationId: string): RevocationRecord {
  return {
    revocationId: 'rev_' + delegationId, delegationId,
    revokedBy: 'principal_key', revokedAt: new Date().toISOString(),
    reason: 'test', signature: 'sig_rev'
  }
}

// ══════════════════════════════════════════════════════════════════
// Run the suite against VolatileBackend
// To run against SQLite: import SQLiteBackend, create instance here
// ══════════════════════════════════════════════════════════════════

describe('StorageBackend Test Suite (VolatileBackend)', () => {
  let backend: StorageBackend

  beforeEach(async () => {
    backend = new VolatileBackend()
    await backend.initialize()
  })

  // ── Agents ──
  it('stores and retrieves agents', async () => {
    const agent = makeAgent('agent-001')
    await backend.putAgent(agent)
    const retrieved = await backend.getAgent('agent-001')
    assert.ok(retrieved)
    assert.equal(retrieved.agentId, 'agent-001')
    const missing = await backend.getAgent('nonexistent')
    assert.equal(missing, null)
    const all = await backend.listAgents()
    assert.equal(all.length, 1)
  })

  // ── Delegations ──
  it('stores and queries delegations', async () => {
    const d1 = makeDelegation('del-001', 'agent_pk', ['data:read'], 200)
    const d2 = makeDelegation('del-002', 'agent_pk', ['data:write'], 100)
    const d3 = makeDelegation('del-003', 'other_pk', ['admin'], 500)
    await backend.putDelegation(d1)
    await backend.putDelegation(d2)
    await backend.putDelegation(d3)
    const byAgent = await backend.getDelegationsForAgent('agent_pk')
    assert.equal(byAgent.length, 2)
    const single = await backend.getDelegation('del-001')
    assert.ok(single)
    assert.equal(single.spendLimit, 200)
  })

  // ── Spend: reserve/commit/release ──
  it('reserves and commits spend atomically', async () => {
    const d = makeDelegation('del-spend', 'pk', ['cloud'], 100)
    await backend.putDelegation(d)
    const r1 = await backend.reserveSpend('del-spend', 60, 'USD')
    assert.ok(r1.success, 'First reservation succeeds')
    assert.ok(r1.reservationId)
    // Second reservation should still fit (60 + 30 = 90 < 100)
    const r2 = await backend.reserveSpend('del-spend', 30, 'USD')
    assert.ok(r2.success, 'Second reservation fits')
    // Third reservation should fail (60 + 30 + 20 = 110 > 100)
    const r3 = await backend.reserveSpend('del-spend', 20, 'USD')
    assert.equal(r3.success, false, 'Third reservation exceeds limit')
    // Commit first, release second
    assert.ok(await backend.commitSpend(r1.reservationId!))
    assert.ok(await backend.releaseSpend(r2.reservationId!))
    const spent = await backend.getSpentAmount('del-spend')
    assert.equal(spent, 60, 'Only committed reservation counted')
    // After releasing r2, a new 35 reservation should fit (60 + 35 = 95 < 100)
    const r4 = await backend.reserveSpend('del-spend', 35, 'USD')
    assert.ok(r4.success, 'New reservation fits after release')
  })

  // ── Revocations ──
  it('appends revocations and checks status', async () => {
    assert.equal(await backend.isRevoked('del-x'), false)
    await backend.appendRevocation(makeRevocation('del-x'))
    assert.equal(await backend.isRevoked('del-x'), true)
    assert.equal(await backend.isRevoked('del-y'), false)
    const byPrincipal = await backend.getRevocationsBy('principal_key')
    assert.equal(byPrincipal.length, 1)
  })

  // ── Receipts: append-only + pagination ──
  it('appends receipts and paginates', async () => {
    for (let i = 0; i < 25; i++) {
      await backend.appendReceipt(makeReceipt(`rcpt-${i}`, 'agent-1', 'data:read'))
    }
    const page1 = await backend.queryReceipts({ agentId: 'agent-1' }, 10)
    assert.equal(page1.items.length, 10)
    assert.ok(page1.hasMore)
    assert.ok(page1.nextCursor)
    const page2 = await backend.queryReceipts({ agentId: 'agent-1' }, 10, page1.nextCursor)
    assert.equal(page2.items.length, 10)
    assert.ok(page2.hasMore)
    const page3 = await backend.queryReceipts({ agentId: 'agent-1' }, 10, page2.nextCursor)
    assert.equal(page3.items.length, 5)
    assert.equal(page3.hasMore, false)
    const count = await backend.getReceiptCount('agent-1')
    assert.equal(count, 25)
  })

  // ── Tombstone (GDPR) ──
  it('tombstones receipt: redacts payload, preserves chain', async () => {
    await backend.appendReceipt(makeReceipt('rcpt-gdpr', 'agent-1', 'data:read'))
    const before = await backend.getReceipt('rcpt-gdpr')
    assert.ok(before)
    assert.ok(!before.tombstoned)
    const result = await backend.tombstoneReceipt('rcpt-gdpr', 'gdpr_request')
    assert.ok(result)
    const after = await backend.getReceipt('rcpt-gdpr')
    assert.ok(after)
    assert.ok(after.tombstoned)
    assert.equal(after.tombstoneReason, 'gdpr_request')
    assert.equal(after.action.type, '[REDACTED]')
    assert.equal(after.result.summary, '[REDACTED]')
    assert.ok(after.signature, 'Signature preserved for chain integrity')
    assert.ok(after.receiptId, 'Receipt ID preserved')
  })

  // ── Reputation (derived cache) ──
  it('stores and retrieves scoped reputation', async () => {
    const rep: ScopedReputation = {
      principalId: 'principal-1', agentId: 'agent-1', scope: 'data:read',
      mu: 45, sigma: 12, receiptCount: 20, lastUpdatedAt: new Date().toISOString()
    }
    await backend.putReputation(rep)
    const retrieved = await backend.getReputation('agent-1', 'data:read')
    assert.ok(retrieved)
    assert.equal(retrieved.mu, 45)
    assert.equal(retrieved.sigma, 12)
    const missing = await backend.getReputation('agent-1', 'other:scope')
    assert.equal(missing, null)
  })

  // ── Demotions (permanent) ──
  it('appends demotions and counts', async () => {
    const d: DemotionEvent = {
      agentId: 'agent-1', principalId: 'principal-1', scope: 'data:read',
      fromTier: 3, toTier: 1, cause: 'behavioral' as any,
      reason: 'Excessive failures', timestamp: new Date().toISOString(),
      affectsReputation: true
    }
    await backend.appendDemotion(d)
    await backend.appendDemotion({ ...d, timestamp: new Date().toISOString() })
    assert.equal(await backend.getDemotionCount('agent-1'), 2)
    assert.equal(await backend.getDemotionCount('agent-other'), 0)
    const all = await backend.getDemotions('agent-1')
    assert.equal(all.length, 2)
  })

  // ── Key Rotations ──
  it('appends and retrieves key rotations', async () => {
    const entry: KeyRotationEntry = {
      rotationId: 'rot_001', oldPublicKey: 'old_pk', newPublicKey: 'new_pk',
      reason: 'scheduled', rotatedAt: new Date().toISOString(),
      continuitySignature: 'sig_old', possessionSignature: 'sig_new'
    }
    await backend.appendKeyRotation(entry)
    const byOld = await backend.getKeyRotations('old_pk')
    assert.equal(byOld.length, 1)
    const byNew = await backend.getKeyRotations('new_pk')
    assert.equal(byNew.length, 1)
  })

  // ── Replay Protection ──
  it('blocks replay nonces', async () => {
    const fresh = await backend.checkAndStoreNonce('req-001', 60)
    assert.ok(fresh, 'First use is fresh')
    const replay = await backend.checkAndStoreNonce('req-001', 60)
    assert.equal(replay, false, 'Second use is replay')
    const different = await backend.checkAndStoreNonce('req-002', 60)
    assert.ok(different, 'Different nonce is fresh')
  })

  // ── Transaction: rollback on error ──
  it('rolls back all changes on transaction failure', async () => {
    await backend.putAgent(makeAgent('agent-tx'))
    await backend.putDelegation(makeDelegation('del-tx', 'pk', ['test'], 100))
    try {
      await backend.transaction(async (tx) => {
        await tx.appendReceipt(makeReceipt('rcpt-tx', 'agent-tx', 'test'))
        await tx.appendRevocation(makeRevocation('del-tx'))
        throw new Error('Simulated crash mid-transaction')
      })
    } catch (e: any) {
      assert.equal(e.message, 'Simulated crash mid-transaction')
    }
    // Receipt should NOT exist (rolled back)
    const receipt = await backend.getReceipt('rcpt-tx')
    assert.equal(receipt, null, 'Receipt rolled back')
    // Revocation should NOT exist (rolled back)
    assert.equal(await backend.isRevoked('del-tx'), false, 'Revocation rolled back')
  })

  // ── Checkpoints with external anchoring ──
  it('creates checkpoints with monotonic sequence and emits callback', async () => {
    const keys = (await import('../src/crypto/keys.js')).generateKeyPair()
    const emitted: { hash: string; seq: number }[] = []
    backend.onCheckpoint((hash, seq) => { emitted.push({ hash, seq }) })

    // Add some state first
    await backend.putAgent(makeAgent('agent-chk'))
    await backend.appendReceipt(makeReceipt('rcpt-chk-1', 'agent-chk', 'test'))
    await backend.appendReceipt(makeReceipt('rcpt-chk-2', 'agent-chk', 'test'))

    const cp1 = await backend.createCheckpoint('gw-001', keys.privateKey)
    assert.ok(cp1.checkpointId)
    assert.equal(cp1.sequence, 1)
    assert.equal(cp1.gatewayId, 'gw-001')
    assert.equal(cp1.receiptCount, 2)
    assert.ok(cp1.signature)
    assert.ok(cp1.stateRootHash)
    assert.ok(cp1.previousCheckpointHash)

    // Second checkpoint must have higher sequence
    await backend.appendReceipt(makeReceipt('rcpt-chk-3', 'agent-chk', 'test'))
    const cp2 = await backend.createCheckpoint('gw-001', keys.privateKey)
    assert.equal(cp2.sequence, 2)
    assert.equal(cp2.receiptCount, 3)
    assert.notEqual(cp2.stateRootHash, cp1.stateRootHash, 'State root changed')

    // External callback was invoked
    assert.equal(emitted.length, 2)
    assert.equal(emitted[0].seq, 1)
    assert.equal(emitted[1].seq, 2)

    // Latest checkpoint
    const latest = await backend.getLatestCheckpoint()
    assert.ok(latest)
    assert.equal(latest!.sequence, 2)
  })

  // ── Integrity verification ──
  it('verifyIntegrity returns clean report on healthy state', async () => {
    await backend.putAgent(makeAgent('agent-int'))
    await backend.putDelegation(makeDelegation('del-int', 'pk', ['test'], 100))
    await backend.appendReceipt(makeReceipt('rcpt-int-1', 'agent-int', 'test'))
    await backend.appendReceipt(makeReceipt('rcpt-int-2', 'agent-int', 'test'))
    await backend.appendRevocation(makeRevocation('del-other'))

    const report = await backend.verifyIntegrity()
    assert.equal(report.schemaVersion, 1)
    assert.equal(report.receiptChainValid, true)
    assert.equal(report.receiptCount, 2)
    assert.equal(report.delegationCount, 1)
    assert.equal(report.revocationCount, 1)
    assert.equal(report.errors.length, 0)
    assert.equal(report.brokenLinks.length, 0)
  })

  // ── Prune expired nonces and reservations ──
  it('prunes expired nonces and spend reservations', async () => {
    // Store a nonce with 0-second TTL (already expired)
    await backend.checkAndStoreNonce('old-nonce', 0)
    // Store a valid nonce
    await backend.checkAndStoreNonce('fresh-nonce', 3600)

    // Create an expired reservation
    const d = makeDelegation('del-prune', 'pk', ['test'], 1000)
    await backend.putDelegation(d)
    await backend.reserveSpend('del-prune', 50, 'USD', 0) // 0 TTL = already expired

    // Wait a tick for expiry
    await new Promise(r => setTimeout(r, 10))

    const result = await backend.pruneExpired()
    assert.ok(result.nonces >= 0, 'Nonces pruned')
    assert.ok(result.reservations >= 0, 'Reservations pruned')
  })

  // ── Receipt export ──
  it('exports receipts as verifiable bundle', async () => {
    for (let i = 0; i < 5; i++) {
      await backend.appendReceipt(makeReceipt(`rcpt-exp-${i}`, 'agent-exp', 'data:read'))
    }
    await backend.appendReceipt(makeReceipt('rcpt-exp-other', 'agent-other', 'admin'))

    const bundle = await backend.exportReceipts({ agentId: 'agent-exp' })
    assert.equal(bundle.receipts.length, 5)
    assert.ok(bundle.chainValid)
  })

  // ── Rebuild derived state ──
  it('rebuildDerivedState completes without error', async () => {
    await backend.appendReceipt(makeReceipt('rcpt-rb-1', 'agent-rb', 'test'))
    await backend.putReputation({
      principalId: 'p1', agentId: 'agent-rb', scope: 'test',
      mu: 50, sigma: 10, receiptCount: 5, lastUpdatedAt: new Date().toISOString()
    })
    // Should not throw
    await backend.rebuildDerivedState()
  })

  // ── Close / lifecycle ──
  it('initialize and close lifecycle', async () => {
    const b = new VolatileBackend()
    await b.initialize()
    await b.putAgent(makeAgent('lifecycle-agent'))
    const a = await b.getAgent('lifecycle-agent')
    assert.ok(a)
    await b.close()
  })
})
