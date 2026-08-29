// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// R-PROVE-REACHABLE: fail_closed must be selectable from a shipped
// entrypoint, not only from a direct verifyDelegation call.
// ══════════════════════════════════════════════════════════════════
// Round 1 made the three revocation policies genuinely distinct inside
// verifyDelegation, and every test exercised verifyDelegation directly.
// There were nine internal call sites in src/ and ZERO of them passed an
// options argument, so no caller of any shipped primitive could select the
// repaired policy: the fix changed nothing anyone could reach.
//
// Each test below drives a PUBLIC entrypoint twice with identical inputs,
// changing only the revocation posture, and asserts the outcome differs.
// A regression that stops threading the options through makes the two runs
// agree, and the test fails.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, subDelegate, createReceipt,
  createPassport, signPassport,
  type RevocationCheckOptions,
} from '../src/index.js'
import { verifyOnAccept } from '../src/v2/credential-check-policy/check.js'
import { governMCPToolCall } from '../src/adapters/mcp.js'
import { consultAdvisor } from '../src/v2/sub-delegate-advisor.js'

const principal = generateKeyPair()
const agent = generateKeyPair()

const STALE = () => new Date(Date.now() - 2 * 3_600_000).toISOString()
const FRESH = () => new Date().toISOString()

/** No revocation evidence at all, which fail_closed must refuse. */
const FAIL_CLOSED: RevocationCheckOptions = { revocationCheckPolicy: 'fail_closed' }
/** Two-hour-stale evidence saying "not revoked", which fail_closed must refuse. */
const FAIL_CLOSED_STALE: RevocationCheckOptions = {
  revocationCheckPolicy: 'fail_closed',
  cachedRevocationState: { revoked: false, checkedAt: STALE() },
}
/** Fresh evidence saying "not revoked", which fail_closed must accept. */
const FAIL_CLOSED_FRESH: RevocationCheckOptions = {
  revocationCheckPolicy: 'fail_closed',
  cachedRevocationState: { revoked: false, checkedAt: FRESH() },
}

function delegation() {
  return createDelegation({
    delegatedTo: agent.publicKey,
    delegatedBy: principal.publicKey,
    scope: ['data:read'],
    maxDepth: 3,
    privateKey: principal.privateKey,
  })
}

describe('reachability: verifyOnAccept (acceptance-time gate)', () => {
  it('admits without a posture and refuses under fail_closed with no evidence', () => {
    const d = delegation()
    assert.equal(verifyOnAccept({ delegation: d }).valid, true)
    const closed = verifyOnAccept({ delegation: d, revocation: FAIL_CLOSED })
    assert.equal(closed.valid, false, 'fail_closed is not reachable through verifyOnAccept')
    assert.equal(closed.stamp, undefined, 'no acceptance stamp is minted on a refusal')
    assert.ok(closed.errors.some(e => e.includes('revocation')), closed.errors.join(' | '))
  })

  it('refuses two-hour-stale evidence and admits fresh evidence', () => {
    const d = delegation()
    assert.equal(verifyOnAccept({ delegation: d, revocation: FAIL_CLOSED_STALE }).valid, false)
    const ok = verifyOnAccept({ delegation: d, revocation: FAIL_CLOSED_FRESH })
    assert.equal(ok.valid, true, ok.errors.join(' | '))
    assert.ok(ok.stamp, 'a stamp is minted against fresh evidence')
  })
})

describe('reachability: createReceipt', () => {
  const action = {
    type: 'read', target: 'db', scopeUsed: 'data:read',
  } as Parameters<typeof createReceipt>[0]['action']

  it('mints without a posture and throws under fail_closed with no evidence', () => {
    const d = delegation()
    assert.ok(createReceipt({
      agentId: 'a', delegationId: d.delegationId, delegation: d,
      action, result: { status: 'success', summary: 'ok' },
      delegationChain: [d.delegationId], privateKey: agent.privateKey,
    }))
    assert.throws(
      () => createReceipt({
        agentId: 'a', delegationId: d.delegationId, delegation: d,
        action, result: { status: 'success', summary: 'ok' },
        delegationChain: [d.delegationId], privateKey: agent.privateKey,
        revocation: FAIL_CLOSED,
      }),
      /revocation/,
      'fail_closed is not reachable through createReceipt',
    )
  })

  it('mints against fresh evidence', () => {
    const d = delegation()
    assert.ok(createReceipt({
      agentId: 'a', delegationId: d.delegationId, delegation: d,
      action, result: { status: 'success', summary: 'ok' },
      delegationChain: [d.delegationId], privateKey: agent.privateKey,
      revocation: FAIL_CLOSED_FRESH,
    }))
  })
})

describe('reachability: subDelegate', () => {
  it('extends authority without a posture and refuses under fail_closed', () => {
    const parent = delegation()
    const child = generateKeyPair()
    assert.ok(subDelegate({
      parentDelegation: parent, delegatedTo: child.publicKey,
      scope: ['data:read'], privateKey: agent.privateKey,
    }))
    assert.throws(
      () => subDelegate({
        parentDelegation: parent, delegatedTo: child.publicKey,
        scope: ['data:read'], privateKey: agent.privateKey,
        revocation: FAIL_CLOSED,
      }),
      /revocation/,
      'fail_closed is not reachable through subDelegate',
    )
  })
})

describe('reachability: consultAdvisor', () => {
  function advisorDelegation() {
    return createDelegation({
      delegatedTo: agent.publicKey, delegatedBy: principal.publicKey,
      scope: ['advice:give'], spendLimit: 5, spendLimitUnit: 'invocations',
      privateKey: principal.privateKey,
    })
  }
  const base = {
    decisionType: 'test', decisionArtifactId: 'art-1',
    adviceHash: 'a'.repeat(64), privateKey: agent.privateKey,
  }

  it('consults without a posture and refuses under fail_closed', () => {
    assert.ok(consultAdvisor({ ...base, advisorDelegation: advisorDelegation() }))
    assert.throws(
      () => consultAdvisor({ ...base, advisorDelegation: advisorDelegation(), revocation: FAIL_CLOSED }),
      /invalid|revocation/,
      'fail_closed is not reachable through consultAdvisor',
    )
  })
})

describe('reachability: the MCP adapter execution gate', () => {
  function config(revocation?: RevocationCheckOptions) {
    const { signedPassport, keyPair } = createPassport({
      agentId: 'agent-mcp', agentName: 'mcp', ownerAlias: 'o', mission: 'm',
      capabilities: ['data:read'],
      runtime: { platform: 'node', models: ['t'], toolsCount: 0, memoryType: 'none' },
      expiresInDays: 30,
    })
    return {
      passport: signPassport(signedPassport.passport, keyPair.privateKey),
      delegation: createDelegation({
        delegatedTo: keyPair.publicKey, delegatedBy: principal.publicKey,
        scope: ['data:read', 'tools:read_file'], privateKey: principal.privateKey,
      }),
      privateKey: keyPair.privateKey,
      ...(revocation ? { revocation } : {}),
    }
  }

  it('executes without a posture and denies under fail_closed with no evidence', async () => {
    const call = { name: 'read_file', arguments: {} }
    let executed = 0
    const run = async () => { executed++; return 'contents' }

    const permitted = await governMCPToolCall(call, run, config())
    assert.ok(!('denied' in permitted), 'baseline call should execute')
    assert.equal(executed, 1)

    const denied = await governMCPToolCall(call, run, config(FAIL_CLOSED))
    assert.ok('denied' in denied, 'fail_closed is not reachable through the MCP adapter')
    assert.match(denied.reason, /revocation/)
    assert.equal(executed, 1, 'the tool must not run when the gate denies')
  })

  it('executes against fresh revocation evidence', async () => {
    const call = { name: 'read_file', arguments: {} }
    let executed = 0
    const result = await governMCPToolCall(call, async () => { executed++; return 'contents' }, config(FAIL_CLOSED_FRESH))
    assert.ok(!('denied' in result))
    assert.equal(executed, 1)
  })
})
