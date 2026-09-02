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
  createPassport, signPassport, verifyDelegation, REVOCATION_CHECK_POLICIES,
  traceBeneficiary,
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
    // The message always begins 'consultAdvisor: delegation invalid', so a
    // /invalid/ alternative would match the constant prefix and pass whatever
    // the reason was. The assertion names the revocation-specific text that
    // only a fail_closed refusal produces.
    assert.throws(
      () => consultAdvisor({ ...base, advisorDelegation: advisorDelegation(), revocation: FAIL_CLOSED }),
      /no revocation evidence supplied/,
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
      // The trust-anchor axis is pinned in adapter-trust-posture.test.ts; this
      // file isolates the revocation axis, so the posture is stated explicitly.
      allowSelfSigned: true as const,
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

// ── Per-site pinning ────────────────────────────────────────────────
// Mutation survivors M24, M25 and M26: un-threading `revocation` from
// crewai, langchain or gonka INDIVIDUALLY caused zero failures, because the
// only adapter exercised above was MCP. Moving all five together and
// counting six failures proved that SOMETHING was threaded, not that each
// site was. Each adapter now has its own case, so one gate regressing is
// one test failing.
//
// These pass allowSelfSigned because they are testing the revocation axis;
// the trust-anchor axis is pinned separately in adapter-trust-posture.test.ts.

import { governLangChainTool } from '../src/adapters/langchain.js'
import { verifyCrewMember } from '../src/adapters/crewai.js'
import { verifyGonkaHost } from '../src/adapters/gonka.js'

function adapterConfig(revocation?: RevocationCheckOptions) {
  const { signedPassport, keyPair } = createPassport({
    agentId: 'agent-adapter', agentName: 'adapter', ownerAlias: 'o', mission: 'm',
    capabilities: ['data:read'],
    runtime: { platform: 'node', models: ['gpt'], toolsCount: 0, memoryType: 'none' },
    expiresInDays: 30,
  })
  return {
    passport: signPassport(signedPassport.passport, keyPair.privateKey),
    delegation: createDelegation({
      delegatedTo: keyPair.publicKey, delegatedBy: principal.publicKey,
      scope: ['*'], privateKey: principal.privateKey,
    }),
    privateKey: keyPair.privateKey,
    allowSelfSigned: true as const,
    ...(revocation ? { revocation } : {}),
  }
}

describe('reachability: the LangChain adapter execution gate (M25)', () => {
  const call = { name: 'search', arguments: {} }

  it('executes without a posture and denies under fail_closed with no evidence', async () => {
    let executed = 0
    const run = async () => { executed++; return 'result' }

    const permitted = await governLangChainTool(call, run, adapterConfig())
    assert.ok(!('denied' in permitted), 'baseline call should execute')
    assert.equal(executed, 1)

    const denied = await governLangChainTool(call, run, adapterConfig(FAIL_CLOSED))
    assert.ok('denied' in denied, 'fail_closed is not reachable through the LangChain adapter')
    assert.match(denied.reason, /revocation/)
    assert.equal(executed, 1, 'the tool must not run when the gate denies')
  })

  it('executes against fresh revocation evidence', async () => {
    let executed = 0
    const r = await governLangChainTool(call, async () => { executed++; return 'ok' }, adapterConfig(FAIL_CLOSED_FRESH))
    assert.ok(!('denied' in r))
    assert.equal(executed, 1)
  })
})

describe('reachability: the CrewAI adapter gate (M24)', () => {
  const task = { description: 'do the thing', expectedOutput: 'a thing', tools: ['search'] }

  it('authorizes without a posture and refuses under fail_closed with no evidence', () => {
    const permitted = verifyCrewMember('agent', task as never, adapterConfig())
    assert.equal(permitted.authorized, true, permitted.reason)

    const denied = verifyCrewMember('agent', task as never, adapterConfig(FAIL_CLOSED))
    assert.equal(denied.authorized, false, 'fail_closed is not reachable through the CrewAI adapter')
    assert.match(denied.reason, /revocation/)
  })

  it('refuses two-hour-stale evidence and authorizes against fresh evidence', () => {
    assert.equal(verifyCrewMember('agent', task as never, adapterConfig(FAIL_CLOSED_STALE)).authorized, false)
    assert.equal(verifyCrewMember('agent', task as never, adapterConfig(FAIL_CLOSED_FRESH)).authorized, true)
  })
})

describe('reachability: the Gonka adapter gate (M26)', () => {
  it('authorizes without a posture and refuses under fail_closed with no evidence', () => {
    const permitted = verifyGonkaHost('host-1', 'gpt', adapterConfig())
    assert.equal(permitted.authorized, true, permitted.reason)

    const denied = verifyGonkaHost('host-1', 'gpt', adapterConfig(FAIL_CLOSED))
    assert.equal(denied.authorized, false, 'fail_closed is not reachable through the Gonka adapter')
    assert.match(denied.reason, /revocation/)
  })

  it('refuses two-hour-stale evidence and authorizes against fresh evidence', () => {
    assert.equal(verifyGonkaHost('host-1', 'gpt', adapterConfig(FAIL_CLOSED_STALE)).authorized, false)
    assert.equal(verifyGonkaHost('host-1', 'gpt', adapterConfig(FAIL_CLOSED_FRESH)).authorized, true)
  })
})

// ── The policy value itself cannot be a silent typo ──────────────────

describe('revocation policy values are validated, not silently defaulted', () => {
  it("a mis-cased 'FAIL_CLOSED' throws instead of quietly meaning fail_open", () => {
    assert.throws(
      () => verifyDelegation(delegation(), { revocationCheckPolicy: 'FAIL_CLOSED' as never }),
      /unknown revocationCheckPolicy/,
      'a typo in the strictest setting silently selected the weakest one',
    )
  })

  it('every documented policy value is accepted', () => {
    for (const policy of REVOCATION_CHECK_POLICIES) {
      assert.doesNotThrow(() => verifyDelegation(delegation(), { revocationCheckPolicy: policy }))
    }
  })

  it('omitting the policy is still the fail_open default', () => {
    assert.equal(verifyDelegation(delegation()).valid, true)
  })
})

// ── attribution: the ninth call site, now threaded ──────────────────
// Round 2 left this one out with an argument that did not survive review:
// it claimed a revocation posture would let present-day state flip a
// historical verdict, on a line whose verifyDelegation call already does
// exactly that via EXPIRY. The posture is now available, defaults to
// fail_open, and takes evidence PER DELEGATION, since one cached state
// applied to every hop of a chain would be a new defect rather than a fix.

describe('reachability: the attribution chain walk', () => {
  function chainFixture() {
    const mid = generateKeyPair()
    const leaf = generateKeyPair()
    const first = createDelegation({
      delegatedTo: mid.publicKey, delegatedBy: principal.publicKey,
      scope: ['data:read'], maxDepth: 3, privateKey: principal.privateKey,
    })
    const second = createDelegation({
      delegatedTo: leaf.publicKey, delegatedBy: mid.publicKey,
      scope: ['data:read'], maxDepth: 3, currentDepth: 1, privateKey: mid.privateKey,
    })
    const receipt = createReceipt({
      agentId: 'leaf', delegationId: second.delegationId, delegation: second,
      action: { type: 'read', target: 'db', scopeUsed: 'data:read' },
      result: { status: 'success', summary: 'ok' },
      delegationChain: [principal.publicKey, mid.publicKey, leaf.publicKey],
      privateKey: leaf.privateKey,
    })
    return { delegations: [first, second], receipt }
  }

  it('defaults to fail_open, so the historical behaviour is unchanged', () => {
    const { delegations, receipt } = chainFixture()
    const trace = traceBeneficiary(receipt, delegations, new Map())
    assert.equal(trace.verified, true, 'the default walk must be what it always was')
  })

  it('fail_closed with no evidence resolver makes every hop unauthenticated', () => {
    const { delegations, receipt } = chainFixture()
    const trace = traceBeneficiary(receipt, delegations, new Map(), {
      revocationCheckPolicy: 'fail_closed',
    })
    assert.equal(trace.verified, false, 'fail_closed is not reachable through traceBeneficiary')
  })

  it('fail_closed with fresh per-delegation evidence verifies again', () => {
    const { delegations, receipt } = chainFixture()
    const trace = traceBeneficiary(receipt, delegations, new Map(), {
      revocationCheckPolicy: 'fail_closed',
      resolveRevocation: () => ({ revoked: false, checkedAt: new Date().toISOString() }),
    })
    assert.equal(trace.verified, true)
  })

  it('the resolver is consulted PER delegation, not once for the whole chain', () => {
    const { delegations, receipt } = chainFixture()
    const seen: string[] = []
    traceBeneficiary(receipt, delegations, new Map(), {
      revocationCheckPolicy: 'fail_closed',
      resolveRevocation: (d) => {
        seen.push(d.delegationId)
        return { revoked: false, checkedAt: new Date().toISOString() }
      },
    })
    assert.equal(new Set(seen).size, delegations.length,
      `expected one lookup per delegation, saw ${JSON.stringify(seen)}`)
  })

  // The resolver is caller-supplied code inside a ledger read. Every
  // mis-wired shape must fail CLOSED under fail_closed and must never crash
  // the read. Same class as the MA1 resolver-normalization gap in the v2
  // authority-delegation verifier.
  it('a throwing resolver grades absent instead of propagating out of a ledger read', () => {
    const { delegations, receipt } = chainFixture()
    let trace: ReturnType<typeof traceBeneficiary> | undefined
    assert.doesNotThrow(() => {
      trace = traceBeneficiary(receipt, delegations, new Map(), {
        revocationCheckPolicy: 'fail_closed',
        resolveRevocation: () => { throw new Error('revocation registry unreachable') },
      })
    })
    assert.equal(trace!.verified, false, 'a failed lookup must not read as not-revoked')
  })

  it('a throwing resolver under fail_open leaves the historical default intact', () => {
    const { delegations, receipt } = chainFixture()
    const trace = traceBeneficiary(receipt, delegations, new Map(), {
      resolveRevocation: () => { throw new Error('down') },
    })
    assert.equal(trace.verified, true)
  })

  it('a resolver return value that is not revocation evidence grades absent', () => {
    const { delegations, receipt } = chainFixture()
    const shapes: unknown[] = [
      Promise.resolve({ revoked: false, checkedAt: new Date().toISOString() }), // async by mistake
      null,
      {},
      { revoked: 'no', checkedAt: new Date().toISOString() },
      { revoked: false },
      { checkedAt: new Date().toISOString() },
      'active',
      42,
      true,
    ]
    for (const shape of shapes) {
      const trace = traceBeneficiary(receipt, delegations, new Map(), {
        revocationCheckPolicy: 'fail_closed',
        resolveRevocation: () => shape as never,
      })
      assert.equal(
        trace.verified, false,
        `resolver returning ${JSON.stringify(shape) ?? typeof shape} was read as usable evidence`,
      )
    }
  })

  it('a revoked hop breaks the chain when the caller asks about revocation', () => {
    const { delegations, receipt } = chainFixture()
    const trace = traceBeneficiary(receipt, delegations, new Map(), {
      revocationCheckPolicy: 'fail_closed',
      resolveRevocation: (d) => d.delegationId === delegations[0].delegationId
        ? { revoked: true, checkedAt: new Date().toISOString() }
        : { revoked: false, checkedAt: new Date().toISOString() },
    })
    assert.equal(trace.verified, false)
  })
})
