// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Invariant 4, at EVERY execution gate, not just the offline verifier.
// ══════════════════════════════════════════════════════════════════
// The relying-party middleware was hardened to require a stated trust
// posture. The five adapter gates that also call verifyPassport were not,
// and they are the gates that actually run the tool. Driven against the
// SDK: governMCPToolCall EXECUTED the tool and minted a SUCCESS receipt
// for an attacker's self-signed passport declaring admin:everything,
// carrying a delegation the attacker had issued to themselves, and
// verifyA2AIdentity returned {valid:true, errors:[]} for the same passport.
//
// Each gate is pinned SEPARATELY here. A per-file mutation is what catches
// one gate regressing; a test that only drives MCP leaves the other four
// free to rot, which is how they got into this state.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair, createDelegation, createPassport, signPassport,
  countersignPassport,
} from '../src/index.js'
import type { SignedPassport } from '../src/types/passport.js'
import { governMCPToolCall } from '../src/adapters/mcp.js'
import { governLangChainTool } from '../src/adapters/langchain.js'
import { verifyCrewMember } from '../src/adapters/crewai.js'
import { verifyGonkaHost } from '../src/adapters/gonka.js'
import { verifyA2AIdentity } from '../src/adapters/a2a.js'

/** An attacker with nothing but their own keypair: self-signed passport
 *  claiming admin:everything, plus a delegation they issued to themselves. */
function attackerCredentials() {
  const { signedPassport, keyPair } = createPassport({
    agentId: 'attacker', agentName: 'attacker', ownerAlias: 'nobody',
    mission: 'take over', capabilities: ['admin:everything'],
    runtime: { platform: 'node', models: ['gpt'], toolsCount: 0, memoryType: 'none' },
    expiresInDays: 30,
  })
  const passport = signPassport(signedPassport.passport, keyPair.privateKey)
  const delegation = createDelegation({
    delegatedTo: keyPair.publicKey, delegatedBy: keyPair.publicKey,
    scope: ['*'], privateKey: keyPair.privateKey,
  })
  return { passport, delegation, privateKey: keyPair.privateKey, publicKey: keyPair.publicKey }
}

/** The same agent, countersigned by a CA the gate is told to trust. */
function issuedCredentials(issuerPrivateKey: string) {
  const c = attackerCredentials()
  return { ...c, passport: countersignPassport(c.passport, issuerPrivateKey, 'test-ca') as SignedPassport }
}

const SELF_SIGNED = { allowSelfSigned: true } as const

describe('Invariant 4: the MCP gate', () => {
  const call = { name: 'read_file', arguments: {} }

  it('does NOT execute the tool for a self-signed admin passport', async () => {
    const c = attackerCredentials()
    let executed = 0
    const r = await governMCPToolCall(call, async () => { executed++; return 'SECRETS' }, {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey,
    })
    assert.ok('denied' in r, 'the gate admitted a self-issued claim of authority')
    assert.equal(executed, 0, 'the tool ran before the gate decided')
    assert.match(r.reason, /Untrusted issuer/)
  })

  it('does not mint a success receipt on that denial', async () => {
    const c = attackerCredentials()
    const r = await governMCPToolCall(call, async () => 'SECRETS', {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey,
    })
    assert.ok('denied' in r)
    assert.equal(r.receipt.result.status, 'failure')
  })

  it('an empty trustedIssuers list does not mean trust anyone', async () => {
    const c = attackerCredentials()
    const r = await governMCPToolCall(call, async () => 'SECRETS', {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey, trustedIssuers: [],
    })
    assert.ok('denied' in r)
  })

  it('executes under explicit allowSelfSigned', async () => {
    const c = attackerCredentials()
    let executed = 0
    const r = await governMCPToolCall(call, async () => { executed++; return 'ok' }, {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey, ...SELF_SIGNED,
    })
    assert.ok(!('denied' in r), 'denied: ' + JSON.stringify(r))
    assert.equal(executed, 1)
  })

  it('executes under a matching trusted issuer', async () => {
    const issuer = generateKeyPair()
    const c = issuedCredentials(issuer.privateKey)
    const r = await governMCPToolCall(call, async () => 'ok', {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey,
      trustedIssuers: [issuer.publicKey],
    })
    assert.ok(!('denied' in r), 'denied: ' + JSON.stringify(r))
  })

  it('denies a countersignature from an issuer outside the allowlist', async () => {
    const rogue = generateKeyPair()
    const trusted = generateKeyPair()
    const c = issuedCredentials(rogue.privateKey)
    const r = await governMCPToolCall(call, async () => 'ok', {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey,
      trustedIssuers: [trusted.publicKey],
    })
    assert.ok('denied' in r)
  })
})

describe('Invariant 4: the LangChain gate', () => {
  const call = { name: 'search', arguments: {} }

  it('does NOT execute the tool for a self-signed admin passport', async () => {
    const c = attackerCredentials()
    let executed = 0
    const r = await governLangChainTool(call, async () => { executed++; return 'SECRETS' }, {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey,
    })
    assert.ok('denied' in r, 'the gate admitted a self-issued claim of authority')
    assert.equal(executed, 0)
    assert.match(r.reason, /Untrusted issuer/)
  })

  it('executes under explicit allowSelfSigned', async () => {
    const c = attackerCredentials()
    let executed = 0
    const r = await governLangChainTool(call, async () => { executed++; return 'ok' }, {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey, ...SELF_SIGNED,
    })
    assert.ok(!('denied' in r), 'denied: ' + JSON.stringify(r))
    assert.equal(executed, 1)
  })
})

describe('Invariant 4: the CrewAI gate', () => {
  const task = { description: 'do the thing', expectedOutput: 'a thing', tools: ['search'] }

  it('does NOT authorize a self-signed admin passport', () => {
    const c = attackerCredentials()
    const r = verifyCrewMember('agent', task as never, {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey,
    })
    assert.equal(r.authorized, false, 'the gate admitted a self-issued claim of authority')
    assert.match(r.reason, /Untrusted issuer/)
  })

  it('authorizes under explicit allowSelfSigned', () => {
    const c = attackerCredentials()
    const r = verifyCrewMember('agent', task as never, {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey, ...SELF_SIGNED,
    })
    assert.equal(r.authorized, true, r.reason)
  })
})

describe('Invariant 4: the Gonka gate', () => {
  it('does NOT authorize a self-signed admin passport', () => {
    const c = attackerCredentials()
    const r = verifyGonkaHost('host-1', 'gpt', {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey,
    })
    assert.equal(r.authorized, false, 'the gate admitted a self-issued claim of authority')
    assert.match(r.reason, /Untrusted issuer/)
  })

  it('authorizes under explicit allowSelfSigned', () => {
    const c = attackerCredentials()
    const r = verifyGonkaHost('host-1', 'gpt', {
      passport: c.passport, delegation: c.delegation, privateKey: c.privateKey, ...SELF_SIGNED,
    })
    assert.equal(r.authorized, true, r.reason)
  })
})

describe('Invariant 4: the A2A identity gate', () => {
  function card(publicKey: string) {
    return { name: 'attacker', securitySchemes: { aps_ed25519: { publicKey } } }
  }

  it('does NOT report a self-signed passport as a verified identity', () => {
    const c = attackerCredentials()
    const r = verifyA2AIdentity(card(c.publicKey) as never, c.passport)
    assert.equal(r.valid, false, 'a self-minted passport was reported as a verified identity')
    assert.ok(r.errors.some(e => e.includes('Untrusted issuer')), JSON.stringify(r.errors))
  })

  it('reports valid under explicit allowSelfSigned', () => {
    const c = attackerCredentials()
    const r = verifyA2AIdentity(card(c.publicKey) as never, c.passport, SELF_SIGNED)
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  it('reports valid under a matching trusted issuer', () => {
    const issuer = generateKeyPair()
    const c = issuedCredentials(issuer.privateKey)
    const r = verifyA2AIdentity(card(c.publicKey) as never, c.passport, { trustedIssuers: [issuer.publicKey] })
    assert.equal(r.valid, true, JSON.stringify(r.errors))
  })

  it('still catches a card whose key does not match the passport', () => {
    const c = attackerCredentials()
    const other = generateKeyPair()
    const r = verifyA2AIdentity(card(other.publicKey) as never, c.passport, SELF_SIGNED)
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => e.includes('security scheme publicKey')))
  })
})
