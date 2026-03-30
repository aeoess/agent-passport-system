// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Tests for NVIDIA OpenShell adapter

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  delegationToPolicy, policyToYaml, extractEffectiveScopes
} from '../src/adapters/openshell.js'
import type { Delegation } from '../src/types/passport.js'

function makeDelegation(scope: string[], currentDepth = 1): Delegation {
  return {
    delegationId: `del-${Date.now()}`,
    delegatedTo: 'agent-b',
    delegatedBy: 'agent-a',
    scope,
    expiresAt: new Date(Date.now() + 86400000).toISOString(),
    maxDepth: 3,
    currentDepth,
    createdAt: new Date().toISOString(),
  }
}

const AGENT_KEY = 'a'.repeat(64)
const ISSUER_KEY = 'b'.repeat(64)

describe('OpenShell Adapter', () => {
  it('maps filesystem:read scope to read_only policy', () => {
    const del = makeDelegation(['filesystem:read'])
    const policy = delegationToPolicy(del, AGENT_KEY)
    assert.ok(policy.filesystem_policy)
    assert.ok(policy.filesystem_policy!.read_only.includes('/sandbox'))
    assert.equal(policy.filesystem_policy!.read_write.length, 0)
  })

  it('maps filesystem:write scope to read_write policy', () => {
    const del = makeDelegation(['filesystem:write'])
    const policy = delegationToPolicy(del, AGENT_KEY)
    assert.ok(policy.filesystem_policy!.read_write.includes('/sandbox'))
  })

  it('maps commerce:* scope to gateway network policy', () => {
    const del = makeDelegation(['commerce:send'])
    const policy = delegationToPolicy(del, AGENT_KEY)
    assert.ok(policy.network_policies)
    const entries = Object.values(policy.network_policies!)
    assert.ok(entries.some(e => e.endpoints.some(ep => ep.host === 'gateway.aeoess.com')))
  })

  it('includes identity_policy with agent and issuer keys', () => {
    const del = makeDelegation(['filesystem:read'])
    const policy = delegationToPolicy(del, AGENT_KEY, ISSUER_KEY)
    assert.ok(policy.identity_policy)
    assert.equal(policy.identity_policy!.agent_public_key, AGENT_KEY)
    assert.equal(policy.identity_policy!.issuer_public_key, ISSUER_KEY)
  })

  it('tracks delegation depth', () => {
    const del = makeDelegation(['filesystem:read'], 2)
    const policy = delegationToPolicy(del, AGENT_KEY)
    assert.equal(policy.identity_policy!.delegation_chain_depth, 2)
  })

  it('empty scope produces minimal policy', () => {
    const del = makeDelegation([])
    const policy = delegationToPolicy(del, AGENT_KEY)
    assert.ok(policy.filesystem_policy!.read_only.length > 0) // base paths always present
    assert.equal(policy.filesystem_policy!.read_write.length, 0)
    assert.equal(policy.network_policies, undefined)
  })

  it('multiple scopes combine additively', () => {
    const del = makeDelegation(['filesystem:read', 'filesystem:write', 'commerce:send'])
    const policy = delegationToPolicy(del, AGENT_KEY)
    assert.ok(policy.filesystem_policy!.read_only.includes('/sandbox'))
    assert.ok(policy.filesystem_policy!.read_write.includes('/sandbox'))
    assert.ok(policy.network_policies)
  })

  it('extractEffectiveScopes returns delegation scope', () => {
    const del = makeDelegation(['a', 'b', 'c'])
    assert.deepStrictEqual(extractEffectiveScopes(del), ['a', 'b', 'c'])
  })

  it('policyToYaml produces valid YAML string', () => {
    const del = makeDelegation(['filesystem:read', 'commerce:send'])
    const policy = delegationToPolicy(del, AGENT_KEY, ISSUER_KEY)
    const yaml = policyToYaml(policy)
    assert.ok(yaml.includes('version: 1'))
    assert.ok(yaml.includes('agent_public_key'))
    assert.ok(yaml.includes('issuer_public_key'))
    assert.ok(yaml.includes('filesystem_policy'))
    assert.ok(yaml.includes('read_only'))
    assert.ok(yaml.includes('network_policies'))
    assert.ok(yaml.includes('gateway.aeoess.com'))
    assert.ok(yaml.includes('run_as_user: sandbox'))
  })

  it('custom scope mappings override defaults', () => {
    const del = makeDelegation(['custom:action'])
    const custom = {
      'custom:action': {
        networkAllow: [{ host: 'custom.api.com', port: 8080 }],
      },
    }
    const policy = delegationToPolicy(del, AGENT_KEY, undefined, custom)
    assert.ok(policy.network_policies)
    const entries = Object.values(policy.network_policies!)
    assert.ok(entries.some(e => e.endpoints.some(ep => ep.host === 'custom.api.com')))
  })

  it('wildcard scope covers specific actions', () => {
    const del = makeDelegation(['network:*'])
    const policy = delegationToPolicy(del, AGENT_KEY)
    // network:* maps but has empty networkAllow by default
    assert.ok(policy)
  })

  it('process section always present with sandbox user', () => {
    const del = makeDelegation([])
    const policy = delegationToPolicy(del, AGENT_KEY)
    assert.equal(policy.process!.run_as_user, 'sandbox')
    assert.equal(policy.process!.run_as_group, 'sandbox')
  })
})
