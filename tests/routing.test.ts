// ══════════════════════════════════════
// Task Routing Protocol — Tests
// ══════════════════════════════════════

import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import { createDelegation } from '../src/core/delegation.js'
import { createPassport, signPassport } from '../src/core/passport.js'
import {
  createTaskRequest, verifyTaskRequest,
  advertiseCapabilities, verifyAdvertisement,
  claimTask, verifyClaim,
  declineTask, verifyDecline,
  routeTask, verifyRoutingDecision,
  scoreCandidate,
  capabilityMatches, capabilityCoverage,
  checkDelegationScope, isAdvertisementFresh,
  DEFAULT_ROUTER_CONFIG,
} from '../src/index.js'
import type {
  TaskRequest, CapabilityAdvertisement, ClaimResponse,
  RoutingDecision, CandidateScore,
} from '../src/index.js'
import type { Delegation, KeyPair } from '../src/types/passport.js'

// ── Test Helpers ──

let operator: KeyPair
let agent1: KeyPair
let agent2: KeyPair
let agent3: KeyPair

function makePassportAndDelegation(keys: KeyPair, operatorKeys: KeyPair, scope: string[]): Delegation {
  const passport = createPassport({
    name: 'test-agent',
    capabilities: [],
    publicKey: keys.publicKey,
  })
  const signed = signPassport(passport, keys.privateKey)
  return createDelegation({
    delegatedBy: operatorKeys.publicKey,
    privateKey: operatorKeys.privateKey,
    delegatedTo: keys.publicKey,
    scope,
    expiresInHours: 1,
  })
}

describe('Task Routing Protocol', () => {
  beforeEach(() => {
    operator = generateKeyPair()
    agent1 = generateKeyPair()
    agent2 = generateKeyPair()
    agent3 = generateKeyPair()
  })

  // ═══════════════════════════════════════
  // Capability Matching
  // ═══════════════════════════════════════

  describe('Capability Matching', () => {
    it('exact match', () => {
      assert.ok(capabilityMatches('code:deploy', 'code:deploy'))
    })

    it('parent covers child (hierarchical)', () => {
      assert.ok(capabilityMatches('code', 'code:deploy'))
    })

    it('child satisfies parent requirement', () => {
      assert.ok(capabilityMatches('code:deploy', 'code'))
    })

    it('no match across different roots', () => {
      assert.ok(!capabilityMatches('code:deploy', 'research:web'))
    })

    it('no partial string match', () => {
      assert.ok(!capabilityMatches('cod', 'code'))
    })

    it('coverage computation', () => {
      const result = capabilityCoverage(
        ['code:deploy', 'research:web', 'spec:write'],
        ['code:deploy', 'research:web', 'commerce:checkout'],
      )
      assert.equal(result.matched.length, 2)
      assert.equal(result.missing.length, 1)
      assert.deepEqual(result.missing, ['commerce:checkout'])
    })
  })

  // ═══════════════════════════════════════
  // Delegation Scope Gate
  // ═══════════════════════════════════════

  describe('Delegation Scope Gate', () => {
    it('passes when all capabilities in scope', () => {
      const result = checkDelegationScope(
        ['code:deploy', 'code:review'],
        ['code:deploy', 'code:review', 'code:test'],
      )
      assert.ok(result.valid)
      assert.equal(result.violations.length, 0)
    })

    it('fails when capability outside scope', () => {
      const result = checkDelegationScope(
        ['code:deploy', 'commerce:checkout'],
        ['code:deploy', 'code:review'],
      )
      assert.ok(!result.valid)
      assert.deepEqual(result.violations, ['commerce:checkout'])
    })

    it('hierarchical scope covers child capabilities', () => {
      const result = checkDelegationScope(
        ['code:deploy', 'code:review'],
        ['code'],  // broad scope covers all code:*
      )
      assert.ok(result.valid)
    })
  })

  // ═══════════════════════════════════════
  // Advertisement Freshness
  // ═══════════════════════════════════════

  describe('Advertisement Freshness', () => {
    it('fresh advertisement within TTL', () => {
      const ad = advertiseCapabilities({
        agentId: 'agent-1', capabilities: ['code'], publicKey: agent1.publicKey, privateKey: agent1.privateKey,
        advertisementTTL: 3600,
      })
      assert.ok(isAdvertisementFresh(ad))
    })

    it('stale advertisement past TTL', () => {
      const ad = advertiseCapabilities({
        agentId: 'agent-1', capabilities: ['code'], publicKey: agent1.publicKey, privateKey: agent1.privateKey,
        advertisementTTL: 1,  // 1 second TTL
      })
      const future = new Date(Date.now() + 5000)  // 5 seconds later
      assert.ok(!isAdvertisementFresh(ad, future))
    })
  })

  // ═══════════════════════════════════════
  // TaskRequest CRUD + Signatures
  // ═══════════════════════════════════════

  describe('TaskRequest', () => {
    it('creates and verifies a task request', () => {
      const req = createTaskRequest({
        requesterId: 'op-001',
        title: 'Build routing engine',
        description: 'Implement task routing protocol',
        requiredCapabilities: ['code:typescript', 'spec:protocol'],
        estimatedTokens: 50000,
        priority: 'high',
        publicKey: operator.publicKey,
        privateKey: operator.privateKey,
      })
      assert.ok(req.id.startsWith('task-req-'))
      assert.equal(req.status, 'open')
      assert.equal(req.priority, 'high')
      assert.ok(verifyTaskRequest(req))
    })

    it('rejects tampered task request', () => {
      const req = createTaskRequest({
        requesterId: 'op-001',
        title: 'Build routing engine',
        description: 'Implement task routing',
        requiredCapabilities: ['code'],
        publicKey: operator.publicKey,
        privateKey: operator.privateKey,
      })
      const tampered = { ...req, title: 'HACKED' }
      assert.ok(!verifyTaskRequest(tampered))
    })
  })

  // ═══════════════════════════════════════
  // Claims and Declines
  // ═══════════════════════════════════════

  describe('Claims and Declines', () => {
    it('creates and verifies a claim', () => {
      const claim = claimTask({
        taskRequestId: 'task-req-123',
        claimantId: 'agent-1',
        proposedApproach: 'Will implement in TypeScript',
        capabilitiesMatched: ['code:typescript'],
        publicKey: agent1.publicKey,
        privateKey: agent1.privateKey,
      })
      assert.equal(claim.claimantId, 'agent-1')
      assert.ok(verifyClaim(claim))
    })

    it('creates and verifies a decline', () => {
      const decline = declineTask({
        taskRequestId: 'task-req-123',
        declinerId: 'agent-2',
        reason: 'Scope mismatch: delegation is research-only',
        suggestedAlternative: 'agent-1',
        publicKey: agent2.publicKey,
        privateKey: agent2.privateKey,
      })
      assert.equal(decline.reason, 'Scope mismatch: delegation is research-only')
      assert.equal(decline.suggestedAlternative, 'agent-1')
      assert.ok(verifyDecline(decline))
    })
  })

  // ═══════════════════════════════════════
  // Routing Engine
  // ═══════════════════════════════════════

  describe('Routing Engine', () => {
    let request: TaskRequest
    let ad1: CapabilityAdvertisement
    let ad2: CapabilityAdvertisement
    let claim1: ClaimResponse
    let claim2: ClaimResponse
    let deleg1: Delegation
    let deleg2: Delegation

    beforeEach(() => {
      request = createTaskRequest({
        requesterId: 'op-001',
        title: 'Build routing engine',
        description: 'Implement routing',
        requiredCapabilities: ['code:typescript', 'spec:protocol'],
        estimatedTokens: 50000,
        priority: 'high',
        publicKey: operator.publicKey,
        privateKey: operator.privateKey,
      })

      ad1 = advertiseCapabilities({
        agentId: 'agent-1',
        capabilities: ['code:typescript', 'spec:protocol', 'research:web'],
        currentLoad: 0.2,
        publicKey: agent1.publicKey,
        privateKey: agent1.privateKey,
      })

      ad2 = advertiseCapabilities({
        agentId: 'agent-2',
        capabilities: ['code:typescript'],  // only partial match
        currentLoad: 0.1,
        publicKey: agent2.publicKey,
        privateKey: agent2.privateKey,
      })

      claim1 = claimTask({
        taskRequestId: request.id,
        claimantId: 'agent-1',
        proposedApproach: 'Full implementation',
        capabilitiesMatched: ['code:typescript', 'spec:protocol'],
        publicKey: agent1.publicKey,
        privateKey: agent1.privateKey,
      })

      claim2 = claimTask({
        taskRequestId: request.id,
        claimantId: 'agent-2',
        proposedApproach: 'Partial implementation',
        capabilitiesMatched: ['code:typescript'],
        publicKey: agent2.publicKey,
        privateKey: agent2.privateKey,
      })

      deleg1 = createDelegation({
        delegatedBy: operator.publicKey,
        privateKey: operator.privateKey,
        delegatedTo: agent1.publicKey,
        scope: ['code:typescript', 'spec:protocol', 'research:web'],
        expiresInHours: 1,
      })

      deleg2 = createDelegation({
        delegatedBy: operator.publicKey,
        privateKey: operator.privateKey,
        delegatedTo: agent2.publicKey,
        scope: ['code:typescript'],
        expiresInHours: 1,
      })
    })

    it('selects best match from multiple claims', () => {
      const delegations = new Map([['agent-1', deleg1], ['agent-2', deleg2]])
      const result = routeTask({
        request, claims: [claim1, claim2], advertisements: [ad1, ad2],
        delegations, routerPublicKey: operator.publicKey, routerPrivateKey: operator.privateKey,
      })
      assert.equal(result.decision.selectedAgentId, 'agent-1')
      assert.ok(result.decision.matchScore > 0.5)
      assert.ok(verifyRoutingDecision(result.decision))
    })

    it('rejects claim with delegation scope violation', () => {
      const delegations = new Map([['agent-2', deleg2]])
      const result = routeTask({
        request, claims: [claim2], advertisements: [ad2],
        delegations, routerPublicKey: operator.publicKey, routerPrivateKey: operator.privateKey,
      })
      assert.equal(result.rejectedClaims.length, 1)
      assert.ok(result.rejectedClaims[0].reason.includes('delegation_scope_violation'))
      assert.equal(result.decision.selectedAgentId, null)
    })

    it('rejects claim with stale advertisement', () => {
      const staleAd = advertiseCapabilities({
        agentId: 'agent-1', capabilities: ['code:typescript', 'spec:protocol'],
        advertisementTTL: 1, publicKey: agent1.publicKey, privateKey: agent1.privateKey,
      })
      const future = new Date(Date.now() + 5000)
      const delegations = new Map([['agent-1', deleg1]])
      const result = routeTask({
        request, claims: [claim1], advertisements: [staleAd],
        delegations, routerPublicKey: operator.publicKey, routerPrivateKey: operator.privateKey,
        now: future,
      })
      assert.equal(result.rejectedClaims.length, 1)
      assert.ok(result.rejectedClaims[0].reason.includes('stale_advertisement'))
    })

    it('rejects claim with no advertisement', () => {
      const delegations = new Map([['agent-1', deleg1]])
      const result = routeTask({
        request, claims: [claim1], advertisements: [],  // no ads
        delegations, routerPublicKey: operator.publicKey, routerPrivateKey: operator.privateKey,
      })
      assert.equal(result.rejectedClaims.length, 1)
      assert.ok(result.rejectedClaims[0].reason.includes('no_capability_advertisement'))
    })

    it('rejects claim from agent without delegation (R2-PX2-009)', () => {
      // Empty delegations map — agent-1 has ad and claim but no delegation
      const delegations = new Map<string, typeof deleg1>()
      const result = routeTask({
        request, claims: [claim1], advertisements: [ad1],
        delegations, routerPublicKey: operator.publicKey, routerPrivateKey: operator.privateKey,
      })
      assert.equal(result.rejectedClaims.length, 1)
      assert.equal(result.rejectedClaims[0].claimantId, 'agent-1')
      assert.ok(result.rejectedClaims[0].reason.includes('no_delegation'))
      assert.equal(result.decision.selectedAgentId, null)
    })

    it('returns null when no claims meet coverage threshold', () => {
      const lowReq = createTaskRequest({
        requesterId: 'op-001', title: 'Complex task',
        description: 'Needs many skills',
        requiredCapabilities: ['code:typescript', 'spec:protocol', 'research:web', 'commerce:checkout'],
        publicKey: operator.publicKey, privateKey: operator.privateKey,
      })
      const delegations = new Map([['agent-2', deleg2]])
      const ad2broad = advertiseCapabilities({
        agentId: 'agent-2', capabilities: ['code:typescript'],
        publicKey: agent2.publicKey, privateKey: agent2.privateKey,
      })
      const claim = claimTask({
        taskRequestId: lowReq.id, claimantId: 'agent-2',
        proposedApproach: 'try', capabilitiesMatched: ['code:typescript'],
        publicKey: agent2.publicKey, privateKey: agent2.privateKey,
      })
      // agent-2 will be rejected by scope gate (missing spec:protocol, research:web, commerce:checkout)
      const result = routeTask({
        request: lowReq, claims: [claim], advertisements: [ad2broad],
        delegations, routerPublicKey: operator.publicKey, routerPrivateKey: operator.privateKey,
      })
      assert.equal(result.decision.selectedAgentId, null)
    })

    it('priority boost affects ranking', () => {
      // Two identical agents, but request is critical
      const critReq = createTaskRequest({
        requesterId: 'op-001', title: 'Urgent fix',
        description: 'Critical bug', requiredCapabilities: ['code:typescript'],
        priority: 'critical',
        publicKey: operator.publicKey, privateKey: operator.privateKey,
      })
      const ad = advertiseCapabilities({
        agentId: 'agent-1', capabilities: ['code:typescript'],
        currentLoad: 0.5, publicKey: agent1.publicKey, privateKey: agent1.privateKey,
      })
      const deleg = createDelegation({
        delegatedBy: operator.publicKey, privateKey: operator.privateKey,
        delegatedTo: agent1.publicKey, scope: ['code:typescript'], expiresInHours: 1,
      })
      const score = scoreCandidate(critReq, ad, deleg, undefined, undefined)
      // Critical boost = +0.10
      assert.ok(score.matchScore > 0.6)
    })

    it('reputation-weighted load damping penalizes low-rep agents', () => {
      const ad = advertiseCapabilities({
        agentId: 'agent-1', capabilities: ['code:typescript', 'spec:protocol'],
        currentLoad: 0.1,  // claims low load
        publicKey: agent1.publicKey, privateKey: agent1.privateKey,
      })
      const highRep = scoreCandidate(request, ad, deleg1, 8.0)   // rep 8/10
      const lowRep = scoreCandidate(request, ad, deleg1, 1.0)    // rep 1/10
      // Low rep agent gets penalized on load score
      assert.ok(highRep.loadScore > lowRep.loadScore)
    })

    it('verifies routing decision signature', () => {
      const delegations = new Map([['agent-1', deleg1]])
      const result = routeTask({
        request, claims: [claim1], advertisements: [ad1],
        delegations, routerPublicKey: operator.publicKey, routerPrivateKey: operator.privateKey,
      })
      assert.ok(verifyRoutingDecision(result.decision))
      // Tamper
      const tampered = { ...result.decision, selectedAgentId: 'hacked' }
      assert.ok(!verifyRoutingDecision(tampered))
    })

    it('provides fallback agents ordered by score', () => {
      // Give agent-2 broad enough scope and capabilities
      const deleg2broad = createDelegation({
        delegatedBy: operator.publicKey, privateKey: operator.privateKey,
        delegatedTo: agent2.publicKey, scope: ['code', 'spec'], expiresInHours: 1,
      })
      const ad2broad = advertiseCapabilities({
        agentId: 'agent-2', capabilities: ['code:typescript', 'spec:protocol'],
        currentLoad: 0.8, publicKey: agent2.publicKey, privateKey: agent2.privateKey,
      })
      const delegations = new Map([['agent-1', deleg1], ['agent-2', deleg2broad]])
      const result = routeTask({
        request, claims: [claim1, claim2], advertisements: [ad1, ad2broad],
        delegations, routerPublicKey: operator.publicKey, routerPrivateKey: operator.privateKey,
      })
      assert.equal(result.decision.selectedAgentId, 'agent-1')
      assert.ok(result.decision.fallbackAgents.includes('agent-2'))
    })
  })
})
