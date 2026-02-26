import { describe, it, beforeEach } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createTaskBrief, verifyTaskBrief,
  assignTask, acceptTask,
  submitEvidence, verifyEvidence,
  reviewEvidence, verifyReview,
  handoffEvidence, verifyHandoff,
  submitDeliverable, verifyDeliverable,
  completeTask, verifyCompletion,
  createTaskUnit, getTaskStatus, validateTaskUnit,
  createDelegation, clearStores,
} from '../src/index.js'
import type { TaskUnit, EvidencePacket, ReviewDecision } from '../src/index.js'

// Shared keys for all tests
let operator: { publicKey: string; privateKey: string }
let researcher: { publicKey: string; privateKey: string }
let analyst: { publicKey: string; privateKey: string }

beforeEach(() => {
  clearStores()
  operator = generateKeyPair()
  researcher = generateKeyPair()
  analyst = generateKeyPair()
})

describe('Task Brief', () => {
  it('creates and verifies a task brief', () => {
    const brief = createTaskBrief({
      title: 'Competitive Protocol Analysis',
      description: 'Analyze 5 agent identity protocols across 10 dimensions',
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      roles: [
        { role: 'researcher', description: 'Search and extract evidence', allowedScopes: ['web:search', 'data:extract'], forbiddenScopes: ['data:synthesize'] },
        { role: 'analyst', description: 'Synthesize evidence into matrix', allowedScopes: ['data:synthesize', 'output:format'], forbiddenScopes: ['web:search'] },
      ],
      deliverables: [
        { name: 'Evidence Table', description: '50 cited claims', format: 'json', producedBy: 'researcher' },
        { name: 'Comparison Matrix', description: '5x10 matrix', format: 'markdown', producedBy: 'analyst' },
      ],
      acceptanceCriteria: ['All claims have source URLs', 'Gaps explicitly flagged', 'Matrix covers all 10 dimensions'],
    })

    assert.ok(brief.taskId.startsWith('task-'))
    assert.equal(brief.version, '1.0')
    assert.equal(brief.roles.length, 2)
    assert.equal(brief.deliverables.length, 2)
    assert.equal(brief.status, 'draft')

    const result = verifyTaskBrief(brief)
    assert.ok(result.valid, `Errors: ${result.errors.join(', ')}`)
  })

  it('[ADVERSARIAL] rejects tampered brief', () => {
    const brief = createTaskBrief({
      title: 'Test',
      description: 'Test task',
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      roles: [{ role: 'researcher', description: 'Search', allowedScopes: ['web:search'], forbiddenScopes: [] }],
      deliverables: [{ name: 'Output', description: 'Test', format: 'json', producedBy: 'researcher' }],
      acceptanceCriteria: ['Done'],
    })

    const tampered = { ...brief, title: 'Tampered Title' }
    const result = verifyTaskBrief(tampered)
    assert.ok(!result.valid)
  })

  it('rejects brief with missing roles for deliverables', () => {
    const brief = createTaskBrief({
      title: 'Test',
      description: 'Test',
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      roles: [{ role: 'researcher', description: 'Search', allowedScopes: ['web:search'], forbiddenScopes: [] }],
      deliverables: [{ name: 'Matrix', description: 'Output', format: 'md', producedBy: 'analyst' }],
      acceptanceCriteria: ['Done'],
    })

    const result = verifyTaskBrief(brief)
    assert.ok(!result.valid)
    assert.ok(result.errors.some(e => e.includes('analyst')))
  })
})

describe('Task Assignment', () => {
  it('assigns agent to role and updates brief', () => {
    const brief = createTaskBrief({
      title: 'Test',
      description: 'Test',
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      roles: [
        { role: 'researcher', description: 'Search', allowedScopes: ['web:search'], forbiddenScopes: [] },
        { role: 'analyst', description: 'Synthesize', allowedScopes: ['data:synthesize'], forbiddenScopes: [] },
      ],
      deliverables: [{ name: 'Output', description: 'Test', format: 'json', producedBy: 'researcher' }],
      acceptanceCriteria: ['Done'],
    })

    const delegation = createDelegation({
      delegatorId: 'operator-001',
      delegateId: 'researcher-001',
      scope: ['web:search'],
      spendLimit: 100,
      maxDepth: 1,
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      delegatorKey: operator.publicKey,
      privateKey: operator.privateKey,
    })

    const { assignment, updatedBrief } = assignTask({
      brief,
      role: 'researcher',
      agentId: 'researcher-001',
      agentPublicKey: researcher.publicKey,
      delegationId: delegation.delegationId,
      operatorPrivateKey: operator.privateKey,
    })

    assert.ok(assignment.assignmentId.startsWith('assign-'))
    assert.equal(assignment.role, 'researcher')
    assert.equal(updatedBrief.status, 'draft') // analyst not assigned yet

    // Role should be filled in updated brief
    const researcherRole = updatedBrief.roles.find(r => r.role === 'researcher')
    assert.equal(researcherRole?.assignedTo, researcher.publicKey)
  })

  it('agent accepts assignment', () => {
    const brief = createTaskBrief({
      title: 'Test',
      description: 'Test',
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      roles: [{ role: 'researcher', description: 'Search', allowedScopes: ['web:search'], forbiddenScopes: [] }],
      deliverables: [{ name: 'Output', description: 'Test', format: 'json', producedBy: 'researcher' }],
      acceptanceCriteria: ['Done'],
    })

    const delegation = createDelegation({
      delegatorId: 'op', delegateId: 'res', scope: ['web:search'], spendLimit: 100,
      maxDepth: 1, expiresAt: new Date(Date.now() + 3600000).toISOString(),
      delegatorKey: operator.publicKey, privateKey: operator.privateKey,
    })

    const { assignment } = assignTask({
      brief, role: 'researcher', agentId: 'res', agentPublicKey: researcher.publicKey,
      delegationId: delegation.delegationId, operatorPrivateKey: operator.privateKey,
    })

    const accepted = acceptTask(assignment, researcher.privateKey)
    assert.ok(accepted.acceptedAt)
    assert.ok(accepted.agentSignature)
  })

  it('[ADVERSARIAL] rejects double assignment', () => {
    const brief = createTaskBrief({
      title: 'Test', description: 'Test',
      operatorPublicKey: operator.publicKey, operatorPrivateKey: operator.privateKey,
      roles: [{ role: 'researcher', description: 'Search', allowedScopes: ['web:search'], forbiddenScopes: [] }],
      deliverables: [{ name: 'Output', description: 'Test', format: 'json', producedBy: 'researcher' }],
      acceptanceCriteria: ['Done'],
    })

    const delegation = createDelegation({
      delegatorId: 'op', delegateId: 'res', scope: ['web:search'], spendLimit: 100,
      maxDepth: 1, expiresAt: new Date(Date.now() + 3600000).toISOString(),
      delegatorKey: operator.publicKey, privateKey: operator.privateKey,
    })

    const { updatedBrief } = assignTask({
      brief, role: 'researcher', agentId: 'res', agentPublicKey: researcher.publicKey,
      delegationId: delegation.delegationId, operatorPrivateKey: operator.privateKey,
    })

    assert.throws(() => {
      assignTask({
        brief: updatedBrief, role: 'researcher', agentId: 'res2', agentPublicKey: analyst.publicKey,
        delegationId: delegation.delegationId, operatorPrivateKey: operator.privateKey,
      })
    }, /already assigned/)
  })
})

describe('Evidence Submission', () => {
  it('creates and verifies evidence packet', () => {
    const packet = submitEvidence({
      taskId: 'task-test',
      submitterPublicKey: researcher.publicKey,
      submitterPrivateKey: researcher.privateKey,
      role: 'researcher',
      claims: [
        { dimension: 'identity', subject: 'APS', claim: 'Uses Ed25519 signatures', quote: 'Ed25519 cryptographic identity for AI agents with zero dependencies', sourceUrl: 'https://github.com/aeoess/agent-passport-system', confidence: 'high' },
        { dimension: 'governance', subject: 'APS', claim: 'Has values floor', quote: 'Layer 2 Human Values Floor with 7 universal principles and 5 technically enforced', sourceUrl: 'https://github.com/aeoess/agent-passport-system', confidence: 'high' },
        { dimension: 'identity', subject: 'ANG', claim: 'Not found in README', quote: '', sourceUrl: '', confidence: 'not_found' },
      ],
      methodology: 'GitHub API full text reading of repository READMEs',
    })

    assert.ok(packet.packetId.startsWith('evid-'))
    assert.equal(packet.metadata.totalClaims, 3)
    assert.equal(packet.metadata.citedClaims, 2)
    assert.equal(packet.metadata.gapCount, 1)

    const result = verifyEvidence(packet)
    assert.ok(result.valid, `Errors: ${result.errors.join(', ')}`)
  })

  it('[ADVERSARIAL] rejects tampered evidence', () => {
    const packet = submitEvidence({
      taskId: 'task-test',
      submitterPublicKey: researcher.publicKey,
      submitterPrivateKey: researcher.privateKey,
      role: 'researcher',
      claims: [{ dimension: 'test', subject: 'test', claim: 'test claim', quote: 'a real quote here', sourceUrl: 'https://example.com', confidence: 'high' }],
      methodology: 'test',
    })

    const tampered = { ...packet, claims: [{ ...packet.claims[0], claim: 'TAMPERED CLAIM' }] }
    const result = verifyEvidence(tampered)
    assert.ok(!result.valid)
  })
})

describe('Review Decision', () => {
  it('operator approves evidence above threshold', () => {
    const packet = submitEvidence({
      taskId: 'task-test',
      submitterPublicKey: researcher.publicKey,
      submitterPrivateKey: researcher.privateKey,
      role: 'researcher',
      claims: [{ dimension: 'test', subject: 'test', claim: 'valid', quote: 'a proper supporting quote', sourceUrl: 'https://example.com', confidence: 'high' }],
      methodology: 'test',
    })

    const review = reviewEvidence({
      taskId: 'task-test',
      packet,
      reviewerPublicKey: operator.publicKey,
      reviewerPrivateKey: operator.privateKey,
      verdict: 'approve',
      score: 85,
      threshold: 70,
      rationale: 'Evidence meets quality standards',
    })

    assert.equal(review.verdict, 'approve')
    assert.equal(review.score, 85)
    const result = verifyReview(review)
    assert.ok(result.valid)
  })

  it('operator requests rework', () => {
    const packet = submitEvidence({
      taskId: 'task-test',
      submitterPublicKey: researcher.publicKey,
      submitterPrivateKey: researcher.privateKey,
      role: 'researcher',
      claims: [{ dimension: 'test', subject: 'test', claim: 'weak', quote: 'just one word', sourceUrl: '', confidence: 'low' }],
      methodology: 'keyword grep',
    })

    const review = reviewEvidence({
      taskId: 'task-test',
      packet,
      reviewerPublicKey: operator.publicKey,
      reviewerPrivateKey: operator.privateKey,
      verdict: 'rework',
      score: 40,
      threshold: 70,
      rationale: 'Quotes too short, sources missing',
      issues: [{ claimId: packet.claims[0].claimId, issue: 'quote too short', severity: 'critical' }],
    })

    assert.equal(review.verdict, 'rework')
    assert.equal(review.issues?.length, 1)
  })

  it('[ADVERSARIAL] cannot approve below threshold', () => {
    const packet = submitEvidence({
      taskId: 'task-test',
      submitterPublicKey: researcher.publicKey,
      submitterPrivateKey: researcher.privateKey,
      role: 'researcher',
      claims: [{ dimension: 'test', subject: 'test', claim: 'bad', quote: 'keyword', sourceUrl: '', confidence: 'low' }],
      methodology: 'test',
    })

    assert.throws(() => {
      reviewEvidence({
        taskId: 'task-test', packet,
        reviewerPublicKey: operator.publicKey, reviewerPrivateKey: operator.privateKey,
        verdict: 'approve', score: 30, threshold: 70,
        rationale: 'Trying to approve bad evidence',
      })
    }, /below threshold/)
  })
})

describe('Evidence Handoff', () => {
  it('hands off approved evidence to analyst', () => {
    const packet = submitEvidence({
      taskId: 'task-test',
      submitterPublicKey: researcher.publicKey,
      submitterPrivateKey: researcher.privateKey,
      role: 'researcher',
      claims: [{ dimension: 'test', subject: 'test', claim: 'valid', quote: 'a proper supporting quote here', sourceUrl: 'https://example.com', confidence: 'high' }],
      methodology: 'test',
    })

    const review = reviewEvidence({
      taskId: 'task-test', packet,
      reviewerPublicKey: operator.publicKey, reviewerPrivateKey: operator.privateKey,
      verdict: 'approve', score: 90, threshold: 70, rationale: 'Good evidence',
    })

    const handoff = handoffEvidence({
      taskId: 'task-test', packet, review,
      fromRole: 'researcher', toRole: 'analyst',
      toAgentPublicKey: analyst.publicKey,
      operatorPrivateKey: operator.privateKey,
    })

    assert.ok(handoff.handoffId.startsWith('handoff-'))
    assert.equal(handoff.fromRole, 'researcher')
    assert.equal(handoff.toRole, 'analyst')

    const result = verifyHandoff(handoff, operator.publicKey)
    assert.ok(result.valid)
  })

  it('[ADVERSARIAL] rejects handoff of unapproved evidence', () => {
    const packet = submitEvidence({
      taskId: 'task-test',
      submitterPublicKey: researcher.publicKey, submitterPrivateKey: researcher.privateKey,
      role: 'researcher',
      claims: [{ dimension: 'test', subject: 'test', claim: 'bad', quote: 'short', sourceUrl: '', confidence: 'low' }],
      methodology: 'test',
    })

    const review = reviewEvidence({
      taskId: 'task-test', packet,
      reviewerPublicKey: operator.publicKey, reviewerPrivateKey: operator.privateKey,
      verdict: 'rework', score: 30, threshold: 70, rationale: 'Bad quality',
    })

    assert.throws(() => {
      handoffEvidence({
        taskId: 'task-test', packet, review,
        fromRole: 'researcher', toRole: 'analyst',
        toAgentPublicKey: analyst.publicKey,
        operatorPrivateKey: operator.privateKey,
      })
    }, /not approved/)
  })
})

describe('Deliverable Submission', () => {
  it('analyst submits deliverable citing evidence', () => {
    const deliverable = submitDeliverable({
      taskId: 'task-test',
      specId: 'task-test-del-0',
      submitterPublicKey: analyst.publicKey,
      submitterPrivateKey: analyst.privateKey,
      role: 'analyst',
      content: '## Comparison Matrix\n\n| Protocol | Identity | Delegation |\n|---|---|---|\n| APS | Ed25519 | Scoped chains |',
      evidencePacketIds: ['evid-test-1'],
      citationCount: 15,
      gapsFlagged: 2,
    })

    assert.ok(deliverable.deliverableId.startsWith('deliv-'))
    assert.equal(deliverable.gapsFlagged, 2)

    const result = verifyDeliverable(deliverable)
    assert.ok(result.valid)
  })
})

describe('Full Coordination Lifecycle', () => {
  it('complete workflow: brief → assign → evidence → review → handoff → deliver → complete', () => {
    // 1. Operator creates task brief
    const brief = createTaskBrief({
      title: 'Competitive Protocol Analysis',
      description: 'Analyze 5 agent identity protocols',
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      roles: [
        { role: 'researcher', description: 'Gather evidence', allowedScopes: ['web:search', 'data:extract'], forbiddenScopes: ['data:synthesize'] },
        { role: 'analyst', description: 'Produce matrix', allowedScopes: ['data:synthesize'], forbiddenScopes: ['web:search'] },
      ],
      deliverables: [
        { name: 'Evidence Table', description: '50 cited claims', format: 'json', producedBy: 'researcher' },
        { name: 'Comparison Matrix', description: '5x10 matrix', format: 'markdown', producedBy: 'analyst' },
      ],
      acceptanceCriteria: ['All claims cited', 'Gaps flagged', '10+ word quotes'],
    })

    const unit = createTaskUnit(brief)
    assert.equal(getTaskStatus(unit), 'draft')

    // 2. Operator assigns researcher
    const resDelegation = createDelegation({
      delegatorId: 'operator-001', delegateId: 'researcher-001',
      scope: ['web:search', 'data:extract'], spendLimit: 200, maxDepth: 1,
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      delegatorKey: operator.publicKey, privateKey: operator.privateKey,
    })

    const { assignment: resAssign, updatedBrief: brief2 } = assignTask({
      brief, role: 'researcher', agentId: 'researcher-001',
      agentPublicKey: researcher.publicKey,
      delegationId: resDelegation.delegationId,
      operatorPrivateKey: operator.privateKey,
    })

    // 3. Operator assigns analyst
    const anlDelegation = createDelegation({
      delegatorId: 'operator-001', delegateId: 'analyst-001',
      scope: ['data:synthesize'], spendLimit: 150, maxDepth: 1,
      expiresAt: new Date(Date.now() + 3600000).toISOString(),
      delegatorKey: operator.publicKey, privateKey: operator.privateKey,
    })

    const { assignment: anlAssign, updatedBrief: brief3 } = assignTask({
      brief: brief2, role: 'analyst', agentId: 'analyst-001',
      agentPublicKey: analyst.publicKey,
      delegationId: anlDelegation.delegationId,
      operatorPrivateKey: operator.privateKey,
    })

    assert.equal(brief3.status, 'assigned')

    // Agents accept
    const resAccepted = acceptTask(resAssign, researcher.privateKey)
    const anlAccepted = acceptTask(anlAssign, analyst.privateKey)
    unit.brief = brief3
    unit.assignments.push(resAccepted, anlAccepted)
    assert.equal(getTaskStatus(unit), 'in_progress')

    // 4. Researcher submits evidence
    const evidence = submitEvidence({
      taskId: brief.taskId,
      submitterPublicKey: researcher.publicKey,
      submitterPrivateKey: researcher.privateKey,
      role: 'researcher',
      claims: [
        { dimension: 'identity', subject: 'APS', claim: 'Uses Ed25519', quote: 'Ed25519 cryptographic identity for AI agents with zero external dependencies', sourceUrl: 'https://github.com/aeoess/agent-passport-system', confidence: 'high' },
        { dimension: 'delegation', subject: 'APS', claim: 'Scoped delegation chains', quote: 'Scoped delegation with depth limits, spend caps, and automatic scope narrowing', sourceUrl: 'https://github.com/aeoess/agent-passport-system', confidence: 'high' },
        { dimension: 'governance', subject: 'ANG', claim: 'Not found', quote: '', sourceUrl: '', confidence: 'not_found' },
      ],
      methodology: 'GitHub API full text reading',
    })

    unit.evidencePackets.push(evidence)
    assert.equal(getTaskStatus(unit), 'evidence_submitted')

    // 5. Operator reviews — APPROVE
    const review = reviewEvidence({
      taskId: brief.taskId, packet: evidence,
      reviewerPublicKey: operator.publicKey, reviewerPrivateKey: operator.privateKey,
      verdict: 'approve', score: 85, threshold: 70,
      rationale: 'Good coverage, quotes meet length requirement',
    })

    unit.reviews.push(review)
    assert.equal(getTaskStatus(unit), 'approved')

    // 6. Operator hands off to analyst
    const handoff = handoffEvidence({
      taskId: brief.taskId, packet: evidence, review,
      fromRole: 'researcher', toRole: 'analyst',
      toAgentPublicKey: analyst.publicKey,
      operatorPrivateKey: operator.privateKey,
    })

    unit.handoffs.push(handoff)

    // 7. Analyst produces deliverable
    const deliverable = submitDeliverable({
      taskId: brief.taskId,
      specId: brief.deliverables[1].deliverableId,
      submitterPublicKey: analyst.publicKey,
      submitterPrivateKey: analyst.privateKey,
      role: 'analyst',
      content: '| Protocol | Identity | Delegation | Governance |\n|---|---|---|---|\n| APS | Ed25519 ✓ | Scoped chains ✓ | [EVIDENCE GAP] |',
      evidencePacketIds: [evidence.packetId],
      citationCount: 2,
      gapsFlagged: 1,
    })

    unit.deliverables.push(deliverable)
    assert.equal(getTaskStatus(unit), 'delivered')

    // 8. Operator completes task
    const completion = completeTask({
      brief: brief3, unit,
      operatorPublicKey: operator.publicKey,
      operatorPrivateKey: operator.privateKey,
      status: 'completed',
      retrospective: 'Evidence quality met threshold. 1 gap correctly flagged by analyst. Process worked.',
    })

    unit.completion = completion
    assert.equal(getTaskStatus(unit), 'completed')
    assert.equal(completion.metrics.agentCount, 2)
    assert.equal(completion.metrics.reworkCount, 0)

    // 9. Validate the entire unit
    const validation = validateTaskUnit(unit)
    assert.ok(validation.valid, `Unit validation errors: ${validation.errors.join(', ')}`)

    // Print summary
    console.log('\n  ═══ Coordination Lifecycle Complete ═══')
    console.log(`  Task: ${brief.title}`)
    console.log(`  Agents: ${completion.metrics.agentCount}`)
    console.log(`  Evidence: ${evidence.metadata.totalClaims} claims, ${evidence.metadata.gapCount} gaps`)
    console.log(`  Review: ${review.verdict} (${review.score}/${review.threshold})`)
    console.log(`  Deliverable: ${deliverable.citationCount} citations, ${deliverable.gapsFlagged} gaps flagged`)
    console.log(`  Rework cycles: ${completion.metrics.reworkCount}`)
    console.log(`  Status: ${completion.status}`)
  })
})

describe('Task Unit Validation', () => {
  it('catches mismatched taskIds', () => {
    const brief = createTaskBrief({
      title: 'Test', description: 'Test',
      operatorPublicKey: operator.publicKey, operatorPrivateKey: operator.privateKey,
      roles: [{ role: 'researcher', description: 'Search', allowedScopes: ['web:search'], forbiddenScopes: [] }],
      deliverables: [{ name: 'Output', description: 'Test', format: 'json', producedBy: 'researcher' }],
      acceptanceCriteria: ['Done'],
    })

    const unit = createTaskUnit(brief)

    // Evidence with wrong taskId
    const wrongEvidence = submitEvidence({
      taskId: 'wrong-task-id',
      submitterPublicKey: researcher.publicKey, submitterPrivateKey: researcher.privateKey,
      role: 'researcher',
      claims: [{ dimension: 'test', subject: 'test', claim: 'valid', quote: 'a proper quote here', sourceUrl: 'https://example.com', confidence: 'high' }],
      methodology: 'test',
    })

    unit.evidencePackets.push(wrongEvidence)

    const result = validateTaskUnit(unit)
    assert.ok(!result.valid)
    assert.ok(result.errors.some(e => e.includes('taskId mismatch')))
  })

  it('catches handoff without approved review', () => {
    const brief = createTaskBrief({
      title: 'Test', description: 'Test',
      operatorPublicKey: operator.publicKey, operatorPrivateKey: operator.privateKey,
      roles: [{ role: 'researcher', description: 'Search', allowedScopes: ['web:search'], forbiddenScopes: [] }],
      deliverables: [{ name: 'Output', description: 'Test', format: 'json', producedBy: 'researcher' }],
      acceptanceCriteria: ['Done'],
    })

    const unit = createTaskUnit(brief)

    // Fake handoff referencing non-existent review
    unit.handoffs.push({
      handoffId: 'handoff-fake',
      taskId: brief.taskId,
      packetId: 'evid-fake',
      reviewId: 'review-nonexistent',
      fromRole: 'researcher',
      toRole: 'analyst',
      fromAgent: researcher.publicKey,
      toAgent: analyst.publicKey,
      handoffAt: new Date().toISOString(),
      operatorSignature: 'fake',
    })

    const result = validateTaskUnit(unit)
    assert.ok(!result.valid)
    assert.ok(result.errors.some(e => e.includes('unknown review')))
  })
})
