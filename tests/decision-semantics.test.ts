// ══════════════════════════════════════════════════════════════════
// Module 37: Decision Semantics & Cross-Engine Interop — Tests
// ══════════════════════════════════════════════════════════════════

import { describe, it, before } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import { createDelegation } from '../src/core/delegation.js'
import {
  createActionIntent, evaluateIntent, FloorValidatorV1,
  verifyActionIntent, verifyPolicyDecision
} from '../src/core/policy.js'
import {
  computeContentHash, verifyContentHash,
  createContentAddressableIntent,
  classifyEvaluationMethod, decomposeDecision,
  createDecisionArtifact, verifyDecisionArtifact,
  getEffectiveScopeInterpretation,
  validateIdentityBoundary, sha256Hex,
} from '../src/core/decision-semantics.js'
import type { ValidationContext } from '../src/types/policy.js'

// ── Test fixtures ──

let agentKeys: { privateKey: string; publicKey: string }
let evaluatorKeys: { privateKey: string; publicKey: string }
let signerKeys: { privateKey: string; publicKey: string }
let delegation: ReturnType<typeof createDelegation>
let validContext: ValidationContext

before(() => {
  agentKeys = generateKeyPair()
  evaluatorKeys = generateKeyPair()
  signerKeys = generateKeyPair()

  delegation = createDelegation({
    delegatedTo: agentKeys.publicKey,
    delegatedBy: evaluatorKeys.publicKey,
    scope: ['data:read', 'data:write', 'search'],
    scopeInterpretation: 'hierarchical',
    spendLimit: 100,
    maxDepth: 3,
    privateKey: evaluatorKeys.privateKey
  })

  validContext = {
    floorVersion: '0.1',
    floorPrinciples: [
      { id: 'F-001', name: 'Traceability', enforcement: { mode: 'inline' as const, mechanism: 'registration' }, weight: 'mandatory' as const },
      { id: 'F-002', name: 'Honest Identity', enforcement: { mode: 'inline' as const, mechanism: 'attestation' }, weight: 'mandatory' as const },
      { id: 'F-003', name: 'Scoped Authority', enforcement: { mode: 'inline' as const, mechanism: 'scope-check' }, weight: 'mandatory' as const },
      { id: 'F-004', name: 'Revocability', enforcement: { mode: 'inline' as const, mechanism: 'revocation-check' }, weight: 'mandatory' as const },
      { id: 'F-005', name: 'Auditability', enforcement: { mode: 'inline' as const, mechanism: 'depth-check' }, weight: 'mandatory' as const },
      { id: 'F-006', name: 'Non-Deception', enforcement: { mode: 'audit' as const, mechanism: 'reasoning' }, weight: 'strong_consideration' as const },
      { id: 'F-007', name: 'Proportionality', enforcement: { mode: 'audit' as const, mechanism: 'reputation' }, weight: 'strong_consideration' as const },
    ],
    delegation: {
      scope: ['data:read', 'data:write', 'search'],
      spendLimit: 100,
      spentAmount: 0,
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      revoked: false,
      currentDepth: 0,
      maxDepth: 3
    },
    agentRegistered: true,
    agentAttestationValid: true
  }
})

// ══════════════════════════════════════
// Content Hashing
// ══════════════════════════════════════

describe('Content Hashing', () => {
  it('computes SHA-256 hash of unsigned intent', async () => {
    const intent = createActionIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:read', target: 'database', scopeRequired: 'data:read' },
      privateKey: agentKeys.privateKey
    })
    const { signature, ...unsigned } = intent
    const hash = await computeContentHash(unsigned)
    assert.equal(hash.algorithm, 'sha256')
    assert.equal(hash.canonicalForm, 'canonical_json_sorted_keys')
    assert.equal(hash.hash.length, 64) // SHA-256 hex = 64 chars
  })

  it('produces deterministic hashes for same content', async () => {
    const unsigned = {
      intentId: 'intent_fixed001',
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: 'del_fixed001',
      action: { type: 'search', target: 'index', scopeRequired: 'search' },
      createdAt: '2026-03-20T00:00:00.000Z'
    }
    const hash1 = await computeContentHash(unsigned)
    const hash2 = await computeContentHash(unsigned)
    assert.equal(hash1.hash, hash2.hash)
  })

  it('produces different hashes for different content', async () => {
    const base = {
      intentId: 'intent_abc',
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: 'del_abc',
      action: { type: 'search', target: 'index', scopeRequired: 'search' },
      createdAt: '2026-03-20T00:00:00.000Z'
    }
    const hash1 = await computeContentHash(base)
    const hash2 = await computeContentHash({ ...base, agentId: 'agent-2' })
    assert.notEqual(hash1.hash, hash2.hash)
  })
})

// ══════════════════════════════════════
// Content-Addressable Intent Creation
// ══════════════════════════════════════

describe('Content-Addressable Intent', () => {
  it('creates intent with embedded content hash', async () => {
    const intent = await createContentAddressableIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:read', target: 'db', scopeRequired: 'data:read' },
      privateKey: agentKeys.privateKey
    })
    assert.ok(intent.contentHash, 'contentHash should be present')
    assert.equal(intent.contentHash!.algorithm, 'sha256')
    assert.equal(intent.contentHash!.hash.length, 64)
  })

  it('signature covers the content hash', async () => {
    const intent = await createContentAddressableIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:read', target: 'db', scopeRequired: 'data:read' },
      privateKey: agentKeys.privateKey
    })
    // Signature should verify (it was signed over intent INCLUDING contentHash)
    const check = verifyActionIntent(intent)
    assert.ok(check.valid, `Intent should verify: ${check.errors.join(', ')}`)
  })

  it('content hash verifies correctly', async () => {
    const intent = await createContentAddressableIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:read', target: 'db', scopeRequired: 'data:read' },
      privateKey: agentKeys.privateKey
    })
    const result = await verifyContentHash(intent)
    assert.ok(result.valid, `Content hash should verify: ${result.error}`)
  })

  it('[ADVERSARIAL] detects tampered content hash', async () => {
    const intent = await createContentAddressableIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:read', target: 'db', scopeRequired: 'data:read' },
      privateKey: agentKeys.privateKey
    })
    // Tamper with the hash
    const tampered = { ...intent, contentHash: { ...intent.contentHash!, hash: 'a'.repeat(64) } }
    const result = await verifyContentHash(tampered)
    assert.ok(!result.valid, 'Tampered hash should fail verification')
  })

  it('returns invalid when no content hash present', async () => {
    const intent = createActionIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:read', target: 'db', scopeRequired: 'data:read' },
      privateKey: agentKeys.privateKey
    })
    const result = await verifyContentHash(intent)
    assert.ok(!result.valid)
    assert.ok(result.error?.includes('No content hash'))
  })
})

// ══════════════════════════════════════
// Evaluation Method Classification
// ══════════════════════════════════════

describe('Evaluation Method Classification', () => {
  it('FloorValidatorV1 produces deterministic evaluation method', () => {
    const intent = createActionIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:read', target: 'db', scopeRequired: 'data:read' },
      privateKey: agentKeys.privateKey
    })
    const decision = evaluateIntent({
      intent,
      validator: new FloorValidatorV1(),
      validationContext: validContext,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluatorKeys.publicKey,
      evaluatorPrivateKey: evaluatorKeys.privateKey
    })
    assert.equal(decision.evaluationMethod, 'deterministic')
  })

  it('classifies decision with explicit evaluationMethod', () => {
    const mockDecision = {
      evaluationMethod: 'model_dependent' as const,
      principlesEvaluated: []
    } as any
    assert.equal(classifyEvaluationMethod(mockDecision), 'model_dependent')
  })

  it('infers deterministic when only F-001..F-005 evaluated', () => {
    const mockDecision = {
      principlesEvaluated: [
        { principleId: 'F-001', status: 'pass' },
        { principleId: 'F-003', status: 'pass' },
      ]
    } as any
    assert.equal(classifyEvaluationMethod(mockDecision), 'deterministic')
  })

  it('infers hybrid when both structural and trust principles active', () => {
    const mockDecision = {
      principlesEvaluated: [
        { principleId: 'F-001', status: 'pass' },
        { principleId: 'F-006', status: 'fail' },  // trust-layer, not 'not_applicable'
      ]
    } as any
    assert.equal(classifyEvaluationMethod(mockDecision), 'hybrid')
  })
})

// ══════════════════════════════════════
// Decision Decomposition
// ══════════════════════════════════════

describe('Decision Decomposition', () => {
  it('decomposes a permit decision into structural-only', () => {
    const intent = createActionIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:read', target: 'db', scopeRequired: 'data:read' },
      privateKey: agentKeys.privateKey
    })
    const decision = evaluateIntent({
      intent,
      validator: new FloorValidatorV1(),
      validationContext: validContext,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluatorKeys.publicKey,
      evaluatorPrivateKey: evaluatorKeys.privateKey
    })
    const semantics = decomposeDecision(decision)
    assert.equal(semantics.structuralVerdict, 'permit')
    assert.equal(semantics.trustVerdict, null)  // V1 doesn't eval trust principles
    assert.equal(semantics.override, undefined)
    assert.equal(semantics.finalVerdictRule, 'structural only')
    assert.ok(semantics.reproducibility.includes('structural_by_any_engine'))
  })

  it('decomposes a deny decision with structural failure', () => {
    const intent = createActionIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'admin:delete', target: 'db', scopeRequired: 'admin:delete' },
      privateKey: agentKeys.privateKey
    })
    const decision = evaluateIntent({
      intent,
      validator: new FloorValidatorV1(),
      validationContext: validContext,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluatorKeys.publicKey,
      evaluatorPrivateKey: evaluatorKeys.privateKey
    })
    const semantics = decomposeDecision(decision)
    assert.equal(semantics.structuralVerdict, 'deny')
    assert.equal(decision.verdict, 'deny')
  })

  it('detects trust override pattern', () => {
    // Simulate a decision where structural passes but trust fails
    const mockDecision = {
      verdict: 'deny' as const,
      principlesEvaluated: [
        { principleId: 'F-001', principleName: 'Traceability', status: 'pass' as const, detail: 'ok' },
        { principleId: 'F-003', principleName: 'Scoped Authority', status: 'pass' as const, detail: 'ok' },
        { principleId: 'F-006', principleName: 'Non-Deception', status: 'fail' as const, detail: 'trust score below threshold' },
      ]
    } as any
    const semantics = decomposeDecision(mockDecision)
    assert.equal(semantics.structuralVerdict, 'permit')
    assert.equal(semantics.trustVerdict, 'deny')
    assert.ok(semantics.override?.active, 'Override should be active')
    assert.equal(semantics.override?.wouldHaveBeen, 'permit')
    assert.equal(semantics.finalVerdictRule, 'structural AND trust')
  })
})

// ══════════════════════════════════════
// Scope Interpretation
// ══════════════════════════════════════

describe('Scope Interpretation', () => {
  it('defaults to hierarchical when not set', () => {
    assert.equal(getEffectiveScopeInterpretation({}), 'hierarchical')
  })

  it('respects explicit scope interpretation', () => {
    assert.equal(getEffectiveScopeInterpretation({ scopeInterpretation: 'exact' }), 'exact')
    assert.equal(getEffectiveScopeInterpretation({ scopeInterpretation: 'glob' }), 'glob')
    assert.equal(getEffectiveScopeInterpretation({ scopeInterpretation: 'hierarchical' }), 'hierarchical')
  })

  it('delegation carries scope interpretation', () => {
    assert.equal(delegation.scopeInterpretation, 'hierarchical')
  })

  it('delegation without scope interpretation is undefined', () => {
    const d = createDelegation({
      delegatedTo: agentKeys.publicKey,
      delegatedBy: evaluatorKeys.publicKey,
      scope: ['data:read'],
      privateKey: evaluatorKeys.privateKey
    })
    assert.equal(d.scopeInterpretation, undefined)
    assert.equal(getEffectiveScopeInterpretation(d), 'hierarchical')
  })
})

// ══════════════════════════════════════
// Decision Artifact (Cross-Engine)
// ══════════════════════════════════════

describe('Decision Artifact', () => {
  it('creates a complete decision artifact', async () => {
    const intent = await createContentAddressableIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:read', target: 'db', scopeRequired: 'data:read' },
      privateKey: agentKeys.privateKey
    })
    const decision = evaluateIntent({
      intent,
      validator: new FloorValidatorV1(),
      validationContext: validContext,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluatorKeys.publicKey,
      evaluatorPrivateKey: evaluatorKeys.privateKey
    })
    const artifact = await createDecisionArtifact({
      intent,
      decision,
      engine: 'aps',
      signerPrivateKey: signerKeys.privateKey
    })
    assert.ok(artifact.artifactId.startsWith('dart_'))
    assert.equal(artifact.artifactType, 'decision')
    assert.equal(artifact.engine, 'aps')
    assert.equal(artifact.version, '1.0.0')
    assert.equal(artifact.intent.intentId, intent.intentId)
    assert.ok(artifact.intent.contentHash.hash.length === 64)
    assert.equal(artifact.evaluation.verdict, 'permit')
    assert.equal(artifact.evaluation.evaluationMethod, 'deterministic')
    assert.equal(artifact.semantics.structuralVerdict, 'permit')
    assert.equal(artifact.semantics.finalVerdictRule, 'structural only')
    assert.ok(artifact.proof.intentSignature)
    assert.ok(artifact.proof.decisionSignature)
    assert.ok(artifact.proof.artifactSignature)
  })

  it('verifies a valid decision artifact', async () => {
    const intent = await createContentAddressableIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'search', target: 'index', scopeRequired: 'search' },
      privateKey: agentKeys.privateKey
    })
    const decision = evaluateIntent({
      intent,
      validator: new FloorValidatorV1(),
      validationContext: validContext,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluatorKeys.publicKey,
      evaluatorPrivateKey: evaluatorKeys.privateKey
    })
    const artifact = await createDecisionArtifact({
      intent,
      decision,
      engine: 'aps',
      signerPrivateKey: signerKeys.privateKey
    })
    const verification = await verifyDecisionArtifact(
      artifact,
      {
        intentSignerPublicKey: agentKeys.publicKey,
        decisionSignerPublicKey: evaluatorKeys.publicKey,
        artifactSignerPublicKey: signerKeys.publicKey
      },
      intent,
      decision
    )
    assert.ok(verification.valid, `Artifact should verify: ${verification.errors.join(', ')}`)
    assert.ok(verification.contentHashValid)
    assert.ok(verification.intentSignatureValid)
    assert.ok(verification.decisionSignatureValid)
    assert.ok(verification.artifactSignatureValid)
    assert.equal(verification.errors.length, 0)
  })

  it('[ADVERSARIAL] detects tampered artifact signature', async () => {
    const intent = await createContentAddressableIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:read', target: 'db', scopeRequired: 'data:read' },
      privateKey: agentKeys.privateKey
    })
    const decision = evaluateIntent({
      intent,
      validator: new FloorValidatorV1(),
      validationContext: validContext,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluatorKeys.publicKey,
      evaluatorPrivateKey: evaluatorKeys.privateKey
    })
    const artifact = await createDecisionArtifact({
      intent,
      decision,
      engine: 'aps',
      signerPrivateKey: signerKeys.privateKey
    })
    // Tamper with the artifact (change engine name)
    const tampered = { ...artifact, engine: 'evil-engine' }
    const verification = await verifyDecisionArtifact(
      tampered,
      {
        intentSignerPublicKey: agentKeys.publicKey,
        decisionSignerPublicKey: evaluatorKeys.publicKey,
        artifactSignerPublicKey: signerKeys.publicKey
      },
      intent,
      decision
    )
    assert.ok(!verification.valid, 'Tampered artifact should fail')
    assert.ok(!verification.artifactSignatureValid)
  })

  it('[ADVERSARIAL] detects wrong signer key', async () => {
    const intent = await createContentAddressableIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'search', target: 'idx', scopeRequired: 'search' },
      privateKey: agentKeys.privateKey
    })
    const decision = evaluateIntent({
      intent,
      validator: new FloorValidatorV1(),
      validationContext: validContext,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluatorKeys.publicKey,
      evaluatorPrivateKey: evaluatorKeys.privateKey
    })
    const artifact = await createDecisionArtifact({
      intent,
      decision,
      engine: 'aps',
      signerPrivateKey: signerKeys.privateKey
    })
    // Verify with wrong artifact signer key
    const wrongKeys = generateKeyPair()
    const verification = await verifyDecisionArtifact(
      artifact,
      {
        intentSignerPublicKey: agentKeys.publicKey,
        decisionSignerPublicKey: evaluatorKeys.publicKey,
        artifactSignerPublicKey: wrongKeys.publicKey  // wrong key
      },
      intent,
      decision
    )
    assert.ok(!verification.valid)
    assert.ok(!verification.artifactSignatureValid)
  })

  it('creates artifact from intent without pre-existing content hash', async () => {
    // Use a regular intent (no contentHash) — artifact should compute one
    const intent = createActionIntent({
      agentId: 'agent-1',
      agentPublicKey: agentKeys.publicKey,
      delegationId: delegation.delegationId,
      action: { type: 'data:write', target: 'db', scopeRequired: 'data:write' },
      privateKey: agentKeys.privateKey
    })
    assert.equal(intent.contentHash, undefined)
    const decision = evaluateIntent({
      intent,
      validator: new FloorValidatorV1(),
      validationContext: validContext,
      evaluatorId: 'evaluator-1',
      evaluatorPublicKey: evaluatorKeys.publicKey,
      evaluatorPrivateKey: evaluatorKeys.privateKey
    })
    const artifact = await createDecisionArtifact({
      intent,
      decision,
      engine: 'aps',
      signerPrivateKey: signerKeys.privateKey
    })
    // Should have computed a content hash even though intent didn't have one
    assert.ok(artifact.intent.contentHash)
    assert.equal(artifact.intent.contentHash.hash.length, 64)
  })
})


// ══════════════════════════════════════════════════════════════════
// Identity Boundary — Portable Identity via Committed Boundaries
// ══════════════════════════════════════════════════════════════════

describe('Identity Boundary', () => {
  it('content hash includes identityBoundary field', async () => {
    const keys = generateKeyPair()
    const intent = await createContentAddressableIntent({
      agentId: 'agent-001', agentPublicKey: keys.publicKey,
      delegationId: 'del-001', action: { type: 'test', target: 'x', scopeRequired: 'test' },
      privateKey: keys.privateKey
    })
    assert.ok(intent.contentHash!.identityBoundary)
    assert.ok(Array.isArray(intent.contentHash!.identityBoundary))
    assert.ok(intent.contentHash!.identityBoundary!.length > 0)
    // Boundary should be sorted
    const boundary = intent.contentHash!.identityBoundary!
    const sorted = [...boundary].sort()
    assert.deepEqual(boundary, sorted)
  })

  it('boundary is committed — changing it changes the hash', async () => {
    const keys = generateKeyPair()
    const { canonicalize } = await import('../src/core/canonical.js')
    const unsigned = {
      intentId: 'intent_test', agentId: 'agent-001',
      agentPublicKey: keys.publicKey, delegationId: 'del-001',
      action: { type: 'test', target: 'x', scopeRequired: 'test' },
      createdAt: '2026-01-01T00:00:00Z'
    }
    const hash1 = await computeContentHash(unsigned)
    // Manually compute with a different boundary — should produce different hash
    const fakeBoundary = ['agentId']  // subset of actual fields
    const fakeInput = { _identityBoundary: fakeBoundary, ...unsigned }
    const fakeHash = await sha256Hex(canonicalize(fakeInput))
    // Different boundary = different hash (boundary is committed)
    assert.notEqual(hash1.hash, fakeHash)
  })

  it('verifyContentHash succeeds with committed boundary', async () => {
    const keys = generateKeyPair()
    const intent = await createContentAddressableIntent({
      agentId: 'agent-001', agentPublicKey: keys.publicKey,
      delegationId: 'del-001', action: { type: 'test', target: 'x', scopeRequired: 'test' },
      privateKey: keys.privateKey
    })
    const result = await verifyContentHash(intent)
    assert.equal(result.valid, true)
  })

  it('validateIdentityBoundary passes for complete boundary', () => {
    const boundary = ['action', 'agentId', 'agentPublicKey', 'delegationId', 'intentId', 'createdAt']
    const result = validateIdentityBoundary(boundary, 'action_intent')
    assert.equal(result.valid, true)
    assert.equal(result.missing.length, 0)
  })

  it('validateIdentityBoundary fails when required fields missing', () => {
    const boundary = ['agentId', 'action']  // missing agentPublicKey, delegationId, intentId
    const result = validateIdentityBoundary(boundary, 'action_intent')
    assert.equal(result.valid, false)
    assert.ok(result.missing.includes('agentPublicKey'))
    assert.ok(result.missing.includes('delegationId'))
    assert.ok(result.missing.includes('intentId'))
  })

  it('validateIdentityBoundary passes for unknown artifact type', () => {
    const result = validateIdentityBoundary(['anything'], 'unknown_type')
    assert.equal(result.valid, true)
  })
})
