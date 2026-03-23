import { describe, it } from 'node:test'
import assert from 'node:assert'
import {
  DataEnforcementGate,
} from '../src/core/data-enforcement.js'
import {
  createTrainingAttribution,
  verifyTrainingAttribution,
  createTrainingLedger,
  recordTrainingAttribution,
  getModelDataSources,
  getSourceTrainingCount,
} from '../src/core/training-attribution.js'
import { registerSelfAttestedSource } from '../src/core/data-source.js'
import { generateKeyPair } from '../src/crypto/keys.js'
import type { DataTerms } from '../src/types/data-source.js'

const GW_KP = generateKeyPair()
const AGENT_KP = generateKeyPair()

const TERMS_PAID: DataTerms = {
  allowedPurposes: ['read', 'analyze', 'summarize'],
  requireAttribution: true,
  requireNotification: false,
  compensation: { type: 'per_access', amount: 0.05, currency: 'usd' },
  derivativePolicy: 'attribution_required',
  auditVisibility: 'source_and_principal',
  revocable: false,
}

const TERMS_RESTRICTED: DataTerms = {
  allowedPurposes: ['read'],
  excludedPurposes: ['train', 'embed'],
  requireAttribution: true,
  requireNotification: true,
  compensation: { type: 'per_access', amount: 0.10, currency: 'usd' },
  derivativePolicy: 'no_derivatives',
  auditVisibility: 'source_only',
  revocable: true,
  maxAccessCount: 5,
}

function makeSource(terms: DataTerms, id?: string) {
  const kp = generateKeyPair()
  return registerSelfAttestedSource({
    ownerPrincipalId: 'principal_test',
    ownerPublicKey: kp.publicKey,
    ownerPrivateKey: kp.privateKey,
    contentCommitment: 'abc123hash',
    contentType: 'dataset',
    contentDescriptor: id || 'Test Dataset',
    dataTerms: terms,
  })
}

function makeGate(mode: 'enforce' | 'audit' | 'off' = 'enforce') {
  return new DataEnforcementGate({
    gatewayId: 'gw_test',
    gatewayPublicKey: GW_KP.publicKey,
    gatewayPrivateKey: GW_KP.privateKey,
    mode,
  })
}

function makeRequest(sourceReceiptId: string, overrides: any = {}) {
  return {
    agentId: 'agent_bot',
    agentPublicKey: AGENT_KP.publicKey,
    principalId: 'principal_tima',
    sourceReceiptId,
    declaredPurpose: 'analyze' as const,
    accessMethod: 'api_call' as const,
    accessScope: 'data:read',
    executionFrameId: 'frame_' + Math.random().toString(36).slice(2),
    ...overrides,
  }
}

// ══════════════════════════════════════
// Data Enforcement Gate
// ══════════════════════════════════════

describe('Data Enforcement Gate — Basic Access', () => {
  it('allows compliant access and generates receipt', () => {
    const gate = makeGate()
    const source = makeSource(TERMS_PAID)
    gate.registerSource(source, 'Paid Dataset')
    const decision = gate.checkAccess(makeRequest(source.sourceReceiptId))
    assert.strictEqual(decision.allowed, true)
    assert.ok(decision.receipt)
    assert.strictEqual(decision.hardViolations.length, 0)
  })

  it('feeds contribution ledger automatically', () => {
    const gate = makeGate()
    const source = makeSource(TERMS_PAID)
    gate.registerSource(source, 'Paid Dataset')
    gate.checkAccess(makeRequest(source.sourceReceiptId))
    gate.checkAccess(makeRequest(source.sourceReceiptId))
    gate.checkAccess(makeRequest(source.sourceReceiptId))
    const ledger = gate.getLedger()
    assert.strictEqual(ledger.records.size, 1)
    const record = Array.from(ledger.records.values())[0]
    assert.strictEqual(record.accessCount, 3)
  })

  it('tracks receipts and builds Merkle root', () => {
    const gate = makeGate()
    const source = makeSource(TERMS_PAID)
    gate.registerSource(source, 'Dataset')
    gate.checkAccess(makeRequest(source.sourceReceiptId))
    gate.checkAccess(makeRequest(source.sourceReceiptId))
    assert.strictEqual(gate.getReceipts().length, 2)
    assert.ok(gate.getMerkleRoot().length === 64)
  })

  it('returns not-allowed for unregistered source', () => {
    const gate = makeGate()
    const decision = gate.checkAccess(makeRequest('srcr_nonexistent'))
    assert.strictEqual(decision.allowed, false)
    assert.ok(decision.hardViolations[0].includes('not registered'))
  })
})

describe('Data Enforcement Gate — Enforce vs Audit Mode', () => {
  it('[ENFORCE] blocks access exceeding maxAccessCount', () => {
    const gate = makeGate('enforce')
    const source = makeSource(TERMS_RESTRICTED)
    gate.registerSource(source, 'Restricted')
    for (let i = 0; i < 5; i++) {
      const d = gate.checkAccess(makeRequest(source.sourceReceiptId))
      assert.strictEqual(d.allowed, true)
    }
    // 6th access should be blocked
    const blocked = gate.checkAccess(makeRequest(source.sourceReceiptId))
    assert.strictEqual(blocked.allowed, false)
    assert.ok(blocked.hardViolations.length > 0)
  })

  it('[AUDIT] logs but allows access exceeding maxAccessCount', () => {
    const gate = makeGate('audit')
    const source = makeSource(TERMS_RESTRICTED)
    gate.registerSource(source, 'Restricted')
    for (let i = 0; i < 6; i++) {
      const d = gate.checkAccess(makeRequest(source.sourceReceiptId))
      assert.strictEqual(d.allowed, true) // audit mode always allows
    }
    assert.strictEqual(gate.getReceipts().length, 6)
  })

  it('[OFF] skips all checks', () => {
    const gate = makeGate('off')
    const decision = gate.checkAccess(makeRequest('anything'))
    assert.strictEqual(decision.allowed, true)
    assert.strictEqual(decision.hardViolations.length, 0)
  })
})

describe('Data Enforcement Gate — Preflight', () => {
  it('preflight checks multiple sources without generating receipts', () => {
    const gate = makeGate('enforce')
    const s1 = makeSource(TERMS_PAID)
    const s2 = makeSource(TERMS_PAID, 'Dataset 2')
    gate.registerSource(s1, 'D1')
    gate.registerSource(s2, 'D2')
    const result = gate.preflightCheck([
      makeRequest(s1.sourceReceiptId),
      makeRequest(s2.sourceReceiptId),
    ])
    assert.strictEqual(result.allAllowed, true)
    assert.strictEqual(result.decisions.length, 2)
    assert.strictEqual(gate.getReceipts().length, 0) // no receipts generated
  })

  it('preflight detects blocked source', () => {
    const gate = makeGate('enforce')
    const result = gate.preflightCheck([makeRequest('srcr_missing')])
    assert.strictEqual(result.allAllowed, false)
  })
})

// ══════════════════════════════════════
// Training Attribution
// ══════════════════════════════════════

describe('Training Attribution — Receipt Creation', () => {
  it('creates a signed training attribution receipt', () => {
    const kp = generateKeyPair()
    const receipt = createTrainingAttribution({
      trainingUseType: 'fine_tune',
      modelId: 'model-gpt-custom-v1',
      trainerId: 'trainer_001',
      trainerPublicKey: kp.publicKey,
      trainerPrivateKey: kp.privateKey,
      sourceAccessReceiptIds: ['dacr_001', 'dacr_002', 'dacr_003'],
      executionFrameId: 'frame_train_001',
      outputContentHash: 'sha256_of_training_output',
      inputDataHashes: ['hash1', 'hash2', 'hash3'],
      datasetSize: 10000,
      trainingSplit: 'train',
    })
    assert.ok(receipt.trainingReceiptId.startsWith('trar_'))
    assert.strictEqual(receipt.trainingUseType, 'fine_tune')
    assert.strictEqual(receipt.sourceAccessReceiptIds.length, 3)
    assert.ok(receipt.signature.length === 64)
  })

  it('creates receipt with fractional contribution weights', () => {
    const kp = generateKeyPair()
    const receipt = createTrainingAttribution({
      trainingUseType: 'embedding',
      modelId: 'embeddings-v2',
      trainerId: 'trainer_002',
      trainerPublicKey: kp.publicKey,
      trainerPrivateKey: kp.privateKey,
      sourceAccessReceiptIds: ['dacr_A', 'dacr_B'],
      executionFrameId: 'frame_embed',
      outputContentHash: 'sha256_embed',
      inputDataHashes: ['hA', 'hB'],
      contributionWeights: { 'dacr_A': 0.7, 'dacr_B': 0.3 },
    })
    assert.strictEqual(receipt.contributionWeights!['dacr_A'], 0.7)
    assert.strictEqual(receipt.contributionWeights!['dacr_B'], 0.3)
  })
})

describe('Training Attribution — Verification', () => {
  it('verifies a valid receipt', () => {
    const kp = generateKeyPair()
    const receipt = createTrainingAttribution({
      trainingUseType: 'rag_index',
      modelId: 'rag-v1',
      trainerId: 'tr',
      trainerPublicKey: kp.publicKey,
      trainerPrivateKey: kp.privateKey,
      sourceAccessReceiptIds: ['dacr_x'],
      executionFrameId: 'frame',
      outputContentHash: 'hash',
      inputDataHashes: ['h1'],
    })
    const v = verifyTrainingAttribution(receipt, new Set(['dacr_x']))
    assert.strictEqual(v.valid, true)
    assert.strictEqual(v.sourcesTraceable, true)
  })

  it('[ADVERSARIAL] detects missing source receipts', () => {
    const kp = generateKeyPair()
    const receipt = createTrainingAttribution({
      trainingUseType: 'fine_tune',
      modelId: 'm',
      trainerId: 'tr',
      trainerPublicKey: kp.publicKey,
      trainerPrivateKey: kp.privateKey,
      sourceAccessReceiptIds: ['dacr_known', 'dacr_unknown'],
      executionFrameId: 'f',
      outputContentHash: 'h',
      inputDataHashes: ['h1', 'h2'],
    })
    const v = verifyTrainingAttribution(receipt, new Set(['dacr_known']))
    assert.strictEqual(v.sourcesTraceable, false)
    assert.ok(v.errors.some(e => e.includes('dacr_unknown')))
  })

  it('[ADVERSARIAL] detects invalid contribution weights', () => {
    const kp = generateKeyPair()
    const receipt = createTrainingAttribution({
      trainingUseType: 'fine_tune',
      modelId: 'm',
      trainerId: 'tr',
      trainerPublicKey: kp.publicKey,
      trainerPrivateKey: kp.privateKey,
      sourceAccessReceiptIds: ['dacr_a', 'dacr_b'],
      executionFrameId: 'f',
      outputContentHash: 'h',
      inputDataHashes: ['h1', 'h2'],
      contributionWeights: { 'dacr_a': 0.9, 'dacr_b': 0.9 }, // sum = 1.8, not 1.0
    })
    const v = verifyTrainingAttribution(receipt)
    assert.strictEqual(v.weightsValid, false)
  })
})

describe('Training Attribution — Ledger', () => {
  it('tracks which data sources contributed to a model', () => {
    const ledger = createTrainingLedger()
    const kp = generateKeyPair()
    const r1 = createTrainingAttribution({
      trainingUseType: 'fine_tune', modelId: 'model-v1', trainerId: 'tr',
      trainerPublicKey: kp.publicKey, trainerPrivateKey: kp.privateKey,
      sourceAccessReceiptIds: ['dacr_1', 'dacr_2'],
      executionFrameId: 'f1', outputContentHash: 'h1', inputDataHashes: ['a', 'b'],
      contributionWeights: { 'dacr_1': 0.6, 'dacr_2': 0.4 },
    })
    const r2 = createTrainingAttribution({
      trainingUseType: 'fine_tune', modelId: 'model-v1', trainerId: 'tr',
      trainerPublicKey: kp.publicKey, trainerPrivateKey: kp.privateKey,
      sourceAccessReceiptIds: ['dacr_3'],
      executionFrameId: 'f2', outputContentHash: 'h2', inputDataHashes: ['c'],
    })
    recordTrainingAttribution(ledger, r1)
    recordTrainingAttribution(ledger, r2)
    const sources = getModelDataSources(ledger, 'model-v1')
    assert.strictEqual(sources.length, 3) // dacr_1, dacr_2, dacr_3
    const s1 = sources.find(s => s.accessReceiptId === 'dacr_1')!
    assert.ok(Math.abs(s1.weight - 0.6) < 0.01)
  })

  it('counts training uses per data source', () => {
    const ledger = createTrainingLedger()
    const kp = generateKeyPair()
    for (let i = 0; i < 3; i++) {
      const r = createTrainingAttribution({
        trainingUseType: 'embedding', modelId: `model-${i}`, trainerId: 'tr',
        trainerPublicKey: kp.publicKey, trainerPrivateKey: kp.privateKey,
        sourceAccessReceiptIds: ['dacr_shared'],
        executionFrameId: `f${i}`, outputContentHash: `h${i}`, inputDataHashes: ['x'],
      })
      recordTrainingAttribution(ledger, r)
    }
    assert.strictEqual(getSourceTrainingCount(ledger, 'dacr_shared'), 3)
    assert.strictEqual(getSourceTrainingCount(ledger, 'dacr_nonexistent'), 0)
  })

  it('returns empty for unknown model', () => {
    const ledger = createTrainingLedger()
    assert.deepStrictEqual(getModelDataSources(ledger, 'unknown'), [])
  })
})
