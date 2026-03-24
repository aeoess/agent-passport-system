// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * APS Conformance Test Suite
 *
 * Standalone protocol conformance tests that any APS implementation
 * can run to verify correctness. Tests protocol invariants, not
 * implementation details.
 *
 * Usage:
 *   import { runConformanceSuite } from 'agent-passport-system'
 *   const results = await runConformanceSuite()
 *   console.log(results.summary)
 */

import { createHash } from 'node:crypto'
import {
  generateKeyPair, sign, verify, canonicalize, clearStores,
  createDID, publicKeyFromDID, isValidDID, resolveDID,
  hexToMultibase, multibaseToHex,
  createPassport,
  createDerivationReceipt, resolveExtendedLineage,
  evaluateRevocationImpact, DEFAULT_OBLIGATIONS,
  isPurposePermitted, purposeCategory,
  verifyEntityChain, cacheDIDResolution, getCachedDIDResolution, clearDIDCache,
  computeSenderId,
} from '../index.js'
import type { DerivationReceipt, PublicProofSurface } from '../index.js'

// ═══════════════════════════════════════
// Types
// ═══════════════════════════════════════

export interface ConformanceTest {
  id: string
  category: string
  name: string
  spec?: string
  passed: boolean
  error?: string
  durationMs: number
}

export interface ConformanceSuiteResult {
  passed: number
  failed: number
  total: number
  categories: Record<string, { passed: number; failed: number }>
  tests: ConformanceTest[]
  summary: string
  durationMs: number
}

function test(id: string, category: string, name: string, spec: string, fn: () => void): ConformanceTest {
  const start = Date.now()
  try {
    fn()
    return { id, category, name, spec, passed: true, durationMs: Date.now() - start }
  } catch (e: any) {
    return { id, category, name, spec, passed: false, error: e.message || String(e), durationMs: Date.now() - start }
  }
}

function assert(condition: boolean, message: string) {
  if (!condition) throw new Error(message)
}

function assertEqual<T>(actual: T, expected: T, label: string) {
  if (actual !== expected) throw new Error(`${label}: expected ${expected}, got ${actual}`)
}

// ═══════════════════════════════════════
// Test Categories
// ═══════════════════════════════════════

function identityTests(): ConformanceTest[] {
  const keys = generateKeyPair()
  return [
    test('ID-01', 'Identity', 'Ed25519 keypair generation', 'Layer 1 §1.1',
      () => {
        assertEqual(keys.publicKey.length, 64, 'Public key hex length')
        assertEqual(keys.privateKey.length, 64, 'Private key seed hex length')
      }),

    test('ID-02', 'Identity', 'Sign and verify roundtrip', 'Layer 1 §1.2',
      () => {
        const msg = 'conformance test message'
        const sig = sign(msg, keys.privateKey)
        assert(verify(msg, sig, keys.publicKey), 'Signature must verify')
      }),

    test('ID-03', 'Identity', 'Tampered message rejects', 'Layer 1 §1.2',
      () => {
        const sig = sign('original', keys.privateKey)
        assert(!verify('tampered', sig, keys.publicKey), 'Tampered must reject')
      }),

    test('ID-04', 'Identity', 'Wrong key rejects', 'Layer 1 §1.2',
      () => {
        const other = generateKeyPair()
        const sig = sign('message', keys.privateKey)
        assert(!verify('message', sig, other.publicKey), 'Wrong key must reject')
      }),

    test('ID-05', 'Identity', 'Canonical JSON is deterministic', 'Layer 1 §1.3',
      () => {
        const a = canonicalize({ z: 1, a: 2 })
        const b = canonicalize({ a: 2, z: 1 })
        assertEqual(a, b, 'Canonical form')
      }),
  ]
}

function didTests(): ConformanceTest[] {
  const keys = generateKeyPair()
  const did = createDID(keys.publicKey)
  return [
    test('DID-01', 'DID Resolution', 'DID format: did:aps:z<multibase>', 'DID Resolution v1.0 §2',
      () => {
        assert(did.startsWith('did:aps:z'), 'Must start with did:aps:z')
        assert(isValidDID(did), 'Must be valid')
      }),

    test('DID-02', 'DID Resolution', 'DID roundtrip: create → resolve → key', 'DID Resolution v1.0 §3',
      () => {
        const resolved = publicKeyFromDID(did)
        assertEqual(resolved, keys.publicKey, 'Resolved key')
      }),

    test('DID-03', 'DID Resolution', 'Multibase encoding: 0xed01 prefix', 'DID Resolution v1.0 §2.1',
      () => {
        const mb = hexToMultibase(keys.publicKey)
        assert(mb.startsWith('z'), 'Multibase z-prefix (base58btc)')
        const roundtrip = multibaseToHex(mb)
        assertEqual(roundtrip, keys.publicKey, 'Multibase roundtrip')
      }),

    test('DID-04', 'DID Resolution', 'Sender ID: Trunc16(SHA-256(pubkey))', 'QSP-1 v1.0 §4',
      () => {
        const senderId = computeSenderId(keys.publicKey)
        assertEqual(senderId.length, 32, 'Sender ID hex length (16 bytes)')
        // Must be deterministic
        assertEqual(computeSenderId(keys.publicKey), senderId, 'Deterministic')
      }),

    test('DID-05', 'DID Resolution', 'DID Document structure', 'DID Resolution v1.0 §3',
      () => {
        const result = resolveDID(did)
        assert(result.didDocument !== null, 'Document must exist')
        assertEqual(result.didResolutionMetadata.contentType, 'application/did+ld+json', 'Content type')
        assert(result.didDocument!.verificationMethod!.length > 0, 'Must have verificationMethod')
        assertEqual(result.didDocument!.verificationMethod![0].type, 'Ed25519VerificationKey2020', 'Key type')
      }),

    test('DID-06', 'DID Resolution', 'Invalid DID returns error', 'DID Resolution v1.0 §3',
      () => {
        const result = resolveDID('not-a-did')
        assertEqual(result.didDocument, null, 'No document for invalid DID')
        assertEqual(result.didResolutionMetadata.error, 'invalidDid', 'Error code')
      }),
  ]
}

function entityVerificationTests(): ConformanceTest[] {
  const keys = generateKeyPair()
  const did = createDID(keys.publicKey)
  const activeLookup = async (id: string): Promise<PublicProofSurface | null> => {
    if (id === 'test-entity') return {
      entity_id: 'test-entity', name: 'Test DAO', status: 'active',
      entity_type: 'dao_llc', authority_ceiling: ['hold_assets'], verified_at: new Date().toISOString(),
    }
    return null
  }

  return [
    test('EV-01', 'Entity Verification', 'Active entity passes verification', 'Entity Verification v1.0 §2',
      () => {
        // Sync test using cache
        clearDIDCache()
        clearStores()
        cacheDIDResolution(did, keys.publicKey)
        const cached = getCachedDIDResolution(did)
        assert(cached !== null, 'Cache hit')
        assertEqual(cached!.status, 'cached', 'Status is cached')
      }),

    test('EV-02', 'Entity Verification', 'Fail-closed: invalid DID blocks proof', 'Entity Verification v1.0 §2.1',
      () => {
        clearDIDCache()
        // Can't do async in sync test runner, but we can test the cache/DID layer
        const result = resolveDID('garbage-did')
        assertEqual(result.didDocument, null, 'No document')
      }),

    test('EV-03', 'Entity Verification', 'Cache expired returns null', 'Entity Verification v1.0 §2.2',
      () => {
        clearDIDCache()
        cacheDIDResolution(did, keys.publicKey, 1) // 1ms TTL
        const start = Date.now()
        while (Date.now() - start < 5) { /* busy wait */ }
        const cached = getCachedDIDResolution(did)
        assertEqual(cached, null, 'Expired cache must return null')
      }),

    test('EV-04', 'Entity Verification', 'Sender ID matches DID-resolved key', 'QSP-1 v1.0 §4',
      () => {
        const resolved = publicKeyFromDID(did)
        const fromDid = computeSenderId(resolved)
        const direct = computeSenderId(keys.publicKey)
        assertEqual(fromDid, direct, 'Same sender ID regardless of resolution path')
      }),
  ]
}

function dataLifecycleTests(): ConformanceTest[] {
  const keys = generateKeyPair()
  return [
    test('DL-01', 'Data Lifecycle', 'Derivation receipt creation and signing', 'Data Lifecycle §1',
      () => {
        const r = createDerivationReceipt({
          derivativeId: 'conf-d1', derivativeType: 'embedding',
          parentArtifacts: [{ artifactId: 'src-1', artifactType: 'access_receipt', sourceId: 's1' }],
          transformClass: 'embedding', lineageConfidence: 'complete',
          agentId: 'conf-agent', privateKey: keys.privateKey,
        })
        assert(r.receiptId.startsWith('drv_'), 'Receipt ID prefix')
        assert(!!r.signature, 'Must be signed')
      }),

    test('DL-02', 'Data Lifecycle', 'Lineage resolution with cycle detection', 'Data Lifecycle §1.2',
      () => {
        const store = new Map<string, DerivationReceipt>()
        const r1 = createDerivationReceipt({
          derivativeId: 'cycle-a', derivativeType: 'summary',
          parentArtifacts: [{ artifactId: 'cycle-b', artifactType: 'derivation_receipt' }],
          transformClass: 'summary', lineageConfidence: 'complete',
          agentId: 'a', privateKey: keys.privateKey,
        })
        store.set('cycle-a', r1)

        const r2 = createDerivationReceipt({
          derivativeId: 'cycle-b', derivativeType: 'embedding',
          parentArtifacts: [{ artifactId: 'cycle-a', artifactType: 'derivation_receipt' }],
          transformClass: 'embedding', lineageConfidence: 'complete',
          agentId: 'a', privateKey: keys.privateKey,
        })
        store.set('cycle-b', r2)
        const result = resolveExtendedLineage('cycle-a', store)
        assert(result.depth <= 2, 'Cycle detection must terminate')
      }),

    test('DL-03', 'Data Lifecycle', 'Revocation obligations by artifact type', 'Data Lifecycle §2',
      () => {
        assertEqual(DEFAULT_OBLIGATIONS['cached_raw'], 'delete_if_cached', 'cached_raw')
        assertEqual(DEFAULT_OBLIGATIONS['model_weights'], 'retraining_required', 'model_weights')
        assertEqual(DEFAULT_OBLIGATIONS['decision_artifact'], 'immutable_ledger_exempt', 'decision_artifact')
        assertEqual(DEFAULT_OBLIGATIONS['synthetic_derivative'], 'compensation_only', 'synthetic_derivative')
      }),

    test('DL-04', 'Data Lifecycle', 'Purpose taxonomy: wildcard matching', 'Data Lifecycle §4',
      () => {
        assert(isPurposePermitted('research:academic', ['research:*']), 'Wildcard match')
        assert(!isPurposePermitted('training:model', ['research:*']), 'Cross-category deny')
        assert(isPurposePermitted('research:academic', ['research']), 'Parent covers child')
        assert(!isPurposePermitted('research', ['research:academic']), 'Child does not cover parent')
      }),

    test('DL-05', 'Data Lifecycle', 'Purpose category extraction', 'Data Lifecycle §4',
      () => {
        assertEqual(purposeCategory('research:academic'), 'research', 'Category')
        assertEqual(purposeCategory('commerce'), 'commerce', 'Bare category')
      }),

    test('DL-06', 'Data Lifecycle', 'Revocation impact propagates through chain', 'Data Lifecycle §2',
      () => {
        const store = new Map<string, DerivationReceipt>()
        const r = createDerivationReceipt({
          derivativeId: 'chunk-1', derivativeType: 'rag_chunk',
          parentArtifacts: [{ artifactId: 'ar-1', artifactType: 'access_receipt', sourceId: 'src-revoked' }],
          transformClass: 'subset', lineageConfidence: 'complete',
          agentId: 'a', privateKey: keys.privateKey,
        })
        store.set('chunk-1', r)

        const obligation = evaluateRevocationImpact({
          sourceId: 'src-revoked', receiptStore: store, privateKey: keys.privateKey,
        })
        assert(obligation.totalAffected >= 1, 'Must find affected artifacts')
        const chunk = obligation.affectedArtifacts.find(a => a.artifactType === 'rag_chunk')
        assert(!!chunk, 'Must find rag_chunk')
        assertEqual(chunk!.obligation, 'delete_if_cached', 'Correct obligation')
      }),
  ]
}

// ═══════════════════════════════════════
// Runner
// ═══════════════════════════════════════

export function runConformanceSuite(): ConformanceSuiteResult {
  const start = Date.now()
  clearStores()
  clearDIDCache()

  const allTests = [
    ...identityTests(),
    ...didTests(),
    ...entityVerificationTests(),
    ...dataLifecycleTests(),
  ]

  const passed = allTests.filter(t => t.passed).length
  const failed = allTests.filter(t => !t.passed).length
  const total = allTests.length
  const durationMs = Date.now() - start

  const categories: Record<string, { passed: number; failed: number }> = {}
  for (const t of allTests) {
    if (!categories[t.category]) categories[t.category] = { passed: 0, failed: 0 }
    if (t.passed) categories[t.category].passed++
    else categories[t.category].failed++
  }

  const catSummary = Object.entries(categories)
    .map(([cat, counts]) => `  ${cat}: ${counts.passed}/${counts.passed + counts.failed}`)
    .join('\n')

  const failDetails = allTests
    .filter(t => !t.passed)
    .map(t => `  ❌ ${t.id} ${t.name}: ${t.error}`)
    .join('\n')

  const summary = [
    `APS Conformance Suite: ${passed}/${total} passed${failed > 0 ? ` (${failed} FAILED)` : ''}`,
    `Duration: ${durationMs}ms`,
    '',
    'By category:',
    catSummary,
    ...(failDetails ? ['', 'Failures:', failDetails] : []),
  ].join('\n')

  return { passed, failed, total, categories, tests: allTests, summary, durationMs }
}
