// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: Phase 1 functional tests (inclusion disclosure, mutual
// binding, content binding, disclosure policy). Positive coverage plus a
// few sanity-negatives. The independent adversarial fail-closed suite is
// written separately.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { publicKeyFromPrivate } from '../../../crypto/keys.js'
import { hexToMultibase } from '../../../core/did.js'
import type { RotatableDIDDocument } from '../../../types/passport.js'

import {
  buildCPA,
  computeCpaRef,
  carryCpaRef,
  bindCpaRefToReceipt,
  verifyCPA,
  buildInclusionProof,
  verifyInclusionProof,
  buildPartitionRoot,
} from '../index.js'
import type { ContextItem, ContextProvenanceAttestation } from '../index.js'

// ── Deterministic key material (mirrors roundtrip.test.ts) ─────────
const PRIV = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const PUB = publicKeyFromPrivate(PRIV)
const PRODUCER_DID = `did:aps:${hexToMultibase(PUB)}`
const ATTESTED_AT = '2026-06-03T12:00:00Z'

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

function makeDIDDoc(pubHex: string, did: string): RotatableDIDDocument {
  const keyId = `${did}#key-1`
  return {
    '@context': [
      'https://www.w3.org/ns/did/v1',
      'https://w3id.org/security/suites/ed25519-2020/v1',
    ],
    id: did,
    controller: did,
    verificationMethod: [
      {
        id: keyId,
        type: 'Ed25519VerificationKey2020',
        controller: did,
        publicKeyMultibase: hexToMultibase(pubHex),
      },
    ],
    authentication: [keyId],
    assertionMethod: [keyId],
    capabilityDelegation: [keyId],
    rotationLog: [],
    created: '2026-01-01T00:00:00Z',
    updated: '2026-01-01T00:00:00Z',
  }
}

const DID_DOC = makeDIDDoc(PUB, PRODUCER_DID)
const ACTION_REF = sha256Hex('cpa.action.request.001')

function item(channel: ContextItem['channel'], ctx_id: string, body: string): ContextItem {
  const bytes = Buffer.from(body, 'utf8')
  return {
    ctx_id,
    channel,
    content_ref: sha256Hex(body),
    byte_len: bytes.byteLength,
    content: bytes.toString('base64'),
  }
}

// developer has 5 leaves (exercises odd levels at multiple heights);
// tool-result has 2; system-config single-leaf.
function sampleItems(): ContextItem[] {
  return [
    item('system-config', 'sc-001', 'system prompt v3'),
    item('developer', 'dev-005', 'dev instruction epsilon'),
    item('developer', 'dev-003', 'dev instruction gamma'),
    item('developer', 'dev-001', 'dev instruction alpha'),
    item('developer', 'dev-004', 'dev instruction delta'),
    item('developer', 'dev-002', 'dev instruction beta'),
    item('tool-result', 'tr-002', 'tool output two'),
    item('tool-result', 'tr-001', 'tool output one'),
  ]
}

// ── (1) Inclusion proofs fold to partition_root for every leaf ─────

describe('CPA: inclusion proof folds to partition_root (all positions)', () => {
  it('every leaf in a 5-leaf partition has a proof that verifies', () => {
    const dev = sampleItems().filter(i => i.channel === 'developer')
    const root = buildPartitionRoot(dev)
    for (const leaf of dev) {
      const proof = buildInclusionProof(dev, leaf.ctx_id)
      assert.equal(proof.ctx_id, leaf.ctx_id)
      assert.equal(verifyInclusionProof(leaf, proof, root), true)
    }
  })

  it('a single-leaf partition yields an empty path that folds to the root', () => {
    const sc = sampleItems().filter(i => i.channel === 'system-config')
    const root = buildPartitionRoot(sc)
    const proof = buildInclusionProof(sc, 'sc-001')
    assert.deepEqual(proof.path, [])
    assert.equal(verifyInclusionProof(sc[0], proof, root), true)
  })

  it('a proof does not verify against a different partition_root', () => {
    const dev = sampleItems().filter(i => i.channel === 'developer')
    const proof = buildInclusionProof(dev, 'dev-003')
    const leaf = dev.find(l => l.ctx_id === 'dev-003')!
    const wrongRoot = sha256Hex('not the root').slice(0, 64)
    assert.equal(verifyInclusionProof(leaf, proof, wrongRoot), false)
  })
})

// ── (2) Inclusion mode with a disclosed subset ─────────────────────

describe('CPA: inclusion mode with disclosed subset', () => {
  it('builds, signs, verifies valid, NOT_PROVEN; proofs verify; counts and content_ref check', () => {
    const items = sampleItems()
    // Disclose 2 of 5 developer leaves and 1 of 2 tool-result leaves;
    // system-config stays count-only.
    const disclose = ['dev-002', 'dev-004', 'tr-001']
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'inclusion',
      items,
      disclose,
    })

    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    assert.equal(dev.leaf_count, 5)
    assert.equal(dev.leaves!.length, 2)
    assert.equal(dev.inclusion_proofs!.length, 2)
    assert.equal(dev.context_profile!.hidden_leaf_count, 3) // 5 - 2

    const tr = cpa.partitions.find(p => p.channel === 'tool-result')!
    assert.equal(tr.leaf_count, 2)
    assert.equal(tr.leaves!.length, 1)
    assert.equal(tr.context_profile!.hidden_leaf_count, 1) // 2 - 1

    const sc = cpa.partitions.find(p => p.channel === 'system-config')!
    assert.equal(sc.leaves, undefined) // count-only
    assert.equal(sc.inclusion_proofs, undefined)
    assert.equal(sc.context_profile!.hidden_leaf_count, 1) // 1 - 0

    // Each disclosed leaf's inclusion proof folds to its partition_root.
    for (const part of cpa.partitions) {
      for (const leaf of part.leaves ?? []) {
        const proof = part.inclusion_proofs!.find(p => p.ctx_id === leaf.ctx_id)!
        assert.equal(verifyInclusionProof(leaf, proof, part.partition_root), true)
      }
    }

    const result = verifyCPA(cpa, DID_DOC)
    assert.deepEqual(result.reasons, [])
    assert.equal(result.valid, true)
    assert.equal(result.completeness, 'NOT_PROVEN')
  })

  it('inclusion count-only CPA (no disclose) verifies valid, NOT_PROVEN', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'inclusion',
      items: sampleItems(),
    })
    for (const p of cpa.partitions) {
      assert.equal(p.leaves, undefined)
      assert.equal(p.context_profile!.hidden_leaf_count, p.leaf_count)
    }
    const result = verifyCPA(cpa, DID_DOC)
    assert.deepEqual(result.reasons, [])
    assert.equal(result.valid, true)
    assert.equal(result.completeness, 'NOT_PROVEN')
  })
})

// ── (3) Mutual binding (positive + sanity-negatives) ───────────────

describe('CPA: mutual binding against a receipt', () => {
  function makeInclusionCpa(): ContextProvenanceAttestation {
    return buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'inclusion',
      items: sampleItems(),
      disclose: ['dev-002'],
    })
  }

  it('matching action_ref + cpa_ref => valid', () => {
    const cpa = makeInclusionCpa()
    const cpa_ref = computeCpaRef(cpa)
    const result = verifyCPA(cpa, DID_DOC, { action_ref: ACTION_REF, cpa_ref })
    assert.deepEqual(result.reasons, [])
    assert.equal(result.valid, true)
  })

  it('carryCpaRef + bindCpaRefToReceipt produce the field the verifier accepts', () => {
    const cpa = makeInclusionCpa()
    const carried = carryCpaRef(cpa)
    assert.match(carried.cpa_ref, /^[0-9a-f]{64}$/)

    const receiptBody = { action_ref: ACTION_REF, executionResult: 'success' }
    const bound = bindCpaRefToReceipt(receiptBody, carried.cpa_ref)
    // Pure binder: new object, original untouched.
    assert.equal((receiptBody as Record<string, unknown>).cpa_ref, undefined)
    assert.equal(bound.cpa_ref, carried.cpa_ref)

    const result = verifyCPA(cpa, DID_DOC, { action_ref: bound.action_ref, cpa_ref: bound.cpa_ref })
    assert.deepEqual(result.reasons, [])
    assert.equal(result.valid, true)
  })

  it('mismatched cpa_ref => CPA_REF_MISMATCH (sanity-negative)', () => {
    const cpa = makeInclusionCpa()
    const wrong = sha256Hex('wrong cpa ref')
    const result = verifyCPA(cpa, DID_DOC, { action_ref: ACTION_REF, cpa_ref: wrong })
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('CPA_REF_MISMATCH'))
  })

  it('mismatched action_ref => ACTION_REF_MISMATCH (sanity-negative)', () => {
    const cpa = makeInclusionCpa()
    const wrong = sha256Hex('wrong action ref')
    const result = verifyCPA(cpa, DID_DOC, { action_ref: wrong })
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('ACTION_REF_MISMATCH'))
  })
})

// ── (4) Disclosure policy (opts.requireContent) ────────────────────

describe('CPA: disclosure policy requireContent', () => {
  it('count-only inclusion CPA + requireContent => DISCLOSURE_POLICY_UNSATISFIED', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'inclusion',
      items: sampleItems(),
    })
    const result = verifyCPA(cpa, DID_DOC, undefined, { requireContent: true })
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('DISCLOSURE_POLICY_UNSATISFIED'))
  })

  it('disclosed leaf without content + requireContent => DISCLOSURE_POLICY_UNSATISFIED', () => {
    // Items WITHOUT content (existence-only disclosure).
    const bare: ContextItem[] = sampleItems().map(({ content, ...rest }) => rest)
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'inclusion',
      items: bare,
      disclose: ['dev-002'],
    })
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    assert.equal(dev.leaves!.length, 1)
    assert.equal(dev.leaves![0].content, undefined) // existence-only

    // Without the policy it is valid (existence-only is allowed by default).
    const baseline = verifyCPA(cpa, DID_DOC)
    assert.deepEqual(baseline.reasons, [])
    assert.equal(baseline.valid, true)

    // With requireContent the existence-only disclosure is rejected.
    const result = verifyCPA(cpa, DID_DOC, undefined, { requireContent: true })
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('DISCLOSURE_POLICY_UNSATISFIED'))
  })

  it('content-bearing disclosure + requireContent => satisfied', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'inclusion',
      items: sampleItems(),
      disclose: ['dev-002', 'tr-001'],
    })
    const result = verifyCPA(cpa, DID_DOC, undefined, { requireContent: true })
    assert.deepEqual(result.reasons, [])
    assert.equal(result.valid, true)
  })
})

// ── (5) Content binding (sanity-negative) ──────────────────────────

describe('CPA: content binding', () => {
  it('a disclosed leaf whose content does not hash to content_ref => CONTENT_REF_MISMATCH', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'inclusion',
      items: sampleItems(),
      disclose: ['dev-002'],
    })
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    const leaf0 = dev.leaves![0]
    // Replace content with bytes that do not hash to content_ref, keeping
    // content_ref and the partition_root untouched. The signature is now
    // broken too (content is inside the signed CPA), but the content-ref
    // check is the targeted signal here.
    const tamperedLeaf = { ...leaf0, content: Buffer.from('different bytes', 'utf8').toString('base64') }
    const tamperedDev = { ...dev, leaves: [tamperedLeaf] }
    const tampered = {
      ...cpa,
      partitions: cpa.partitions.map(p => (p.channel === 'developer' ? tamperedDev : p)),
    } as ContextProvenanceAttestation

    const result = verifyCPA(tampered, DID_DOC)
    assert.equal(result.valid, false)
    assert.ok(result.reasons.includes('CONTENT_REF_MISMATCH'))
  })

  it('full-set mode also content-binds disclosed leaves', () => {
    const cpa = buildCPA({
      privateKey: PRIV,
      action_ref: ACTION_REF,
      producer_did: PRODUCER_DID,
      attested_at: ATTESTED_AT,
      mode: 'full-set',
      items: sampleItems(),
    })
    // Untampered full-set: content binding passes for every disclosed leaf.
    const result = verifyCPA(cpa, DID_DOC)
    assert.deepEqual(result.reasons, [])
    assert.equal(result.valid, true)
    assert.equal(result.completeness, 'PROVEN')
  })
})
