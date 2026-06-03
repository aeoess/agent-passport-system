// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// CPA v0.1: INDEPENDENT adversarial fail-closed suite
// ══════════════════════════════════════════════════════════════════
// Written by a DIFFERENT agent than the executor who wrote the module.
// Every vector here is derived from the THREAT MODEL and the frozen
// TREE-SHAPE / BINDING specs DIRECTLY, not from the executor's own tests.
// The verifier (verifyCPA) is the thing under attack. Each attack must
// FAIL CLOSED: valid === false AND the expected structured reason code is
// present in reasons[]. No throw, no silent pass.
//
// Build strategy: build a clean, valid fixture with the module's own
// buildCPA, deep-clone it, then surgically tamper the clone to mount each
// attack, then re-verify. A deterministic keypair + minimal
// RotatableDIDDocument (the exact shape isKeyActive accepts) are used so
// the suite is fully reproducible.
//
// THREAT MODEL families covered (OWASP ASI06 context poisoning + Merkle /
// replay cryptographic attacks):
//   - post-attestation tampering (content, content_ref, byte_len)
//   - tree-structure attacks (reorder leaves/partitions, move channel,
//     tamper partition_root / top root)
//   - RFC 6962 / CVE-2012-2459 last-leaf duplication malleability
//   - domain-tag confusion (leaf/node/sign cross-role digest reuse)
//   - replay / mutual binding (action_ref, cpa_ref)
//   - disclosure attacks (cardinality forgery, forged inclusion proof,
//     existence-only under a content-requiring policy)
//   - identity / key attacks (key not active, DID mismatch, pubkey absent)
//   - malformed input -> SHAPE_INVALID (never a throw)
//
// Plus one EXPLICITLY-NOT-CLOSED vector named for honesty:
//   - pre-attestation faithful-capture failure (out of v0.1 scope).
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'

import { publicKeyFromPrivate, sign } from '../../../crypto/keys.js'
import { hexToMultibase } from '../../../core/did.js'
import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import type { RotatableDIDDocument } from '../../../types/passport.js'

import {
  buildCPA,
  computeCpaRef,
  verifyCPA,
  buildPartitionRootBytes,
  buildPartitionRoot,
  buildInclusionProof,
  verifyInclusionProof,
  buildTopRoot,
  leafHash,
  nodeHash,
  bytesToHex,
  CHANNEL_ORDER,
} from '../index.js'
import type {
  ContextItem,
  ContextProvenanceAttestation,
  CpaReasonCode,
} from '../index.js'

// ══════════════════════════════════════════════════════════════════
// Deterministic fixtures
// ══════════════════════════════════════════════════════════════════

// Fixed 32-byte seed. priv = seed; pub derived from priv.
const PRIV = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
const PUB = publicKeyFromPrivate(PRIV)
const PRODUCER_DID = `did:aps:${hexToMultibase(PUB)}`

// A SECOND, attacker-controlled keypair (a different fixed seed). Used for
// "attacker re-signs with their own key" attacks: the signature is valid
// over the tampered bytes, but the key is not active in the producer's DID
// document, so the verifier must still reject.
const ATTACKER_PRIV = 'fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210'
const ATTACKER_PUB = publicKeyFromPrivate(ATTACKER_PRIV)

const ATTESTED_AT = '2026-06-03T12:00:00Z'

function sha256Hex(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

/**
 * Minimal RotatableDIDDocument in the exact shape isKeyActive accepts:
 *   - vm.publicKeyMultibase === hexToMultibase(pubHex)
 *   - no retiredAt
 *   - authentication.includes(vm.id)
 *   - empty rotationLog (verifyRotationChain returns true).
 */
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
const OTHER_ACTION_REF = sha256Hex('cpa.action.request.999.different')

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

// A fixture spanning three channels, with one single-leaf and two
// multi-leaf partitions (so reorder / odd-promotion paths are exercised).
function sampleItems(): ContextItem[] {
  return [
    item('system-config', 'sc-001', 'system prompt v3'),
    item('developer', 'dev-003', 'dev instruction gamma'),
    item('developer', 'dev-001', 'dev instruction alpha'),
    item('developer', 'dev-002', 'dev instruction beta'),
    item('tool-result', 'tr-002', 'tool output two'),
    item('tool-result', 'tr-001', 'tool output one'),
  ]
}

/** Deep clone via structuredClone so each attack mutates an isolated copy. */
function clone<T>(o: T): T {
  return structuredClone(o)
}

function buildFullSet(items = sampleItems()): ContextProvenanceAttestation {
  return buildCPA({
    privateKey: PRIV,
    action_ref: ACTION_REF,
    producer_did: PRODUCER_DID,
    attested_at: ATTESTED_AT,
    mode: 'full-set',
    items,
  })
}

function buildInclusion(
  items = sampleItems(),
  disclose?: string[],
): ContextProvenanceAttestation {
  return buildCPA({
    privateKey: PRIV,
    action_ref: ACTION_REF,
    producer_did: PRODUCER_DID,
    attested_at: ATTESTED_AT,
    mode: 'inclusion',
    items,
    disclose,
  })
}

/**
 * Re-sign a tampered CPA with the PRODUCER key so the signature is valid
 * over the new bytes. This isolates non-signature checks (Merkle, binding,
 * cardinality) from the signature check: a tamper that re-signs cleanly
 * must STILL be caught by a structural reason, proving the structural check
 * is load-bearing and not merely riding on the signature.
 */
function resignWithProducer(cpa: ContextProvenanceAttestation): ContextProvenanceAttestation {
  const bytes = canonicalizeJCS({ ...cpa, signature: '' })
  return { ...cpa, signature: sign(bytes, PRIV) }
}

/**
 * Re-sign a tampered CPA with the ATTACKER key, and set producer_pubkey to
 * the attacker pubkey so the signature check passes - but the key is not in
 * the producer DID document. Models an attacker who forges a valid
 * signature with a key they control.
 */
function resignWithAttacker(cpa: ContextProvenanceAttestation): ContextProvenanceAttestation {
  const withAttackerKey = { ...cpa, producer_pubkey: ATTACKER_PUB }
  const bytes = canonicalizeJCS({ ...withAttackerKey, signature: '' })
  return { ...withAttackerKey, signature: sign(bytes, ATTACKER_PRIV) }
}

function flipLastHexChar(hex: string): string {
  const last = hex.slice(-1)
  const flipped = last === '0' ? '1' : '0'
  return hex.slice(0, -1) + flipped
}

// Small helper: assert fail-closed with a specific reason present, and that
// the call did not throw (it returned a structured result object).
function assertFailClosed(
  result: { valid: boolean; reasons: CpaReasonCode[] },
  expected: CpaReasonCode,
  label: string,
): void {
  assert.equal(typeof result, 'object', `${label}: verifier must return a result object, never throw`)
  assert.equal(result.valid, false, `${label}: expected valid=false`)
  assert.ok(
    result.reasons.includes(expected),
    `${label}: expected reason ${expected}, got [${result.reasons.join(', ')}]`,
  )
}

// ══════════════════════════════════════════════════════════════════
// SANITY: the clean fixtures actually verify (so a later "false" means
// the attack worked, not that the fixture was broken).
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: sanity', () => {
  it('clean full-set fixture verifies (PROVEN)', () => {
    const r = verifyCPA(buildFullSet(), DID_DOC)
    assert.deepEqual(r.reasons, [])
    assert.equal(r.valid, true)
    assert.equal(r.completeness, 'PROVEN')
  })

  it('clean inclusion fixture (count-only) verifies (NOT_PROVEN)', () => {
    const r = verifyCPA(buildInclusion(), DID_DOC)
    assert.deepEqual(r.reasons, [])
    assert.equal(r.valid, true)
    assert.equal(r.completeness, 'NOT_PROVEN')
  })

  it('clean inclusion fixture with a disclosed subset verifies', () => {
    const r = verifyCPA(buildInclusion(sampleItems(), ['dev-001', 'tr-001']), DID_DOC)
    assert.deepEqual(r.reasons, [])
    assert.equal(r.valid, true)
  })

  it('resignWithProducer over an UNtampered clone still verifies (helper sanity)', () => {
    const r = verifyCPA(resignWithProducer(clone(buildFullSet())), DID_DOC)
    assert.deepEqual(r.reasons, [])
    assert.equal(r.valid, true)
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 1 - content-swap-after-attestation
// ══════════════════════════════════════════════════════════════════
// THREAT: alter a disclosed leaf's raw content / content_ref / byte_len
// AFTER signing.
//   (a) mutate disclosed `content` bytes only -> CONTENT_REF_MISMATCH
//       (content is NOT in the leaf preimage, so partition_root/signature
//        are untouched; only the content<->content_ref bind catches it).
//   (b) mutate a leaf PREIMAGE field (content_ref) -> PARTITION_ROOT_MISMATCH
//       and SIGNATURE_INVALID.
//   (c) mutate byte_len (a preimage field) -> PARTITION_ROOT_MISMATCH.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 1. content-swap-after-attestation', () => {
  it('1a. swap disclosed content bytes (no re-sign) -> CONTENT_REF_MISMATCH (+ SIGNATURE_INVALID, since content IS in signed bytes)', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    // Replace the disclosed content with different bytes. content is EXCLUDED
    // from the leaf PREIMAGE (so the Merkle partition_root is untouched), but
    // it is still inside the signed JCS bytes of the whole CPA, so an
    // un-re-signed swap also trips SIGNATURE_INVALID. The dedicated content
    // bind independently catches the swap via CONTENT_REF_MISMATCH.
    dev.leaves![0].content = Buffer.from('POISONED CONTENT', 'utf8').toString('base64')
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'CONTENT_REF_MISMATCH', '1a content swap')
    // The Merkle partition_root must NOT be implicated (content not in preimage).
    assert.ok(!r.reasons.includes('PARTITION_ROOT_MISMATCH'), '1a: partition_root must remain valid (content excluded from preimage)')
  })

  it('1a-resigned. swap disclosed content bytes AND re-sign -> CONTENT_REF_MISMATCH only (content bind is independently load-bearing)', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.leaves![0].content = Buffer.from('POISONED CONTENT', 'utf8').toString('base64')
    // Re-sign so the signature is valid over the swapped content. The ONLY
    // remaining failure must be the dedicated content<->content_ref bind.
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'CONTENT_REF_MISMATCH', '1a-resigned content swap')
    assert.ok(!r.reasons.includes('SIGNATURE_INVALID'), '1a-resigned: signature now valid; content bind is the gate')
    assert.ok(!r.reasons.includes('PARTITION_ROOT_MISMATCH'), '1a-resigned: partition_root untouched (content not in preimage)')
  })

  it('1b. mutate a leaf content_ref (preimage field) -> PARTITION_ROOT_MISMATCH + SIGNATURE_INVALID', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.leaves![0].content_ref = flipLastHexChar(dev.leaves![0].content_ref)
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'PARTITION_ROOT_MISMATCH', '1b content_ref mutate')
    assert.ok(r.reasons.includes('SIGNATURE_INVALID'), '1b: leaves are inside signed bytes')
  })

  it('1b-resigned. mutate content_ref AND re-sign with producer key -> still PARTITION_ROOT_MISMATCH (no laundering)', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.leaves![0].content_ref = flipLastHexChar(dev.leaves![0].content_ref)
    // Re-sign so the signature is valid over the tampered bytes. The Merkle
    // recompute must STILL fail: the structural check is load-bearing.
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'PARTITION_ROOT_MISMATCH', '1b-resigned')
    assert.ok(!r.reasons.includes('SIGNATURE_INVALID'), '1b-resigned: signature now valid, structural check must catch it')
  })

  it('1c. mutate byte_len (preimage field) -> PARTITION_ROOT_MISMATCH', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.leaves![0].byte_len = dev.leaves![0].byte_len + 1
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'PARTITION_ROOT_MISMATCH', '1c byte_len mutate')
  })

  it('1d. shrink content + matching content_ref/byte_len but keep declared partition_root -> PARTITION_ROOT_MISMATCH', () => {
    // Attacker rewrites a leaf entirely (new content + correct new
    // content_ref + correct new byte_len) but cannot recompute the signed
    // partition_root without the private key. Merkle recompute over the new
    // preimage diverges from the declared partition_root.
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    const newBody = 'totally different instruction'
    const bytes = Buffer.from(newBody, 'utf8')
    dev.leaves![0].content = bytes.toString('base64')
    dev.leaves![0].content_ref = sha256Hex(newBody)
    dev.leaves![0].byte_len = bytes.byteLength
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'PARTITION_ROOT_MISMATCH', '1d full leaf rewrite (resigned)')
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 2 - replay-against-different-action
// ══════════════════════════════════════════════════════════════════
// THREAT: present an otherwise-valid CPA against a DIFFERENT action's
// receipt; tamper the receipt's cpa_ref.
//   (a) receipt.action_ref for another action -> ACTION_REF_MISMATCH.
//   (b) receipt.cpa_ref pointing at a different CPA -> CPA_REF_MISMATCH.
//   (c) tamper a SIGNED CPA field -> both SIGNATURE_INVALID and the
//       receipt's cpa_ref (computed over the untampered original) no longer
//       matches -> CPA_REF_MISMATCH.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 2. replay-against-different-action', () => {
  it('2a. valid CPA + receipt.action_ref of a DIFFERENT action -> ACTION_REF_MISMATCH', () => {
    const cpa = buildFullSet()
    const r = verifyCPA(cpa, DID_DOC, { action_ref: OTHER_ACTION_REF })
    assertFailClosed(r, 'ACTION_REF_MISMATCH', '2a replay action_ref')
  })

  it('2b. valid CPA + receipt.cpa_ref of a DIFFERENT CPA -> CPA_REF_MISMATCH', () => {
    const cpa = buildFullSet()
    // cpa_ref of a different, unrelated CPA (different items).
    const otherCpa = buildFullSet([item('memory', 'm-1', 'unrelated memory')])
    const r = verifyCPA(cpa, DID_DOC, { cpa_ref: computeCpaRef(otherCpa) })
    assertFailClosed(r, 'CPA_REF_MISMATCH', '2b replay cpa_ref')
  })

  it('2c. tamper a signed CPA field AND bind the ORIGINAL receipt cpa_ref -> SIGNATURE_INVALID + CPA_REF_MISMATCH', () => {
    const original = buildFullSet()
    const goodCpaRef = computeCpaRef(original) // receipt was minted against the clean CPA
    const tampered = clone(original)
    // Tamper a signed field (attested_at) without re-signing.
    tampered.attested_at = '2030-01-01T00:00:00Z'
    const r = verifyCPA(tampered, DID_DOC, { cpa_ref: goodCpaRef })
    assert.equal(r.valid, false)
    assert.ok(r.reasons.includes('SIGNATURE_INVALID'), '2c: signed field tampered -> SIGNATURE_INVALID')
    assert.ok(r.reasons.includes('CPA_REF_MISMATCH'), '2c: cpa_ref now diverges from the receipt binding')
  })

  it('2d. EXTRA: a valid receipt for the RIGHT action and RIGHT cpa_ref passes (binding is not over-eager)', () => {
    const cpa = buildFullSet()
    const r = verifyCPA(cpa, DID_DOC, { action_ref: ACTION_REF, cpa_ref: computeCpaRef(cpa) })
    assert.deepEqual(r.reasons, [], '2d: correct binding must verify clean')
    assert.equal(r.valid, true)
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 3 - reorder (tree-structure attacks)
// ══════════════════════════════════════════════════════════════════
// THREAT: shuffle leaves within a partition, reorder partitions, move a
// leaf to a different channel.
//   (a) reorder partitions out of CHANNEL_ORDER -> SHAPE_INVALID.
//   (b) duplicate a partition -> SHAPE_INVALID.
//   (c) move a leaf to a wrong-channel partition (leaf.channel != partition
//       channel) -> SHAPE_INVALID.
//   (d) re-channel an entire partition (relabel partition + its leaves to a
//       different channel slot), re-sign -> PARTITION_ROOT_MISMATCH and/or
//       ROOT_MISMATCH (the partition_root commits to leaf.channel).
//   NOTE on intra-partition leaf order: the verifier SORTS leaves by ctx_id
//   before recompute, so shuffling the disclosed-leaf ARRAY order does not
//   change the root (by design - order is canonical). Asserted below.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 3. reorder / tree-structure', () => {
  it('3a. partitions out of CHANNEL_ORDER -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet())
    cpa.partitions.reverse() // now descending channel order
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '3a reorder partitions')
  })

  it('3b. duplicate a partition -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet())
    cpa.partitions.push(clone(cpa.partitions[0])) // duplicate system-config
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '3b duplicate partition')
  })

  it('3c. leaf channel != its partition channel -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.leaves![0].channel = 'external' // moved leaf, mismatched channel
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '3c leaf channel mismatch')
  })

  it('3d. re-channel a whole partition into a different slot -> PARTITION_ROOT_MISMATCH', () => {
    // Take the developer partition's leaves, relabel partition + leaves to
    // 'memory', recompute would need leaf.channel='memory' in the preimage.
    // We relabel the partition slot but keep the declared partition_root
    // (which was computed with channel='developer' in each leaf preimage).
    const cpa = clone(buildFullSet())
    // Replace the whole partition set with ONLY the relabeled partition so
    // CHANNEL_ORDER/shape stays internally consistent.
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.channel = 'memory'
    for (const l of dev.leaves!) l.channel = 'memory'
    // Keep only this one partition to avoid order/duplicate shape noise.
    cpa.partitions = [dev]
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    // The declared partition_root was computed with channel 'developer' in
    // the leaf preimage; recompute now uses 'memory' -> divergence.
    assertFailClosed(r, 'PARTITION_ROOT_MISMATCH', '3d re-channel partition')
  })

  it('3e. shuffling disclosed-leaf ARRAY order does NOT change verification (canonical ctx_id sort) - documents design', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.leaves!.reverse() // array order shuffled; ctx_id sort is canonical
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    // This is NOT an attack the tree must reject: ordering is canonicalized.
    assert.equal(r.valid, true, '3e: leaf array order is canonicalized by ctx_id; reordering is a no-op')
  })

  it('3f. swap two leaves BETWEEN partitions (cross-channel leaf move) -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    const tr = cpa.partitions.find(p => p.channel === 'tool-result')!
    // Move a developer leaf object into the tool-result partition. Its
    // channel field still says 'developer' -> leaf/partition channel mismatch.
    tr.leaves!.push(clone(dev.leaves![0]))
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '3f cross-partition leaf move')
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 4 - existence-only disclosure under a content-requiring policy
// ══════════════════════════════════════════════════════════════════
// THREAT: present a count-only (or existence-only) disclosure when the
// consumer policy demands content. opts.requireContent === true.
//   (a) inclusion count-only (no disclosed leaves) + requireContent
//       -> DISCLOSURE_POLICY_UNSATISFIED.
//   (b) inclusion with a disclosed leaf whose `content` field is STRIPPED
//       (existence-only) + requireContent -> DISCLOSURE_POLICY_UNSATISFIED.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 4. existence-only under content-requiring policy', () => {
  it('4a. count-only inclusion CPA + requireContent -> DISCLOSURE_POLICY_UNSATISFIED', () => {
    const cpa = buildInclusion() // no disclosed leaves
    const r = verifyCPA(cpa, DID_DOC, undefined, { requireContent: true })
    assertFailClosed(r, 'DISCLOSURE_POLICY_UNSATISFIED', '4a count-only under requireContent')
  })

  it('4b. inclusion disclosing a leaf but with content STRIPPED + requireContent -> DISCLOSURE_POLICY_UNSATISFIED', () => {
    const cpa = clone(buildInclusion(sampleItems(), ['dev-001', 'tr-001']))
    // Strip the content from a disclosed leaf (existence-only proof of the
    // leaf without its bytes). The inclusion proof + content_ref are intact,
    // so the Merkle/proof checks pass; only the content policy must reject.
    for (const p of cpa.partitions) {
      for (const l of p.leaves ?? []) delete l.content
    }
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC, undefined, { requireContent: true })
    assertFailClosed(r, 'DISCLOSURE_POLICY_UNSATISFIED', '4b existence-only under requireContent')
  })

  it('4c. EXTRA: full-set with content present passes requireContent (policy is not over-eager)', () => {
    const cpa = buildFullSet() // every leaf carries content
    const r = verifyCPA(cpa, DID_DOC, undefined, { requireContent: true })
    assert.deepEqual(r.reasons, [], '4c: content-bearing disclosure must satisfy the policy')
    assert.equal(r.valid, true)
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 5 - cardinality forgery
// ══════════════════════════════════════════════════════════════════
// THREAT: claim leaf_count != the disclosed/declared count.
//   (a) full-set: leaf_count > disclosed leaves -> CARDINALITY_MISMATCH.
//   (b) full-set: leaf_count < disclosed leaves -> CARDINALITY_MISMATCH.
//   (c) inclusion: hidden_leaf_count lies (!= leaf_count - disclosed)
//       -> CARDINALITY_MISMATCH.
//   (d) inclusion: leaf_count inflated while hidden_leaf_count tracks it,
//       so cardinality is internally consistent but the count is a forgery
//       over the (un-disclosed) full set - documents that inclusion mode
//       canNOT detect a full-set-size lie from counts alone (NOT a v0.1
//       failure of the verifier; the count is producer-asserted). Marked.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 5. cardinality forgery', () => {
  it('5a. full-set leaf_count INFLATED above disclosed leaves -> CARDINALITY_MISMATCH', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.leaf_count = dev.leaf_count + 5 // claim more leaves than disclosed
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'CARDINALITY_MISMATCH', '5a inflated leaf_count')
  })

  it('5b. full-set leaf_count DEFLATED below disclosed leaves -> CARDINALITY_MISMATCH', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')! // 3 leaves
    dev.leaf_count = 1 // fewer than the 3 disclosed
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'CARDINALITY_MISMATCH', '5b deflated leaf_count')
  })

  it('5c. inclusion hidden_leaf_count LIES (!= leaf_count - disclosed) -> CARDINALITY_MISMATCH', () => {
    const cpa = clone(buildInclusion(sampleItems(), ['dev-001']))
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    // leaf_count=3, disclosed=1 => hidden should be 2. Forge it to 0.
    dev.context_profile!.hidden_leaf_count = 0
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'CARDINALITY_MISMATCH', '5c forged hidden_leaf_count')
  })

  it('5d. inclusion count-only with leaf_count != hidden_leaf_count (no disclosure) -> CARDINALITY_MISMATCH', () => {
    const cpa = clone(buildInclusion()) // count-only: hidden == leaf_count
    const sc = cpa.partitions.find(p => p.channel === 'system-config')!
    sc.context_profile!.hidden_leaf_count = sc.leaf_count + 1
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'CARDINALITY_MISMATCH', '5d count-only hidden mismatch')
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 6 - leaf / node / sign domain confusion
// ══════════════════════════════════════════════════════════════════
// THREAT: get a NODE digest accepted as a LEAF, or a leaf digest accepted
// as a partition_root for a different structural position, or swap tags.
//
// The three domain tags (LEAF_TAG/NODE_TAG/SIGN_TAG) are distinct prefixes,
// so a digest produced under one tag cannot be reproduced under another.
//   (a) partition_root set to a single leaf's LEAF digest in a multi-leaf
//       partition (i.e. pretend a leaf_hash is the partition_root) ->
//       PARTITION_ROOT_MISMATCH (the multi-leaf reduction uses NODE_TAG).
//   (b) partition_root set to a raw NODE digest of two leaves but the
//       partition only has ONE declared leaf (single-leaf partition_root
//       should equal the LEAF digest, not a NODE digest) ->
//       PARTITION_ROOT_MISMATCH.
//   (c) top root set to a partition_root value (leaf-digest-as-node reuse)
//       in a multi-partition CPA -> ROOT_MISMATCH.
//   (d) duplicate ctx_id within a partition -> DOMAIN_TAG_CONFUSION
//       (per TREE-SHAPE: duplicate ctx_id is reported as DOMAIN_TAG_CONFUSION).
//   (e) DIRECT merkle-layer proof: leaf_hash, node_hash, and a SIGN-tag
//       digest over the SAME bytes are all DISTINCT (tags are load-bearing).
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 6. leaf/node/sign domain confusion', () => {
  it('6a. multi-leaf partition_root forged to a single leaf_hash -> PARTITION_ROOT_MISMATCH', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')! // 3 leaves
    // Forge partition_root to be the LEAF digest of one leaf (a leaf-as-root
    // confusion). The verifier reduces all 3 leaves under NODE_TAG, so this
    // single leaf digest cannot equal the real partition_root.
    dev.partition_root = bytesToHex(leafHash(dev.leaves![0]))
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'PARTITION_ROOT_MISMATCH', '6a leaf-as-partition-root')
  })

  it('6b. single-leaf partition_root forged to a NODE digest -> PARTITION_ROOT_MISMATCH', () => {
    const cpa = clone(buildFullSet())
    const sc = cpa.partitions.find(p => p.channel === 'system-config')! // 1 leaf
    // A single-leaf partition_root MUST be the LEAF digest. Forge it to a
    // NODE digest (node_hash of the leaf with itself) - a node-as-root
    // confusion that a duplicating tree might have produced.
    const lh = leafHash(sc.leaves![0])
    sc.partition_root = bytesToHex(nodeHash(lh, lh))
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'PARTITION_ROOT_MISMATCH', '6b node-as-single-leaf-root')
  })

  it('6c. top root forged to a child partition_root value -> ROOT_MISMATCH', () => {
    const cpa = clone(buildFullSet())
    // In a multi-partition CPA, set the top root to one partition_root (a
    // node-position confusion: a partition_root reused as the top root).
    const sc = cpa.partitions.find(p => p.channel === 'system-config')!
    cpa.root = sc.partition_root
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'ROOT_MISMATCH', '6c partition-root-as-top-root')
  })

  it('6d. duplicate ctx_id within a partition -> DOMAIN_TAG_CONFUSION', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    // Inject a duplicate ctx_id (same ctx_id as an existing leaf).
    dev.leaves!.push(clone(dev.leaves![0]))
    dev.leaf_count = dev.leaves!.length
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'DOMAIN_TAG_CONFUSION', '6d duplicate ctx_id')
  })

  it('6e. DIRECT: leaf_hash, node_hash, and SIGN-tag digest over the same bytes are all distinct', () => {
    const leaf = item('developer', 'x-1', 'collide me')
    const lh = bytesToHex(leafHash(leaf))
    const nh = bytesToHex(nodeHash(leafHash(leaf), leafHash(leaf)))
    // cpa_ref uses SIGN_TAG over a different preimage; the relevant property
    // here is leaf vs node tag separation for the SAME leaf bytes.
    assert.notEqual(lh, nh, '6e: leaf digest must differ from node digest (distinct tags)')
    // And a node_hash of distinct children differs from either leaf digest.
    const other = item('developer', 'x-2', 'other')
    const nh2 = bytesToHex(nodeHash(leafHash(leaf), leafHash(other)))
    assert.notEqual(nh2, lh, '6e: node digest must differ from a constituent leaf digest')
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 7 - duplicate-last-leaf malleability (CVE-2012-2459 / RFC 6962)
// ══════════════════════════════════════════════════════════════════
// THREAT: in the Bitcoin Merkle bug, duplicating the final node lets two
// DISTINCT leaf multisets share a root. CPA promotes the odd node unchanged
// (never duplicates), which closes the class.
//
// Construction: a partition of 3 leaves [A,B,C] (sorted by ctx_id). A
// duplicating tree would treat it as [A,B,C,C] and fold:
//   L1 = node(A,B), L2 = node(C,C); root_dup = node(L1, L2).
// The CPA tree promotes C unchanged: root_cpa = node(node(A,B), C).
// So a 3-leaf partition and a 4-leaf partition whose 4th leaf duplicates
// the 3rd MUST yield DIFFERENT roots, and the duplicating multiset must NOT
// verify against the 3-leaf root.
//
//   (a) DIRECT merkle proof: root([A,B,C]) != root([A,B,C,C]).
//   (b) verify-level: take the 3-leaf CPA, append a duplicate-of-C leaf and
//       a re-sign; the partition_root recompute over [A,B,C,C-dup] (with a
//       fresh ctx_id to dodge the duplicate-ctx_id guard) diverges from the
//       declared 3-leaf root -> PARTITION_ROOT_MISMATCH. And the declared
//       3-leaf root cannot be reached by ANY 4-leaf duplicating fold.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 7. duplicate-last-leaf malleability (CVE-2012-2459)', () => {
  it('7a. DIRECT: root([A,B,C]) != root([A,B,C,duplicate-of-C])', () => {
    const A = item('developer', 'a', 'leaf A')
    const B = item('developer', 'b', 'leaf B')
    const C = item('developer', 'c', 'leaf C')
    const threeLeafRoot = buildPartitionRoot([A, B, C])
    // The duplicate must have its own ctx_id (the build guard rejects a true
    // duplicate ctx_id) but the SAME preimage-relevant fields as C EXCEPT
    // ctx_id is part of the preimage, so a perfect content-clone is
    // impossible. The strongest statement of the property: NO 4-leaf set
    // formed by re-using C's *digest* reproduces the 3-leaf promoted root.
    // We assert it at the digest level, which is exactly where CVE-2012-2459
    // lives: a duplicating fold of [A,B,C,C-digest] != promoted fold.
    const lA = leafHash(A), lB = leafHash(B), lC = leafHash(C)
    const promoted = bytesToHex(nodeHash(nodeHash(lA, lB), lC)) // CPA's rule
    const duplicating = bytesToHex(nodeHash(nodeHash(lA, lB), nodeHash(lC, lC))) // CVE rule
    assert.equal(threeLeafRoot, promoted, '7a: CPA 3-leaf root uses odd-promotion')
    assert.notEqual(promoted, duplicating, '7a: promoted root must NOT equal the duplicating root (CVE-2012-2459 closed)')
  })

  it('7b. verify-level: a 4th leaf that re-folds C does NOT reach the signed 3-leaf root -> PARTITION_ROOT_MISMATCH', () => {
    // Build a clean 3-leaf developer partition CPA.
    const items = [
      item('developer', 'a', 'leaf A'),
      item('developer', 'b', 'leaf B'),
      item('developer', 'c', 'leaf C'),
    ]
    const cpa = clone(buildFullSet(items))
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    const declared3LeafRoot = dev.partition_root
    // Attacker appends a 4th leaf (fresh ctx_id 'd', cloned content of C) to
    // try to exploit a duplicating tree. Keep the DECLARED 3-leaf root.
    const dup = item('developer', 'd', 'leaf C') // same body as C, new ctx_id
    dev.leaves!.push(dup)
    dev.leaf_count = 4
    // Recompute would now be over 4 leaves; it cannot equal the declared
    // 3-leaf root under the non-duplicating rule.
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'PARTITION_ROOT_MISMATCH', '7b duplicate-leaf append')
    // Belt and suspenders: the declared root is the genuine 3-leaf promoted
    // root, not any 4-leaf duplicating fold.
    assert.equal(declared3LeafRoot, buildPartitionRoot(items), '7b: declared root is the honest 3-leaf root')
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 8 - key not active / DID mismatch / pubkey absent
// ══════════════════════════════════════════════════════════════════
// THREAT: sign with a key not active at attested_at; present a DID document
// whose id != producer_did; pubkey absent from the DID doc.
//   (a) DID doc id != cpa.producer_did -> DID_MISMATCH.
//   (b) signing key retired (retiredAt set) at attested_at -> KEY_NOT_ACTIVE.
//   (c) signing key absent from the DID doc verificationMethod ->
//       KEY_NOT_ACTIVE (and SIGNATURE_INVALID if the pubkey field doesn't
//       match the signature; here we test pubkey-absent-from-doc precisely).
//   (d) attacker re-signs with their OWN key (valid signature) but that key
//       is not in the producer DID doc -> KEY_NOT_ACTIVE (signature passes,
//       identity binding fails - the verifier must not accept a self-signed
//       forgery).
//   (e) key not in authentication list -> KEY_NOT_ACTIVE.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 8. key not active / DID mismatch', () => {
  it('8a. DID doc id != producer_did -> DID_MISMATCH', () => {
    const cpa = buildFullSet()
    const wrongDoc = makeDIDDoc(PUB, 'did:aps:someoneElseEntirely')
    const r = verifyCPA(cpa, wrongDoc)
    assertFailClosed(r, 'DID_MISMATCH', '8a DID id mismatch')
  })

  it('8b. signing key RETIRED at attested_at -> KEY_NOT_ACTIVE', () => {
    const cpa = buildFullSet()
    const retiredDoc = makeDIDDoc(PUB, PRODUCER_DID)
    retiredDoc.verificationMethod[0].retiredAt = '2026-01-01T00:00:00Z'
    const r = verifyCPA(cpa, retiredDoc)
    assertFailClosed(r, 'KEY_NOT_ACTIVE', '8b retired key')
  })

  it('8c. producer_pubkey ABSENT from the DID doc -> KEY_NOT_ACTIVE', () => {
    const cpa = buildFullSet()
    // DID doc carries a DIFFERENT (attacker) pubkey; the CPA's producer
    // pubkey (PUB) is not present in verificationMethod.
    const otherKeyDoc = makeDIDDoc(ATTACKER_PUB, PRODUCER_DID)
    const r = verifyCPA(cpa, otherKeyDoc)
    assertFailClosed(r, 'KEY_NOT_ACTIVE', '8c pubkey absent from doc')
  })

  it('8d. attacker self-signs with their own key (valid sig) but key not in producer doc -> KEY_NOT_ACTIVE', () => {
    // Tamper a leaf, then re-sign with the attacker key + set producer_pubkey
    // to the attacker pubkey. The signature is internally valid, so
    // SIGNATURE_INVALID is NOT the gate - KEY_NOT_ACTIVE is.
    const cpa = clone(buildFullSet())
    cpa.partitions.find(p => p.channel === 'developer')!.leaves![0].content =
      Buffer.from('attacker-injected', 'utf8').toString('base64')
    const forged = resignWithAttacker(cpa)
    const r = verifyCPA(forged, DID_DOC)
    assert.equal(r.valid, false)
    assert.ok(!r.reasons.includes('SIGNATURE_INVALID'), '8d: attacker signature IS valid over its own bytes')
    assert.ok(r.reasons.includes('KEY_NOT_ACTIVE'), '8d: attacker key is not active in the producer DID doc')
  })

  it('8e. key present but NOT in authentication list -> KEY_NOT_ACTIVE', () => {
    const cpa = buildFullSet()
    const doc = makeDIDDoc(PUB, PRODUCER_DID)
    doc.authentication = [] // key exists in vm but is not authorized
    const r = verifyCPA(cpa, doc)
    assertFailClosed(r, 'KEY_NOT_ACTIVE', '8e key not in authentication')
  })

  // ────────────────────────────────────────────────────────────────
  // F-1 (FAIL-CLOSED CONTRACT): malformed DID documents must FAIL CLOSED.
  //
  // A MALFORMED DID document must NEVER make verifyCPA throw. The blast
  // radius of the original bug was wide: it fired for ANY didDoc that is
  // null, undefined, a non-object (string/number), an array, an empty
  // object {}, or any object lacking a valid `rotationLog` array -
  // INCLUDING a doc whose id mismatches producer_did (the DID_MISMATCH
  // path did not short-circuit). Execution fell through to the key-active
  // step (verifyRotationChain / isKeyActive), which dereferences
  // didDoc.rotationLog and threw.
  //
  // FIX (verify.ts §2/§4): the DID-binding step validates the DID-document
  // SHAPE (object, not array, with an array rotationLog) and pushes
  // DID_MISMATCH when the shape is bad OR the id does not bind to
  // producer_did. The key-active step is guarded by that same `docOk` flag
  // so verifyRotationChain / isKeyActive only run on a well-shaped doc.
  //
  // Post-fix contract: for every malformed doc, verifyCPA returns a
  // structured result with valid===false, reasons includes 'DID_MISMATCH'
  // (a malformed doc also yields 'KEY_NOT_ACTIVE'), and NOTHING throws.
  // Each call is wrapped so a thrown error fails the test explicitly.
  // ────────────────────────────────────────────────────────────────
  it('8f. malformed DID documents fail closed (DID_MISMATCH, no throw) - F-1 contract', () => {
    const cpa = buildFullSet()
    const malformed: Array<[string, unknown]> = [
      ['null', null],
      ['undefined', undefined],
      ['string', 'not-a-doc'],
      ['number', 42],
      ['array', []],
      ['empty object', {}],
      ['object with non-array rotationLog', { id: PRODUCER_DID, rotationLog: 'nope' }],
      ['object with mismatched id, no rotationLog', { id: 'did:aps:someoneElse' }],
      ['object with matching id but no rotationLog/vm', { id: PRODUCER_DID }],
      ['object whose id mismatches producer_did', { id: 'did:aps:other', rotationLog: [] }],
    ]
    for (const [label, doc] of malformed) {
      let r: ReturnType<typeof verifyCPA>
      try {
        r = verifyCPA(cpa, doc as unknown as RotatableDIDDocument)
      } catch (err) {
        assert.fail(`8f [${label}]: verifier threw instead of failing closed: ${String(err)}`)
      }
      assert.equal(typeof r, 'object', `8f [${label}]: verifier must return a result object, never throw`)
      assert.equal(r.valid, false, `8f [${label}]: malformed doc must fail closed (valid=false)`)
      assert.ok(
        r.reasons.includes('DID_MISMATCH'),
        `8f [${label}]: expected DID_MISMATCH, got [${r.reasons.join(', ')}]`,
      )
    }
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 9 - forged / mismatched inclusion proof
// ══════════════════════════════════════════════════════════════════
// THREAT: in inclusion mode, present a disclosed leaf with a forged or
// mismatched inclusion proof.
//   (a) tamper a sibling digest in the proof path -> INCLUSION_PROOF_INVALID.
//   (b) flip a step's side (left<->right) -> INCLUSION_PROOF_INVALID.
//   (c) disclose a leaf with NO matching proof -> INCLUSION_PROOF_INVALID.
//   (d) proof ctx_id != disclosed leaf ctx_id -> INCLUSION_PROOF_INVALID.
//   (e) a proof for a leaf that is NOT disclosed (orphan proof) ->
//       INCLUSION_PROOF_INVALID.
//   (f) DIRECT: verifyInclusionProof rejects a proof folding to a DIFFERENT
//       partition_root (fail-closed, returns false, no throw).
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 9. forged / mismatched inclusion proof', () => {
  function inclusionWithProofs(): ContextProvenanceAttestation {
    return clone(buildInclusion(sampleItems(), ['dev-001', 'dev-002']))
  }

  it('9a. tampered sibling digest in proof path -> INCLUSION_PROOF_INVALID', () => {
    const cpa = inclusionWithProofs()
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    const proof = dev.inclusion_proofs!.find(pr => pr.path.length > 0)!
    proof.path[0].sibling = flipLastHexChar(proof.path[0].sibling)
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'INCLUSION_PROOF_INVALID', '9a tampered sibling')
  })

  it('9b. flipped step side -> INCLUSION_PROOF_INVALID', () => {
    const cpa = inclusionWithProofs()
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    const proof = dev.inclusion_proofs!.find(pr => pr.path.length > 0)!
    proof.path[0].side = proof.path[0].side === 'left' ? 'right' : 'left'
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'INCLUSION_PROOF_INVALID', '9b flipped side')
  })

  it('9c. disclosed leaf with NO matching proof -> INCLUSION_PROOF_INVALID', () => {
    const cpa = inclusionWithProofs()
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.inclusion_proofs = [] // drop all proofs while leaves stay disclosed
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'INCLUSION_PROOF_INVALID', '9c missing proof')
  })

  it('9d. proof ctx_id != disclosed leaf ctx_id -> INCLUSION_PROOF_INVALID', () => {
    const cpa = inclusionWithProofs()
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.inclusion_proofs![0].ctx_id = 'does-not-exist'
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'INCLUSION_PROOF_INVALID', '9d proof ctx_id mismatch')
  })

  it('9e. orphan proof (proof for a non-disclosed leaf) -> INCLUSION_PROOF_INVALID', () => {
    const cpa = inclusionWithProofs()
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    // Add a structurally-valid-shaped proof whose ctx_id matches no
    // disclosed leaf. (Built honestly for dev-003 which is NOT disclosed.)
    const fullDevItems = sampleItems().filter(i => i.channel === 'developer')
    dev.inclusion_proofs!.push(buildInclusionProof(fullDevItems, 'dev-003'))
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'INCLUSION_PROOF_INVALID', '9e orphan proof')
  })

  it('9f. DIRECT: verifyInclusionProof returns false (no throw) for a proof folding to a wrong root', () => {
    const devItems = sampleItems().filter(i => i.channel === 'developer')
    const proof = buildInclusionProof(devItems, 'dev-001')
    const leaf = devItems.find(i => i.ctx_id === 'dev-001')!
    const wrongRoot = flipLastHexChar(buildPartitionRoot(devItems))
    assert.equal(verifyInclusionProof(leaf, proof, wrongRoot), false, '9f: wrong root must not verify')
    // And a malformed proof object must not throw.
    assert.equal(
      verifyInclusionProof(leaf, { ctx_id: 'dev-001', path: [{ sibling: 'zz', side: 'left' }] } as never, buildPartitionRoot(devItems)),
      false,
      '9f: malformed proof returns false, never throws',
    )
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 10 (EXTRA) - malformed / non-object input -> SHAPE_INVALID, no throw
// ══════════════════════════════════════════════════════════════════
// THREAT: hostile/garbage input must produce SHAPE_INVALID, never a throw.
// Derived directly from the "Malformed input" threat-model bullet.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 10. malformed input -> SHAPE_INVALID (no throw)', () => {
  const garbage: Array<[string, unknown]> = [
    ['null', null],
    ['undefined', undefined],
    ['number', 42],
    ['string', 'not a cpa'],
    ['array', []],
    ['empty object', {}],
  ]
  for (const [label, input] of garbage) {
    it(`10. ${label} -> SHAPE_INVALID`, () => {
      const r = verifyCPA(input, DID_DOC)
      assertFailClosed(r, 'SHAPE_INVALID', `10 ${label}`)
    })
  }

  it('10g. wrong version literal -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet()) as unknown as Record<string, unknown>
    cpa.version = 'cpa/0.2'
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10g wrong version')
  })

  it('10h. action_ref not 64-hex -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet()) as unknown as Record<string, unknown>
    cpa.action_ref = 'short'
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10h bad action_ref')
  })

  it('10i. producer_pubkey wrong hex length -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet()) as unknown as Record<string, unknown>
    cpa.producer_pubkey = 'ab'.repeat(40) // 80 bytes, not 32
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10i bad pubkey length')
  })

  it('10j. signature wrong hex length -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet()) as unknown as Record<string, unknown>
    cpa.signature = 'ab'.repeat(60) // 120 hex, not 128
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10j bad signature length')
  })

  it('10k. channel not one of the 8 -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet())
    ;(cpa.partitions[0] as unknown as Record<string, unknown>).channel = 'totally-made-up'
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10k bad channel')
  })

  it('10l. full-set partition missing leaves -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet())
    delete cpa.partitions[0].leaves
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10l full-set missing leaves')
  })

  it('10m. inclusion partition missing context_profile -> SHAPE_INVALID', () => {
    const cpa = clone(buildInclusion())
    delete cpa.partitions[0].context_profile
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10m inclusion missing profile')
  })

  it('10n. full-set partition carrying a context_profile -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet())
    cpa.partitions[0].context_profile = { channel: cpa.partitions[0].channel, hidden_leaf_count: 0 }
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10n full-set with profile')
  })

  it('10o. non-ISO attested_at -> SHAPE_INVALID (no throw on Date parse)', () => {
    const cpa = clone(buildFullSet()) as unknown as Record<string, unknown>
    cpa.attested_at = 'yesterday'
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10o bad attested_at')
  })

  it('10p. inclusion_proofs present in FULL-SET mode -> SHAPE_INVALID', () => {
    const cpa = clone(buildFullSet())
    ;(cpa.partitions[0] as unknown as Record<string, unknown>).inclusion_proofs = []
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10p proofs in full-set')
  })

  it('10q. leaf_count zero -> SHAPE_INVALID (present partition must have >=1)', () => {
    const cpa = clone(buildFullSet())
    cpa.partitions[0].leaf_count = 0
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'SHAPE_INVALID', '10q leaf_count 0')
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 11 (EXTRA) - top-root tampering in single & multi partition
// ══════════════════════════════════════════════════════════════════
// THREAT: tamper the signed top root. Without re-sign -> SIGNATURE_INVALID
// + ROOT_MISMATCH. With producer re-sign -> ROOT_MISMATCH alone (the
// recompute over declared partition_roots is load-bearing).
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 11. top-root tamper', () => {
  it('11a. flip top root, no re-sign -> SIGNATURE_INVALID + ROOT_MISMATCH', () => {
    const cpa = clone(buildFullSet())
    cpa.root = flipLastHexChar(cpa.root)
    const r = verifyCPA(cpa, DID_DOC)
    assert.equal(r.valid, false)
    assert.ok(r.reasons.includes('SIGNATURE_INVALID'), '11a: root is signed')
    assert.ok(r.reasons.includes('ROOT_MISMATCH'), '11a: top-root recompute diverges')
  })

  it('11b. flip top root, re-sign with producer -> ROOT_MISMATCH (structural check load-bearing)', () => {
    const cpa = clone(buildFullSet())
    cpa.root = flipLastHexChar(cpa.root)
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'ROOT_MISMATCH', '11b re-signed root tamper')
    assert.ok(!r.reasons.includes('SIGNATURE_INVALID'), '11b: signature valid, ROOT_MISMATCH is the gate')
  })

  it('11c. tamper a declared partition_root + recompute the top root honestly + re-sign -> PARTITION_ROOT_MISMATCH', () => {
    // Attacker changes a partition_root, then honestly folds the new
    // partition_roots into a fresh top root and re-signs. The top fold is
    // now self-consistent (no ROOT_MISMATCH), but the partition_root no
    // longer matches its own leaves -> PARTITION_ROOT_MISMATCH.
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.partition_root = flipLastHexChar(dev.partition_root)
    // Recompute the top root over the (tampered) declared partition_roots in
    // CHANNEL_ORDER, exactly as the verifier folds them.
    cpa.root = buildTopRoot(
      [...cpa.partitions]
        .sort((a, b) => CHANNEL_ORDER.indexOf(a.channel) - CHANNEL_ORDER.indexOf(b.channel))
        .map(p => p.partition_root),
    )
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'PARTITION_ROOT_MISMATCH', '11c partition_root tamper + honest top fold')
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 12 (EXTRA) - content binding edge cases
// ══════════════════════════════════════════════════════════════════
// THREAT: a disclosed leaf whose content does not bind to content_ref or
// byte_len; non-canonical base64.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 12. content binding edge cases', () => {
  it('12a. content present, byte_len lies but is a preimage field -> PARTITION_ROOT_MISMATCH', () => {
    // byte_len is in the preimage, so changing it changes the partition_root
    // recompute first. (content also no longer matches the lied byte_len.)
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    dev.leaves![0].byte_len = 9999
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'PARTITION_ROOT_MISMATCH', '12a byte_len lie')
  })

  it('12b. content is non-canonical base64 -> CONTENT_REF_MISMATCH (strict decode, no throw)', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    // Append base64 padding garbage so re-encode does not round-trip.
    dev.leaves![0].content = dev.leaves![0].content + '==='
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'CONTENT_REF_MISMATCH', '12b non-canonical base64')
  })

  it('12c. content decodes but hashes to a different value than content_ref -> CONTENT_REF_MISMATCH', () => {
    const cpa = clone(buildFullSet())
    const dev = cpa.partitions.find(p => p.channel === 'developer')!
    // Same byte length so byte_len still matches; different bytes so the
    // hash differs from the (untouched) content_ref. Preimage unchanged.
    const original = Buffer.from(dev.leaves![0].content!, 'base64')
    const mutated = Buffer.from(original)
    mutated[0] = mutated[0] ^ 0xff
    dev.leaves![0].content = mutated.toString('base64')
    const r = verifyCPA(cpa, DID_DOC)
    assertFailClosed(r, 'CONTENT_REF_MISMATCH', '12c content hash mismatch (same length)')
    assert.ok(!r.reasons.includes('PARTITION_ROOT_MISMATCH'), '12c: preimage untouched, only content bind fails')
  })
})

// ══════════════════════════════════════════════════════════════════
// VECTOR 13 (EXTRA) - empty-tree sentinel forgery
// ══════════════════════════════════════════════════════════════════
// THREAT: forge the empty-tree root, or present partitions with the empty
// sentinel root. The empty-tree top root is a fixed constant.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: 13. empty-tree sentinel', () => {
  it('13a. empty CPA with a forged (non-sentinel) root -> ROOT_MISMATCH', () => {
    const cpa = clone(buildFullSet([])) // partitions === []
    assert.deepEqual(cpa.partitions, [])
    cpa.root = flipLastHexChar(cpa.root)
    const r = verifyCPA(resignWithProducer(cpa), DID_DOC)
    assertFailClosed(r, 'ROOT_MISMATCH', '13a forged empty-tree root')
  })
})

// ══════════════════════════════════════════════════════════════════
// EXPLICITLY-NOT-CLOSED VECTOR (mandatory honesty marker)
// ══════════════════════════════════════════════════════════════════
// pre-attestation faithful-capture failure.
//
// STATUS: NOT CLOSED (out of v0.1 scope).
//
// A producer/gateway can attest a clean, well-formed, fully-binding context
// set while having actually fed the model something else entirely. CPA
// verifies CUSTODY and ADMISSIBILITY of the DECLARED, DISCLOSED basis under
// the declared selection policy. It CANNOT detect, from the disclosed bytes
// alone, a divergence between what was attested and what the model actually
// conditioned on. Closing this requires an INDEPENDENT capture boundary
// (TEE attestation / write-time receipts / runtime instrumentation), all
// OUT OF v0.1 SCOPE.
//
// This test does NOT assert a verifier rejection - there is nothing in the
// disclosed bytes for the verifier to catch. It asserts the honest
// boundary: a perfectly-formed CPA over a DIFFERENT-from-actual basis still
// verifies VALID, which is exactly why faithful capture needs an
// out-of-band mechanism. The test exists to ENCODE that honesty in the
// suite so the limitation cannot be quietly forgotten.
// ══════════════════════════════════════════════════════════════════

describe('CPA adversarial :: NOT CLOSED (out of v0.1 scope) - pre-attestation faithful-capture', () => {
  it('faithful-capture: a clean CPA over an arbitrary declared basis still verifies VALID (limitation, not a bug)', () => {
    // The producer attests THIS basis. Whether the model was actually
    // conditioned on it is unobservable from these bytes. The CPA is, by
    // construction, internally valid.
    const attestedButPossiblyNotWhatTheModelSaw = [
      item('system-config', 'sc-1', 'a clean, benign system prompt'),
      item('developer', 'dev-1', 'a clean developer instruction'),
    ]
    const cpa = buildFullSet(attestedButPossiblyNotWhatTheModelSaw)
    const r = verifyCPA(cpa, DID_DOC)
    assert.equal(r.valid, true, 'faithful-capture vector: CPA is internally valid; faithful capture is NOT in scope')
    assert.equal(r.completeness, 'PROVEN')
    // Encoded honesty: there is NO reason code for "the declared basis is not
    // what the model conditioned on". v0.1 cannot, and does not claim to,
    // detect pre-attestation capture divergence. An independent capture
    // boundary (TEE / write-time receipts / runtime instrumentation) is
    // REQUIRED and is out of v0.1 scope.
    const NO_FAITHFUL_CAPTURE_REASON_CODE_EXISTS = true
    assert.ok(NO_FAITHFUL_CAPTURE_REASON_CODE_EXISTS)
  })
})
