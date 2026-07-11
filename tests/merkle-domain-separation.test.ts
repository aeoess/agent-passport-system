// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Merkle domain separation (CVE-2012-2459 class) — DAY-145 audit.
//
// Bitcoin-style odd-node duplication with no leaf/internal domain
// separation lets distinct receipt multisets collide to the same root:
// buildMerkleRoot([a, b, c]) === buildMerkleRoot([a, b, c, c]). That in
// turn lets an inclusion proof forge a phantom-duplicate membership.
// These tests fail on the unpatched primitives and pass once leaves are
// hashed under 0x00, internal nodes under 0x01, and odd nodes are
// promoted unchanged instead of silently duplicated.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildMerkleRoot,
  generateMerkleProof,
  verifyMerkleProof,
} from '../src/index.js'
import {
  settlementBuildMerkleRoot,
  buildContributorMerklePath,
  verifySettlementMerklePath,
  settlementLeafHash,
} from '../src/v2/index.js'

const A = 'a'.repeat(64)
const B = 'b'.repeat(64)
const C = 'c'.repeat(64)

describe('core Merkle — domain separation defeats duplicate-leaf collision', () => {
  it('a 3-leaf set and its odd-duplicate 4-leaf sibling produce DIFFERENT roots', () => {
    const three = buildMerkleRoot([A, B, C])
    const dup = buildMerkleRoot([A, B, C, C])
    assert.notEqual(
      three,
      dup,
      'CVE-2012-2459: distinct multisets must not collide to one root',
    )
  })

  it('a genuine 3-leaf inclusion proof still verifies against its root', () => {
    const three = buildMerkleRoot([A, B, C])
    const proof = generateMerkleProof([A, B, C], C)
    assert.ok(proof, 'proof for a present leaf must be generated')
    assert.equal(proof!.root, three, 'proof root must equal the 3-leaf root')
    assert.equal(verifyMerkleProof(proof!), true, 'genuine proof must verify')
  })

  it('a phantom-duplicate proof cannot masquerade as the honest 3-leaf commitment', () => {
    const three = buildMerkleRoot([A, B, C])
    // The forged view claims a 4th duplicate receipt C is in the tree.
    const phantom = generateMerkleProof([A, B, C, C], C)
    assert.ok(phantom, 'phantom proof is internally generatable')
    // It is internally consistent against ITS OWN (4-leaf) root ...
    assert.equal(verifyMerkleProof(phantom!), true)
    // ... but that root must NOT equal the root a verifier committed to
    // for the honest 3-receipt set, so the phantom cannot be replayed.
    assert.notEqual(
      phantom!.root,
      three,
      'phantom-duplicate root must not equal the honest 3-leaf root',
    )
  })
})

describe('settlement Merkle — domain separation defeats duplicate-leaf collision', () => {
  const la = settlementLeafHash({ id: 'a' })
  const lb = settlementLeafHash({ id: 'b' })
  const lc = settlementLeafHash({ id: 'c' })

  it('a 3-leaf set and its odd-duplicate 4-leaf sibling produce DIFFERENT roots', () => {
    const three = settlementBuildMerkleRoot([la, lb, lc]).toString('hex')
    const dup = settlementBuildMerkleRoot([la, lb, lc, lc]).toString('hex')
    assert.notEqual(three, dup, 'CVE-2012-2459: settlement roots must differ')
  })

  it('a genuine contributor path still reconstructs the axis root', () => {
    const three = settlementBuildMerkleRoot([la, lb, lc]).toString('hex')
    // index 2 is the odd/promoted leaf — the worst case for the fold.
    const path = buildContributorMerklePath([la, lb, lc], 2)
    assert.equal(
      verifySettlementMerklePath(lc, 2, path, three),
      true,
      'genuine promoted-leaf path must reconstruct the root',
    )
    // every non-promoted leaf must also still verify
    assert.equal(verifySettlementMerklePath(la, 0, buildContributorMerklePath([la, lb, lc], 0), three), true)
    assert.equal(verifySettlementMerklePath(lb, 1, buildContributorMerklePath([la, lb, lc], 1), three), true)
  })

  it('a phantom-duplicate path cannot reconstruct the honest 3-leaf root', () => {
    const three = settlementBuildMerkleRoot([la, lb, lc]).toString('hex')
    // A path built against the 4-leaf duplicate tree for the duplicated
    // leaf must not reconstruct the honest 3-leaf commitment.
    const phantomPath = buildContributorMerklePath([la, lb, lc, lc], 3)
    assert.equal(
      verifySettlementMerklePath(lc, 3, phantomPath, three),
      false,
      'phantom-duplicate path must not reconstruct the honest root',
    )
  })
})
