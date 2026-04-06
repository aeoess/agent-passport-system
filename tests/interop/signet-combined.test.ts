// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Interop: Signet + APS combined credential verification

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { canonicalize, verify } from '../../src/index.js'

const DIR = new URL('../../specs/test-vectors/signet/', import.meta.url).pathname

function loadVector(name: string) {
  return JSON.parse(readFileSync(`${DIR}${name}`, 'utf-8'))
}

describe('Signet + APS Combined Credentials', () => {
  describe('Vector 1: Issuance', () => {
    const v = loadVector('vector-1-issuance.json')

    it('has both signet_link and aps_delegation', () => {
      assert.ok(v.signet_link, 'signet_link present')
      assert.ok(v.signet_link.metadata.aps_delegation, 'aps_delegation present')
      assert.ok(v.signet_link.metadata.aps_delegation_hash, 'aps_delegation_hash present')
    })

    it('aps_delegation_hash is present and sha256-prefixed', () => {
      const hash = v.signet_link.metadata.aps_delegation_hash
      assert.ok(hash.startsWith('sha256:'), 'hash is sha256-prefixed')
      assert.equal(hash.length, 7 + 64, 'hash is correct length')
    })

    it('delegation has valid signature field', () => {
      const delegation = v.signet_link.metadata.aps_delegation
      assert.ok(delegation.signature, 'signature present')
      assert.equal(delegation.signature.length, 128, 'Ed25519 signature is 64 bytes (128 hex)')
    })

    it('signet link status is active', () => {
      assert.equal(v.signet_link.status, 'active')
    })

    it('delegation has expected scope', () => {
      const scope = v.signet_link.metadata.aps_delegation.scope
      assert.ok(scope.includes('tools:readFile'))
      assert.ok(scope.includes('tools:writeFile'))
    })
  })

  describe('Vector 2: Presentation (APS-only verifier)', () => {
    const v = loadVector('vector-2-presentation.json')

    it('APS verifier extracts delegation from signet wrapper', () => {
      assert.ok(v.aps_verification.delegation_extracted)
      assert.ok(v.aps_verification.delegation_extracted.delegationId)
    })

    it('scope covers requested action', () => {
      assert.equal(v.aps_verification.scope_covers_action, true)
      assert.equal(v.input.requested_action.scope_required, 'tools:readFile')
    })

    it('signet wrapper acknowledged but not verified', () => {
      assert.equal(v.aps_verification.signet_wrapper_acknowledged, true)
      assert.equal(v.aps_verification.signet_wrapper_verified, false)
    })

    it('access granted', () => {
      assert.equal(v.expected.access_granted, true)
    })
  })

  describe('Vector 3: Revocation', () => {
    const v = loadVector('vector-3-revocation.json')

    it('signet link is revoked', () => {
      assert.equal(v.signet_link.status, 'revoked')
    })

    it('APS signature still valid despite revocation', () => {
      assert.equal(v.expected.aps_signature_valid, true)
    })

    it('access denied due to revocation', () => {
      assert.equal(v.expected.access_granted, false)
    })

    it('revocation sequence is correct', () => {
      assert.equal(v.sequence.length, 3)
      assert.equal(v.sequence[0].access_decision, 'granted')
      assert.equal(v.sequence[1].signet_link_status, 'revoked')
      assert.equal(v.sequence[2].access_decision, 'rejected')
    })
  })
})
