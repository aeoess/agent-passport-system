// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Mutual Auth conformance: verify generated vectors round-trip through
// the current SDK. If a code change breaks canonical form, this test
// fails and the vectors must be regenerated intentionally.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { canonicalizeJCS } from '../../../src/core/canonical-jcs.js'
import { buildCertificate, buildBundle } from '../../../src/index.js'

const VEC_DIR = 'src/conformance/mutual-auth-vectors'

function loadVec(name: string): any {
  return JSON.parse(readFileSync(`${VEC_DIR}/${name}`, 'utf8'))
}

function sha256(bytes: Uint8Array): string {
  return 'sha256:' + createHash('sha256').update(bytes).digest('hex')
}

describe('mutual-auth conformance vectors', () => {
  it('vec01: minimum certificate canonical form reproduces', () => {
    const vec = loadVec('vec01-certificate-canonical.json')
    const { issuer_pubkey_hex, ...input } = vec.input
    const unsigned = buildCertificate(input, issuer_pubkey_hex)
    const canonical = new TextEncoder().encode(canonicalizeJCS(unsigned))
    assert.equal(
      Buffer.from(canonical).toString('base64'),
      vec.expected.canonical_bytes_b64,
    )
    assert.equal(sha256(canonical), vec.expected.canonical_sha256)
  })

  it('vec02: all-fields certificate canonical form reproduces', () => {
    const vec = loadVec('vec02-certificate-all-fields.json')
    const { issuer_pubkey_hex, ...input } = vec.input
    const unsigned = buildCertificate(input, issuer_pubkey_hex)
    const canonical = new TextEncoder().encode(canonicalizeJCS(unsigned))
    assert.equal(
      Buffer.from(canonical).toString('base64'),
      vec.expected.canonical_bytes_b64,
    )
    assert.equal(sha256(canonical), vec.expected.canonical_sha256)
  })

  it('vec03: bundle canonical form reproduces', () => {
    const vec = loadVec('vec03-bundle-canonical.json')
    const T0 = 1_745_000_000_000
    const ROOT_PK = '00'.repeat(32)
    const unsigned = buildBundle(
      {
        bundle_id: 'test-bundle-001',
        anchors: [
          {
            anchor_id: 'root', display_name: 'Root', role: 'trust_anchor',
            pubkey_hex: ROOT_PK,
            not_before: T0 - 86400_000, not_after: T0 + 31_536_000_000,
          },
        ],
        issued_at: T0,
        refresh_after: T0 + 7 * 86400_000,
      },
      ROOT_PK,
    )
    const canonical = new TextEncoder().encode(canonicalizeJCS(unsigned))
    assert.equal(
      Buffer.from(canonical).toString('base64'),
      vec.expected.canonical_bytes_b64,
    )
    assert.equal(sha256(canonical), vec.expected.canonical_sha256)
  })

  it('vec04 + vec05: session_id derivation is stable', () => {
    const vec05 = loadVec('vec05-session-derivation.json')
    const material = canonicalizeJCS({
      spec_version: '1.0',
      chosen_version: vec05.input.chosen_version,
      agent_cert_id: vec05.input.agent_cert_id,
      is_cert_id: vec05.input.is_cert_id,
      agent_nonce_b64: vec05.input.agent_nonce_b64,
      is_nonce_b64: vec05.input.is_nonce_b64,
    })
    const computed =
      'sha256:' + createHash('sha256').update(material).digest('hex')
    assert.equal(computed, vec05.expected.session_id)
  })
})
