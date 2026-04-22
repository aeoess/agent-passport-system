// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Mutual Authentication — adversarial / attack surface

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildCertificate, signCertificate, verifyCertificateSignature,
  buildAttest, verifyAttest, newNonce, chooseVersion,
  deriveSession,
  generateKeyPair,
} from '../../../src/index.js'
import type {
  MutualAuthCertificate, MutualAuthPolicy, TrustAnchor,
} from '../../../src/index.js'

const NOW = 1_745_000_000_000
const HOUR = 60 * 60 * 1000
const DAY = 24 * HOUR
const VERSIONS_12 = ['1.2', '1.1', '1.0']

function mkCert(
  role: 'agent' | 'information_system',
  subject_pk: string,
  issuer_pk: string,
  issuer_sk: string,
  versions = VERSIONS_12,
  binding = role === 'agent' ? 'agent:a' : 'mcp://api.example.com',
  attestation_grade: 0 | 1 | 2 | 3 | undefined = role === 'agent' ? 2 : undefined,
): MutualAuthCertificate {
  const u = buildCertificate(
    {
      role, subject_id: binding, subject_pubkey_hex: subject_pk,
      issuer_id: 'root', issuer_role: 'trust_anchor',
      binding, not_before: NOW - HOUR, not_after: NOW + DAY,
      supported_versions: versions, attestation_grade,
    },
    issuer_pk,
  )
  return signCertificate(u, issuer_sk)
}

function mkAnchor(pk: string): TrustAnchor {
  return {
    anchor_id: 'root', display_name: 'root', role: 'trust_anchor',
    pubkey_hex: pk, not_before: NOW - DAY, not_after: NOW + 365 * DAY,
  }
}

function policy(overrides: Partial<MutualAuthPolicy> = {}): MutualAuthPolicy {
  return {
    accepted_versions: VERSIONS_12,
    max_clock_skew_ms: 60_000,
    max_session_ms: HOUR,
    ...overrides,
  }
}

describe('mutual-auth adversarial: downgrade attack', () => {
  it('detects forced downgrade when higher version is mutually supported', () => {
    const root = generateKeyPair()
    const is = generateKeyPair()
    const cert = mkCert('information_system', is.publicKey, root.publicKey, root.privateKey, VERSIONS_12)

    // Attacker forces chosen_version=1.0 even though both sides support 1.2
    const agentNonce = newNonce()
    const isNonce = newNonce()
    const attest = buildAttest(
      {
        role: 'information_system', chosen_version: '1.0',
        own_nonce_b64: isNonce, peer_nonce_b64: agentNonce,
        certificate: cert, now_ms: NOW,
      },
      is.privateKey,
    )

    const res = verifyAttest({
      attest, expected_peer_nonce_b64: agentNonce, expected_own_nonce_b64: isNonce,
      policy: policy(), trust_anchors: [mkAnchor(root.publicKey)], now_ms: NOW,
    })
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'downgrade_detected')
  })

  it('accepts legitimate lowest-common-version when that is all both sides have', () => {
    const root = generateKeyPair()
    const is = generateKeyPair()
    // IS only supports 1.0; verifier policy supports 1.2 + 1.0
    const cert = mkCert('information_system', is.publicKey, root.publicKey, root.privateKey, ['1.0'])

    const agentNonce = newNonce()
    const isNonce = newNonce()
    const attest = buildAttest(
      {
        role: 'information_system', chosen_version: '1.0',
        own_nonce_b64: isNonce, peer_nonce_b64: agentNonce,
        certificate: cert, now_ms: NOW,
      },
      is.privateKey,
    )

    const res = verifyAttest({
      attest, expected_peer_nonce_b64: agentNonce, expected_own_nonce_b64: isNonce,
      policy: policy({ accepted_versions: VERSIONS_12 }),
      trust_anchors: [mkAnchor(root.publicKey)], now_ms: NOW,
    })
    assert.equal(res.ok, true, 'legitimate 1.0 negotiation should succeed')
  })
})

describe('mutual-auth adversarial: replay', () => {
  it('rejects nonce mismatch (peer_nonce swap)', () => {
    const root = generateKeyPair()
    const is = generateKeyPair()
    const cert = mkCert('information_system', is.publicKey, root.publicKey, root.privateKey)

    const agentNonce = newNonce()
    const isNonce = newNonce()
    const attackerNonce = newNonce()

    const attest = buildAttest(
      {
        role: 'information_system', chosen_version: '1.2',
        own_nonce_b64: isNonce, peer_nonce_b64: attackerNonce,
        certificate: cert, now_ms: NOW,
      },
      is.privateKey,
    )
    const res = verifyAttest({
      attest, expected_peer_nonce_b64: agentNonce, expected_own_nonce_b64: isNonce,
      policy: policy(), trust_anchors: [mkAnchor(root.publicKey)], now_ms: NOW,
    })
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'nonce_mismatch')
  })

  it('rejects replay after clock skew exceeded', () => {
    const root = generateKeyPair()
    const is = generateKeyPair()
    const cert = mkCert('information_system', is.publicKey, root.publicKey, root.privateKey)

    const agentNonce = newNonce()
    const isNonce = newNonce()
    const attest = buildAttest(
      {
        role: 'information_system', chosen_version: '1.2',
        own_nonce_b64: isNonce, peer_nonce_b64: agentNonce,
        certificate: cert,
        now_ms: NOW - 2 * HOUR, // captured 2 hours ago
      },
      is.privateKey,
    )
    const res = verifyAttest({
      attest, expected_peer_nonce_b64: agentNonce, expected_own_nonce_b64: isNonce,
      policy: policy(), trust_anchors: [mkAnchor(root.publicKey)], now_ms: NOW,
    })
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'replay_detected')
  })
})

describe('mutual-auth adversarial: MITM certificate swap', () => {
  it('rejects attest with forged peer certificate (wrong issuer)', () => {
    const root = generateKeyPair()
    const rogue = generateKeyPair()
    const is = generateKeyPair()
    const rogueCert = mkCert('information_system', is.publicKey, rogue.publicKey, rogue.privateKey)

    const agentNonce = newNonce()
    const isNonce = newNonce()
    const attest = buildAttest(
      {
        role: 'information_system', chosen_version: '1.2',
        own_nonce_b64: isNonce, peer_nonce_b64: agentNonce,
        certificate: rogueCert, now_ms: NOW,
      },
      is.privateKey,
    )
    const res = verifyAttest({
      attest, expected_peer_nonce_b64: agentNonce, expected_own_nonce_b64: isNonce,
      policy: policy(), trust_anchors: [mkAnchor(root.publicKey)], now_ms: NOW,
    })
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'unknown_issuer')
  })

  it('rejects attest signed by a different key than the certificate subject', () => {
    const root = generateKeyPair()
    const realIs = generateKeyPair()
    const attacker = generateKeyPair()
    const realCert = mkCert('information_system', realIs.publicKey, root.publicKey, root.privateKey)

    const agentNonce = newNonce()
    const isNonce = newNonce()
    // Attacker signs with their key, but the cert says realIs is the subject
    const attest = buildAttest(
      {
        role: 'information_system', chosen_version: '1.2',
        own_nonce_b64: isNonce, peer_nonce_b64: agentNonce,
        certificate: realCert, now_ms: NOW,
      },
      attacker.privateKey,
    )
    const res = verifyAttest({
      attest, expected_peer_nonce_b64: agentNonce, expected_own_nonce_b64: isNonce,
      policy: policy(), trust_anchors: [mkAnchor(root.publicKey)], now_ms: NOW,
    })
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'signature_invalid')
    assert.equal(res.detail, 'attest')
  })
})

describe('mutual-auth adversarial: revocation + expiry', () => {
  it('rejects cert from revoked anchor', () => {
    const root = generateKeyPair()
    const is = generateKeyPair()
    const cert = mkCert('information_system', is.publicKey, root.publicKey, root.privateKey)

    const agentNonce = newNonce()
    const isNonce = newNonce()
    const attest = buildAttest(
      {
        role: 'information_system', chosen_version: '1.2',
        own_nonce_b64: isNonce, peer_nonce_b64: agentNonce,
        certificate: cert, now_ms: NOW,
      },
      is.privateKey,
    )
    const res = verifyAttest({
      attest, expected_peer_nonce_b64: agentNonce, expected_own_nonce_b64: isNonce,
      policy: policy(), trust_anchors: [mkAnchor(root.publicKey)],
      revoked_anchor_ids: ['root'], now_ms: NOW,
    })
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'revoked_anchor')
  })

  it('rejects expired certificate', () => {
    const root = generateKeyPair()
    const is = generateKeyPair()
    const u = buildCertificate(
      {
        role: 'information_system', subject_id: 'mcp://x', subject_pubkey_hex: is.publicKey,
        issuer_id: 'root', issuer_role: 'trust_anchor',
        binding: 'mcp://x',
        not_before: NOW - 2 * DAY, not_after: NOW - HOUR, // already expired
        supported_versions: VERSIONS_12,
      },
      root.publicKey,
    )
    const cert = signCertificate(u, root.privateKey)
    const agentNonce = newNonce()
    const isNonce = newNonce()
    const attest = buildAttest(
      {
        role: 'information_system', chosen_version: '1.2',
        own_nonce_b64: isNonce, peer_nonce_b64: agentNonce,
        certificate: cert, now_ms: NOW,
      },
      is.privateKey,
    )
    const res = verifyAttest({
      attest, expected_peer_nonce_b64: agentNonce, expected_own_nonce_b64: isNonce,
      policy: policy(), trust_anchors: [mkAnchor(root.publicKey)], now_ms: NOW,
    })
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'expired_certificate')
  })
})

describe('mutual-auth adversarial: grade + capability policy', () => {
  it('rejects agent cert with insufficient attestation grade', () => {
    const root = generateKeyPair()
    const agent = generateKeyPair()
    const cert = mkCert('agent', agent.publicKey, root.publicKey, root.privateKey, VERSIONS_12, 'agent:x', 1)

    const agentNonce = newNonce()
    const isNonce = newNonce()
    const attest = buildAttest(
      {
        role: 'agent', chosen_version: '1.2',
        own_nonce_b64: agentNonce, peer_nonce_b64: isNonce,
        certificate: cert, now_ms: NOW,
      },
      agent.privateKey,
    )
    const res = verifyAttest({
      attest, expected_peer_nonce_b64: isNonce, expected_own_nonce_b64: agentNonce,
      policy: policy({ min_agent_grade: 3 }),
      trust_anchors: [mkAnchor(root.publicKey)], now_ms: NOW,
    })
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'grade_insufficient')
  })

  it('rejects peer cert missing required capability', () => {
    const root = generateKeyPair()
    const agent = generateKeyPair()
    const u = buildCertificate(
      {
        role: 'agent', subject_id: 'agent:x', subject_pubkey_hex: agent.publicKey,
        issuer_id: 'root', issuer_role: 'trust_anchor',
        binding: 'agent:x',
        not_before: NOW - HOUR, not_after: NOW + DAY,
        supported_versions: VERSIONS_12, attestation_grade: 2,
        capabilities: ['mcp:read'],
      },
      root.publicKey,
    )
    const cert = signCertificate(u, root.privateKey)

    const agentNonce = newNonce()
    const isNonce = newNonce()
    const attest = buildAttest(
      {
        role: 'agent', chosen_version: '1.2',
        own_nonce_b64: agentNonce, peer_nonce_b64: isNonce,
        certificate: cert, now_ms: NOW,
      },
      agent.privateKey,
    )
    const res = verifyAttest({
      attest, expected_peer_nonce_b64: isNonce, expected_own_nonce_b64: agentNonce,
      policy: policy({ required_capabilities: ['mcp:write'] }),
      trust_anchors: [mkAnchor(root.publicKey)], now_ms: NOW,
    })
    assert.equal(res.ok, false)
    assert.equal(res.detail, 'missing_capability:mcp:write')
  })
})

describe('mutual-auth adversarial: role misuse in session derivation', () => {
  it('rejects session derivation with swapped roles', () => {
    const root = generateKeyPair()
    const agent = generateKeyPair()
    const is = generateKeyPair()
    const agentCert = mkCert('agent', agent.publicKey, root.publicKey, root.privateKey)
    const isCert = mkCert('information_system', is.publicKey, root.publicKey, root.privateKey)

    const agentNonce = newNonce()
    const isNonce = newNonce()

    // Build both attests correctly
    const agentAttest = buildAttest(
      {
        role: 'agent', chosen_version: '1.2',
        own_nonce_b64: agentNonce, peer_nonce_b64: isNonce,
        certificate: agentCert, now_ms: NOW,
      },
      agent.privateKey,
    )
    const isAttest = buildAttest(
      {
        role: 'information_system', chosen_version: '1.2',
        own_nonce_b64: isNonce, peer_nonce_b64: agentNonce,
        certificate: isCert, now_ms: NOW,
      },
      is.privateKey,
    )

    // Call deriveSession with args swapped (pretending is_attest is agent_attest)
    const swapped = deriveSession(isAttest, agentAttest, policy(), NOW)
    assert.equal(swapped.ok, false)
    assert.equal(swapped.failure?.reason, 'binding_mismatch')
  })
})
