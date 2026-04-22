// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Mutual Authentication — happy-path + invariants

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildCertificate,
  signCertificate,
  certificateId,
  verifyCertificateSignature,
  isCertificateTemporallyValid,
  checkAnchor,
  buildBundle,
  signBundle,
  verifyBundle,
  newNonce,
  buildHello,
  chooseVersion,
  buildAttest,
  verifyAttest,
  deriveSession,
  isSessionActive,
  generateKeyPair,
} from '../../../src/index.js'
import type {
  MutualAuthCertificate,
  MutualAuthPolicy,
  TrustAnchor,
} from '../../../src/index.js'

// ── Fixture helpers ──

const VERSIONS = ['1.0']
const NOW = 1_745_000_000_000 // stable base timestamp (ms)
const HOUR = 60 * 60 * 1000
const DAY = 24 * HOUR

function makeAnchor(kid: string, pk_hex: string, role: 'agent' | 'information_system' | 'trust_anchor' = 'trust_anchor'): TrustAnchor {
  return {
    anchor_id: kid,
    display_name: kid,
    role,
    pubkey_hex: pk_hex,
    not_before: NOW - DAY,
    not_after: NOW + 365 * DAY,
  }
}

function buildPolicy(overrides: Partial<MutualAuthPolicy> = {}): MutualAuthPolicy {
  return {
    accepted_versions: VERSIONS,
    max_clock_skew_ms: 60_000,
    max_session_ms: HOUR,
    ...overrides,
  }
}

function makeAgentCert(
  agent_pk: string,
  issuer_pk: string,
  issuer_sk: string,
  binding = 'agent:alpha-1',
): MutualAuthCertificate {
  const unsigned = buildCertificate(
    {
      role: 'agent',
      subject_id: binding,
      subject_pubkey_hex: agent_pk,
      issuer_id: 'root-agent-issuer',
      issuer_role: 'trust_anchor',
      binding,
      not_before: NOW - HOUR,
      not_after: NOW + 30 * DAY,
      supported_versions: VERSIONS,
      attestation_grade: 2,
      capabilities: ['mcp:read', 'mcp:write'],
    },
    issuer_pk,
  )
  return signCertificate(unsigned, issuer_sk)
}

function makeISCert(
  is_pk: string,
  issuer_pk: string,
  issuer_sk: string,
  binding = 'mcp://api.example.com',
): MutualAuthCertificate {
  const unsigned = buildCertificate(
    {
      role: 'information_system',
      subject_id: binding,
      subject_pubkey_hex: is_pk,
      issuer_id: 'root-is-issuer',
      issuer_role: 'trust_anchor',
      binding,
      not_before: NOW - HOUR,
      not_after: NOW + 30 * DAY,
      supported_versions: VERSIONS,
    },
    issuer_pk,
  )
  return signCertificate(unsigned, issuer_sk)
}

// ── Tests ──

describe('mutual-auth: certificate primitives', () => {
  it('signs and verifies a valid certificate', () => {
    const root = generateKeyPair()
    const agent = generateKeyPair()
    const cert = makeAgentCert(agent.publicKey, root.publicKey, root.privateKey)
    const res = verifyCertificateSignature(cert)
    assert.equal(res.ok, true)
  })

  it('rejects tampered binding', () => {
    const root = generateKeyPair()
    const agent = generateKeyPair()
    const cert = makeAgentCert(agent.publicKey, root.publicKey, root.privateKey)
    const tampered = { ...cert, binding: 'agent:attacker' }
    const res = verifyCertificateSignature(tampered)
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'signature_invalid')
  })

  it('rejects certificate with empty supported_versions', () => {
    const root = generateKeyPair()
    const agent = generateKeyPair()
    const cert = makeAgentCert(agent.publicKey, root.publicKey, root.privateKey)
    const bad = { ...cert, supported_versions: [] }
    const res = verifyCertificateSignature(bad)
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'version_empty')
  })

  it('detects temporal validity', () => {
    const root = generateKeyPair()
    const agent = generateKeyPair()
    const cert = makeAgentCert(agent.publicKey, root.publicKey, root.privateKey)

    const nowOk = isCertificateTemporallyValid(cert, NOW)
    assert.equal(nowOk.ok, true)

    const past = isCertificateTemporallyValid(cert, cert.not_before - 1)
    assert.equal(past.ok, false)
    assert.equal(past.reason, 'not_yet_valid')

    const future = isCertificateTemporallyValid(cert, cert.not_after + 1)
    assert.equal(future.ok, false)
    assert.equal(future.reason, 'expired')
  })

  it('certificateId is stable under signature change', () => {
    const root = generateKeyPair()
    const agent = generateKeyPair()
    const cert = makeAgentCert(agent.publicKey, root.publicKey, root.privateKey)
    const id1 = certificateId(cert)
    const resigned = { ...cert, signature_b64: 'AAAA' + cert.signature_b64.slice(4) }
    const id2 = certificateId(resigned)
    assert.equal(id1, id2, 'id must ignore the signature')
  })

  it('checkAnchor enforces binding constraints', () => {
    const root = generateKeyPair()
    const is = generateKeyPair()
    const cert = makeISCert(is.publicKey, root.publicKey, root.privateKey, 'mcp://api.example.com')
    const anchorGlob = makeAnchor('root', root.publicKey)
    anchorGlob.binding_constraints = ['mcp://api.example.com']
    const okRes = checkAnchor(cert, [anchorGlob])
    assert.equal(okRes.ok, true)

    const anchorWrong = makeAnchor('root', root.publicKey)
    anchorWrong.binding_constraints = ['mcp://api.other.com']
    const badRes = checkAnchor(cert, [anchorWrong])
    assert.equal(badRes.ok, false)
    assert.equal(badRes.reason, 'binding_mismatch')
  })

  it('checkAnchor honours revocation', () => {
    const root = generateKeyPair()
    const is = generateKeyPair()
    const cert = makeISCert(is.publicKey, root.publicKey, root.privateKey)
    const anchor = makeAnchor('root', root.publicKey)
    const res = checkAnchor(cert, [anchor], ['root'])
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'revoked_anchor')
  })

  it('checkAnchor rejects unknown issuer', () => {
    const root = generateKeyPair()
    const other = generateKeyPair()
    const is = generateKeyPair()
    const cert = makeISCert(is.publicKey, root.publicKey, root.privateKey)
    const anchor = makeAnchor('other', other.publicKey)
    const res = checkAnchor(cert, [anchor])
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'unknown_issuer')
  })
})

describe('mutual-auth: trust anchor bundle', () => {
  it('signs and verifies a bundle', () => {
    const publisher = generateKeyPair()
    const root = generateKeyPair()
    const unsigned = buildBundle(
      {
        bundle_id: 'test-2026-04-22',
        anchors: [makeAnchor('root', root.publicKey)],
        issued_at: NOW,
        refresh_after: NOW + 7 * DAY,
      },
      publisher.publicKey,
    )
    const bundle = signBundle(unsigned, publisher.privateKey)
    const res = verifyBundle(bundle, [publisher.publicKey], NOW + HOUR)
    assert.equal(res.ok, true)
  })

  it('rejects untrusted publisher', () => {
    const publisher = generateKeyPair()
    const rogue = generateKeyPair()
    const unsigned = buildBundle(
      { bundle_id: 'b', anchors: [], issued_at: NOW, refresh_after: NOW + DAY },
      publisher.publicKey,
    )
    const bundle = signBundle(unsigned, publisher.privateKey)
    const res = verifyBundle(bundle, [rogue.publicKey], NOW)
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'untrusted_publisher')
  })

  it('rejects expired bundle', () => {
    const publisher = generateKeyPair()
    const unsigned = buildBundle(
      { bundle_id: 'b', anchors: [], issued_at: NOW - DAY, refresh_after: NOW - HOUR },
      publisher.publicKey,
    )
    const bundle = signBundle(unsigned, publisher.privateKey)
    const res = verifyBundle(bundle, [publisher.publicKey], NOW)
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'bundle_expired')
  })

  it('detects tampered anchors list (signature_invalid)', () => {
    const publisher = generateKeyPair()
    const root = generateKeyPair()
    const rogue = generateKeyPair()
    const unsigned = buildBundle(
      {
        bundle_id: 'b',
        anchors: [makeAnchor('root', root.publicKey)],
        issued_at: NOW,
        refresh_after: NOW + DAY,
      },
      publisher.publicKey,
    )
    const bundle = signBundle(unsigned, publisher.privateKey)
    // Swap in a rogue anchor without resigning
    const tampered = { ...bundle, anchors: [makeAnchor('root', rogue.publicKey)] }
    const res = verifyBundle(tampered, [publisher.publicKey], NOW)
    assert.equal(res.ok, false)
    assert.equal(res.reason, 'signature_invalid')
  })
})

describe('mutual-auth: handshake', () => {
  function scenario() {
    const root = generateKeyPair()
    const agent = generateKeyPair()
    const is = generateKeyPair()
    const agentCert = makeAgentCert(agent.publicKey, root.publicKey, root.privateKey)
    const isCert = makeISCert(is.publicKey, root.publicKey, root.privateKey)
    const anchor = makeAnchor('root', root.publicKey)
    const policy = buildPolicy()
    return { root, agent, is, agentCert, isCert, anchor, policy }
  }

  it('completes full four-step handshake', () => {
    const s = scenario()
    const agentNonce = newNonce()
    const isNonce = newNonce()

    // Agent -> IS: hello
    const hello = buildHello('agent', s.agentCert.supported_versions, NOW, agentNonce)
    const chosen = chooseVersion(hello.supported_versions, s.policy.accepted_versions)
    assert.equal(chosen, '1.0')

    // IS -> Agent: attest
    const isAttest = buildAttest(
      {
        role: 'information_system',
        chosen_version: chosen!,
        own_nonce_b64: isNonce,
        peer_nonce_b64: agentNonce,
        certificate: s.isCert,
        now_ms: NOW,
      },
      s.is.privateKey,
    )

    // Agent verifies IS attest
    const isVerify = verifyAttest({
      attest: isAttest,
      expected_peer_nonce_b64: agentNonce,
      expected_own_nonce_b64: isNonce,
      policy: s.policy,
      trust_anchors: [s.anchor],
      now_ms: NOW,
    })
    assert.equal(isVerify.ok, true)

    // Agent -> IS: counter-attest
    const agentAttest = buildAttest(
      {
        role: 'agent',
        chosen_version: chosen!,
        own_nonce_b64: agentNonce,
        peer_nonce_b64: isNonce,
        certificate: s.agentCert,
        now_ms: NOW,
      },
      s.agent.privateKey,
    )

    // IS verifies agent attest
    const agentVerify = verifyAttest({
      attest: agentAttest,
      expected_peer_nonce_b64: isNonce,
      expected_own_nonce_b64: agentNonce,
      policy: s.policy,
      trust_anchors: [s.anchor],
      now_ms: NOW,
    })
    assert.equal(agentVerify.ok, true)

    // Derive shared session
    const sess = deriveSession(agentAttest, isAttest, s.policy, NOW)
    assert.equal(sess.ok, true)
    assert.ok(sess.session)
    assert.ok(sess.session!.session_id.startsWith('sha256:'))
    assert.equal(sess.session!.chosen_version, '1.0')
    assert.equal(sess.session!.agent_nonce_b64, agentNonce)
    assert.equal(sess.session!.is_nonce_b64, isNonce)
    assert.ok(isSessionActive(sess.session!, NOW))
    assert.ok(!isSessionActive(sess.session!, sess.session!.expires_at + 1))
  })

  it('produces identical session_id on both sides', () => {
    const s = scenario()
    const agentNonce = newNonce()
    const isNonce = newNonce()
    const chosen = '1.0'

    const agentAttest = buildAttest(
      {
        role: 'agent',
        chosen_version: chosen,
        own_nonce_b64: agentNonce,
        peer_nonce_b64: isNonce,
        certificate: s.agentCert,
        now_ms: NOW,
      },
      s.agent.privateKey,
    )
    const isAttest = buildAttest(
      {
        role: 'information_system',
        chosen_version: chosen,
        own_nonce_b64: isNonce,
        peer_nonce_b64: agentNonce,
        certificate: s.isCert,
        now_ms: NOW,
      },
      s.is.privateKey,
    )

    const a = deriveSession(agentAttest, isAttest, s.policy, NOW)
    const b = deriveSession(agentAttest, isAttest, s.policy, NOW)
    assert.equal(a.session!.session_id, b.session!.session_id)
  })
})
