// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Interop: MolTrust governance attestation signal verification

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateKeyPair,
  createPassport,
  createDelegation,
  sign,
  verify,
  canonicalize,
  canonicalizeJCS,
} from '../../src/index.js'
import { createHash } from 'node:crypto'

describe('MolTrust Governance Attestation', () => {
  const gatewayKeys = generateKeyPair()
  const agentKeys = generateKeyPair()
  const principalKeys = generateKeyPair()

  const { signedPassport } = createPassport({
    agentId: 'agent-moltrust-test-001',
    agentName: 'MolTrust Test Agent',
    ownerAlias: 'aeoess',
    mission: 'MolTrust attestation interop test',
    capabilities: ['governance'],
    runtime: { platform: 'node', version: process.version },
  })

  const delegation = createDelegation({
    delegatedTo: agentKeys.publicKey,
    delegatedBy: principalKeys.publicKey,
    scope: ['governance'],
    privateKey: principalKeys.privateKey,
  })

  // Build a governance_attestation signal (matches gateway output format)
  function buildGovernanceAttestation() {
    const now = new Date()
    const delegationChainHash = createHash('sha256')
      .update(canonicalize({ delegationId: delegation.delegationId, scope: delegation.scope }))
      .digest('hex')

    const payload = {
      signal_type: 'governance_attestation',
      iss: `did:aps:gateway-test`,
      sub: signedPassport.passport.agentId,
      delegation_chain_hash: delegationChainHash,
      evaluation_timestamp: now.toISOString(),
      expires_at: new Date(now.getTime() + 300_000).toISOString(),
      active_constraints: delegation.scope,
      grade: 2,
      trust_level: 'endorsed',
    }

    const header = { alg: 'EdDSA', kid: `did:aps:gateway-test#key-1`, typ: 'JWT' }

    // JWS compact serialization (header.payload.signature)
    const headerB64 = Buffer.from(JSON.stringify(header)).toString('base64url')
    const payloadB64 = Buffer.from(canonicalizeJCS(payload)).toString('base64url')
    const signingInput = `${headerB64}.${payloadB64}`
    const sig = sign(signingInput, gatewayKeys.privateKey)

    return { header, payload, jws: `${headerB64}.${payloadB64}.${sig}`, gatewayPublicKey: gatewayKeys.publicKey }
  }

  it('JWS structure: header.alg = EdDSA, header.kid present', () => {
    const { header } = buildGovernanceAttestation()
    assert.equal(header.alg, 'EdDSA')
    assert.ok(header.kid)
    assert.ok(header.kid.includes('#'))
  })

  it('payload has required governance fields', () => {
    const { payload } = buildGovernanceAttestation()
    assert.equal(payload.signal_type, 'governance_attestation')
    assert.ok(payload.iss, 'iss present')
    assert.ok(payload.delegation_chain_hash, 'delegation_chain_hash present')
    assert.ok(payload.evaluation_timestamp, 'evaluation_timestamp present')
    assert.ok(payload.expires_at, 'expires_at present')
    assert.ok(payload.active_constraints, 'active_constraints present')
    assert.ok(Array.isArray(payload.active_constraints))
  })

  it('JWS signature verifies against gateway public key', () => {
    const { jws, gatewayPublicKey } = buildGovernanceAttestation()
    const parts = jws.split('.')
    assert.equal(parts.length, 3)
    const signingInput = `${parts[0]}.${parts[1]}`
    const sig = parts[2]
    assert.ok(verify(signingInput, sig, gatewayPublicKey))
  })

  it('delegation_chain_hash is deterministic', () => {
    const a1 = buildGovernanceAttestation()
    const a2 = buildGovernanceAttestation()
    assert.equal(a1.payload.delegation_chain_hash, a2.payload.delegation_chain_hash)
  })

  it('tampered payload fails verification', () => {
    const { jws, gatewayPublicKey } = buildGovernanceAttestation()
    const parts = jws.split('.')
    // Tamper the payload
    const tamperedPayload = Buffer.from(JSON.stringify({ signal_type: 'tampered' })).toString('base64url')
    const tamperedInput = `${parts[0]}.${tamperedPayload}`
    assert.ok(!verify(tamperedInput, parts[2], gatewayPublicKey))
  })
})
