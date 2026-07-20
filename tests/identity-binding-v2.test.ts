// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import {
  issuePassportV2,
  verifyPassportV2,
} from '../src/v2/identity-binding/passport.js'
import {
  issuePrincipalBindingV1,
  verifyPrincipalBindingV1,
} from '../src/v2/identity-binding/principal-binding.js'
import {
  issuePrincipalBindingRevocationV1,
  verifyPrincipalBindingRevocationV1,
} from '../src/v2/identity-binding/revocation.js'
import { didKeyFromPublicKey, publicKeyFromDidKey } from '../src/v2/identity-binding/did-aps.js'

const issuedAt = '2026-07-16T18:00:00.000Z'
const expiresAt = '2026-07-19T18:00:00.000Z'

describe('PassportV2 identity and principal separation', () => {
  it('issues an immutable self-certifying did:key passport', async () => {
    const key = generateKeyPair()
    const passport = issuePassportV2({
      public_key_hex: key.publicKey,
      private_key_hex: key.privateKey,
      issued_at: issuedAt,
      expires_at: expiresAt,
      nonce: '01'.repeat(16),
      display_name: 'Procurement agent',
      capabilities: ['tools:read', 'commerce:checkout'],
    })
    assert.match(passport.agent_id, /^did:key:z6Mk/)
    assert.equal(publicKeyFromDidKey(passport.agent_id), key.publicKey)
    assert.equal('principal_id' in passport, false)
    const verified = await verifyPassportV2(passport, { now: '2026-07-17T00:00:00.000Z' })
    assert.deepEqual(verified, {
      state: 'valid', code: 'OK', proof_of_possession: true, key_authority: 'verified',
    })
  })

  it('changes the self-certifying identifier on rotation', () => {
    const first = generateKeyPair()
    const second = generateKeyPair()
    assert.notEqual(didKeyFromPublicKey(first.publicKey), didKeyFromPublicKey(second.publicKey))
  })

  it('does not upgrade proof of possession into authority for an unresolved stable DID', async () => {
    const key = generateKeyPair()
    const passport = issuePassportV2({
      public_key_hex: key.publicKey,
      private_key_hex: key.privateKey,
      agent_id: 'did:web:agent.example',
      verification_method: 'did:web:agent.example#key-2026-07',
      issued_at: issuedAt,
      expires_at: expiresAt,
      nonce: '02'.repeat(16),
    })
    const verified = await verifyPassportV2(passport, { now: '2026-07-17T00:00:00.000Z' })
    assert.equal(verified.state, 'indeterminate')
    assert.equal(verified.proof_of_possession, true)
    assert.equal(verified.key_authority, 'unresolved')
  })

  it('principal binding is a separate principal-signed, scoped record', async () => {
    const agent = generateKeyPair()
    const principal = generateKeyPair()
    const agentId = didKeyFromPublicKey(agent.publicKey)
    const principalId = didKeyFromPublicKey(principal.publicKey)
    const binding = issuePrincipalBindingV1({
      agent_id: agentId,
      principal_id: principalId,
      verification_method: `${principalId}#${principalId.slice('did:key:'.length)}`,
      audiences: ['https://mcp.example'],
      authority_profiles: ['aps-authority-delegation-v1'],
      status_uri: 'https://principal.example/aps/status/binding-1',
      issued_at: issuedAt,
      expires_at: expiresAt,
      nonce: '03'.repeat(16),
      principal_private_key_hex: principal.privateKey,
    })
    const verified = await verifyPrincipalBindingV1(binding, {
      now: '2026-07-17T00:00:00.000Z',
      resolve_key: () => ({ state: 'resolved', public_key_hex: principal.publicKey }),
    })
    assert.equal(verified.state, 'valid')
    assert.equal(verified.principal_claim_level, 'principal_attested')
    const tampered = { ...binding, agent_id: didKeyFromPublicKey(generateKeyPair().publicKey) }
    assert.equal((await verifyPrincipalBindingV1(tampered, {
      now: '2026-07-17T00:00:00.000Z',
      resolve_key: () => ({ state: 'resolved', public_key_hex: principal.publicKey }),
    })).state, 'invalid')
  })

  it('binding revocation is separately content-addressed and signed', async () => {
    const principal = generateKeyPair()
    const principalId = didKeyFromPublicKey(principal.publicKey)
    const revocation = issuePrincipalBindingRevocationV1({
      binding_id: 'ab'.repeat(32),
      principal_id: principalId,
      verification_method: `${principalId}#${principalId.slice('did:key:'.length)}`,
      revoked_at: '2026-07-17T01:00:00.000Z',
      reason_code: 'principal_request',
      nonce: '04'.repeat(16),
      principal_private_key_hex: principal.privateKey,
    })
    const verified = await verifyPrincipalBindingRevocationV1(
      revocation,
      () => ({ state: 'resolved', public_key_hex: principal.publicKey }),
    )
    assert.equal(verified.state, 'valid')
  })
})
