// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair } from '../src/crypto/keys.js'
import { didKeyFromPublicKey } from '../src/v2/identity-binding/did-aps.js'
import {
  computeIdJagGrantRefV1,
  createIdJagActorBindingSignatureV1,
  createIdJagImportV1,
  verifyIdJagImportV1,
} from '../src/adapters/oauth-id-jag/import-v1.js'

function compact(header: Record<string, unknown>, claims: Record<string, unknown>): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url')
  return `${encode(header)}.${encode(claims)}.${Buffer.from('external-signature').toString('base64url')}`
}

describe('OAuth ID-JAG exact-grant import profile', () => {
  it('keeps grant, verification decision, and delegation root as separate commitments', async () => {
    const agent = generateKeyPair()
    const importer = generateKeyPair()
    const agentId = didKeyFromPublicKey(agent.publicKey)
    const importerId = didKeyFromPublicKey(importer.publicKey)
    const claims = {
      iss: 'https://issuer.example',
      sub: 'principal-123',
      aud: 'https://resource.example',
      client_id: 'oauth-client-7',
      jti: 'grant-1',
      exp: 1780000000,
      iat: 1779990000,
      scope: 'read write',
    }
    const compactJws = compact({ alg: 'EdDSA', kid: 'issuer-key-1' }, claims)
    const grantRef = computeIdJagGrantRefV1(compactJws)
    const agentMethod = `${agentId}#${agentId.slice('did:key:'.length)}`
    const binding = {
      method: 'dual_signature' as const,
      agent_id: agentId,
      verification_method: agentMethod,
      signature: createIdJagActorBindingSignatureV1(grantRef, agentId, agentMethod, agent.privateKey),
    }
    const grant = {
      compact_jws: compactJws,
      claims,
      verification: {
        status: 'verified' as const,
        verified_by: importerId,
        verification_method: `${importerId}#${importerId.slice('did:key:'.length)}`,
        grant_key_id: 'issuer-key-1',
        verified_at: '2026-07-17T01:00:00.000Z',
      },
    }
    const record = await createIdJagImportV1({
      grant,
      delegation_chain_root: 'ab'.repeat(32),
      agent_binding: binding,
      importer_private_key_hex: importer.privateKey,
      issued_at: '2026-07-17T01:00:01.000Z',
      resolve_agent_key: () => ({ state: 'resolved', public_key_hex: agent.publicKey }),
    })
    assert.equal(record.grant_ref, grantRef)
    assert.notEqual(record.grant_ref, record.grant_decision_ref)
    assert.notEqual(record.grant_ref, record.delegation_chain_root)
    assert.equal(record.subject, 'principal-123')
    assert.equal(record.client_id, 'oauth-client-7')
    assert.equal(record.agent_id, agentId)

    const verified = await verifyIdJagImportV1(record, { compact_jws: compactJws, claims }, {
      resolve_importer_key: () => ({ state: 'resolved', public_key_hex: importer.publicKey }),
      resolve_agent_key: () => ({ state: 'resolved', public_key_hex: agent.publicKey }),
    })
    assert.deepEqual(verified, {
      state: 'valid', code: 'OK', grant_bytes: 'matched',
      importer_signature: 'verified', actor_binding: 'verified',
    })
  })

  it('grant_ref commits to exact compact JWS bytes', () => {
    const claims = { iss: 'i', sub: 's', aud: 'a', client_id: 'c', jti: 'j', exp: 2, iat: 1 }
    const first = compact({ alg: 'EdDSA', kid: 'k1' }, claims)
    const second = compact({ kid: 'k1', alg: 'EdDSA' }, claims)
    assert.notEqual(first, second)
    assert.notEqual(computeIdJagGrantRefV1(first), computeIdJagGrantRefV1(second))
  })
})
