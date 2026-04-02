import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateApsTxt,
  enforceApsTxt,
} from '../src/core/aps-txt.ts'
import {
  generateGovernanceBlock,
  bindGovernanceToImplementation,
  verifyGovernanceBinding,
} from '../src/core/governance-block.ts'
import { generateKeyPair } from '../src/crypto/keys.ts'
import { createHash } from 'node:crypto'

const publisher = generateKeyPair()
const attacker = generateKeyPair()

function makeApsTxt(overrides?: Record<string, unknown>) {
  return generateApsTxt({
    domain: 'example.com',
    publisherName: 'Test Publisher',
    publicKey: publisher.publicKey,
    privateKey: publisher.privateKey,
    defaultTerms: {
      inference: 'permitted',
      training: 'prohibited',
      redistribution: 'attribution_required',
    },
    ...overrides,
  })
}

describe('Security: MoltyCel AV-2 through AV-5 (qntm#7)', () => {

  // ── AV-2: aps.txt Manipulation — strict mode blocks unsigned ──
  describe('AV-2: aps.txt signature enforcement', () => {
    it('strict mode blocks when signature cannot be verified', () => {
      const doc = makeApsTxt()
      const result = enforceApsTxt(doc, '/api/data', {
        publisherPublicKey: attacker.publicKey, // wrong key
        mode: 'strict',
      })
      assert.equal(result.allowed, false)
      assert.equal(result.signatureVerified, false)
      assert.ok(result.error?.includes('strict mode'))
    })

    it('strict mode allows when signature is valid', () => {
      const doc = makeApsTxt()
      const result = enforceApsTxt(doc, '/api/data', {
        publisherPublicKey: publisher.publicKey,
        mode: 'strict',
      })
      assert.equal(result.allowed, true)
      assert.equal(result.signatureVerified, true)
      assert.equal(result.error, undefined)
    })

    it('warn mode allows but warns on invalid signature', () => {
      const doc = makeApsTxt()
      const result = enforceApsTxt(doc, '/api/data', {
        publisherPublicKey: attacker.publicKey,
        mode: 'warn',
      })
      assert.equal(result.allowed, true)
      assert.equal(result.signatureVerified, false)
      assert.ok(result.warning)
    })

    it('permissive mode allows without checking signature', () => {
      const doc = makeApsTxt()
      const result = enforceApsTxt(doc, '/api/data', {
        mode: 'permissive',
      })
      assert.equal(result.allowed, true)
    })
  })
