import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  generateApsTxt,
  verifyApsTxt,
  enforceApsTxt,
  evaluateApsTxtRisk,
} from '../src/core/aps-txt.ts'
import {
  generateGovernanceBlock,
  verifyGovernanceBlock,
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

  // ── AV-2: verifyApsTxt strict option ──
  describe('AV-2: verifyApsTxt strict mode', () => {
    it('strict mode rejects unsigned aps.txt (no public key)', () => {
      const doc = makeApsTxt()
      const result = verifyApsTxt(doc, undefined, { strict: true })
      assert.equal(result.valid, false)
      assert.equal(result.reason, 'UNSIGNED')
    })

    it('strict mode rejects when signature fails', () => {
      const doc = makeApsTxt()
      const result = verifyApsTxt(doc, attacker.publicKey, { strict: true })
      assert.equal(result.valid, false)
      assert.equal(result.reason, 'UNSIGNED')
    })

    it('strict mode accepts valid signature', () => {
      const doc = makeApsTxt()
      const result = verifyApsTxt(doc, publisher.publicKey, { strict: true })
      assert.equal(result.valid, true)
      assert.equal(result.reason, undefined)
    })

    it('default mode accepts unsigned (backward compat)', () => {
      const doc = makeApsTxt()
      const result = verifyApsTxt(doc)
      assert.equal(result.valid, true)
    })
  })

  // ── AV-4: aps.txt DoS Risk Evaluation ──
  describe('AV-4: aps.txt DoS defense', () => {
    it('blanket block on default terms → high risk', () => {
      const doc = makeApsTxt({
        defaultTerms: {
          inference: 'prohibited',
          training: 'prohibited',
          redistribution: 'prohibited',
          derivative: 'prohibited',
          caching: 'prohibited',
        },
      })
      const result = evaluateApsTxtRisk(doc)
      assert.equal(result.risk, 'high')
      assert.ok(result.warnings.includes('blanket_block'))
    })

    it('blanket block via wildcard path override → high risk', () => {
      const doc = makeApsTxt({
        pathOverrides: [{
          pattern: '/**',
          user_agent: 'did:*',
          terms: {
            inference: 'prohibited',
            training: 'prohibited',
            redistribution: 'prohibited',
            derivative: 'prohibited',
            caching: 'prohibited',
          },
        }],
      })
      const result = evaluateApsTxtRisk(doc)
      assert.equal(result.risk, 'high')
      assert.ok(result.warnings.includes('blanket_block'))
    })

    it('unsigned restrictive → medium risk', () => {
      const doc = makeApsTxt({
        defaultTerms: {
          inference: 'prohibited',
          training: 'prohibited',
          redistribution: 'prohibited',
          derivative: 'prohibited',
          caching: 'prohibited',
        },
      })
      // No public key = unsigned
      const result = evaluateApsTxtRisk(doc)
      assert.ok(result.warnings.includes('unsigned_restrictive'))
    })

    it('signed restrictive → low risk', () => {
      const doc = makeApsTxt()
      const result = evaluateApsTxtRisk(doc, { publisherPublicKey: publisher.publicKey })
      assert.equal(result.risk, 'low')
      assert.equal(result.warnings.length, 0)
    })

    it('unknown author with restrictions → medium risk', () => {
      const doc = makeApsTxt({ publisherName: '' })
      const result = evaluateApsTxtRisk(doc, { publisherPublicKey: publisher.publicKey })
      assert.ok(result.risk === 'medium' || result.risk === 'high')
      assert.ok(result.warnings.includes('new_author_restrictive'))
    })
  })

  // ── AV-5: Governance Block ↔ Skill Binding via skillHash ──
  describe('AV-5: GovernanceBlock skillHash binding', () => {
    const skillCode = 'export function mySkill() { return "hello" }'
    const differentCode = 'export function evilSkill() { return "pwned" }'

    it('block with correct skillHash verifies', () => {
      const block = generateGovernanceBlock({
        content: 'some article',
        publicKey: publisher.publicKey,
        privateKey: publisher.privateKey,
        terms: { inference: 'permitted' },
        skillContent: skillCode,
      })
      assert.ok(block.skill_hash)
      assert.ok(block.skill_hash!.startsWith('sha256:'))
      const result = verifyGovernanceBlock(block, 'some article', publisher.publicKey, {
        skillContent: skillCode,
      })
      assert.equal(result.valid, true)
    })

    it('block with wrong skillHash fails verification', () => {
      const block = generateGovernanceBlock({
        content: 'some article',
        publicKey: publisher.publicKey,
        privateKey: publisher.privateKey,
        terms: { inference: 'permitted' },
        skillContent: skillCode,
      })
      const result = verifyGovernanceBlock(block, 'some article', publisher.publicKey, {
        skillContent: differentCode,
      })
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('Skill hash mismatch')))
    })

    it('block without skillHash is valid (backward compat)', () => {
      const block = generateGovernanceBlock({
        content: 'some article',
        publicKey: publisher.publicKey,
        privateKey: publisher.privateKey,
        terms: { inference: 'permitted' },
      })
      assert.equal(block.skill_hash, undefined)
      const result = verifyGovernanceBlock(block, 'some article', publisher.publicKey)
      assert.equal(result.valid, true)
    })

    it('skillContent provided but block has no skill_hash → invalid', () => {
      const block = generateGovernanceBlock({
        content: 'some article',
        publicKey: publisher.publicKey,
        privateKey: publisher.privateKey,
        terms: { inference: 'permitted' },
        // no skillContent
      })
      const result = verifyGovernanceBlock(block, 'some article', publisher.publicKey, {
        skillContent: skillCode,
      })
      assert.equal(result.valid, false)
      assert.ok(result.errors.some(e => e.includes('no skill_hash')))
    })
  })
})
