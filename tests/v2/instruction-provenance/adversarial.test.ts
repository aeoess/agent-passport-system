// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// IPR — adversarial tests against fixture-vector negatives + spec §9 surfaces.

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  IPRConstructionError,
  IPRPathError,
  canonicalizePath,
  canonicalizeEnvelope,
  createInstructionProvenanceReceipt,
  matchesAnyPattern,
  sha256Hex,
  verifyInstructionProvenanceReceipt,
} from '../../../src/v2/instruction-provenance/index.js'
import type {
  CreateIPRInput,
  InstructionProvenanceReceipt,
} from '../../../src/v2/instruction-provenance/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = join(__dirname, '..', '..', '..', 'fixtures', 'instruction-provenance', 'canonicalize-fixture-v1.json')

interface FixtureFile {
  keypair: { publicKeyHex: string }
  vectors: Array<{
    name: string
    expected_verification: boolean
    rejection_kind?: 'construction' | 'verification' | 'canonicalization'
    expected_error_code?: string
    envelope?: InstructionProvenanceReceipt
    canonicalize_input?: { raw: string; workingRoot: string; filesystemMode: 'case-sensitive' | 'case-insensitive' }
  }>
}

const fixture: FixtureFile = JSON.parse(readFileSync(FIXTURE_PATH, 'utf8'))
const PUBKEY = fixture.keypair.publicKeyHex
const NEGATIVES = fixture.vectors.filter(v => v.expected_verification === false)

const FIXED_DELEGATION_ROOT = sha256Hex('demo-delegation-chain-root')
// Re-derive the deterministic fixture private key so signatures match.
const PRIVATE_KEY = createHash('sha256').update('aps-instruction-provenance-fixture-v1', 'utf8').digest().toString('hex')

function baseInput(overrides: Partial<CreateIPRInput> = {}): CreateIPRInput {
  return {
    delegation_chain_root: FIXED_DELEGATION_ROOT,
    agent_did: 'did:key:zIPRfixtureAgentV1',
    discovery_patterns: ['./CLAUDE.md'],
    working_root: '/Users/agent/workspace',
    filesystem_mode: 'case-sensitive',
    instruction_files: [{
      path: 'CLAUDE.md',
      digest: sha256Hex('content'),
      bytes: 7,
      role: 'agent_md',
    }],
    issued_at: '2026-04-26T00:00:00.000Z',
    bound_to: { type: 'session', ref: 'sess_test_001' },
    privateKeyHex: PRIVATE_KEY,
    publicKeyHex: PUBKEY,
    ...overrides,
  }
}

// ─── Fixture-vector negative coverage ──────────────────────────────

describe('IPR adversarial — fixture negatives', () => {
  it('expected-rejection-witnessed-tier: verifier rejects tier=witnessed', () => {
    const v = NEGATIVES.find(n => n.name === 'expected-rejection-witnessed-tier')!
    const r = verifyInstructionProvenanceReceipt({ envelope: v.envelope!, publicKeyHex: PUBKEY })
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => /reserved for v0\.3/.test(e)), `expected tier-reserved error; got ${r.errors.join('; ')}`)
  })

  it('expected-rejection-omitted-file: verifier rejects when filesystem walk finds an undeclared match', () => {
    const v = NEGATIVES.find(n => n.name === 'expected-rejection-omitted-file')!
    // Synthesize a temp working root that has BOTH CLAUDE.md and MEMORY.md so
    // the discovery_patterns ['./*.md'] walk finds both, but the envelope
    // declares only CLAUDE.md.
    const tmp = mkdtempSync(join(tmpdir(), 'ipr-omit-'))
    writeFileSync(join(tmp, 'CLAUDE.md'), 'only one')
    writeFileSync(join(tmp, 'MEMORY.md'), 'second file')
    try {
      // Re-issue under tmp working_root with envelope-style file list (just CLAUDE.md).
      const env = createInstructionProvenanceReceipt(baseInput({
        working_root: tmp,
        discovery_patterns: ['./*.md'],
        instruction_files: [{
          path: 'CLAUDE.md',
          digest: sha256Hex('only one'),
          bytes: 8,
          role: 'agent_md',
        }],
      }))
      const r = verifyInstructionProvenanceReceipt({ envelope: env, publicKeyHex: PUBKEY, filesystemCheck: true })
      assert.equal(r.valid, false)
      assert.ok(r.errors.some(e => /omission detected/.test(e)), `expected omission error; got ${r.errors.join('; ')}`)
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
    // Sanity: the fixture envelope itself (without filesystem check) is signature-valid.
    void v
  })

  it('expected-rejection-smuggled-path: verifier rejects path matching no pattern', () => {
    const v = NEGATIVES.find(n => n.name === 'expected-rejection-smuggled-path')!
    const r = verifyInstructionProvenanceReceipt({ envelope: v.envelope!, publicKeyHex: PUBKEY })
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => /path smuggling/.test(e)), `expected smuggling error; got ${r.errors.join('; ')}`)
  })

  it('expected-rejection-trailing-slash: canonicalizePath throws TRAILING_SLASH', () => {
    const v = NEGATIVES.find(n => n.name === 'expected-rejection-trailing-slash')!
    assert.throws(
      () => canonicalizePath(v.canonicalize_input!.raw, {
        workingRoot: v.canonicalize_input!.workingRoot,
        filesystemMode: v.canonicalize_input!.filesystemMode,
      }),
      (e: unknown) => e instanceof IPRPathError && e.code === 'TRAILING_SLASH',
    )
  })
})

// ─── Spec §9 attack surface coverage ──────────────────────────────

describe('IPR adversarial — spec §9 surfaces', () => {
  it('§9.1 self-attestation: tier MUST lock to self-asserted at construction time', () => {
    assert.throws(
      () => createInstructionProvenanceReceipt({ ...baseInput(), attestation_tier: 'witnessed' as never }),
      (e: unknown) => e instanceof IPRConstructionError && e.code === 'TIER_RESERVED',
    )
  })

  it('§9.3 path canonicalization: rejects "..":', () => {
    assert.throws(
      () => canonicalizePath('foo/../etc/passwd', { workingRoot: '/r', filesystemMode: 'case-sensitive' }),
      (e: unknown) => e instanceof IPRPathError && e.code === 'TRAVERSAL',
    )
  })

  it('§9.3 path canonicalization: rejects percent-encoded paths', () => {
    assert.throws(
      () => canonicalizePath('CLAUDE%2Emd', { workingRoot: '/r', filesystemMode: 'case-sensitive' }),
      (e: unknown) => e instanceof IPRPathError && e.code === 'PERCENT_ENCODING',
    )
  })

  it('§9.3 path canonicalization: rejects path outside working root', () => {
    assert.throws(
      () => canonicalizePath('/elsewhere/CLAUDE.md', { workingRoot: '/Users/agent/workspace', filesystemMode: 'case-sensitive' }),
      (e: unknown) => e instanceof IPRPathError && e.code === 'OUTSIDE_ROOT',
    )
  })

  it('§9.3 path canonicalization: NFC normalization', () => {
    // U+00E9 (é precomposed) and U+0065+U+0301 (e + combining acute) decompose differently;
    // canonicalizePath must produce NFC, so both forms should produce identical output.
    const precomposed = canonicalizePath('café/CLAUDE.md', { workingRoot: '/r', filesystemMode: 'case-sensitive' })
    const decomposed = canonicalizePath('café/CLAUDE.md', { workingRoot: '/r', filesystemMode: 'case-sensitive' })
    assert.equal(precomposed, decomposed)
    assert.equal(precomposed, 'café/CLAUDE.md')
  })

  it('§9.3 path canonicalization: case-insensitive FS lowercases', () => {
    const r = canonicalizePath('Foo/CLAUDE.md', { workingRoot: '/r', filesystemMode: 'case-insensitive' })
    assert.equal(r, 'foo/claude.md')
  })

  it('§9.3 path canonicalization: rejects empty path', () => {
    assert.throws(
      () => canonicalizePath('', { workingRoot: '/r', filesystemMode: 'case-sensitive' }),
      (e: unknown) => e instanceof IPRPathError && e.code === 'EMPTY',
    )
  })

  it('§9.3 path canonicalization: strips leading "./"', () => {
    const r = canonicalizePath('./CLAUDE.md', { workingRoot: '/r', filesystemMode: 'case-sensitive' })
    assert.equal(r, 'CLAUDE.md')
  })

  it('§9.5 ToCToU: tampering with context_root in envelope fails verification', () => {
    const env = createInstructionProvenanceReceipt(baseInput())
    const tampered: InstructionProvenanceReceipt = JSON.parse(JSON.stringify(env))
    tampered.context_root = '0'.repeat(64)
    const r = verifyInstructionProvenanceReceipt({ envelope: tampered, publicKeyHex: PUBKEY })
    assert.equal(r.valid, false)
    // Either the receipt_id mismatch fires first, or the context_root mismatch fires.
    assert.ok(r.errors.length > 0)
  })

  it('§9.5 ToCToU: tampering with file digest invalidates context_root', () => {
    const env = createInstructionProvenanceReceipt(baseInput())
    const tampered: InstructionProvenanceReceipt = JSON.parse(JSON.stringify(env))
    tampered.instruction_files[0]!.digest = '0'.repeat(64)
    // Recompute receipt_id under tampered (bypass the integrity check) so we
    // exercise the context_root re-derivation specifically.
    const canon = canonicalizeEnvelope(tampered)
    tampered.receipt_id = sha256Hex(canon)
    // But signature was over OLD canonical bytes, so verification must fail.
    const r = verifyInstructionProvenanceReceipt({ envelope: tampered, publicKeyHex: PUBKEY })
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => /signature/.test(e) || /context_root mismatch/.test(e)))
  })

  it('§6.3 sort order: out-of-order instruction_files fails verify', () => {
    const env = createInstructionProvenanceReceipt(baseInput({
      discovery_patterns: ['./*.md'],
      instruction_files: [
        { path: 'a.md', digest: sha256Hex('a'), bytes: 1, role: 'agent_md' },
        { path: 'b.md', digest: sha256Hex('b'), bytes: 1, role: 'agent_md' },
      ],
    }))
    // Manually scramble after construction.
    const tampered: InstructionProvenanceReceipt = JSON.parse(JSON.stringify(env))
    tampered.instruction_files = [...env.instruction_files].reverse()
    const r = verifyInstructionProvenanceReceipt({ envelope: tampered, publicKeyHex: PUBKEY })
    assert.equal(r.valid, false)
  })

  it('§9.4 tool-result laundering is out-of-scope: paths matching no discovery_pattern get rejected', () => {
    // The defense for laundering is partial — IPR can't see in-context instruction
    // additions — but at least: paths added to instruction_files outside any
    // declared pattern are rejected as smuggling. See §6.3 step 10.
    const env = createInstructionProvenanceReceipt(baseInput({
      discovery_patterns: ['./CLAUDE.md'],
      instruction_files: [
        { path: 'CLAUDE.md', digest: sha256Hex('legit'), bytes: 5, role: 'agent_md' },
        { path: 'sneaky.md', digest: sha256Hex('sneaky'), bytes: 6, role: 'other' },
      ],
    }))
    const r = verifyInstructionProvenanceReceipt({ envelope: env, publicKeyHex: PUBKEY })
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => /path smuggling/.test(e)))
  })

  it('expires_at in the past fails verification', () => {
    const env = createInstructionProvenanceReceipt(baseInput({
      expires_at: '2025-01-01T00:00:00.000Z',
    }))
    const r = verifyInstructionProvenanceReceipt({
      envelope: env,
      publicKeyHex: PUBKEY,
      now: new Date('2026-04-26T00:00:00.000Z'),
    })
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => /expired/.test(e)))
  })

  it('issued_at far in the future fails verification', () => {
    const env = createInstructionProvenanceReceipt(baseInput({
      issued_at: '2099-01-01T00:00:00.000Z',
    }))
    const r = verifyInstructionProvenanceReceipt({
      envelope: env,
      publicKeyHex: PUBKEY,
      now: new Date('2026-04-26T00:00:00.000Z'),
    })
    assert.equal(r.valid, false)
    assert.ok(r.errors.some(e => /future/.test(e)))
  })
})

// ─── Glob matcher coverage ──────────────────────────────

describe('IPR adversarial — matchesAnyPattern', () => {
  it('matches simple file name', () => {
    assert.equal(matchesAnyPattern('CLAUDE.md', ['./CLAUDE.md']), true)
  })
  it('matches *.md glob', () => {
    assert.equal(matchesAnyPattern('CLAUDE.md', ['./*.md']), true)
    assert.equal(matchesAnyPattern('MEMORY.md', ['./*.md']), true)
  })
  it('does not match across directory boundary with single *', () => {
    assert.equal(matchesAnyPattern('docs/CLAUDE.md', ['./*.md']), false)
  })
  it('matches across directories with **', () => {
    assert.equal(matchesAnyPattern('docs/CLAUDE.md', ['./**/*.md']), true)
    assert.equal(matchesAnyPattern('docs/sub/CLAUDE.md', ['./**/*.md']), true)
  })
  it('rejects non-matching extension', () => {
    assert.equal(matchesAnyPattern('CLAUDE.txt', ['./*.md']), false)
  })
})

// ─── Live filesystem walk coverage ──────────────────────────────

describe('IPR adversarial — filesystem walk', () => {
  it('detects symlink without dereferencing', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'ipr-fs-'))
    try {
      mkdirSync(join(tmp, 'templates'))
      writeFileSync(join(tmp, 'templates', 'base.md'), '# base')
      symlinkSync('templates/base.md', join(tmp, 'CLAUDE.md'))
      // Build envelope claiming CLAUDE.md is a symlink + templates/base.md is the target.
      const env = createInstructionProvenanceReceipt(baseInput({
        working_root: tmp,
        discovery_patterns: ['./*.md', './templates/**/*.md'],
        instruction_files: [
          { path: 'CLAUDE.md', digest: sha256Hex('# base'), bytes: 6, role: 'agent_md', is_symlink: true, symlink_target: 'templates/base.md' },
          { path: 'templates/base.md', digest: sha256Hex('# base'), bytes: 6, role: 'agent_md' },
        ],
      }))
      const r = verifyInstructionProvenanceReceipt({ envelope: env, publicKeyHex: PUBKEY, filesystemCheck: true })
      assert.equal(r.valid, true, r.errors.join('; '))
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })

  it('matches discovered files but does not require symlink declaration when target is in patterns', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'ipr-fs2-'))
    try {
      writeFileSync(join(tmp, 'CLAUDE.md'), 'rules')
      writeFileSync(join(tmp, 'MEMORY.md'), 'mem')
      const env = createInstructionProvenanceReceipt(baseInput({
        working_root: tmp,
        discovery_patterns: ['./CLAUDE.md', './MEMORY.md'],
        instruction_files: [
          { path: 'CLAUDE.md', digest: sha256Hex('rules'), bytes: 5, role: 'agent_md' },
          { path: 'MEMORY.md', digest: sha256Hex('mem'),   bytes: 3, role: 'memory' },
        ],
      }))
      const r = verifyInstructionProvenanceReceipt({ envelope: env, publicKeyHex: PUBKEY, filesystemCheck: true })
      assert.equal(r.valid, true, r.errors.join('; '))
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })
})
