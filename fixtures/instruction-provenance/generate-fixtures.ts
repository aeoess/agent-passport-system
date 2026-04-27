// Deterministic Ed25519 fixture-vector generator for InstructionProvenanceReceipt.
//
// Pattern mirrors fixtures/bilateral-delegation/generate-keypair.ts. Run as:
//   npx tsx fixtures/instruction-provenance/generate-fixtures.ts
//
// Produces canonicalize-fixture-v1.json with:
//   - Deterministic keypair from sha256("aps-instruction-provenance-fixture-v1")
//   - 10 vectors covering positive paths and expected-rejection cases
//   - canonical_bytes_hex / canonical_sha256 / ed25519_signature for each
//     positive vector; expected_verification: false for negatives.

import crypto from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  IPRConstructionError,
  createInstructionProvenanceReceipt,
} from '../../src/v2/instruction-provenance/index.js'
import {
  IPRPathError,
  canonicalizeEnvelope,
  canonicalizePath,
  computeContextRoot,
  matchesAnyPattern,
  sha256Hex,
} from '../../src/v2/instruction-provenance/index.js'
import type {
  CreateIPRInput,
  InstructionFile,
  InstructionProvenanceReceipt,
} from '../../src/v2/instruction-provenance/index.js'

const SEED_INPUT = 'aps-instruction-provenance-fixture-v1'
const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_PATH = join(__dirname, 'canonicalize-fixture-v1.json')

interface Keypair { seedHex: string; privateKeyHex: string; publicKeyHex: string }

function deriveKeypair(seedInput: string = SEED_INPUT): Keypair {
  const seed = crypto.createHash('sha256').update(seedInput, 'utf-8').digest()
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const pubKey = crypto.createPublicKey(keyObj)
  const pubDer = pubKey.export({ type: 'spki', format: 'der' }) as Buffer
  const publicKeyHex = pubDer.subarray(-32).toString('hex')
  return { seedHex: seed.toString('hex'), privateKeyHex: seed.toString('hex'), publicKeyHex }
}

const KP = deriveKeypair()

const FIXED_DELEGATION_ROOT = sha256Hex('demo-delegation-chain-root')
const FIXED_AGENT_DID = 'did:key:zIPRfixtureAgentV1'
const FIXED_WORKING_ROOT = '/Users/agent/workspace'
const FIXED_ISSUED_AT = '2026-04-26T00:00:00.000Z'
const FIXED_BOUND_TO = { type: 'session' as const, ref: 'sess_ipr_v1_fixture_001' }

function digestOf(content: string): string { return sha256Hex(content) }

function buildInput(overrides: Partial<CreateIPRInput>): CreateIPRInput {
  return {
    delegation_chain_root: FIXED_DELEGATION_ROOT,
    agent_did: FIXED_AGENT_DID,
    discovery_patterns: ['./CLAUDE.md'],
    working_root: FIXED_WORKING_ROOT,
    filesystem_mode: 'case-sensitive',
    instruction_files: [],
    issued_at: FIXED_ISSUED_AT,
    bound_to: FIXED_BOUND_TO,
    privateKeyHex: KP.privateKeyHex,
    publicKeyHex: KP.publicKeyHex,
    ...overrides,
  }
}

interface PositiveVector {
  name: string
  description: string
  input: CreateIPRInput
  expected_verification: true
}

interface NegativeVector {
  name: string
  description: string
  rejection_kind: 'construction' | 'verification' | 'canonicalization'
  /** For 'construction' kind: input that will throw at create-time. */
  construction_input?: CreateIPRInput
  /** For 'verification' kind: a serialized envelope that should fail verify. */
  verification_envelope?: InstructionProvenanceReceipt
  /** For 'canonicalization' kind: a raw path that canonicalizePath rejects. */
  canonicalize_input?: { raw: string; workingRoot: string; filesystemMode: 'case-sensitive' | 'case-insensitive' }
  expected_error_code: string
  expected_verification: false
}

function buildPositiveVectors(): PositiveVector[] {
  // V1: minimal-valid-envelope
  const v1: PositiveVector = {
    name: 'minimal-valid-envelope',
    description: 'Single CLAUDE.md instruction file, single discovery pattern, self-asserted, recompute_at_action=false.',
    input: buildInput({
      instruction_files: [{
        path: 'CLAUDE.md',
        digest: digestOf('# Project: APS\n\nFollow the rules in /Users/agent/workspace.\n'),
        bytes: 56,
        role: 'agent_md',
      }],
    }),
    expected_verification: true,
  }

  // V2: multi-file-multi-pattern
  const v2: PositiveVector = {
    name: 'multi-file-multi-pattern',
    description: 'Three files, two patterns; sorted in canonical order.',
    input: buildInput({
      discovery_patterns: ['./*.md', './.cursorrules'],
      instruction_files: [
        { path: 'CLAUDE.md',     digest: digestOf('claude rules'), bytes: 12, role: 'agent_md' },
        { path: 'MEMORY.md',     digest: digestOf('memory rules'), bytes: 12, role: 'memory' },
        { path: '.cursorrules',  digest: digestOf('cursor rules'), bytes: 12, role: 'rules' },
      ],
    }),
    expected_verification: true,
  }

  // V3: recompute-at-action-true
  const v3: PositiveVector = {
    name: 'recompute-at-action-true',
    description: 'recompute_at_action flag set; verifyActionTimeContextRoot must round-trip.',
    input: buildInput({
      recompute_at_action: true,
      instruction_files: [{
        path: 'CLAUDE.md',
        digest: digestOf('# v0.2 IPR fixture\n'),
        bytes: 19,
        role: 'agent_md',
      }],
    }),
    expected_verification: true,
  }

  // V4: nfc-normalization
  // Content of file irrelevant; canonical path normalizes the directory name to NFC.
  // We write the path with a precomposed é so the input is ALREADY NFC; the test
  // verifies the same byte string survives canonicalization.
  const v4: PositiveVector = {
    name: 'nfc-normalization',
    description: 'Path with non-ASCII (café/CLAUDE.md). NFC-normalized at canonicalization.',
    input: buildInput({
      discovery_patterns: ['./café/*.md'],
      instruction_files: [{
        path: 'café/CLAUDE.md',
        digest: digestOf('non-ascii rules'),
        bytes: 16,
        role: 'agent_md',
      }],
    }),
    expected_verification: true,
  }

  // V5: case-insensitive-fs
  const v5: PositiveVector = {
    name: 'case-insensitive-fs',
    description: 'filesystem_mode=case-insensitive lowercases all paths.',
    input: buildInput({
      filesystem_mode: 'case-insensitive',
      discovery_patterns: ['./*.md'],
      instruction_files: [{
        path: 'claude.md',
        digest: digestOf('case insensitive content'),
        bytes: 24,
        role: 'agent_md',
      }],
    }),
    expected_verification: true,
  }

  // V6: symlink-as-separate-entry
  const v6: PositiveVector = {
    name: 'symlink-as-separate-entry',
    description: 'A symlink CLAUDE.md -> templates/base.md ships as two entries; symlink carries is_symlink=true and symlink_target.',
    input: buildInput({
      discovery_patterns: ['./*.md', './templates/**/*.md'],
      instruction_files: [
        {
          path: 'CLAUDE.md',
          digest: digestOf('# Symlink to templates/base.md\n'),
          bytes: 30,
          role: 'agent_md',
          is_symlink: true,
          symlink_target: 'templates/base.md',
        },
        {
          path: 'templates/base.md',
          digest: digestOf('# Base template\n\nDefault rules.\n'),
          bytes: 33,
          role: 'agent_md',
        },
      ],
    }),
    expected_verification: true,
  }

  return [v1, v2, v3, v4, v5, v6]
}

function buildNegativeVectors(): NegativeVector[] {
  // N7: tier reserved (witnessed) — verification reject
  const tieredOk = createInstructionProvenanceReceipt(buildInput({
    instruction_files: [{
      path: 'CLAUDE.md',
      digest: digestOf('tier-test content'),
      bytes: 17,
      role: 'agent_md',
    }],
  }))
  const tampered: InstructionProvenanceReceipt = JSON.parse(JSON.stringify(tieredOk))
  tampered.attestation_tier = 'witnessed'

  // N8: omitted file (smuggle inverse — agent declares pattern but omits a match)
  // We emit the IPR that DOES include MEMORY.md (legal at construction), but the
  // verifier expects exhaustiveness via filesystem walk. Here we model omission
  // by hand-constructing a vector that DECLARES *.md but only ships CLAUDE.md.
  // The fixture's filesystem-side check is simulated in the test (we provide
  // an in-memory "discovered" set rather than touching disk).
  const omittedOk = createInstructionProvenanceReceipt(buildInput({
    discovery_patterns: ['./*.md'],
    instruction_files: [
      { path: 'CLAUDE.md', digest: digestOf('only one'), bytes: 8, role: 'agent_md' },
    ],
  }))

  // N9: smuggled path — instruction_files contains a path matching no pattern.
  // Built by hand because createInstructionProvenanceReceipt accepts whatever
  // files the caller supplies; it's the verifier that catches the mismatch.
  const smuggledOk = createInstructionProvenanceReceipt(buildInput({
    discovery_patterns: ['./CLAUDE.md'],
    instruction_files: [
      { path: 'CLAUDE.md', digest: digestOf('a'), bytes: 1, role: 'agent_md' },
      { path: 'secrets.md', digest: digestOf('smuggled'), bytes: 8, role: 'other' },
    ],
  }))

  // N10: trailing-slash — canonicalization throws
  const negatives: NegativeVector[] = [
    {
      name: 'expected-rejection-witnessed-tier',
      description: 'Envelope tampered to attestation_tier=witnessed. Verifier rejects per v0.2 tier lock.',
      rejection_kind: 'verification',
      verification_envelope: tampered,
      expected_error_code: 'TIER_RESERVED',
      expected_verification: false,
    },
    {
      name: 'expected-rejection-omitted-file',
      description: 'discovery_patterns: ["./*.md"]; instruction_files omits MEMORY.md that filesystem walk would discover. Verifier rejects when filesystemCheck=true.',
      rejection_kind: 'verification',
      verification_envelope: omittedOk,
      expected_error_code: 'OMISSION',
      expected_verification: false,
    },
    {
      name: 'expected-rejection-smuggled-path',
      description: 'instruction_files contains path matching no discovery_pattern. Verifier rejects per §6.3 step 10.',
      rejection_kind: 'verification',
      verification_envelope: smuggledOk,
      expected_error_code: 'PATH_SMUGGLING',
      expected_verification: false,
    },
    {
      name: 'expected-rejection-trailing-slash',
      description: 'canonicalizePath throws IPRPathError(TRAILING_SLASH) when path ends with /.',
      rejection_kind: 'canonicalization',
      canonicalize_input: { raw: 'docs/CLAUDE.md/', workingRoot: FIXED_WORKING_ROOT, filesystemMode: 'case-sensitive' },
      expected_error_code: 'TRAILING_SLASH',
      expected_verification: false,
    },
  ]

  return negatives
}

function emitVector(v: PositiveVector): Record<string, unknown> {
  const env = createInstructionProvenanceReceipt(v.input)
  const canonical = canonicalizeEnvelope(env)
  return {
    name: v.name,
    description: v.description,
    input: serializeInput(v.input),
    canonical_bytes_hex: Buffer.from(canonical, 'utf8').toString('hex'),
    canonical_sha256: sha256Hex(canonical),
    receipt_id: env.receipt_id,
    context_root: env.context_root,
    ed25519_signature: env.signature,
    expected_verification: true,
    envelope: env,
  }
}

/** Serialize input minus the private key (so the fixture file doesn't leak it
 *  even though the key is deterministic from the public seed_input). */
function serializeInput(input: CreateIPRInput): Record<string, unknown> {
  const { privateKeyHex: _pk, ...rest } = input
  return rest
}

function emitNegative(v: NegativeVector): Record<string, unknown> {
  const out: Record<string, unknown> = {
    name: v.name,
    description: v.description,
    rejection_kind: v.rejection_kind,
    expected_error_code: v.expected_error_code,
    expected_verification: false,
  }
  if (v.verification_envelope) out.envelope = v.verification_envelope
  if (v.canonicalize_input) out.canonicalize_input = v.canonicalize_input
  return out
}

function main(): void {
  const positives = buildPositiveVectors()
  const negatives = buildNegativeVectors()

  // Smoke-check the negatives where we expect throws (to catch generator bugs).
  for (const neg of negatives) {
    if (neg.rejection_kind === 'canonicalization' && neg.canonicalize_input) {
      try {
        canonicalizePath(neg.canonicalize_input.raw, {
          workingRoot: neg.canonicalize_input.workingRoot,
          filesystemMode: neg.canonicalize_input.filesystemMode,
        })
        throw new Error(`generator: expected ${neg.name} to throw, did not`)
      } catch (e) {
        if (!(e instanceof IPRPathError)) throw e
      }
    }
  }

  const fixture = {
    version: '1',
    primitive: 'InstructionProvenanceReceipt',
    spec_ref: 'INSTRUCTION-PROVENANCE-RECEIPT-DRAFT-v0.2.md',
    spec: 'JCS — RFC 8785 + IPR path canonicalization v0.2 §5.1',
    canonicalization: 'APS SDK canonicalizeJCS + IPR canonicalize_path',
    seed_input: SEED_INPUT,
    seed_sha256_hex: KP.seedHex,
    keypair: { publicKeyHex: KP.publicKeyHex },
    generated_at: '2026-04-26',
    vectors: [
      ...positives.map(emitVector),
      ...negatives.map(emitNegative),
    ],
  }

  writeFileSync(FIXTURE_PATH, JSON.stringify(fixture, null, 2) + '\n', 'utf8')
  // eslint-disable-next-line no-console
  console.log(`Wrote ${FIXTURE_PATH} (${positives.length} positive + ${negatives.length} negative vectors)`)
}

// Touch unused imports referenced in JSDoc / future-use to keep noUnusedLocals quiet.
void IPRConstructionError
void computeContextRoot
void matchesAnyPattern
type _IF = InstructionFile

main()
