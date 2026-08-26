// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Revocation verification v0.1: shared cross-language vector generator
// ══════════════════════════════════════════════════════════════════
// Emits vectors/revocation-verification-v0.1-vectors.json, the single
// fixture that __tests__/known-answer.test.ts loads and must reproduce
// byte for byte, and that a second implementation can load unchanged.
//
// LAYERING (honest):
//   - Every SEED, identifier, timestamp and nonce below is FIXED. Nothing
//     in the fixture depends on the clock, on uuid, or on key generation.
//   - Signatures and digests are REFERENCE-IMPLEMENTATION-DERIVED: produced
//     here by the real sign() / issuePrincipalBindingRevocationV1() /
//     revocationArtifactDigest(). The test re-derives all of them from the
//     seeds using node:crypto directly, so the fixture is pinned, not
//     merely self-consistent.
//   - jcs_kats pin the canonical bytes for one record of each kind. The
//     pinned string is asserted against canonicalizeJCSForWrite here; the
//     test additionally rebuilds it with JSON.stringify over a key-sorted
//     literal, which is an independent check of key order and escaping that
//     does not route through the APS canonicalizer.
//   - expected[] results are REFERENCE-IMPLEMENTATION-DERIVED, computed by
//     running verifyRevocationEvidence() on the case inputs.
//
// Run: npx tsx src/v2/revocation-verification/vectors/generate-vectors.ts
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeForWrite } from '../../../core/canonical.js'
import { canonicalizeJCSForWrite } from '../../../core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import { issuePrincipalBindingV1 } from '../../identity-binding/principal-binding.js'
import { issuePrincipalBindingRevocationV1 } from '../../identity-binding/revocation.js'
import type {
  HistoricalKeyResolutionResult,
  HistoricalKeyResolver,
  PrincipalBindingRevocationV1,
  PrincipalBindingV1,
} from '../../identity-binding/types.js'
import type { Delegation, RevocationRecord } from '../../../types/passport.js'
import { revocationArtifactDigest } from '../digest.js'
import { verifyPublicationCommitment } from '../publication.js'
import { verifyRevocationEvidence } from '../verify.js'
import type { RevocationVerificationResult } from '../types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

// ══════════════════════════════════════════════════════════════════
// Fixed inputs. Changing any line here re-pins every output below.
// ══════════════════════════════════════════════════════════════════

const DELEGATOR_SEED = '11'.repeat(32)
const DELEGATE_SEED = '22'.repeat(32)
const FORGER_SEED = '33'.repeat(32)
const PRINCIPAL_CURRENT_SEED = '44'.repeat(32)
const PRINCIPAL_FORMER_SEED = '55'.repeat(32)

const DELEGATOR_PUBKEY = publicKeyFromPrivate(DELEGATOR_SEED)
const DELEGATE_PUBKEY = publicKeyFromPrivate(DELEGATE_SEED)
const FORGER_PUBKEY = publicKeyFromPrivate(FORGER_SEED)
const PRINCIPAL_CURRENT_PUBKEY = publicKeyFromPrivate(PRINCIPAL_CURRENT_SEED)
const PRINCIPAL_FORMER_PUBKEY = publicKeyFromPrivate(PRINCIPAL_FORMER_SEED)

const DELEGATION_ID = 'del_revocation_corpus_01'
const ABSENT_DELEGATION_ID = 'del_revocation_corpus_absent'
const REVOCATION_ID = 'rev_revocation_corpus_01'
const FORGED_REVOCATION_ID = 'rev_revocation_corpus_forged'

const AGENT_ID = 'did:aps:agent-revocation-corpus'
const PRINCIPAL_ID = 'did:aps:principal-revocation-corpus'
const VERIFICATION_METHOD = `${PRINCIPAL_ID}#key-1`
const STATUS_URI = 'https://status.example/aps/revocation-corpus'

const BINDING_NONCE = 'c3'.repeat(16)
const OTHER_BINDING_NONCE = 'd4'.repeat(16)
const NONCE_A = 'a1'.repeat(16)
const NONCE_B = 'b2'.repeat(16)

const ISSUED_AT = '2026-01-01T00:00:00.000Z'
const EXPIRES_AT = '2027-01-01T00:00:00.000Z'
// The one key rotation in the corpus. A revocation stamped at or after this
// instant resolves to principal_current; one stamped earlier resolves to
// principal_former. That split is the whole point of historical resolution.
const ROTATION_AT = '2026-06-01T00:00:00.000Z'
const REVOKED_AT_CURRENT = '2026-08-26T00:00:00.000Z'
const REVOKED_AT_FORMER = '2026-03-01T00:00:00.000Z'
const DELEGATION_REVOKED_AT = '2026-08-26T00:00:00.000Z'
const REVOCATION_REASON = 'revocation verification corpus'
const REASON_CODE = 'corpus_fixture'

// ══════════════════════════════════════════════════════════════════
// Subjects
// ══════════════════════════════════════════════════════════════════

const delegationUnsigned: Omit<Delegation, 'signature'> = {
  delegationId: DELEGATION_ID,
  delegatedTo: DELEGATE_PUBKEY,
  delegatedBy: DELEGATOR_PUBKEY,
  scope: ['data:read'],
  expiresAt: EXPIRES_AT,
  spentAmount: 0,
  maxDepth: 1,
  currentDepth: 0,
  createdAt: ISSUED_AT,
  notBefore: ISSUED_AT,
}
const DELEGATION: Delegation = {
  ...delegationUnsigned,
  signature: sign(canonicalizeForWrite(delegationUnsigned), DELEGATOR_SEED),
}

function issueBinding(nonce: string): PrincipalBindingV1 {
  return issuePrincipalBindingV1({
    agent_id: AGENT_ID,
    principal_id: PRINCIPAL_ID,
    verification_method: VERIFICATION_METHOD,
    audiences: ['https://gateway.example/aps'],
    authority_profiles: ['aps.principal-binding.v1'],
    status_uri: STATUS_URI,
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    nonce,
    principal_private_key_hex: PRINCIPAL_CURRENT_SEED,
  })
}

const BINDING = issueBinding(BINDING_NONCE)
/** Issued so that V08 can name a well-formed binding_id that is deliberately
 *  NOT in the supplied bindings map. Never handed to the verifier. */
const UNSUPPLIED_BINDING = issueBinding(OTHER_BINDING_NONCE)

// ══════════════════════════════════════════════════════════════════
// Artifacts
// ══════════════════════════════════════════════════════════════════

function makeRevocationRecord(fields: Omit<RevocationRecord, 'signature'>, seed: string): RevocationRecord {
  return { ...fields, signature: sign(canonicalizeForWrite(fields), seed) }
}

/** Flip the low bit of the first hex digit. One byte changes, the value stays
 *  128 lowercase hex, so the record still passes shape checks and fails only
 *  where it should: at the signature. */
function flipFirstHexDigit(hex: string): string {
  const digits = '0123456789abcdef'
  return digits[digits.indexOf(hex[0]) ^ 1] + hex.slice(1)
}

const R_VALID = makeRevocationRecord({
  revocationId: REVOCATION_ID,
  delegationId: DELEGATION_ID,
  revokedBy: DELEGATOR_PUBKEY,
  revokedAt: DELEGATION_REVOKED_AT,
  reason: REVOCATION_REASON,
}, DELEGATOR_SEED)

const R_WRONG_SUBJECT = makeRevocationRecord({
  revocationId: REVOCATION_ID,
  delegationId: ABSENT_DELEGATION_ID,
  revokedBy: DELEGATOR_PUBKEY,
  revokedAt: DELEGATION_REVOKED_AT,
  reason: REVOCATION_REASON,
}, DELEGATOR_SEED)

/** The forged record. It self-verifies under verifyRevocation because that
 *  function checks the signature against the record's OWN revokedBy field.
 *  Only the delegation knows that the forger was never the delegator. */
const R_FORGED = makeRevocationRecord({
  revocationId: FORGED_REVOCATION_ID,
  delegationId: DELEGATION_ID,
  revokedBy: FORGER_PUBKEY,
  revokedAt: DELEGATION_REVOKED_AT,
  reason: REVOCATION_REASON,
}, FORGER_SEED)

const R_CORRUPT_SIGNATURE: RevocationRecord = {
  ...R_VALID,
  signature: flipFirstHexDigit(R_VALID.signature),
}

function issueBindingRevocation(input: {
  binding_id: string
  revoked_at: string
  nonce: string
  seed: string
}): PrincipalBindingRevocationV1 {
  return issuePrincipalBindingRevocationV1({
    binding_id: input.binding_id,
    principal_id: PRINCIPAL_ID,
    verification_method: VERIFICATION_METHOD,
    revoked_at: input.revoked_at,
    reason_code: REASON_CODE,
    nonce: input.nonce,
    principal_private_key_hex: input.seed,
  })
}

const B_VALID = issueBindingRevocation({
  binding_id: BINDING.binding_id,
  revoked_at: REVOKED_AT_CURRENT,
  nonce: NONCE_A,
  seed: PRINCIPAL_CURRENT_SEED,
})

const B_SECOND_NONCE = issueBindingRevocation({
  binding_id: BINDING.binding_id,
  revoked_at: REVOKED_AT_CURRENT,
  nonce: NONCE_B,
  seed: PRINCIPAL_CURRENT_SEED,
})

/** Stamped BEFORE the rotation and signed by the key that was current then.
 *  It verifies only if the resolver is asked at revoked_at rather than now. */
const B_HISTORICAL = issueBindingRevocation({
  binding_id: BINDING.binding_id,
  revoked_at: REVOKED_AT_FORMER,
  nonce: NONCE_B,
  seed: PRINCIPAL_FORMER_SEED,
})

/** revocation_id replaced with a well-formed Hex64 that is not the recomputed
 *  one, so the existing verifier's own ID_MISMATCH check is what fires. */
const B_ID_MISMATCH: PrincipalBindingRevocationV1 = {
  ...B_VALID,
  revocation_id: 'e5'.repeat(32),
}

const B_UNSUPPLIED_BINDING = issueBindingRevocation({
  binding_id: UNSUPPLIED_BINDING.binding_id,
  revoked_at: REVOKED_AT_CURRENT,
  nonce: NONCE_A,
  seed: PRINCIPAL_CURRENT_SEED,
})

const SHAPELESS_ARTIFACT = {
  note: 'this object names no delegation and no binding',
  revoked: true,
}

// ══════════════════════════════════════════════════════════════════
// Resolver tables. Each case pins its own, so the fixture is closed:
// a second implementation rebuilds the resolver from the table alone.
// ══════════════════════════════════════════════════════════════════

interface ResolverSegment {
  controller: string
  verification_method: string
  /** Inclusive lower bound, canonical UTC milliseconds. */
  from: string
  /** Exclusive upper bound, canonical UTC milliseconds. */
  until: string
  state: HistoricalKeyResolutionResult['state']
  public_key_hex?: string
}

interface ResolverTable {
  segments: ResolverSegment[]
  fallback: HistoricalKeyResolutionResult['state']
}

const TIME_MIN = '0000-01-01T00:00:00.000Z'
const TIME_MAX = '9999-12-31T23:59:59.999Z'

const ROTATING_TABLE: ResolverTable = {
  segments: [
    {
      controller: PRINCIPAL_ID,
      verification_method: VERIFICATION_METHOD,
      from: TIME_MIN,
      until: ROTATION_AT,
      state: 'resolved',
      public_key_hex: PRINCIPAL_FORMER_PUBKEY,
    },
    {
      controller: PRINCIPAL_ID,
      verification_method: VERIFICATION_METHOD,
      from: ROTATION_AT,
      until: TIME_MAX,
      state: 'resolved',
      public_key_hex: PRINCIPAL_CURRENT_PUBKEY,
    },
  ],
  fallback: 'not_found',
}

const AMBIGUOUS_TABLE: ResolverTable = {
  segments: [
    {
      controller: PRINCIPAL_ID,
      verification_method: VERIFICATION_METHOD,
      from: TIME_MIN,
      until: TIME_MAX,
      state: 'ambiguous',
    },
  ],
  fallback: 'not_found',
}

/** Deliberately duplicated in the test rather than imported, so the JSON
 *  table is the only thing the two sides share. */
function resolverFromTable(table: ResolverTable): HistoricalKeyResolver {
  return request => {
    for (const segment of table.segments) {
      if (segment.controller !== request.controller) continue
      if (segment.verification_method !== request.verification_method) continue
      if (request.at < segment.from || request.at >= segment.until) continue
      return segment.public_key_hex === undefined
        ? { state: segment.state }
        : { state: segment.state, public_key_hex: segment.public_key_hex }
    }
    return { state: table.fallback }
  }
}

// ══════════════════════════════════════════════════════════════════
// Cases
// ══════════════════════════════════════════════════════════════════

interface PublicationCase {
  name: string
  proof: { committed_digest: string }
  artifact: unknown
  expected: { publication_verified: boolean }
}

interface VectorCase {
  name: string
  description: string
  inputs: {
    artifacts: unknown[]
    delegation: Delegation
    binding: PrincipalBindingV1
    resolver_table: ResolverTable
  }
  artifact_digests: Array<{ index: number; canonical: string; revocation_artifact_digest: string }>
  expected: RevocationVerificationResult
  publication?: PublicationCase[]
}

interface CaseSpec {
  name: string
  description: string
  artifacts: unknown[]
  resolver_table?: ResolverTable
  publication?: Array<{ name: string; proof: { committed_digest: string }; artifact: unknown }>
}

async function buildCase(spec: CaseSpec): Promise<VectorCase> {
  const table = spec.resolver_table ?? ROTATING_TABLE
  const expected = await verifyRevocationEvidence({
    artifacts: spec.artifacts,
    delegations: new Map([[DELEGATION.delegationId, DELEGATION]]),
    bindings: new Map([[BINDING.binding_id, BINDING]]),
    resolver: resolverFromTable(table),
  })
  const built: VectorCase = {
    name: spec.name,
    description: spec.description,
    inputs: {
      artifacts: spec.artifacts,
      delegation: DELEGATION,
      binding: BINDING,
      resolver_table: table,
    },
    artifact_digests: spec.artifacts.map((artifact, index) => ({
      index,
      canonical: canonicalizeJCSForWrite(artifact),
      revocation_artifact_digest: revocationArtifactDigest(artifact),
    })),
    expected,
  }
  if (spec.publication) {
    built.publication = spec.publication.map(entry => ({
      name: entry.name,
      proof: entry.proof,
      artifact: entry.artifact,
      expected: verifyPublicationCommitment(entry.proof, entry.artifact),
    }))
  }
  return built
}

const specs: CaseSpec[] = [
  {
    name: 'V01',
    description: 'no artifacts: every supplied subject reports no_revocation_evidence_observed, which is not a claim that the subject is unrevoked',
    artifacts: [],
  },
  {
    name: 'V02',
    description: 'valid delegation revocation against the matching delegation: REVOKED, artifacts 1',
    artifacts: [R_VALID],
  },
  {
    name: 'V03',
    description: 'delegation revocation with a valid signature whose delegationId is not the supplied delegation: invalid_reference',
    artifacts: [R_WRONG_SUBJECT],
  },
  {
    name: 'V04',
    description: 'self-signed delegation revocation, revokedBy is not delegation.delegatedBy: unauthorized_revoker. verifyRevocation alone accepts this record',
    artifacts: [R_FORGED],
  },
  {
    name: 'V05',
    description: 'delegation revocation with one signature byte flipped: invalid_signature',
    artifacts: [R_CORRUPT_SIGNATURE],
  },
  {
    name: 'V06',
    description: 'valid principal-binding revocation resolved through its verification_method: REVOKED, artifacts 1',
    artifacts: [B_VALID],
  },
  {
    name: 'V07',
    description: 'binding revocation whose revocation_id does not recompute: invalid, carrying the existing verifier reason',
    artifacts: [B_ID_MISMATCH],
  },
  {
    name: 'V08',
    description: 'valid binding revocation naming a binding_id that was not supplied: invalid_reference',
    artifacts: [B_UNSUPPLIED_BINDING],
  },
  {
    name: 'V09',
    description: 'binding revocation stamped before the key rotation and signed by the former key: the historical resolver returns the key valid at revoked_at, so REVOKED',
    artifacts: [B_HISTORICAL],
  },
  {
    name: 'V10',
    description: 'historical resolution ambiguous: the existing verifier result is preserved verbatim as the discard reason',
    artifacts: [B_VALID],
    resolver_table: AMBIGUOUS_TABLE,
  },
  {
    name: 'V11',
    description: 'the exact same artifact twice: REVOKED, artifacts 1, duplicate_count 1',
    artifacts: [R_VALID, R_VALID],
  },
  {
    name: 'V12',
    description: 'two different valid binding revocations for one subject, differing only by nonce: REVOKED, artifacts 2, never equivocation',
    artifacts: [B_VALID, B_SECOND_NONCE],
  },
  {
    name: 'V13',
    description: 'one valid artifact and one hostile forged artifact for the same subject: REVOKED on the valid one, the forged one discarded',
    artifacts: [R_VALID, R_FORGED],
  },
  {
    name: 'V14',
    description: 'artifact with no readable subject: reported at the top level as unclassifiable malformed, attributed to no subject',
    artifacts: [SHAPELESS_ARTIFACT],
  },
  {
    name: 'V15',
    description: 'publication boundary: a proof committing to the artifact digest verifies, the same proof against a different artifact does not, and artifact validity is unchanged either way',
    artifacts: [R_VALID],
    publication: [
      {
        name: 'proof commits to this artifact',
        proof: { committed_digest: revocationArtifactDigest(R_VALID) },
        artifact: R_VALID,
      },
      {
        name: 'same proof, different artifact',
        proof: { committed_digest: revocationArtifactDigest(R_VALID) },
        artifact: B_VALID,
      },
    ],
  },
  {
    name: 'V16',
    description: 'mixed subjects, one delegation revocation and one binding revocation: two independent per-subject results',
    artifacts: [R_VALID, B_VALID],
  },
]

const cases: VectorCase[] = []
for (const spec of specs) cases.push(await buildCase(spec))

// ══════════════════════════════════════════════════════════════════
// jcs_kats: pinned canonical bytes for one record of each kind.
// ══════════════════════════════════════════════════════════════════
// The pinned string anchors RFC 8785 key order and escaping for a second
// implementation. It is asserted against canonicalizeJCSForWrite below, and
// the test rebuilds it a second way with JSON.stringify over a key-sorted
// literal, which does not route through the APS canonicalizer.

const KAT_DELEGATION_EXPECTED =
  '{"delegationId":' + JSON.stringify(R_VALID.delegationId) +
  ',"reason":' + JSON.stringify(R_VALID.reason) +
  ',"revocationId":' + JSON.stringify(R_VALID.revocationId) +
  ',"revokedAt":' + JSON.stringify(R_VALID.revokedAt) +
  ',"revokedBy":' + JSON.stringify(R_VALID.revokedBy) +
  ',"signature":' + JSON.stringify(R_VALID.signature) + '}'

const KAT_BINDING_EXPECTED =
  '{"binding_id":' + JSON.stringify(B_VALID.binding_id) +
  ',"nonce":' + JSON.stringify(B_VALID.nonce) +
  ',"principal_id":' + JSON.stringify(B_VALID.principal_id) +
  ',"reason_code":' + JSON.stringify(B_VALID.reason_code) +
  ',"record_type":' + JSON.stringify(B_VALID.record_type) +
  ',"revocation_id":' + JSON.stringify(B_VALID.revocation_id) +
  ',"revoked_at":' + JSON.stringify(B_VALID.revoked_at) +
  ',"signature":' + JSON.stringify(B_VALID.signature) +
  ',"verification_method":' + JSON.stringify(B_VALID.verification_method) +
  ',"version":' + JSON.stringify(B_VALID.version) + '}'

interface JcsKat {
  name: string
  kind: string
  input: unknown
  expected: string
  sha256: string
  revocation_artifact_digest: string
}

const jcs_kats: JcsKat[] = [
  {
    name: 'KAT-REVOCATION-RECORD',
    kind: 'RevocationRecord',
    input: R_VALID,
    expected: KAT_DELEGATION_EXPECTED,
    sha256: sha256Hex(KAT_DELEGATION_EXPECTED),
    revocation_artifact_digest: revocationArtifactDigest(R_VALID),
  },
  {
    name: 'KAT-PRINCIPAL-BINDING-REVOCATION',
    kind: 'PrincipalBindingRevocationV1',
    input: B_VALID,
    expected: KAT_BINDING_EXPECTED,
    sha256: sha256Hex(KAT_BINDING_EXPECTED),
    revocation_artifact_digest: revocationArtifactDigest(B_VALID),
  },
]

for (const kat of jcs_kats) {
  const produced = canonicalizeJCSForWrite(kat.input)
  if (produced !== kat.expected) {
    throw new Error(`${kat.name}: canonicalizeJCSForWrite does not match the pinned canonical string\n got: ${produced}\nwant: ${kat.expected}`)
  }
  if (sha256Hex(kat.expected) !== kat.sha256) {
    throw new Error(`${kat.name}: sha256(expected) does not match the pinned sha256`)
  }
}

// ══════════════════════════════════════════════════════════════════
// ed25519 block for the delegator seed.
// ══════════════════════════════════════════════════════════════════

const ED_MSG = '{"hello":"revocation-verification"}'
const ed25519 = {
  seed: DELEGATOR_SEED,
  pubkey: DELEGATOR_PUBKEY,
  msg: ED_MSG,
  msg_utf8_hex: Buffer.from(ED_MSG, 'utf8').toString('hex'),
  signature: sign(ED_MSG, DELEGATOR_SEED),
}

// ══════════════════════════════════════════════════════════════════
// Assemble and write.
// ══════════════════════════════════════════════════════════════════

const fixture = {
  _layering:
    'Every seed, identifier, timestamp and nonce in fixed_inputs is pinned; nothing here ' +
    'depends on the clock, on uuid, or on key generation. Signatures and digests are ' +
    'REFERENCE-IMPLEMENTATION-DERIVED, produced by the real sign(), ' +
    'issuePrincipalBindingRevocationV1() and revocationArtifactDigest(); the known-answer ' +
    'test re-derives all of them from the seeds with node:crypto directly, so this file is ' +
    'pinned rather than merely self-consistent. jcs_kats pin the canonical bytes for one ' +
    'record of each kind and anchor RFC 8785 key order and escaping. expected[] results are ' +
    'reference-implementation-derived, computed by running verifyRevocationEvidence() on the ' +
    'case inputs. Each case carries its own resolver_table so the file is closed: a second ' +
    'implementation rebuilds the historical key resolver from the table alone.',
  version: 'revocation-verification/0.1',
  fixed_inputs: {
    seeds: {
      delegator: DELEGATOR_SEED,
      delegate: DELEGATE_SEED,
      forger: FORGER_SEED,
      principal_current: PRINCIPAL_CURRENT_SEED,
      principal_former: PRINCIPAL_FORMER_SEED,
    },
    pubkeys: {
      delegator: DELEGATOR_PUBKEY,
      delegate: DELEGATE_PUBKEY,
      forger: FORGER_PUBKEY,
      principal_current: PRINCIPAL_CURRENT_PUBKEY,
      principal_former: PRINCIPAL_FORMER_PUBKEY,
    },
    delegation_id: DELEGATION_ID,
    absent_delegation_id: ABSENT_DELEGATION_ID,
    revocation_id: REVOCATION_ID,
    forged_revocation_id: FORGED_REVOCATION_ID,
    agent_id: AGENT_ID,
    principal_id: PRINCIPAL_ID,
    verification_method: VERIFICATION_METHOD,
    status_uri: STATUS_URI,
    binding_nonce: BINDING_NONCE,
    other_binding_nonce: OTHER_BINDING_NONCE,
    binding_revocation_nonces: { a: NONCE_A, b: NONCE_B },
    issued_at: ISSUED_AT,
    expires_at: EXPIRES_AT,
    rotation_at: ROTATION_AT,
    revoked_at_current: REVOKED_AT_CURRENT,
    revoked_at_former: REVOKED_AT_FORMER,
    delegation_revoked_at: DELEGATION_REVOKED_AT,
    revocation_reason: REVOCATION_REASON,
    reason_code: REASON_CODE,
    delegation: DELEGATION,
    binding: BINDING,
    unsupplied_binding: UNSUPPLIED_BINDING,
  },
  jcs_kats,
  ed25519,
  cases,
}

const outPath = join(__dirname, 'revocation-verification-v0.1-vectors.json')
mkdirSync(__dirname, { recursive: true })
writeFileSync(outPath, JSON.stringify(fixture, null, 2) + '\n', 'utf8')

// eslint-disable-next-line no-console
console.log(`wrote ${outPath}`)
// eslint-disable-next-line no-console
console.log(`  jcs_kats: ${jcs_kats.length}, cases: ${cases.length}`)
for (const entry of cases) {
  const summary = entry.expected.subjects
    .map(subject => `${subject.subject_kind}=${subject.outcome}/${subject.artifacts.length}`)
    .join(' ')
  // eslint-disable-next-line no-console
  console.log(`  ${entry.name}: ${summary} unclassifiable=${entry.expected.unclassifiable.length}`)
}
