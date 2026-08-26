// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Revocation verification v0.1: known-answer corpus
// ══════════════════════════════════════════════════════════════════
// Everything asserted here comes from the shared fixture
// vectors/revocation-verification-v0.1-vectors.json. Nothing is inlined,
// so a second implementation can load the same file and be held to the
// same answers.
//
// What makes this more than a self-consistency check:
//   - every signature in the fixture is re-derived from the five pinned
//     seeds, by trying ALL of them and requiring exactly one to reproduce
//     the record. That also proves which key did NOT sign it.
//   - every revocation_artifact_digest is recomputed with node:crypto
//     directly, assembling the domain bytes here rather than calling
//     digest.ts, so the module cannot certify its own output.
//   - the pinned canonical strings are rebuilt a second way, with
//     JSON.stringify over hand-sorted keys, which does not route through
//     the APS canonicalizer at all.
//   - one negative control (V04) shows verifyRevocation ALONE accepts the
//     forged record, so the cross-object check is not vacuous.
// ══════════════════════════════════════════════════════════════════

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { canonicalizeForWrite } from '../../../core/canonical.js'
import { canonicalizeJCSForWrite } from '../../../core/canonical-jcs.js'
import { verifyRevocation } from '../../../core/delegation.js'
import { sign, publicKeyFromPrivate } from '../../../crypto/keys.js'
import { issuePrincipalBindingV1 } from '../../identity-binding/principal-binding.js'
import { issuePrincipalBindingRevocationV1 } from '../../identity-binding/revocation.js'
import type {
  HistoricalKeyResolutionResult,
  HistoricalKeyResolver,
  PrincipalBindingV1,
} from '../../identity-binding/types.js'
import type { Delegation, RevocationRecord } from '../../../types/passport.js'
import { verifyPublicationCommitment } from '../publication.js'
import { verifyRevocationEvidence } from '../verify.js'
import type { RevocationVerificationResult } from '../types.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

// ── independent primitives (node:crypto only; NOT the module's hashers) ──

const ARTIFACT_DOMAIN = 'APS-REVOCATION-ARTIFACT-V0'

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

/** Reassembles UTF8(domain) || 0x00 || UTF8(canonical) by hand. */
function independentArtifactDigest(canonical: string): string {
  const preimage = Buffer.concat([
    Buffer.from(ARTIFACT_DOMAIN, 'utf8'),
    Buffer.from([0x00]),
    Buffer.from(canonical, 'utf8'),
  ])
  return 'sha256:' + createHash('sha256').update(preimage).digest('hex')
}

const LOWER_HEX = /^[0-9a-f]+$/
const DIGEST_FORM = /^sha256:[0-9a-f]{64}$/

function isHex(value: unknown, length: number): boolean {
  return typeof value === 'string' && value.length === length && LOWER_HEX.test(value)
}

// ── fixture ──

interface ResolverSegment {
  controller: string
  verification_method: string
  from: string
  until: string
  state: HistoricalKeyResolutionResult['state']
  public_key_hex?: string
}
interface ResolverTable {
  segments: ResolverSegment[]
  fallback: HistoricalKeyResolutionResult['state']
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
  publication?: Array<{
    name: string
    proof: { committed_digest: string }
    artifact: unknown
    expected: { publication_verified: boolean }
  }>
}

const fixture = JSON.parse(readFileSync(
  join(__dirname, '..', 'vectors', 'revocation-verification-v0.1-vectors.json'),
  'utf8',
)) as {
  version: string
  fixed_inputs: {
    seeds: Record<string, string>
    pubkeys: Record<string, string>
    agent_id: string
    principal_id: string
    verification_method: string
    status_uri: string
    binding_nonce: string
    other_binding_nonce: string
    issued_at: string
    expires_at: string
    delegation: Delegation
    binding: PrincipalBindingV1
    unsupplied_binding: PrincipalBindingV1
  }
  jcs_kats: Array<{
    name: string
    kind: string
    input: unknown
    expected: string
    sha256: string
    revocation_artifact_digest: string
  }>
  ed25519: { seed: string; pubkey: string; msg: string; msg_utf8_hex: string; signature: string }
  cases: VectorCase[]
}

const SEED_NAMES = ['delegator', 'delegate', 'forger', 'principal_current', 'principal_former']

/** Artifacts the corpus tampers with on purpose, and the single field the
 *  tamper touches. Every other artifact must re-derive exactly. */
const TAMPERED: Record<string, 'signature' | 'revocation_id'> = {
  V05: 'signature',
  V07: 'revocation_id',
  V17: 'signature',
  V18: 'signature',
  V19: 'signature',
}

/** The seed that signed the artifact BEFORE the corpus corrupted it. Only the
 *  cases whose signer is not their path's default appear here: V17 is signed by
 *  the forger, which is the whole point of it. */
const TAMPER_SIGNER: Record<string, string> = {
  V17: 'forger',
}

/** Deliberately reimplemented rather than imported from the generator, so
 *  the JSON table is the only thing the two sides share. */
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

function runCase(entry: VectorCase): Promise<RevocationVerificationResult> {
  const delegation = entry.inputs.delegation
  const binding = entry.inputs.binding
  return verifyRevocationEvidence({
    artifacts: entry.inputs.artifacts,
    delegations: new Map([[delegation.delegationId, delegation]]),
    bindings: new Map([[binding.binding_id, binding]]),
    resolver: resolverFromTable(entry.inputs.resolver_table),
  })
}

function isBindingRevocation(artifact: unknown): artifact is Record<string, string> {
  return typeof artifact === 'object' && artifact !== null &&
    (artifact as Record<string, unknown>).record_type === 'aps.principal-binding-revocation'
}

function isDelegationRevocation(artifact: unknown): artifact is RevocationRecord {
  return typeof artifact === 'object' && artifact !== null &&
    typeof (artifact as Record<string, unknown>).delegationId === 'string' &&
    typeof (artifact as Record<string, unknown>).revokedBy === 'string'
}

// ══════════════════════════════════════════════════════════════════
// 1. Fixed inputs
// ══════════════════════════════════════════════════════════════════

test('fixture: version and case list are the pinned corpus', () => {
  assert.equal(fixture.version, 'revocation-verification/0.1')
  assert.deepEqual(
    fixture.cases.map(entry => entry.name),
    ['V01', 'V02', 'V03', 'V04', 'V05', 'V06', 'V07', 'V08',
      'V09', 'V10', 'V11', 'V12', 'V13', 'V14', 'V15', 'V16',
      'V17', 'V18', 'V19'],
  )
})

test('fixed seeds derive the pinned public keys', () => {
  for (const name of SEED_NAMES) {
    const seed = fixture.fixed_inputs.seeds[name]
    assert.ok(isHex(seed, 64), `${name} seed is 64 lowercase hex`)
    assert.equal(publicKeyFromPrivate(seed), fixture.fixed_inputs.pubkeys[name], name)
    assert.ok(isHex(fixture.fixed_inputs.pubkeys[name], 64), `${name} pubkey is 64 lowercase hex`)
  }
})

test('the pinned delegation is signed by the delegator seed and by no other', () => {
  const { signature, ...unsigned } = fixture.fixed_inputs.delegation
  const canonical = canonicalizeForWrite(unsigned)
  const matches = SEED_NAMES.filter(name => sign(canonical, fixture.fixed_inputs.seeds[name]) === signature)
  assert.deepEqual(matches, ['delegator'])
  assert.equal(fixture.fixed_inputs.delegation.delegatedBy, fixture.fixed_inputs.pubkeys.delegator)
  assert.equal(fixture.fixed_inputs.delegation.delegatedTo, fixture.fixed_inputs.pubkeys.delegate)
  assert.ok(isHex(signature, 128), 'delegation signature is 128 lowercase hex')
})

test('both pinned bindings are re-derived from the principal_current seed', () => {
  const common = {
    agent_id: fixture.fixed_inputs.agent_id,
    principal_id: fixture.fixed_inputs.principal_id,
    verification_method: fixture.fixed_inputs.verification_method,
    audiences: ['https://gateway.example/aps'],
    authority_profiles: ['aps.principal-binding.v1'],
    status_uri: fixture.fixed_inputs.status_uri,
    issued_at: fixture.fixed_inputs.issued_at,
    expires_at: fixture.fixed_inputs.expires_at,
    principal_private_key_hex: fixture.fixed_inputs.seeds.principal_current,
  }
  assert.deepEqual(
    issuePrincipalBindingV1({ ...common, nonce: fixture.fixed_inputs.binding_nonce }),
    fixture.fixed_inputs.binding,
  )
  assert.deepEqual(
    issuePrincipalBindingV1({ ...common, nonce: fixture.fixed_inputs.other_binding_nonce }),
    fixture.fixed_inputs.unsupplied_binding,
  )
  assert.notEqual(
    fixture.fixed_inputs.binding.binding_id,
    fixture.fixed_inputs.unsupplied_binding.binding_id,
  )
})

// ══════════════════════════════════════════════════════════════════
// 2. Every signature re-derived from the seeds
// ══════════════════════════════════════════════════════════════════

test('every delegation revocation artifact is re-derived from exactly one pinned seed', () => {
  let checked = 0
  for (const entry of fixture.cases) {
    for (const artifact of entry.inputs.artifacts) {
      if (!isDelegationRevocation(artifact)) continue
      checked++
      const { signature, ...unsigned } = artifact
      const canonical = canonicalizeForWrite(unsigned)
      const matches = SEED_NAMES.filter(name => sign(canonical, fixture.fixed_inputs.seeds[name]) === signature)
      if (TAMPERED[entry.name] === 'signature') {
        // The corrupted record must be reproducible by NO seed, and must
        // differ from the honest one in exactly the first hex digit.
        assert.deepEqual(matches, [], `${entry.name}: tampered signature reproduces from a seed`)
        const honest = sign(canonical, fixture.fixed_inputs.seeds[TAMPER_SIGNER[entry.name] ?? 'delegator'])
        assert.equal(signature.slice(1), honest.slice(1), `${entry.name}: tamper is wider than one digit`)
        assert.notEqual(signature[0], honest[0], `${entry.name}: tamper changed nothing`)
        continue
      }
      assert.equal(matches.length, 1, `${entry.name}: expected exactly one signing seed, got ${matches.join(',')}`)
      assert.equal(
        fixture.fixed_inputs.pubkeys[matches[0]],
        artifact.revokedBy,
        `${entry.name}: the signing seed is not the key named in revokedBy`,
      )
      assert.ok(isHex(signature, 128), `${entry.name}: signature is 128 lowercase hex`)
    }
  }
  assert.ok(checked >= 8, `expected the corpus to carry delegation artifacts, saw ${checked}`)
})

test('every binding revocation artifact is re-derived from exactly one pinned seed', () => {
  let checked = 0
  for (const entry of fixture.cases) {
    for (const artifact of entry.inputs.artifacts) {
      if (!isBindingRevocation(artifact)) continue
      checked++
      const draft = {
        binding_id: artifact.binding_id,
        principal_id: artifact.principal_id,
        verification_method: artifact.verification_method,
        revoked_at: artifact.revoked_at,
        reason_code: artifact.reason_code,
        nonce: artifact.nonce,
      }
      const reissued = SEED_NAMES.map(name => ({
        name,
        record: issuePrincipalBindingRevocationV1({
          ...draft,
          principal_private_key_hex: fixture.fixed_inputs.seeds[name],
        }),
      }))
      if (TAMPERED[entry.name] === 'signature') {
        // The corrupted record reproduces from NO seed, while its
        // revocation_id still recomputes from every one of them: the digest
        // omits the signature, so the tamper is provably confined to the
        // signature and the discard cannot be an ID mismatch in disguise.
        const bySignature = reissued.filter(candidate => candidate.record.signature === artifact.signature)
        assert.deepEqual(bySignature.map(candidate => candidate.name), [],
          `${entry.name}: tampered signature reproduces from a seed`)
        for (const candidate of reissued) {
          assert.equal(candidate.record.revocation_id, artifact.revocation_id,
            `${entry.name}: revocation_id no longer recomputes, the tamper is wider than the signature`)
        }
        const honestName = TAMPER_SIGNER[entry.name] ?? 'principal_current'
        const honest = reissued.find(candidate => candidate.name === honestName)
        assert.ok(honest, `${entry.name}: no reissue for seed ${honestName}`)
        assert.equal(artifact.signature.slice(1), honest!.record.signature.slice(1),
          `${entry.name}: tamper is wider than one digit`)
        assert.notEqual(artifact.signature[0], honest!.record.signature[0],
          `${entry.name}: tamper changed nothing`)
        continue
      }
      if (TAMPERED[entry.name] === 'revocation_id') {
        // revocation_id is a digest of the draft, so every re-issue agrees on
        // it and every one of them disagrees with the tampered record.
        for (const candidate of reissued) {
          assert.notEqual(candidate.record.revocation_id, artifact.revocation_id,
            `${entry.name}: tampered revocation_id still recomputes`)
        }
        const signer = reissued.filter(candidate => candidate.record.signature === artifact.signature)
        assert.equal(signer.length, 1, `${entry.name}: expected exactly one signing seed`)
        continue
      }
      const matches = reissued.filter(candidate =>
        candidate.record.signature === artifact.signature &&
        candidate.record.revocation_id === artifact.revocation_id)
      assert.equal(matches.length, 1, `${entry.name}: expected exactly one signing seed`)
      assert.ok(isHex(artifact.revocation_id, 64), `${entry.name}: revocation_id is 64 lowercase hex`)
      assert.ok(isHex(artifact.signature, 128), `${entry.name}: signature is 128 lowercase hex`)
      assert.ok(isHex(artifact.nonce, 32), `${entry.name}: nonce is 32 lowercase hex`)
    }
  }
  assert.ok(checked >= 7, `expected the corpus to carry binding artifacts, saw ${checked}`)
})

test('ed25519 block reproduces for the delegator seed', () => {
  const block = fixture.ed25519
  assert.equal(publicKeyFromPrivate(block.seed), block.pubkey)
  assert.equal(Buffer.from(block.msg, 'utf8').toString('hex'), block.msg_utf8_hex)
  assert.equal(sign(block.msg, block.seed), block.signature)
  assert.ok(isHex(block.signature, 128))
})

// ══════════════════════════════════════════════════════════════════
// 3. Canonical bytes and digests
// ══════════════════════════════════════════════════════════════════

test('every pinned canonical string is what canonicalizeJCSForWrite emits', () => {
  for (const entry of fixture.cases) {
    assert.equal(entry.artifact_digests.length, entry.inputs.artifacts.length, entry.name)
    for (const row of entry.artifact_digests) {
      assert.equal(canonicalizeJCSForWrite(entry.inputs.artifacts[row.index]), row.canonical,
        `${entry.name}[${row.index}]`)
    }
  }
})

test('every pinned digest is sha256 plus 64 lowercase hex and matches an independent recomputation', () => {
  let checked = 0
  for (const entry of fixture.cases) {
    for (const row of entry.artifact_digests) {
      checked++
      assert.match(row.revocation_artifact_digest, DIGEST_FORM, `${entry.name}[${row.index}]`)
      assert.equal(row.revocation_artifact_digest.length, 'sha256:'.length + 64)
      assert.equal(independentArtifactDigest(row.canonical), row.revocation_artifact_digest,
        `${entry.name}[${row.index}]`)
    }
    for (const subject of entry.expected.subjects) {
      for (const artifact of subject.artifacts) {
        assert.match(artifact.revocation_artifact_digest, DIGEST_FORM, entry.name)
      }
    }
  }
  assert.ok(checked >= 18, `expected the corpus to carry artifacts, saw ${checked}`)
})

test('jcs_kats reproduce three separate ways', () => {
  assert.equal(fixture.jcs_kats.length, 2)
  for (const kat of fixture.jcs_kats) {
    // (a) the APS canonicalizer
    assert.equal(canonicalizeJCSForWrite(kat.input), kat.expected, `${kat.name}: canonicalizer`)
    // (b) JSON.stringify over hand-sorted keys, which never touches the APS
    //     canonicalizer, so a key-order or escaping regression shows up here
    const source = kat.input as Record<string, unknown>
    const handSorted = kat.kind === 'RevocationRecord'
      ? ['delegationId', 'reason', 'revocationId', 'revokedAt', 'revokedBy', 'signature']
      : ['binding_id', 'nonce', 'principal_id', 'reason_code', 'record_type',
        'revocation_id', 'revoked_at', 'signature', 'verification_method', 'version']
    assert.deepEqual(Object.keys(source).slice().sort(), handSorted.slice().sort(),
      `${kat.name}: the record carries exactly the expected members`)
    const rebuilt = '{' + handSorted
      .map(key => `${JSON.stringify(key)}:${JSON.stringify(source[key])}`)
      .join(',') + '}'
    assert.equal(rebuilt, kat.expected, `${kat.name}: hand-sorted rebuild`)
    // (c) the hashes over those bytes
    assert.equal(sha256Hex(kat.expected), kat.sha256, `${kat.name}: sha256`)
    assert.equal(independentArtifactDigest(kat.expected), kat.revocation_artifact_digest,
      `${kat.name}: artifact digest`)
  }
})

// ══════════════════════════════════════════════════════════════════
// 4. The verifier reproduces every case
// ══════════════════════════════════════════════════════════════════

test('the verifier reproduces every pinned case result exactly', async () => {
  for (const entry of fixture.cases) {
    const produced = await runCase(entry)
    assert.deepEqual(produced, entry.expected, `${entry.name}: ${entry.description}`)
  }
})

test('every pinned outcome is one of the two permitted subject outcomes', () => {
  for (const entry of fixture.cases) {
    for (const subject of entry.expected.subjects) {
      assert.ok(
        subject.outcome === 'REVOKED' || subject.outcome === 'no_revocation_evidence_observed',
        `${entry.name}: ${subject.outcome}`,
      )
    }
    for (const row of entry.expected.unclassifiable) {
      assert.equal(row.outcome, 'malformed', entry.name)
    }
  }
})

// ══════════════════════════════════════════════════════════════════
// 5. Order invariance
// ══════════════════════════════════════════════════════════════════
// discards[].index names a position in the input array, so it is
// order-dependent BY CONSTRUCTION. Everything else must not be: the
// per-subject outcome, the artifact set, duplicate_count, and the multiset
// of discard reasons are all properties of the artifacts, not of the order
// they arrived in.

function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0
}

function orderIndependentView(result: RevocationVerificationResult): unknown {
  return {
    subjects: result.subjects.map(subject => ({
      subject_kind: subject.subject_kind,
      subject_id: subject.subject_id,
      outcome: subject.outcome,
      artifacts: subject.artifacts,
      duplicate_count: subject.duplicate_count,
      discards: subject.discards
        .map(discard => ({ outcome: discard.outcome, reason: discard.reason }))
        .sort((a, b) => compare(a.outcome + ' ' + a.reason, b.outcome + ' ' + b.reason)),
    })),
    unclassifiable: result.unclassifiable
      .map(row => ({ outcome: row.outcome, reason: row.reason }))
      .sort((a, b) => compare(a.outcome + ' ' + a.reason, b.outcome + ' ' + b.reason)),
  }
}

function permutations<T>(items: T[]): T[][] {
  if (items.length <= 1) return [items]
  const out: T[][] = []
  for (let i = 0; i < items.length; i++) {
    const rest = items.slice(0, i).concat(items.slice(i + 1))
    for (const tail of permutations(rest)) out.push([items[i], ...tail])
  }
  return out
}

test('artifact order changes nothing except the input indices', async () => {
  let shuffled = 0
  for (const entry of fixture.cases) {
    if (entry.inputs.artifacts.length < 2) continue
    shuffled++
    const baseline = orderIndependentView(entry.expected)
    for (const order of permutations(entry.inputs.artifacts)) {
      const produced = await runCase({ ...entry, inputs: { ...entry.inputs, artifacts: order } })
      assert.deepEqual(orderIndependentView(produced), baseline, `${entry.name}: permuted`)
    }
  }
  assert.ok(shuffled >= 4, `expected multi-artifact cases to shuffle, saw ${shuffled}`)
})

// ══════════════════════════════════════════════════════════════════
// 6. Publication boundary
// ══════════════════════════════════════════════════════════════════

test('publication commitments reproduce, and a mismatched commitment is false', () => {
  const withPublication = fixture.cases.filter(entry => entry.publication)
  assert.equal(withPublication.length, 1)
  const outcomes: boolean[] = []
  for (const entry of withPublication) {
    for (const proofCase of entry.publication ?? []) {
      const produced = verifyPublicationCommitment(proofCase.proof, proofCase.artifact)
      assert.deepEqual(produced, proofCase.expected, `${entry.name}: ${proofCase.name}`)
      outcomes.push(produced.publication_verified)
    }
  }
  // Both answers must actually occur, or the case proves nothing.
  assert.deepEqual(outcomes, [true, false])
})

test('a proof with no usable committed_digest is false, never thrown', () => {
  const artifact = fixture.cases.find(entry => entry.name === 'V02')?.inputs.artifacts[0]
  assert.ok(artifact)
  assert.deepEqual(
    verifyPublicationCommitment({ committed_digest: 'sha256:' + '0'.repeat(64) }, artifact),
    { publication_verified: false },
  )
  assert.deepEqual(
    verifyPublicationCommitment(undefined as unknown as { committed_digest: string }, artifact),
    { publication_verified: false },
  )
})

// ══════════════════════════════════════════════════════════════════
// 7. Negative control: the cross-object check is not vacuous
// ══════════════════════════════════════════════════════════════════

test('NEGATIVE CONTROL: verifyRevocation alone accepts the V04 forged record', () => {
  const v04 = fixture.cases.find(entry => entry.name === 'V04')
  assert.ok(v04, 'V04 is in the corpus')
  const forged = v04.inputs.artifacts[0] as RevocationRecord

  // 1. The record self-verifies. verifyRevocation checks the signature under
  //    the record's OWN revokedBy field, so a forger who signs their own key
  //    into that field passes.
  assert.equal(verifyRevocation(forged), true,
    'verifyRevocation must accept the forged record, or this control proves nothing')
  assert.equal(forged.revokedBy, fixture.fixed_inputs.pubkeys.forger)

  // 2. The forger is not the delegator, and the delegation says so.
  assert.notEqual(forged.revokedBy, fixture.fixed_inputs.delegation.delegatedBy)
  assert.equal(forged.delegationId, fixture.fixed_inputs.delegation.delegationId)

  // 3. The cross-object verifier rejects it anyway.
  const subject = v04.expected.subjects.find(row =>
    row.subject_kind === 'delegation' && row.subject_id === forged.delegationId)
  assert.ok(subject)
  assert.equal(subject.outcome, 'no_revocation_evidence_observed')
  assert.equal(subject.artifacts.length, 0)
  assert.deepEqual(subject.discards.map(discard => discard.outcome), ['unauthorized_revoker'])
})

test('NEGATIVE CONTROL: the honest record and the forged record differ only in who signed', () => {
  const honest = fixture.cases.find(entry => entry.name === 'V02')?.inputs.artifacts[0] as RevocationRecord
  const forged = fixture.cases.find(entry => entry.name === 'V04')?.inputs.artifacts[0] as RevocationRecord
  assert.equal(verifyRevocation(honest), true)
  assert.equal(verifyRevocation(forged), true)
  assert.equal(honest.delegationId, forged.delegationId)
  assert.notEqual(honest.revokedBy, forged.revokedBy)
})
