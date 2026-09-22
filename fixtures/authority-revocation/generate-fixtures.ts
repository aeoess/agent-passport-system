// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic generator for the `aps:authority-revocation:v1` vector family.
//
//   npx tsx fixtures/authority-revocation/generate-fixtures.ts
//
// Nothing here reads a clock or a random source. Every input is fixed:
//
//   - Ed25519 seeds are sha256 of a published label, so anybody can re-derive
//     them from this file's text alone (see SEED_LABEL_PREFIX below).
//   - The target AuthorityDelegationV1 is minted with a fixed nonce and fixed
//     issued_at / not_before / not_after.
//   - The revocation's `now`, `nonce`, `reason_code` and `detail` are constants.
//   - The key-resolver table is data, written into the vector file, so the
//     resolver a consumer runs is the resolver this generator ran.
//
// Ed25519 signing is deterministic (RFC 8032), so two runs emit byte-identical
// output. `git diff` after a second run is the check that matters.
//
// Every expected verification outcome below is OBSERVED: the generator runs the
// merged verifier and writes down what it returned. Each case also declares the
// state and failure code it expects, and the generator refuses to write the file
// if the verifier disagrees, so a behaviour change surfaces here rather than
// being silently re-baselined into the vector.

import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { publicKeyFromPrivate } from '../../src/crypto/keys.js'
import {
  AUTHORITY_DELEGATION_RECORD_TYPE,
  AUTHORITY_DELEGATION_VERSION,
  REPUTATION_PROFILE_V1,
  REVERSIBILITY_PROFILE_V1,
  SCOPE_PROFILE_V1,
  VALUES_PROFILE_V1,
  issueAuthorityDelegation,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
  KeyResolutionFailure,
} from '../../src/v2/authority-delegation/index.js'
import {
  AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN,
  AUTHORITY_REVOCATION_ID_DOMAIN,
  AUTHORITY_REVOCATION_RECORD_TYPE,
  AUTHORITY_REVOCATION_SIGNATURE_DOMAIN,
  AUTHORITY_REVOCATION_VERSION,
  authorityRevocationBody,
  authorityRevocationCascadeOrigin,
  authorityRevocationCascadeTransactionInput,
  authorityRevocationIdInput,
  authorityRevocationSignatureInput,
  computeAuthorityRevocationCascadeTransactionIdForWrite,
  computeAuthorityRevocationIdForWrite,
  issueAuthorityRevocation,
  signAuthorityRevocation,
  verifyAuthorityRevocation,
} from '../../src/v2/authority-revocation/index.js'
import type {
  AuthorityRevocationBodyV1,
  AuthorityRevocationCascadeOriginV1,
  AuthorityRevocationFailureCode,
  AuthorityRevocationV1,
  AuthorityRevocationVerificationResult,
} from '../../src/v2/authority-revocation/index.js'

// ── the SDK this file's outcomes were produced by ─────────────────────────────
// The commit whose src/ tree the generator ran against. The vector files
// themselves are added on top of it, so the repository HEAD that carries this
// file is a later commit; what this SHA pins is the implementation, not the
// fixture.
const SDK_COMMIT = 'f6792af732f2102b239cca6b18840f6fa7d8fe87'
const GENERATED_AT = '2026-09-21'

// ── keys: seeds derived from published labels ─────────────────────────────────
// Any 32 bytes is a valid Ed25519 seed, and src/crypto/keys.ts takes the seed as
// 64 lowercase hex. Deriving it from a label means the vector carries no opaque
// constant: sha256 of the label string IS the private key, re-derivable in any
// language. These are test keys published in a public repository and control
// nothing.
const SEED_LABEL_PREFIX = 'agent-passport-system:authority-revocation-vector:'

function seedFromLabel(label: string): string {
  return createHash('sha256').update(SEED_LABEL_PREFIX + label, 'utf8').digest('hex')
}

const KEY_LABELS = ['issuer-key', 'issuer-rotated-key', 'impostor-key'] as const
type KeyLabel = (typeof KEY_LABELS)[number]

const PRIVATE: Record<KeyLabel, string> = {
  'issuer-key': seedFromLabel('issuer-key'),
  'issuer-rotated-key': seedFromLabel('issuer-rotated-key'),
  'impostor-key': seedFromLabel('impostor-key'),
}
const PUBLIC: Record<KeyLabel, string> = {
  'issuer-key': publicKeyFromPrivate(PRIVATE['issuer-key']),
  'issuer-rotated-key': publicKeyFromPrivate(PRIVATE['issuer-rotated-key']),
  'impostor-key': publicKeyFromPrivate(PRIVATE['impostor-key']),
}

// ── identifiers ───────────────────────────────────────────────────────────────
const ISSUER = 'did:example:aps-root-authority'
const SUBJECT = 'did:example:aps-agent-alpha'
const IMPOSTOR = 'did:example:aps-impostor'
const ISSUER_VM = `${ISSUER}#key-1`
const ISSUER_ROTATED_VM = `${ISSUER}#key-2`
const IMPOSTOR_VM = `${IMPOSTOR}#key-1`

// ── fixed times ───────────────────────────────────────────────────────────────
const DELEGATION_ISSUED_AT = '2026-03-01T00:00:00.000Z'
const DELEGATION_NOT_BEFORE = '2026-03-01T00:00:00.000Z'
const DELEGATION_NOT_AFTER = '2026-04-01T00:00:00.000Z'
const DELEGATION_NONCE = '0f0e0d0c0b0a09080706050403020100'

const REVOKED_AT = '2026-03-15T12:00:00.000Z'
const REVOCATION_NONCE = '3c3d3e3f404142434445464748494a4b'
// Draft-03 section 3.5.1 names a machine-readable reason code and fixes no
// grammar for one. This value is an arbitrary opaque string, not a registry
// entry, and the vector pins its bytes, not its meaning.
const REASON_CODE = 'issuer-key-compromise'
const DETAIL = 'Issuer signing key retired after a hardware replacement.'

// `#key-2` comes into service on this date. The negative case that exercises a
// revocation timestamped before its key existed uses the time below it.
const KEY_1_VALID_FROM = '2026-03-01T00:00:00.000Z'
const KEY_2_VALID_FROM = '2026-03-10T00:00:00.000Z'
const REVOKED_AT_BEFORE_KEY_2 = '2026-03-05T08:00:00.000Z'

// ── the key resolver, as data ─────────────────────────────────────────────────
interface ResolverEntry {
  controller: string
  verification_method: string
  key_valid_from: string
  public_key_hex: string
  key_label: KeyLabel
}

const RESOLVER_ENTRIES: ResolverEntry[] = [
  {
    controller: ISSUER,
    verification_method: ISSUER_VM,
    key_valid_from: KEY_1_VALID_FROM,
    public_key_hex: PUBLIC['issuer-key'],
    key_label: 'issuer-key',
  },
  {
    controller: ISSUER,
    verification_method: ISSUER_ROTATED_VM,
    key_valid_from: KEY_2_VALID_FROM,
    public_key_hex: PUBLIC['issuer-rotated-key'],
    key_label: 'issuer-rotated-key',
  },
  {
    controller: IMPOSTOR,
    verification_method: IMPOSTOR_VM,
    key_valid_from: KEY_1_VALID_FROM,
    public_key_hex: PUBLIC['impostor-key'],
    key_label: 'impostor-key',
  },
]

/**
 * Time-aware resolver over the table above, reproducing draft section 2.4: the
 * key selected is the one bound to the method at the record's own `revoked_at`,
 * not the one current at verification time.
 *
 * A method the table does not carry, and a method whose key was not yet in
 * service at `at`, both answer `not_found`. Section 2.5 names five outcomes and
 * none of them is "exists but not yet valid", so a resolver that keeps its
 * answers inside that vocabulary says not_found. A consumer of this vector
 * reimplements exactly this function; the outcome recorded for
 * `revoked-at-before-key-valid-from` is what this rule produces.
 */
function resolveVerificationKey(
  controller: string,
  verificationMethod: string,
  at: string,
): string | KeyResolutionFailure {
  const entry = RESOLVER_ENTRIES.find(
    item => item.controller === controller && item.verification_method === verificationMethod,
  )
  if (!entry) return { outcome: 'not_found' }
  if (at < entry.key_valid_from) return { outcome: 'not_found' }
  return entry.public_key_hex
}

// ── the target delegation ─────────────────────────────────────────────────────
const delegationBody: AuthorityDelegationBodyV1 = {
  record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
  version: AUTHORITY_DELEGATION_VERSION,
  parent_delegation_id: null,
  issuer: ISSUER,
  subject: SUBJECT,
  verification_method: ISSUER_VM,
  issued_at: DELEGATION_ISSUED_AT,
  nonce: DELEGATION_NONCE,
  authority: {
    scope: { profile: SCOPE_PROFILE_V1, grants: ['commerce:checkout'] },
    spend: {
      mode: 'bounded',
      unit: 'iso4217:USD:minor',
      per_action: '2500',
      cumulative: '50000',
    },
    depth: { remaining: 2 },
    time: { not_before: DELEGATION_NOT_BEFORE, not_after: DELEGATION_NOT_AFTER },
    reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 75 },
    values: { profile: VALUES_PROFILE_V1, required: ['F-001', 'F-003'] },
    reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'compensable' },
  },
}

const delegation: AuthorityDelegationV1 = issueAuthorityDelegation(
  delegationBody,
  PRIVATE['issuer-key'],
)

// ── the valid revocation ──────────────────────────────────────────────────────
const validRevocation: AuthorityRevocationV1 = issueAuthorityRevocation(
  delegation,
  {
    now: REVOKED_AT,
    revoker: ISSUER,
    verification_method: ISSUER_VM,
    reason_code: REASON_CODE,
    detail: DETAIL,
    nonce: REVOCATION_NONCE,
  },
  PRIVATE['issuer-key'],
)

// ── helpers ───────────────────────────────────────────────────────────────────
const hex = (value: string): string => Buffer.from(value, 'utf8').toString('hex')

type MutableRecord = Record<string, unknown>

/** A plain-JSON clone, so a mutated case never aliases the record it came from. */
function asMutable(revocation: unknown): MutableRecord {
  return JSON.parse(JSON.stringify(revocation)) as MutableRecord
}

/**
 * Mint a self-consistent record whose `revoker` is NOT the target's issuer.
 *
 * issueAuthorityRevocation() refuses this input (REVOKER_NOT_ISSUER) precisely
 * because the draft's section 3.5 authorization rule is applied at issuance, so
 * the record is assembled here from the same write-boundary primitives issuance
 * uses. What comes out is byte-for-byte what issuance would have emitted had the
 * authorization check passed: every identifier recomputes and the signature is
 * genuine. That is the point of the case — the verifier must reject it on the
 * authorization rule alone, with nothing structural to catch.
 */
function mintUnauthorizedRevocation(
  revoker: string,
  verificationMethod: string,
  privateKey: string,
  nonce: string,
): AuthorityRevocationV1 {
  const origin: AuthorityRevocationCascadeOriginV1 = {
    record_type: AUTHORITY_REVOCATION_RECORD_TYPE,
    version: AUTHORITY_REVOCATION_VERSION,
    delegation_id: delegation.delegation_id,
    revoker,
    verification_method: verificationMethod,
    revoked_at: REVOKED_AT,
    reason_code: REASON_CODE,
    detail: DETAIL,
    nonce,
  }
  const body: AuthorityRevocationBodyV1 = {
    ...origin,
    cascade_transaction_id: computeAuthorityRevocationCascadeTransactionIdForWrite(origin),
  }
  const unsigned: Omit<AuthorityRevocationV1, 'signature'> = {
    ...body,
    revocation_id: computeAuthorityRevocationIdForWrite(body),
  }
  return { ...unsigned, signature: signAuthorityRevocation(unsigned, privateKey) }
}

// ── negative cases ────────────────────────────────────────────────────────────
interface NegativeCase {
  name: string
  defect: string
  expect_state: AuthorityRevocationVerificationResult['state']
  expect_code: AuthorityRevocationFailureCode
  record: MutableRecord
}

const TAMPERED_REASON_CODE = 'routine-rotation'

// 1 — one field changed, every identifier and the signature left as minted.
const tamperedStale = asMutable(validRevocation)
tamperedStale.reason_code = TAMPERED_REASON_CODE

// 2 — the same tamper with the cascade identity repaired. `reason_code` is
//     inside the cascade origin, so repairing that is the first thing an
//     attacker who reads canonical.ts can do; `revocation_id` is then stale.
const tamperedCascadeRepaired = asMutable(validRevocation)
tamperedCascadeRepaired.reason_code = TAMPERED_REASON_CODE
tamperedCascadeRepaired.cascade_transaction_id =
  computeAuthorityRevocationCascadeTransactionIdForWrite(
    authorityRevocationCascadeOrigin(
      authorityRevocationBody(tamperedCascadeRepaired as unknown as AuthorityRevocationV1),
    ),
  )

// 3 — both identifiers repaired, the minted signature kept. This is what makes
//     `revocation_id` worth signing: it is inside the signature preimage, so a
//     record whose identifiers all recompute still fails on the signature.
const tamperedIdsRepaired = asMutable(tamperedCascadeRepaired)
tamperedIdsRepaired.revocation_id = computeAuthorityRevocationIdForWrite(
  authorityRevocationBody(tamperedIdsRepaired as unknown as AuthorityRevocationV1),
)

// 7 — a record timestamped before its verification method was in service.
const beforeKeyValid: AuthorityRevocationV1 = issueAuthorityRevocation(
  delegation,
  {
    now: REVOKED_AT_BEFORE_KEY_2,
    revoker: ISSUER,
    verification_method: ISSUER_ROTATED_VM,
    reason_code: REASON_CODE,
    detail: DETAIL,
    nonce: REVOCATION_NONCE,
  },
  PRIVATE['issuer-rotated-key'],
)

// 4 — a shape-valid cascade identity lifted from a different, genuine record.
//     Not a string of zeroes: the defect is that it belongs to another cascade.
const cascadeSwapped = asMutable(validRevocation)
cascadeSwapped.cascade_transaction_id = beforeKeyValid.cascade_transaction_id

// 5 — the impostor revoking somebody else's delegation, self-consistently.
const revokerNotIssuer = mintUnauthorizedRevocation(
  IMPOSTOR,
  IMPOSTOR_VM,
  PRIVATE['impostor-key'],
  REVOCATION_NONCE,
)

// 6 — correct revoker, correct verification method, wrong signing key. The body
//     is identical to the valid record's; only the signature differs, because
//     the private key is not part of any preimage.
const signedByNonIssuer: AuthorityRevocationV1 = issueAuthorityRevocation(
  delegation,
  {
    now: REVOKED_AT,
    revoker: ISSUER,
    verification_method: ISSUER_VM,
    reason_code: REASON_CODE,
    detail: DETAIL,
    nonce: REVOCATION_NONCE,
  },
  PRIVATE['impostor-key'],
)

// 8, 9 — the two version members.
const recordTypeChanged = asMutable(validRevocation)
recordTypeChanged.record_type = 'aps:authority-revocation:v2'

const versionChanged = asMutable(validRevocation)
versionChanged.version = '2.0'

const negativeCases: NegativeCase[] = [
  {
    name: 'tampered-reason-code-stale-ids',
    defect: `reason_code changed from "${REASON_CODE}" to "${TAMPERED_REASON_CODE}"; revocation_id, cascade_transaction_id and signature are the ones minted for the valid record. reason_code is inside the cascade origin, and the verifier checks the cascade identity before the record identifier, so this is caught as CASCADE_TRANSACTION_MISMATCH rather than ID_MISMATCH.`,
    expect_state: 'invalid',
    expect_code: 'CASCADE_TRANSACTION_MISMATCH',
    record: tamperedStale,
  },
  {
    name: 'tampered-reason-code-cascade-repaired',
    defect: 'The same reason_code tamper with cascade_transaction_id recomputed over the tampered origin, so the cascade check passes and the stale revocation_id is what fails.',
    expect_state: 'invalid',
    expect_code: 'ID_MISMATCH',
    record: tamperedCascadeRepaired,
  },
  {
    name: 'tampered-reason-code-ids-repaired',
    defect: 'The same reason_code tamper with BOTH identifiers recomputed, carrying the signature minted for the valid record. revocation_id sits inside the signature preimage, so everything recomputes and the signature still fails.',
    expect_state: 'invalid',
    expect_code: 'SIGNATURE_INVALID',
    record: tamperedIdsRepaired,
  },
  {
    name: 'cascade-transaction-id-swapped',
    defect: 'cascade_transaction_id replaced with the shape-valid identity of a different genuine record (the one in revoked-at-before-key-valid-from). Nothing else changed.',
    expect_state: 'invalid',
    expect_code: 'CASCADE_TRANSACTION_MISMATCH',
    record: cascadeSwapped,
  },
  {
    name: 'revoker-not-issuer',
    defect: `revoker is ${IMPOSTOR}, which is not the target delegation's issuer. Every identifier recomputes and the Ed25519 signature is genuine under the impostor's own key, so only the section 3.5 authorization rule rejects it.`,
    expect_state: 'invalid',
    expect_code: 'REVOKER_NOT_ISSUER',
    record: asMutable(revokerNotIssuer),
  },
  {
    name: 'signed-by-non-issuer-key',
    defect: `Body identical to the valid record, including revoker and verification_method, but signed with the impostor's private key. The resolver answers ${ISSUER_VM} with the issuer's public key, so the signature check is what fails.`,
    expect_state: 'invalid',
    expect_code: 'SIGNATURE_INVALID',
    record: asMutable(signedByNonIssuer),
  },
  {
    name: 'revoked-at-before-key-valid-from',
    defect: `A genuine record signed by ${ISSUER_ROTATED_VM} and timestamped ${REVOKED_AT_BEFORE_KEY_2}, before that key enters service at ${KEY_2_VALID_FROM}. The resolver selects at revoked_at and answers not_found, so no signature is checked and the outcome is indeterminate, never invalid.`,
    expect_state: 'indeterminate',
    expect_code: 'KEY_NOT_FOUND',
    record: asMutable(beforeKeyValid),
  },
  {
    name: 'record-type-changed',
    defect: 'record_type changed to aps:authority-revocation:v2. The schema stops at the first member and the body is never judged.',
    expect_state: 'unsupported',
    expect_code: 'UNSUPPORTED_RECORD_TYPE',
    record: recordTypeChanged,
  },
  {
    name: 'version-changed',
    defect: 'version changed to 2.0. Same early stop as record-type-changed, under its own code.',
    expect_state: 'unsupported',
    expect_code: 'UNSUPPORTED_VERSION',
    record: versionChanged,
  },
]

// ── run the merged verifier and write down what it returned ───────────────────
function observe(candidate: unknown): AuthorityRevocationVerificationResult {
  return verifyAuthorityRevocation(candidate, delegation, { resolveVerificationKey })
}

function assertObserved(
  name: string,
  observed: AuthorityRevocationVerificationResult,
  expectState: AuthorityRevocationVerificationResult['state'],
  expectCode: AuthorityRevocationFailureCode | null,
): void {
  if (observed.state !== expectState) {
    throw new Error(
      `${name}: expected state ${expectState}, the verifier returned ${observed.state} ` +
      `(${observed.failures.map(item => item.code).join(', ') || 'no failures'})`,
    )
  }
  const code = observed.failures[0]?.code ?? null
  if (code !== expectCode) {
    throw new Error(`${name}: expected failure code ${expectCode}, the verifier returned ${code}`)
  }
}

const validObserved = observe(validRevocation)
assertObserved('valid-direct-revocation', validObserved, 'valid', null)

const negatives = negativeCases.map(item => {
  const observed = observe(item.record)
  assertObserved(item.name, observed, item.expect_state, item.expect_code)
  return {
    name: item.name,
    defect: item.defect,
    record: item.record,
    verification: observed,
  }
})

// ── preimages ─────────────────────────────────────────────────────────────────
const validBody = authorityRevocationBody(validRevocation)
const validOrigin = authorityRevocationCascadeOrigin(validBody)
const { signature: _signature, ...validUnsigned } = validRevocation

const out = {
  family: 'authority-revocation',
  version: 'v1',
  record_type: AUTHORITY_REVOCATION_RECORD_TYPE,
  record_version: AUTHORITY_REVOCATION_VERSION,
  spec: 'APS draft-03 section 3.5.1 — direct revocation of an AuthorityDelegationV1',
  module: 'src/v2/authority-revocation/',
  generated_at: GENERATED_AT,
  sdk_reference: {
    repository: 'aeoess/agent-passport-system',
    commit: SDK_COMMIT,
    note: 'Every value under valid_case.verification and negative_cases[].verification was produced by the TypeScript reference implementation at this commit. The vector files are added on top of that commit, so the repository HEAD carrying them is a later one.',
  },
  canonicalization: 'RFC 8785 JCS (src/core/canonical-jcs.ts): keys sorted as UTF-16 code unit sequences, no insignificant whitespace, nulls preserved, an absent OPTIONAL member omitted rather than written as null.',
  signature_algorithm: 'Ed25519 (RFC 8032), deterministic, over the UTF-8 bytes of the domain-tagged preimage. Raw 64-byte signature as 128 lowercase hex.',
  preimage_encoding: 'hex of the UTF-8 bytes. Each domain tag ends in one NUL byte, which is why these are recorded as hex rather than as text.',
  determinism: `Ed25519 signing is deterministic and nothing here reads a clock or a random source, so re-running fixtures/authority-revocation/generate-fixtures.ts reproduces this file byte for byte. Keys are sha256 of "${SEED_LABEL_PREFIX}<label>".`,
  domain_tags: {
    revocation_id: {
      text: 'APS-AUTHORITY-REVOCATION-ID-V1\\0',
      hex: hex(AUTHORITY_REVOCATION_ID_DOMAIN),
    },
    signature: {
      text: 'APS-AUTHORITY-REVOCATION-SIGNATURE-V1\\0',
      hex: hex(AUTHORITY_REVOCATION_SIGNATURE_DOMAIN),
    },
    cascade_transaction_id: {
      text: 'APS-AUTHORITY-REVOCATION-CASCADE-TRANSACTION-ID-V1\\0',
      hex: hex(AUTHORITY_REVOCATION_CASCADE_TRANSACTION_DOMAIN),
    },
  },
  keys: KEY_LABELS.map(label => ({
    label,
    seed_label: SEED_LABEL_PREFIX + label,
    seed_derivation: 'sha256(utf8(seed_label)) — the 32 bytes ARE the Ed25519 seed',
    private_key_hex: PRIVATE[label],
    public_key_hex: PUBLIC[label],
  })),
  key_resolver: {
    description: 'The resolver input this vector was generated against, as data. Look up the (controller, verification_method) pair; when no entry matches, or when the record\'s revoked_at is earlier than the entry\'s key_valid_from, answer the section 2.5 outcome "not_found"; otherwise answer public_key_hex. The verifier hands the resolver the TARGET delegation\'s issuer as the controller, never the revocation\'s own revoker.',
    outcome_vocabulary: ['not_found', 'ambiguous', 'malformed', 'unreachable', 'unsupported_scheme'],
    entries: RESOLVER_ENTRIES,
  },
  valid_case: {
    name: 'valid-direct-revocation',
    description: 'The issuer revokes its own root delegation with a key that is in service at revoked_at.',
    target_delegation: delegation,
    revocation: validRevocation,
    preimages: {
      cascade_transaction_id_preimage_hex: hex(
        authorityRevocationCascadeTransactionInput(validOrigin),
      ),
      cascade_transaction_id_preimage_source: 'cascade_transaction_id domain tag + JCS(revocation without revocation_id, signature and cascade_transaction_id)',
      revocation_id_preimage_hex: hex(authorityRevocationIdInput(validBody)),
      revocation_id_preimage_source: 'revocation_id domain tag + JCS(revocation without revocation_id and signature)',
      signature_preimage_hex: hex(authorityRevocationSignatureInput(validUnsigned)),
      signature_preimage_source: 'signature domain tag + JCS(revocation without signature); revocation_id IS inside these bytes',
    },
    derived: {
      cascade_transaction_id: validRevocation.cascade_transaction_id,
      revocation_id: validRevocation.revocation_id,
      signature: validRevocation.signature,
      public_key_hex: PUBLIC['issuer-key'],
      signing_key_label: 'issuer-key',
    },
    verification: validObserved,
  },
  negative_cases: negatives,
  not_covered: [
    'Derived revocation records for descendants of the revoked delegation (0B). This family covers one direct revocation of one delegation and nothing that a cascade would produce from it.',
    'The cascade-completion record (0C). Section 3.5.1 makes completion depend on the last descendant\'s revocation being persistent, and no store interface in this repository establishes persistence.',
    'Store behaviour: first-wins insertion, the resolver built over a store, and chain-level enforcement of a revoked ancestor. Those live in tests/v2/authority-revocation.test.ts and are not pinned as vectors here.',
    'JCS escaping of non-ASCII and control characters. Every string in this family is printable ASCII on purpose; the escaping rules are pinned by tests/cross-impl/jcs-test-vectors.json.',
  ],
}

const dir = dirname(fileURLToPath(import.meta.url))
const path = join(dir, 'authority-revocation-vectors-v1.json')
writeFileSync(path, JSON.stringify(out, null, 2) + '\n')
process.stdout.write(
  `wrote 1 valid case + ${negatives.length} negative cases -> ${path}\n`,
)
