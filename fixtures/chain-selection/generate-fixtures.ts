// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Deterministic generator for the chain-selection parity vectors.
//
//   npx tsx fixtures/chain-selection/generate-fixtures.ts
//
// The vector file this writes is the cross-language parity check for
// src/v2/chain-selection: the TypeScript test (tests/v2/chain-selection-parity.test.ts)
// and the Python test (tests/test_chain_selection_parity.py in agent-passport-python,
// against a byte-identical vendored copy) each rebuild every case's inputs from this
// file and assert the recorded outcome member for member. A behaviour difference between
// the two SDKs fails one of them.
//
// Nothing here reads a clock or a random source. Ed25519 seeds are sha256 of a published
// label, so anybody can re-derive them from this file's text alone. The delegations carry
// fixed nonces and fixed times, and Ed25519 signing is deterministic (RFC 8032). Two runs
// emit byte-identical output, and `git diff` after a second run is the check that matters.
//
// Every expected outcome below is OBSERVED: the generator runs the implementation and
// writes down what it returned. Each case also declares the outcome it expects, and the
// generator refuses to write the file if the implementation disagrees, so a behaviour
// change surfaces here rather than being silently re-baselined into the vector.

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
  InMemoryAuthorityBudgetLedger,
  issueAuthorityDelegation,
} from '../../src/v2/authority-delegation/index.js'
import type {
  AuthorityDelegationBodyV1,
  AuthorityDelegationV1,
  RevocationResolution,
} from '../../src/v2/authority-delegation/index.js'
import { selectChainForAction, selectWithFallback } from '../../src/v2/chain-selection/index.js'
import type { HeldChain, RequiredSpendV1, SelectionOutcome } from '../../src/v2/chain-selection/index.js'

// The commit whose src/ tree this generator ran against. The vector file is added on top
// of it, so the repository HEAD carrying this file is a later commit. What this pins is
// the implementation, not the fixture.
const SDK_COMMIT = '86fe72df0bbf998b4e952976eefeebcb04753c20'
const GENERATED_AT = '2026-09-24'

const SEED_LABEL_PREFIX = 'agent-passport-system:chain-selection-vector:'

function seedFromLabel(label: string): string {
  return createHash('sha256').update(SEED_LABEL_PREFIX + label, 'utf8').digest('hex')
}

// Test keys published in a public repository. They control nothing.
const ROOT_LABELS = ['p1', 'p2', 'p3'] as const
type RootLabel = (typeof ROOT_LABELS)[number]

const PRIVATE = Object.fromEntries(ROOT_LABELS.map(l => [l, seedFromLabel(l)])) as Record<RootLabel, string>
const PUBLIC = Object.fromEntries(ROOT_LABELS.map(l => [l, publicKeyFromPrivate(PRIVATE[l])])) as Record<RootLabel, string>

const LEAF = 'did:example:aps-agent-l'
const UNIT = 'iso4217:USD:minor'
const NOW = '2026-03-15T00:00:00.000Z'
const NOT_BEFORE = '2026-03-01T00:00:00.000Z'
const NOT_AFTER = '2026-04-01T00:00:00.000Z'
const ISSUED_AT = '2026-03-01T00:00:00.000Z'

function did(root: RootLabel): string {
  return `did:example:aps-root-${root}`
}

function body(root: RootLabel, grants: string[], ceiling: string, nonce: string): AuthorityDelegationBodyV1 {
  return {
    record_type: AUTHORITY_DELEGATION_RECORD_TYPE,
    version: AUTHORITY_DELEGATION_VERSION,
    parent_delegation_id: null,
    issuer: did(root),
    subject: LEAF,
    verification_method: `${did(root)}#key-1`,
    issued_at: ISSUED_AT,
    nonce,
    authority: {
      scope: { profile: SCOPE_PROFILE_V1, grants },
      spend: { mode: 'bounded', unit: UNIT, per_action: ceiling, cumulative: ceiling },
      depth: { remaining: 1 },
      time: { not_before: NOT_BEFORE, not_after: NOT_AFTER },
      reputation: { profile: REPUTATION_PROFILE_V1, ceiling: 100 },
      values: { profile: VALUES_PROFILE_V1, required: [] },
      reversibility: { profile: REVERSIBILITY_PROFILE_V1, ceiling: 'irreversible' },
    },
  }
}

// Nonces are the first 32 hex characters of the seed digest of a published label, so they
// are re-derivable the same way the keys are.
function nonceFromLabel(label: string): string {
  return seedFromLabel(`nonce:${label}`).slice(0, 32)
}

// Three single-hop records, three different roots, all naming the same leaf. read_r1 and
// read_r1_alt cover the same action from different roots, which is what the fallback
// cases need. Equal ceilings of 5 make their sum, 10, strictly larger than either, so an
// amount of 8 discriminates a pooled ceiling from a single one.
const RECORDS: Record<string, AuthorityDelegationV1> = {
  read_r1: issueAuthorityDelegation(body('p1', ['resource1:read'], '5', nonceFromLabel('read_r1')), PRIVATE.p1),
  write_r2: issueAuthorityDelegation(body('p2', ['resource2:write'], '5', nonceFromLabel('write_r2')), PRIVATE.p2),
  read_r1_alt: issueAuthorityDelegation(body('p3', ['resource1:read'], '5', nonceFromLabel('read_r1_alt')), PRIVATE.p3),
}

// chain_concat is not a chain. It is two roots in one array, the shape a caller reaches
// for to have two chains evaluated as one, and the module refuses it by name.
const CHAINS: Record<string, string[]> = {
  chain_read_r1: ['read_r1'],
  chain_write_r2: ['write_r2'],
  chain_read_r1_alt: ['read_r1_alt'],
  chain_concat: ['read_r1', 'write_r2'],
}

const VERIFICATION_KEYS: Record<string, string> = Object.fromEntries(
  ROOT_LABELS.map(root => [`${did(root)}#key-1`, PUBLIC[root]]),
)

const DELEGATION_IDS: Record<string, string> = Object.fromEntries(
  Object.entries(RECORDS).map(([label, record]) => [label, record.delegation_id]),
)
const LABEL_BY_DELEGATION_ID: Record<string, string> = Object.fromEntries(
  Object.entries(DELEGATION_IDS).map(([label, id]) => [id, label]),
)

function actionRef(caseId: string): string {
  return createHash('sha256').update(caseId, 'utf8').digest('hex')
}

interface VectorCase {
  id: string
  note: string
  api: 'selectChainForAction' | 'selectWithFallback'
  held: string[]
  preferred_chain_id?: string
  fallback?: { authorization_ref: string } | null
  required_grants: string[]
  /** null means the action reserves nothing. "omit_ledger" means it does and no ledger is supplied. */
  amount: string | null
  omit_ledger?: boolean
  /** record label -> answer. A label with no entry makes the resolver throw. */
  revocation: Record<string, RevocationResolution>
  expected: unknown
}

const AUTHORIZED = 'proposed:opaque-fallback-authorization-reference-1'

const ALL_ACTIVE: Record<string, RevocationResolution> = {
  read_r1: 'active',
  write_r2: 'active',
  read_r1_alt: 'active',
}

const CASES: VectorCase[] = [
  {
    id: 'CS-01-select-first-covering-chain',
    note: 'Control. The first held chain covers the action and is the one selected.',
    api: 'selectChainForAction',
    held: ['chain_read_r1', 'chain_write_r2'],
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: ALL_ACTIVE,
    expected: {
      selected: true,
      chain_id: 'chain_read_r1',
      state: 'valid',
      evaluations: [{ chain_id: 'chain_read_r1', outcome: 'authorizes', code: 'RESERVED', chain_state: 'valid' }],
    },
  },
  {
    id: 'CS-02-select-passes-over-non-covering-chain',
    note: 'The held chain that does not cover the action is passed over and recorded as passed over, not merged with the one that does.',
    api: 'selectChainForAction',
    held: ['chain_write_r2', 'chain_read_r1'],
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: ALL_ACTIVE,
    expected: {
      selected: true,
      chain_id: 'chain_read_r1',
      state: 'valid',
      evaluations: [
        { chain_id: 'chain_write_r2', outcome: 'refuses', code: 'scope_not_covered', chain_state: 'valid' },
        { chain_id: 'chain_read_r1', outcome: 'authorizes', code: 'RESERVED', chain_state: 'valid' },
      ],
    },
  },
  {
    id: 'CS-03-no-chain-covers-a-grant-from-each',
    note: 'The action needs one grant from each held chain. No union: neither chain covers both, so nothing is selected.',
    api: 'selectChainForAction',
    held: ['chain_read_r1', 'chain_write_r2'],
    required_grants: ['resource1:read', 'resource2:write'],
    amount: '3',
    revocation: ALL_ACTIVE,
    expected: {
      selected: false,
      code: 'no_chain_covers_action',
      evaluations: [
        { chain_id: 'chain_read_r1', outcome: 'refuses', code: 'scope_not_covered', chain_state: 'valid' },
        { chain_id: 'chain_write_r2', outcome: 'refuses', code: 'scope_not_covered', chain_state: 'valid' },
      ],
    },
  },
  {
    id: 'CS-04-budget-refusal-does-not-scan-past-the-selected-chain',
    note: 'Amount 8 against a ceiling of 5, with a second held chain whose own ceiling is also 5. Two ceilings are never summed, and the refusal ends the call: the second chain is never read, which is what the single evaluation shows.',
    api: 'selectChainForAction',
    held: ['chain_read_r1', 'chain_read_r1_alt'],
    required_grants: ['resource1:read'],
    amount: '8',
    revocation: ALL_ACTIVE,
    expected: {
      selected: false,
      code: 'no_chain_covers_action',
      evaluations: [
        { chain_id: 'chain_read_r1', outcome: 'refuses', code: 'PER_ACTION_EXCEEDED', chain_state: 'valid' },
      ],
    },
  },
  {
    id: 'CS-05-concatenated-chains-are-refused-as-a-presentation',
    note: 'Two roots in one array. Refused as a chain set presented as one chain, before verification, and never evaluated as a union.',
    api: 'selectChainForAction',
    held: ['chain_concat'],
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: ALL_ACTIVE,
    expected: {
      selected: false,
      code: 'no_valid_chain',
      evaluations: [
        { chain_id: 'chain_concat', outcome: 'refuses', code: 'chain_set_presented_as_one', chain_state: null },
      ],
    },
  },
  {
    id: 'CS-06-revoked-chain-is-not-selected-when-another-holds',
    note: 'No chain had been selected before this call, so choosing the alternative here is a selection, not a switch. Contrast CS-08.',
    api: 'selectChainForAction',
    held: ['chain_read_r1', 'chain_read_r1_alt'],
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: { ...ALL_ACTIVE, read_r1: 'revoked' },
    expected: {
      selected: true,
      chain_id: 'chain_read_r1_alt',
      state: 'valid',
      evaluations: [
        { chain_id: 'chain_read_r1', outcome: 'refuses', code: 'REVOKED', chain_state: 'invalid' },
        { chain_id: 'chain_read_r1_alt', outcome: 'authorizes', code: 'RESERVED', chain_state: 'valid' },
      ],
    },
  },
  {
    id: 'CS-07-every-held-chain-revoked',
    note: 'Nothing was valid, so the answer names that rather than saying a valid chain failed to cover the action.',
    api: 'selectChainForAction',
    held: ['chain_read_r1', 'chain_read_r1_alt'],
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: { ...ALL_ACTIVE, read_r1: 'revoked', read_r1_alt: 'revoked' },
    expected: {
      selected: false,
      code: 'no_valid_chain',
      evaluations: [
        { chain_id: 'chain_read_r1', outcome: 'refuses', code: 'REVOKED', chain_state: 'invalid' },
        { chain_id: 'chain_read_r1_alt', outcome: 'refuses', code: 'REVOKED', chain_state: 'invalid' },
      ],
    },
  },
  {
    id: 'CS-08-fallback-null-reads-no-other-chain',
    note: 'L11, PROPOSED. The selected chain is revoked and another held chain would independently cover the same action. With fallback null, that chain is never read: one evaluation, no switch.',
    api: 'selectWithFallback',
    held: ['chain_read_r1', 'chain_read_r1_alt'],
    preferred_chain_id: 'chain_read_r1',
    fallback: null,
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: { ...ALL_ACTIVE, read_r1: 'revoked' },
    expected: {
      selected: false,
      code: 'no_valid_chain',
      fallback_considered: false,
      evaluations: [{ chain_id: 'chain_read_r1', outcome: 'refuses', code: 'REVOKED', chain_state: 'invalid' }],
    },
  },
  {
    id: 'CS-09-authorized-fallback-records-the-switch',
    note: 'L11, PROPOSED. Same inputs as CS-08 with an opaque authorization reference. The switch happens and is reported: switched_from names the chain the action had selected and the reference is recorded, never interpreted.',
    api: 'selectWithFallback',
    held: ['chain_read_r1', 'chain_read_r1_alt'],
    preferred_chain_id: 'chain_read_r1',
    fallback: { authorization_ref: AUTHORIZED },
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: { ...ALL_ACTIVE, read_r1: 'revoked' },
    expected: {
      selected: true,
      chain_id: 'chain_read_r1_alt',
      state: 'valid',
      switched_from: 'chain_read_r1',
      fallback_ref: AUTHORIZED,
      fallback_considered: true,
      evaluations: [
        { chain_id: 'chain_read_r1', outcome: 'refuses', code: 'REVOKED', chain_state: 'invalid' },
        { chain_id: 'chain_read_r1_alt', outcome: 'authorizes', code: 'RESERVED', chain_state: 'valid' },
      ],
    },
  },
  {
    id: 'CS-10-authorized-fallback-with-nowhere-to-go',
    note: 'L11, PROPOSED. The authorization is present and every held chain is revoked, so the fallback changes nothing and the refusal is reported with the switch never taken.',
    api: 'selectWithFallback',
    held: ['chain_read_r1', 'chain_read_r1_alt'],
    preferred_chain_id: 'chain_read_r1',
    fallback: { authorization_ref: AUTHORIZED },
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: { ...ALL_ACTIVE, read_r1: 'revoked', read_r1_alt: 'revoked' },
    expected: {
      selected: false,
      code: 'no_valid_chain',
      fallback_considered: true,
      evaluations: [
        { chain_id: 'chain_read_r1', outcome: 'refuses', code: 'REVOKED', chain_state: 'invalid' },
        { chain_id: 'chain_read_r1_alt', outcome: 'refuses', code: 'REVOKED', chain_state: 'invalid' },
      ],
    },
  },
  {
    id: 'CS-11-authorized-fallback-not-used-when-the-selected-chain-holds',
    note: 'L11, PROPOSED. An authorization that is present but not needed does not cause a switch and does not appear as one.',
    api: 'selectWithFallback',
    held: ['chain_read_r1', 'chain_read_r1_alt'],
    preferred_chain_id: 'chain_read_r1',
    fallback: { authorization_ref: AUTHORIZED },
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: ALL_ACTIVE,
    expected: {
      selected: true,
      chain_id: 'chain_read_r1',
      state: 'valid',
      fallback_considered: true,
      evaluations: [{ chain_id: 'chain_read_r1', outcome: 'authorizes', code: 'RESERVED', chain_state: 'valid' }],
    },
  },
  {
    id: 'CS-12-preferred-chain-is-not-held',
    note: 'A selection naming a chain the agent does not hold is a request fault, and no chain is read.',
    api: 'selectWithFallback',
    held: ['chain_read_r1'],
    preferred_chain_id: 'chain_absent',
    fallback: null,
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: ALL_ACTIVE,
    expected: { selected: false, code: 'preferred_chain_not_held', evaluations: [] },
  },
  {
    id: 'CS-13-duplicate-chain-id',
    note: 'Two held entries under one label. Refused rather than disambiguated: a result naming that label would not identify a chain.',
    api: 'selectChainForAction',
    held: ['chain_read_r1', 'chain_read_r1'],
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: ALL_ACTIVE,
    expected: { selected: false, code: 'duplicate_chain_id', evaluations: [] },
  },
  {
    id: 'CS-14-empty-held-set',
    note: 'An agent holding nothing selects nothing.',
    api: 'selectChainForAction',
    held: [],
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: ALL_ACTIVE,
    expected: { selected: false, code: 'held_set_empty', evaluations: [] },
  },
  {
    id: 'CS-15-needed-grant-is-not-a-valid-scope-grant',
    note: 'A request fault, kept apart from scope_not_covered: no chain refused anything here, because no chain was coherently asked.',
    api: 'selectChainForAction',
    held: ['chain_read_r1'],
    required_grants: ['resource1:*:read'],
    amount: '3',
    revocation: ALL_ACTIVE,
    expected: { selected: false, code: 'invalid_action_requirement', evaluations: [] },
  },
  {
    id: 'CS-16-spend-required-and-no-ledger-is-undecided',
    note: 'Not established, not a refusal. The chain verified valid and covers the scope; whether its ceiling covers the amount was never asked.',
    api: 'selectChainForAction',
    held: ['chain_read_r1'],
    required_grants: ['resource1:read'],
    amount: '3',
    omit_ledger: true,
    revocation: ALL_ACTIVE,
    expected: {
      selected: false,
      code: 'selection_undecided',
      evaluations: [
        { chain_id: 'chain_read_r1', outcome: 'undecided', code: 'spend_ledger_unavailable', chain_state: 'valid' },
      ],
    },
  },
  {
    id: 'CS-17-unknown-revocation-is-undecided-not-refused',
    note: 'draft-03 section 3.3 makes an unavailable or stale revocation result indeterminate. The selection keeps it out of refused as well, so the answer is not established rather than a denial.',
    api: 'selectChainForAction',
    held: ['chain_read_r1'],
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: { ...ALL_ACTIVE, read_r1: 'unknown' },
    expected: {
      selected: false,
      code: 'selection_undecided',
      evaluations: [
        { chain_id: 'chain_read_r1', outcome: 'undecided', code: 'REVOCATION_UNKNOWN', chain_state: 'indeterminate' },
      ],
    },
  },
  {
    id: 'CS-18-undecided-chain-does-not-block-a-covering-chain',
    note: 'An undecided candidate is recorded and the selection continues; the chain that does authorize the action is still the one selected.',
    api: 'selectChainForAction',
    held: ['chain_read_r1', 'chain_read_r1_alt'],
    required_grants: ['resource1:read'],
    amount: '3',
    revocation: { ...ALL_ACTIVE, read_r1: 'unknown' },
    expected: {
      selected: true,
      chain_id: 'chain_read_r1_alt',
      state: 'valid',
      evaluations: [
        { chain_id: 'chain_read_r1', outcome: 'undecided', code: 'REVOCATION_UNKNOWN', chain_state: 'indeterminate' },
        { chain_id: 'chain_read_r1_alt', outcome: 'authorizes', code: 'RESERVED', chain_state: 'valid' },
      ],
    },
  },
  {
    id: 'CS-19-no-spend-requirement-selects-on-scope-alone',
    note: 'An action that reserves nothing needs no ledger, and the evaluation says which check admitted it.',
    api: 'selectChainForAction',
    held: ['chain_read_r1'],
    required_grants: ['resource1:read'],
    amount: null,
    revocation: ALL_ACTIVE,
    expected: {
      selected: true,
      chain_id: 'chain_read_r1',
      state: 'valid',
      evaluations: [{ chain_id: 'chain_read_r1', outcome: 'authorizes', code: 'scope_covered', chain_state: 'valid' }],
    },
  },
]

function heldFor(vector: VectorCase): HeldChain[] {
  return vector.held.map(name => ({
    chain_id: name,
    chain: CHAINS[name].map(label => RECORDS[label]),
  }))
}

function resolverFor(vector: VectorCase): (delegation: AuthorityDelegationV1) => RevocationResolution {
  return delegation => {
    const label = LABEL_BY_DELEGATION_ID[delegation.delegation_id]
    const answer = label === undefined ? undefined : vector.revocation[label]
    if (answer === undefined) {
      // Fail loud: a case that forgot to state an answer must not read as active.
      throw new Error(`chain-selection vector ${vector.id} has no revocation answer for ${label ?? 'an unknown record'}`)
    }
    return answer
  }
}

function spendFor(vector: VectorCase): RequiredSpendV1 | null {
  return vector.amount === null
    ? null
    : { unit: UNIT, amount: vector.amount, action_ref: actionRef(vector.id) }
}

function run(vector: VectorCase): SelectionOutcome {
  const options = {
    now: NOW,
    resolveVerificationKey: (_issuer: string, method: string) => VERIFICATION_KEYS[method] ?? null,
    trustRoot: () => true,
    resolveRevocation: resolverFor(vector),
  }
  const shared = {
    held: heldFor(vector),
    requiredGrants: vector.required_grants,
    requiredSpend: spendFor(vector),
    options,
    // A fresh ledger per case, so a reservation never leaks between cases.
    reserveBudget: vector.omit_ledger ? null : new InMemoryAuthorityBudgetLedger(),
  }
  return vector.api === 'selectChainForAction'
    ? selectChainForAction(shared)
    : selectWithFallback({
        ...shared,
        preferred_chain_id: vector.preferred_chain_id as string,
        fallback: vector.fallback ?? null,
      })
}

/** The observed outcome, flattened to the members both SDKs record and compare. */
function observed(outcome: SelectionOutcome): Record<string, unknown> {
  const flat: Record<string, unknown> = {
    selected: outcome.selected,
    evaluations: outcome.evaluations.map(item => ({
      chain_id: item.chain_id,
      outcome: item.outcome,
      code: item.code,
      chain_state: item.chain_state,
    })),
  }
  if (outcome.selected) {
    flat.chain_id = outcome.chain_id
    flat.state = outcome.result.state
    if (outcome.switched_from !== undefined) flat.switched_from = outcome.switched_from
    if (outcome.fallback_ref !== undefined) flat.fallback_ref = outcome.fallback_ref
  } else {
    flat.code = outcome.code
  }
  if (outcome.fallback_considered !== undefined) flat.fallback_considered = outcome.fallback_considered
  return flat
}

/** Member order is not part of the claim: compare by sorted member name. */
function stable(value: unknown): string {
  return JSON.stringify(value, (_key, item) =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? Object.fromEntries(Object.entries(item as Record<string, unknown>).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : item,
  )
}

const emitted: unknown[] = []
let mismatches = 0
for (const vector of CASES) {
  const got = observed(run(vector))
  const want = vector.expected as Record<string, unknown>
  if (stable(got) !== stable(want)) {
    mismatches += 1
    console.error(`MISMATCH ${vector.id}`)
    console.error(`  declared: ${JSON.stringify(want)}`)
    console.error(`  observed: ${JSON.stringify(got)}`)
  }
  emitted.push({
    id: vector.id,
    note: vector.note,
    api: vector.api,
    held: vector.held,
    preferred_chain_id: vector.preferred_chain_id ?? null,
    fallback: vector.fallback ?? null,
    required_grants: vector.required_grants,
    required_spend: spendFor(vector),
    ledger: vector.omit_ledger ? 'none' : 'fresh_in_memory',
    revocation: vector.revocation,
    expected: got,
  })
}

if (mismatches > 0) {
  console.error(`${mismatches} case(s) disagree with the implementation; nothing written.`)
  process.exit(1)
}

const output = {
  profile: 'aps-chain-selection-parity-v0',
  description:
    'Cross-language parity vectors for chain selection over the set of chains an agent holds. ' +
    'draft-pidlisnyi-aps-03 section 3.3 lines 594-596 for selection and no union; the fallback ' +
    'members are proposed against invariant candidate L11 of the aeoess/agent-authority-lifecycle ' +
    'concept document and are marked so at every symbol that carries them.',
  generated_at: GENERATED_AT,
  sdk_commit: SDK_COMMIT,
  seed_label_prefix: SEED_LABEL_PREFIX,
  seed_rule:
    'private key = sha256(seed_label_prefix + <root label>) as 64 lowercase hex, used as the RFC 8032 ' +
    'Ed25519 seed; nonce = the first 32 hex characters of sha256(seed_label_prefix + "nonce:" + <record label>). ' +
    'action_ref = sha256(<case id>) in lowercase hex.',
  now: NOW,
  root_labels: ROOT_LABELS,
  verification_keys: VERIFICATION_KEYS,
  records: RECORDS,
  delegation_ids: DELEGATION_IDS,
  chains: CHAINS,
  cases: emitted,
}

const here = dirname(fileURLToPath(import.meta.url))
writeFileSync(join(here, 'chain-selection-vectors-v0.json'), JSON.stringify(output, null, 2) + '\n', 'utf8')
console.log(`chain-selection: ${emitted.length} vectors written, all observed outcomes match their declarations`)
