// Copyright (c) 2026 Insight (oracleinsight.xyz)
// SPDX-License-Identifier: Apache-2.0
//
// UPSTREAM GENERATOR for the insight.oracle-safety-check:v2 cross-stack
// vectors (conformance issue Agent-Authority-Conformance/aps-conformance-suite#26).
//
// This file is the upstream generator for this evidence type. Per review
// (aeoess/agent-passport-system#119), the committed vectors do NOT live in
// this repo: they are published to the conformance suite at
// fixtures/cross-stack/oracle-safety-check/, which verifies them with the
// published SDK package (agent-passport-system). This repo hosts only the
// generator and the vendored Insight inner-layer implementation.
//
// Every receipt is minted with a FIXED baseline clock so the generated JSON
// is deterministic and independently checkable:
//
//   - OUTER layer uses this repo's own SDK (byte-exact by construction):
//       receipt-core  createReceiptV1 / computeReceiptIdV1
//       action-ref    createActionReferenceInputV2 / computeActionRefV2
//       decision-ref  buildDecisionRefV1
//       delegation    issueAuthorityDelegation / issueSubAuthorityDelegation
//   - INNER layer (Insight OracleSafetyCheck, EIP-712 + ABI-keccak) is
//     vendored in vendor/insight/. Provenance: byte-identical copies of
//     github.com/imokokok/insight-aps, path fixtures/vendor/insight/, commit
//     pinned in the conformance suite's
//     fixtures/cross-stack/oracle-safety-check/SOURCE.md. The
//     deterministic consistency comparison (four ABI-keccak commitments +
//     EIP-712 digest + secp256k1 verification rebuilt from oracle_input,
//     56/56) ships with the vectors in the conformance suite
//     (verify-consistency.ts).
//
// Keypairs are derived per role from the public seed — zero secret material:
//   seed      = SHA-256(utf8(SEED_INPUT))
//   role_seed = SHA-256(utf8(SEED_INPUT) || 0x00 || utf8(role))
//   Ed25519   : private key = role_seed (RFC 8032), public key = derivation
//   secp256k1 : private key = role_seed, address = keccak256(pubkey)[-20:]
//
// Run: npm run fixtures:oracle-safety-check
// The generated oracle-safety-check-v1/ directory is a development artifact:
// it is not committed here. Publish/regenerate the vectors at
// aps-conformance-suite fixtures/cross-stack/oracle-safety-check/.

import crypto from 'node:crypto'
import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { privateKeyToAccount } from 'viem/accounts'

import { canonicalizeJCS } from '../../src/core/canonical-jcs.js'
import { createActionReferenceInputV2, computeActionRefV2, computePayloadRefV1 } from '../../src/v2/action-reference/v2.js'
import { createReceiptV1 } from '../../src/v2/receipt-core/receipt.js'
import { buildDecisionRefV1 } from '../../src/v2/receipt-core/decision-ref.js'
import { issueAuthorityDelegation, issueSubAuthorityDelegation } from '../../src/v2/authority-delegation/issue.js'
import type { AuthorityDelegationBodyV1 } from '../../src/v2/authority-delegation/types.js'

import { signOracleSafetyCheck, type OracleSafetyCheckInput } from './vendor/insight/oracleSafetyCheck.js'
import { OSC_ARTIFACT_TYPE } from './vendor/insight/types.js'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const SEED_INPUT = 'aps-oracle-safety-check-fixture-v1'

export const BASELINE_MS = Date.UTC(2026, 7, 25, 0, 0, 0) // 2026-08-25T00:00:00.000Z
const BASELINE_SEC = Math.floor(BASELINE_MS / 1000)
const BASELINE_ISO = new Date(BASELINE_MS).toISOString()

const ETH_NATIVE = 'eip155:1/slip44:60'
const USDC_ETH = 'eip155:1/erc20:0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48'

const PROVIDERS = ['chainlink', 'api3', 'redstone', 'dia', 'supra', 'winklink', 'switchboard']

export const PRINCIPAL_DID = 'did:aps:insight-principal-001'
export const AGENT_DID = 'did:aps:insight-agent-001'
export const GATEWAY_DID = 'did:aps:insight-gateway-001'
const PRINCIPAL_KEY_ID = `${PRINCIPAL_DID}#keys-1`
const AGENT_KEY_ID = `${AGENT_DID}#keys-1`
const GATEWAY_KEY_ID = `${GATEWAY_DID}#keys-1`

// ---------------------------------------------------------------------------
// Deterministic keys
// ---------------------------------------------------------------------------

export type KeyRole = 'principal' | 'agent' | 'gateway' | 'evm-attester'

const PKCS8_ED25519_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex')

export function sha256Seed(): string {
  return crypto.createHash('sha256').update(SEED_INPUT, 'utf8').digest('hex')
}

export function roleSeedBytes(role: KeyRole): Buffer {
  return crypto
    .createHash('sha256')
    .update(Buffer.concat([Buffer.from(SEED_INPUT, 'utf8'), Buffer.from([0x00]), Buffer.from(role, 'utf8')]))
    .digest()
}

export interface Ed25519Keypair {
  privateKeyHex: string
  publicKeyHex: string
}

function ed25519FromSeed(seed: Buffer): Ed25519Keypair {
  const derKey = Buffer.concat([PKCS8_ED25519_PREFIX, seed])
  const keyObj = crypto.createPrivateKey({ key: derKey, format: 'der', type: 'pkcs8' })
  const pubDer = crypto.createPublicKey(keyObj).export({ type: 'spki', format: 'der' })
  return {
    privateKeyHex: seed.toString('hex'),
    publicKeyHex: Buffer.from(pubDer.slice(-32)).toString('hex'),
  }
}

const keyCache = new Map<KeyRole, Ed25519Keypair>()

export function deriveEd25519(role: Exclude<KeyRole, 'evm-attester'>): Ed25519Keypair {
  const cached = keyCache.get(role)
  if (cached) return cached
  const kp = ed25519FromSeed(roleSeedBytes(role))
  keyCache.set(role, kp)
  return kp
}

export function evmAttester(): { privateKey: `0x${string}`; address: `0x${string}` } {
  const seed = roleSeedBytes('evm-attester')
  const privateKey = `0x${seed.toString('hex')}` as `0x${string}`
  const account = privateKeyToAccount(privateKey)
  return { privateKey, address: account.address }
}

function fixtureNonce(label: string): string {
  return crypto.createHash('sha256').update(`insight-aps:${label}`, 'utf8').digest('hex').slice(0, 32)
}

// ---------------------------------------------------------------------------
// Oracle evidence input (inner layer)
// ---------------------------------------------------------------------------

function oracleInput(verdict: OracleSafetyCheckInput['verdict'], checkedAtSec: number): OracleSafetyCheckInput {
  return {
    verdict,
    sourceAssetId: ETH_NATIVE,
    destinationAssetId: USDC_ETH,
    subjectChainId: 1,
    action: 'swap',
    tradeAmountUsd: 10_000,
    consensusPrice: 3000.12,
    maxDeviationPct: 0.8,
    manipulationRiskScore: 0.05,
    participantCount: PROVIDERS.length,
    crossProviderAgreement: 0.992,
    maxStablecoinDepegPct: 0,
    maxDataAgeSeconds: 9,
    recommendedMaxPositionUsd: 10_000,
    contributingFactors: [],
    providerObservations: PROVIDERS.map((p, i) => ({
      provider: p,
      feedId: p === 'chainlink' ? '0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419' : `${p}:ethusd`,
      value: 3000.12,
      timestamp: checkedAtSec - (2 + i),
      dataAgeSeconds: 2 + i,
      included: true,
      exclusionReason: '',
    })),
    checkedAt: checkedAtSec,
  }
}

// ---------------------------------------------------------------------------
// Authority delegation chain (aps:authority-delegation:v1)
// ---------------------------------------------------------------------------

interface ChainOverrides {
  leafTime?: { not_before: string; not_after: string }
  leafDepthRemaining?: number
}

function authorityVector(
  authority: AuthorityDelegationBodyV1['authority'],
  parent_delegation_id: string | null,
  issuer: string,
  subject: string,
  verification_method: string,
  nonceLabel: string
): Omit<AuthorityDelegationBodyV1, 'record_type' | 'version'> {
  return {
    parent_delegation_id,
    issuer,
    subject,
    verification_method,
    issued_at: BASELINE_ISO,
    nonce: fixtureNonce(nonceLabel),
    authority,
  }
}

function buildChain(overrides: ChainOverrides = {}): {
  root: ReturnType<typeof issueAuthorityDelegation>
  leaf: ReturnType<typeof issueAuthorityDelegation>
} {
  const parentNotBefore = BASELINE_ISO
  const parentNotAfter = new Date(BASELINE_MS + 24 * 3600_000).toISOString()
  const leafNotBefore = overrides.leafTime?.not_before ?? BASELINE_ISO
  const leafNotAfter = overrides.leafTime?.not_after ?? new Date(BASELINE_MS + 3600_000).toISOString()
  const leafDepthRemaining = overrides.leafDepthRemaining ?? 0

  const rootBody: AuthorityDelegationBodyV1 = {
    record_type: 'aps:authority-delegation:v1',
    version: '1.0',
    parent_delegation_id: null,
    issuer: PRINCIPAL_DID,
    subject: AGENT_DID,
    verification_method: PRINCIPAL_KEY_ID,
    issued_at: BASELINE_ISO,
    nonce: fixtureNonce('delegation-root'),
    authority: {
      scope: { profile: 'aps-hierarchical-v1', grants: ['action:swap', 'asset:*', 'chain:eip155:1'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '2000000', cumulative: '2000000' },
      depth: { remaining: 1 },
      time: { not_before: parentNotBefore, not_after: parentNotAfter },
      reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
      values: { profile: 'aps-values-identifiers-v1', required: ['insight:non-manipulated'] },
      reversibility: { profile: 'aps-tci-v1', ceiling: 'compensable' },
    },
  }
  const root = issueAuthorityDelegation(rootBody, deriveEd25519('principal').privateKeyHex)

  const leafBody: AuthorityDelegationBodyV1 = {
    record_type: 'aps:authority-delegation:v1',
    version: '1.0',
    parent_delegation_id: root.delegation_id,
    issuer: AGENT_DID,
    subject: AGENT_DID,
    verification_method: AGENT_KEY_ID,
    issued_at: BASELINE_ISO,
    nonce: fixtureNonce('delegation-leaf'),
    authority: {
      scope: { profile: 'aps-hierarchical-v1', grants: ['action:swap', 'asset:*', 'chain:eip155:1'] },
      spend: { mode: 'bounded', unit: 'iso4217:USD:minor', per_action: '1000000', cumulative: '1000000' },
      depth: { remaining: leafDepthRemaining },
      time: { not_before: leafNotBefore, not_after: leafNotAfter },
      reputation: { profile: 'aps-score-0-100-v1', ceiling: 100 },
      values: { profile: 'aps-values-identifiers-v1', required: ['insight:non-manipulated'] },
      reversibility: { profile: 'aps-tci-v1', ceiling: 'compensable' },
    },
  }
  // Use issueSubAuthorityDelegation to also exercise the parent-attachment
  // checks (continuity, time window, seven-facet narrowing) at mint time.
  const leaf = issueSubAuthorityDelegation(root, leafBody, deriveEd25519('agent').privateKeyHex)
  return { root, leaf }
}

// ---------------------------------------------------------------------------
// Envelope
// ---------------------------------------------------------------------------

export interface Envelope {
  schema: 'insight.aps.pre-action-envelope.v1'
  intent: ReturnType<typeof createReceiptV1>
  decision: ReturnType<typeof createReceiptV1>
  delegations: ReturnType<typeof issueAuthorityDelegation>[]
  oracle: Awaited<ReturnType<typeof signOracleSafetyCheck>>
}

interface BuildEnvelopeOptions {
  verdict: OracleSafetyCheckInput['verdict']
  oracleCheckedAtSec?: number
  mutateOracle?: (a: Envelope['oracle']) => Envelope['oracle']
  oraclePrivateKey?: `0x${string}`
  policyVerdict?: 'permit' | 'deny'
  chainOverrides?: ChainOverrides
  overrideEvidenceRefs?: { artifact_type: string; sha256: string }[]
  overrideDecisionRef?: string
}

export async function buildEnvelope(opts: BuildEnvelopeOptions): Promise<Envelope> {
  const {
    verdict,
    oracleCheckedAtSec = BASELINE_SEC,
    mutateOracle,
    oraclePrivateKey = evmAttester().privateKey,
    policyVerdict = 'permit',
    chainOverrides = {},
    overrideEvidenceRefs,
    overrideDecisionRef,
  } = opts

  const { root, leaf } = buildChain(chainOverrides)

  // --- intent --------------------------------------------------------------
  const intentResult = {
    intent_id: 'itn-20260825-0001',
    description: 'swap ETH for USDC up to 10k USD',
    action: 'swap',
    resources: ['chain:eip155:1', `asset:${USDC_ETH}`],
    amount_usd: 10_000,
  }
  const actionRefInput = createActionReferenceInputV2({
    agent_id: AGENT_DID,
    action_type: 'swap',
    target: USDC_ETH,
    payload_ref: computePayloadRefV1(intentResult),
    scope_required: intentResult.resources,
    issued_at: BASELINE_ISO,
    nonce: fixtureNonce('intent'),
  })
  const action_ref = computeActionRefV2(actionRefInput)

  const intent = createReceiptV1(
    {
      profile: 'aps-receipt-v1',
      receipt_type: 'aps:action-intent:v1',
      issuer: AGENT_DID,
      subject_agent: AGENT_DID,
      action_ref,
      delegation_ref: leaf.delegation_id,
      issued_at: BASELINE_ISO,
      evidence_refs: [],
      result: intentResult,
    },
    [{ signer: AGENT_DID, key_id: AGENT_KEY_ID, private_key: deriveEd25519('agent').privateKeyHex }]
  )

  // --- oracle evidence -----------------------------------------------------
  let oracle = await signOracleSafetyCheck(oracleInput(verdict, oracleCheckedAtSec), {
    privateKey: oraclePrivateKey,
    attesterLabel: 'Insight Oracle Safety Attestation',
  })
  if (mutateOracle) oracle = mutateOracle(oracle)

  const evidenceRefs =
    overrideEvidenceRefs ?? [
      { artifact_type: OSC_ARTIFACT_TYPE, sha256: crypto.createHash('sha256').update(canonicalizeJCS(oracle), 'utf8').digest('hex') },
    ]

  // --- decision ------------------------------------------------------------
  const decisionRef = buildDecisionRefV1({
    action_ref,
    authority_state: {
      delegation_id: leaf.delegation_id,
      chain_root: root.delegation_id,
      depth: 2,
    },
    policy_input: {
      action_ref,
      resources: intentResult.resources,
      amount_usd: intentResult.amount_usd,
    },
    decision_context: {
      subject_chain_id: 1,
      evaluated_at: BASELINE_ISO,
    },
    decision_output: {
      profile: 'aps-core-decision-output-v1',
      verdict: policyVerdict,
      effective_authority_ref: policyVerdict === 'deny' ? null : leaf.delegation_id.slice(7),
      constraints: [],
      valid_until: policyVerdict === 'deny' ? null : new Date(BASELINE_MS + 600_000).toISOString(),
    },
  })

  const decision = createReceiptV1(
    {
      profile: 'aps-receipt-v1',
      receipt_type: 'aps:policy-decision:v1',
      issuer: GATEWAY_DID,
      subject_agent: AGENT_DID,
      action_ref,
      delegation_ref: leaf.delegation_id,
      decision_ref: overrideDecisionRef ?? decisionRef.decision_ref,
      issued_at: BASELINE_ISO,
      prev: intent.receipt_id,
      evidence_refs: evidenceRefs,
      result: {
        verdict: policyVerdict,
        // The reason must describe the layer that decided it, and only that
        // layer. This receipt is signed by the policy engine, which evaluates
        // authority and policy; it does not evaluate the oracle evidence. In
        // every oracle-negative vector the evidence is still committed here and
        // still reaches the gate, but saying "oracle verified" inside a signed
        // envelope would be a false statement: on tampered-oracle the artifact
        // was mutated before this receipt was signed. The composite gate is
        // what halts on oracle evidence.
        reason:
          policyVerdict === 'permit'
            ? 'authorized by delegation and policy'
            : 'scope denied by policy',
      },
    },
    [{ signer: GATEWAY_DID, key_id: GATEWAY_KEY_ID, private_key: deriveEd25519('gateway').privateKeyHex }]
  )

  return {
    schema: 'insight.aps.pre-action-envelope.v1',
    intent,
    decision,
    delegations: [root, leaf],
    oracle,
  }
}

// ---------------------------------------------------------------------------
// Fixture catalog
// ---------------------------------------------------------------------------

interface FixtureCase {
  id: string
  note: string
  oracleInput: OracleSafetyCheckInput
  build: () => Promise<Envelope>
  expected: 'allowed' | 'halt'
  expectReasons?: string[]
  /**
   * Named sub-results the vector declares the runner must observe. Negative
   * expectations live HERE, in the data — the runner must never branch on a
   * fixture's id or name to decide what a negative case means.
   */
  expectedSubResults?: string[]
  revocationFor?: (env: Envelope) => { delegation_id: string; status: 'active' | 'revoked' }[]
}

const CASES: FixtureCase[] = [
  { id: 'pass', note: 'PASS verdict, fresh receipts, delegation chain in force → allowed', oracleInput: oracleInput('PASS', BASELINE_SEC), build: () => buildEnvelope({ verdict: 'PASS' }), expected: 'allowed' },
  { id: 'caution', note: 'CAUTION verdict still permitted (PASS/CAUTION proceed)', oracleInput: oracleInput('CAUTION', BASELINE_SEC), build: () => buildEnvelope({ verdict: 'CAUTION' }), expected: 'allowed' },
  { id: 'danger', note: 'DANGER verdict fails closed', oracleInput: oracleInput('DANGER', BASELINE_SEC), build: () => buildEnvelope({ verdict: 'DANGER' }), expected: 'halt', expectReasons: ['HALT_VERDICT_DANGER'] },
  { id: 'block', note: 'BLOCK verdict fails closed', oracleInput: oracleInput('BLOCK', BASELINE_SEC), build: () => buildEnvelope({ verdict: 'BLOCK' }), expected: 'halt', expectReasons: ['HALT_VERDICT_BLOCK'] },
  { id: 'expired-oracle', note: 'oracle attestation validly signed but past its 600s window', oracleInput: oracleInput('PASS', BASELINE_SEC - 700), build: () => buildEnvelope({ verdict: 'PASS', oracleCheckedAtSec: BASELINE_SEC - 700 }), expected: 'halt', expectReasons: ['HALT_ORACLE_EVIDENCE', 'EXPIRED'] },
  {
    id: 'tampered-oracle', note: 'signed oracle data modified after signing; digest re-pointed so the inner attestation itself is tested',
    oracleInput: oracleInput('PASS', BASELINE_SEC),
    build: () => buildEnvelope({ verdict: 'PASS', mutateOracle: (a) => ({ ...a, data: { ...a.data, consensusPrice: a.data.consensusPrice + 1 } }) }),
    expected: 'halt', expectReasons: ['HALT_ORACLE_EVIDENCE', 'UID_MISMATCH'],
    expectedSubResults: ['oracle_input_rebuild_differs', 'rebuild_digest_equals_declared'],
  },
  {
    id: 'wrong-signer', note: 'attester address does not match the EIP-712 signature',
    oracleInput: oracleInput('PASS', BASELINE_SEC),
    build: () => buildEnvelope({ verdict: 'PASS', mutateOracle: (a) => ({ ...a, attester: '0x00000000000000000000000000000000000000a2' as `0x${string}` }) }),
    expected: 'halt', expectReasons: ['HALT_ORACLE_EVIDENCE', 'SIGNATURE_INVALID'],
    expectedSubResults: ['attester_address_mismatch'],
  },
  { id: 'authority-denied', note: 'policy engine returned deny → halt even though oracle is fine', oracleInput: oracleInput('PASS', BASELINE_SEC), build: () => buildEnvelope({ verdict: 'PASS', policyVerdict: 'deny' }), expected: 'halt', expectReasons: ['HALT_AUTHORITY', 'POLICY_DENIED'] },
  {
    id: 'sig-tampered', note: 'decision receipt signature value corrupted after signing',
    oracleInput: oracleInput('PASS', BASELINE_SEC),
    build: async () => {
      const env = await buildEnvelope({ verdict: 'PASS' })
      const sig = { ...env.decision.signatures[0] }
      sig.value = sig.value.slice(0, -1) + (sig.value.endsWith('0') ? '1' : '0')
      return { ...env, decision: { ...env.decision, signatures: [sig] } }
    },
    expected: 'halt', expectReasons: ['HALT_AUTHORITY', 'SIGNATURE_INVALID'],
    expectedSubResults: ['decision_signature_invalid'],
  },
  { id: 'digest-mismatch', note: 'decision commits to a digest that does not match the presented artifact', oracleInput: oracleInput('PASS', BASELINE_SEC), build: () => buildEnvelope({ verdict: 'PASS', overrideEvidenceRefs: [{ artifact_type: OSC_ARTIFACT_TYPE, sha256: 'a'.repeat(64) }] }), expected: 'halt', expectReasons: ['HALT_ORACLE_EVIDENCE', 'EVIDENCE_DIGEST_MISMATCH'], expectedSubResults: ['evidence_digest_mismatch'] },
  { id: 'evidence-missing', note: 'decision carries no oracle evidence ref at all', oracleInput: oracleInput('PASS', BASELINE_SEC), build: () => buildEnvelope({ verdict: 'PASS', overrideEvidenceRefs: [] }), expected: 'halt', expectReasons: ['HALT_ORACLE_EVIDENCE', 'EVIDENCE_MISSING'], expectedSubResults: ['evidence_ref_absent'] },
  {
    id: 'delegation-expired', note: 'authority grant lapsed before the action (leaf expiry, not_after, in the past)',
    oracleInput: oracleInput('PASS', BASELINE_SEC),
    build: () => buildEnvelope({ verdict: 'PASS' }),
    expected: 'halt', expectReasons: ['HALT_AUTHORITY', 'AUTH_DELEGATION_EXPIRED'],
  },
  { id: 'delegation-revoked', note: 'authority grant revoked (ledger-side revocation status)', oracleInput: oracleInput('PASS', BASELINE_SEC), build: () => buildEnvelope({ verdict: 'PASS' }), revocationFor: (env) => [{ delegation_id: env.delegations[1].delegation_id, status: 'revoked' }], expected: 'halt', expectReasons: ['HALT_AUTHORITY', 'AUTH_DELEGATION_REVOKED'] },
]

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURE_DIR = join(__dirname, 'oracle-safety-check-v1')

function toFixtureDoc(c: FixtureCase, envelope: Envelope): Record<string, unknown> {
  const canonical = canonicalizeJCS(envelope)
  const canonicalBytes = Buffer.from(canonical, 'utf8')
  const agentKp = deriveEd25519('agent')
  const attester = evmAttester()

  // Ed25519 witness over the envelope canonical bytes, by the agent key.
  const sig = crypto.sign(null, canonicalBytes, crypto.createPrivateKey({
    key: Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(agentKp.privateKeyHex, 'hex')]),
    format: 'der',
    type: 'pkcs8',
  })).toString('hex')

  return {
    version: 'v1',
    spec: 'JCS — RFC 8785 (ReceiptV1) + EIP-712 (insight.oracle-safety-check:v2)',
    // §5.5 (Evidence Resolution) is where evidence carried inside a receipt is
    // specified; EIP-712 is the inner artifact's own signature scheme.
    spec_ref: 'draft-pidlisnyi-aps-03 §5.5; https://eips.ethereum.org/EIPS/eip-712',
    seed_input: SEED_INPUT,
    seed_sha256_hex: sha256Seed(),
    keypair: { publicKeyHex: deriveEd25519('principal').publicKeyHex },
    roles: {
      principal: { did: PRINCIPAL_DID, publicKeyHex: deriveEd25519('principal').publicKeyHex },
      agent: { did: AGENT_DID, publicKeyHex: agentKp.publicKeyHex },
      gateway: { did: GATEWAY_DID, publicKeyHex: deriveEd25519('gateway').publicKeyHex },
      evm_attester: { address: attester.address },
    },
    generated_at: '2026-08-26',
    provenance: 'Generated by aeoess/agent-passport-system fixtures/oracle-safety-check/generate-fixtures.ts (deterministic seed; no secret material).',
    fixture: c.id,
    note: c.note,
    baseline: BASELINE_ISO,
    // Coverage is stated in prose in the conformance suite README, not in a
    // `verification_mode` field: that field already carries a different axis in
    // this suite (its existing value `record` describes the nature of the
    // verification), and a machine-readable coverage field is the maintainer's
    // to define.
    expected: c.expected,
    expectReasons: c.expectReasons ?? [],
    // Negative expectations live in the data, never in the runner: the runner
    // must not branch on a fixture's name to decide what a case means.
    expected_sub_results: c.expectedSubResults ?? [],
    canonical_bytes_hex: canonicalBytes.toString('hex'),
    canonical_sha256: crypto.createHash('sha256').update(canonicalBytes).digest('hex'),
    ed25519_pubkey_hex: agentKp.publicKeyHex,
    ed25519_signature_over_canonical_hex: sig,
    eip712_digest_hex: envelope.oracle.uid,
    secp256k1_signature_hex: envelope.oracle.signature,
    oracle_input: c.oracleInput,
    revocation: c.revocationFor ? c.revocationFor(envelope) : undefined,
    verification_time:
      c.id === 'delegation-expired'
        ? new Date(BASELINE_MS + 2 * 3600_000).toISOString()
        : undefined,
    envelope,
  }
}

export async function generateAllFixtures(): Promise<string> {
  mkdirSync(FIXTURE_DIR, { recursive: true })
  const index: Record<string, unknown>[] = []

  for (const c of CASES) {
    const envelope = await c.build()
    const doc = toFixtureDoc(c, envelope)
    writeFileSync(join(FIXTURE_DIR, `${c.id}.json`), JSON.stringify(doc, null, 2))
    // Membership only. Duplicating expected / expectReasons /
    // expected_sub_results here would create a second source of truth that no
    // loader binds, so an index that disagrees with its case file would pass.
    index.push({ id: c.id, file: `${c.id}.json` })
  }

  writeFileSync(
    join(FIXTURE_DIR, 'index.json'),
    JSON.stringify(
      {
        generator: 'agent-passport-system fixtures/oracle-safety-check/generate-fixtures.ts',
        seed_input: SEED_INPUT,
        baseline: BASELINE_ISO,
        cases: index,
      },
      null,
      2
    )
  )

  return FIXTURE_DIR
}

async function main() {
  const dir = await generateAllFixtures()
  console.log(`wrote ${CASES.length} fixtures to ${dir}`)
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((e) => {
    console.error(e)
    process.exit(1)
  })
}
