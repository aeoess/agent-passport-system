// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Deterministic generator for the APS Regulated Action Profile v0 conformance vectors.
// Produces conformance/regulated-action/v0/vectors.json with REAL Ed25519 signatures, then
// self-checks every verifier vector against the frozen expected disposition before writing.
// Run: npx tsx conformance/regulated-action/v0/generate.mts
//
// Keys are derived deterministically from labels (sha256 seed) so the vectors are byte-stable
// across regenerations. Expected dispositions are pinned to RAPV0-VECTORS-SPEC.json V01..V33.

import { createHash } from 'node:crypto'
import { writeFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { canonicalizeJCS, canonicalHashJCS } from '../../../src/core/canonical-jcs.js'
import { sign, publicKeyFromPrivate } from '../../../src/crypto/keys.js'
import { RAPV0_TAG, REGULATED_ACTION_PROFILE } from '../../../src/v2/regulated-action/types.js'
import { verifyRegulatedAction } from '../../../src/v2/regulated-action/verify.js'
import type {
  RegulatedActionReceiptV0,
  VerificationContext,
  AuthorityRef,
  IntentCommitment,
  GatewayPolicyDecision,
  ResourceConfirmationRef,
  TransparencyRef,
  ActionClass,
} from '../../../src/v2/regulated-action/types.js'

const h = (s: string): string => createHash('sha256').update(s).digest('hex')
const priv = (label: string): string => createHash('sha256').update(`rapv0-key-${label}`).digest('hex')

// ── deterministic role keys ──
const idp = { priv: priv('idp') }; const idpPub = publicKeyFromPrivate(idp.priv)
const idpCopy = { priv: priv('idp-operator-copy') }; const idpCopyPub = publicKeyFromPrivate(idpCopy.priv)
const forgedAuth = { priv: priv('forged-authority') }
const gw = { priv: priv('gw'), id: 'gw-key-1', identity: 'op-1' }; const gwPub = publicKeyFromPrivate(gw.priv)
const agent = { priv: priv('agent'), id: 'agent-key-1', identity: 'op-1' }; const agentPub = publicKeyFromPrivate(agent.priv)
const op2 = { priv: priv('op2'), id: 'op2-key-1', identity: 'op-2' }; const op2Pub = publicKeyFromPrivate(op2.priv)
const resIndep = { priv: priv('res-indep'), id: 'res-bank-1' }; const resIndepPub = publicKeyFromPrivate(resIndep.priv)
const resGw = { priv: priv('res-gw'), id: 'res-gw-1' }; const resGwPub = publicKeyFromPrivate(resGw.priv)
const forgedRes = { priv: priv('forged-res'), id: 'res-unknown' }

const ISSUER = 'https://idp.example.com'
const LOG_ID = 'enterprise-log-1'
const RES = 1700000000000          // reserved_ts
const SUB = RES + 60000            // submitted_ts (1 min later)
const MAX_WINDOW = 900000          // 15 min
const ISO = (ms: number): string => new Date(ms).toISOString()

type AuthMode = 'valid' | 'forged' | 'expired' | 'weak' | 'window'
type ResMode = 'valid' | 'weak' | 'echoed' | 'gwkey' | 'unregistered' | 'nonce_mismatch' | 'effect_mismatch'

interface Opts {
  action_class?: ActionClass
  authority?: AuthMode | 'none'
  intent?: boolean
  intentValid?: boolean
  policy?: 'allow' | 'deny' | 'none'
  resource?: ResMode | 'none'
  anchor?: 'before' | 'after' | 'none'
  perClass?: boolean
  perClassMissing?: boolean
  separation?: 'ok' | 'split'
  noneq?: boolean
  tamperOperator?: boolean
  windowExceeded?: boolean
}

function buildAuthority(id: string, mode: AuthMode): AuthorityRef {
  const expires = mode === 'expired' ? ISO(RES - 1000) : ISO(SUB + 3600000)
  const claims = {
    type: 'id_jag' as const,
    issuer: ISSUER,
    subject: 'agent:bot-1',
    audience: 'bank-api',
    scope_hash: h(`scope-${id}`),
    issued_at: ISO(RES - 5000),
    expires_at: expires,
    assertion_hash: h(`assert-${id}`),
    jti: `jti-${id}`,
  }
  const payload = `${RAPV0_TAG.authority}.${canonicalizeJCS(claims)}`
  const signer = mode === 'forged' ? forgedAuth.priv : mode === 'weak' ? idpCopy.priv : idp.priv
  return { ...claims, assertion_sig: sign(payload, signer) }
}

function buildIntent(id: string, action_class: ActionClass, assertionHash: string, dbRoot: string, valid: boolean): IntentCommitment {
  const scope = `transfer:${id}`
  const expected_effect_hash = h(`effect-${id}`)
  const realHash = canonicalHashJCS({
    action_class, scope,
    authority_assertion_hash: assertionHash,
    decision_basis_root_hash: dbRoot,
    expected_effect_hash,
  })
  const core = {
    created_before_execution: true as const,
    intent_hash: valid ? realHash : h(`tampered-intent-${id}`),
    expected_effect_hash,
    gateway_nonce: `nonce-${id}`,
    timestamp_ms: RES,
    scope,
  }
  const payload = `${RAPV0_TAG.intent}.${canonicalizeJCS(core)}`
  return { ...core, signature: sign(payload, gw.priv) }
}

function buildPolicy(id: string, action_class: ActionClass, decision: 'allow' | 'deny'): GatewayPolicyDecision {
  const core = {
    policy_version_hash: h(`policy-${id}`),
    decision,
    action_class_assigned: action_class,
    signer: gw.id,
  }
  const payload = `${RAPV0_TAG.policy}.${canonicalizeJCS(core)}`
  return { ...core, signature: sign(payload, gw.priv) }
}

function buildResource(id: string, expectedEffectHash: string, nonce: string, mode: ResMode): ResourceConfirmationRef {
  const type = mode === 'weak' ? 'boundary_attested_weak' : 'boundary_attested'
  const provenance = mode === 'echoed' ? 'echoed' : 'ban_derived'
  const signer_key_id = mode === 'gwkey' ? resGw.id : mode === 'unregistered' ? forgedRes.id : resIndep.id
  const signerPriv = mode === 'gwkey' ? resGw.priv : mode === 'unregistered' ? forgedRes.priv : resIndep.priv
  const realized_effect_hash = mode === 'effect_mismatch' ? h(`other-effect-${id}`) : expectedEffectHash
  const gateway_nonce_echo = mode === 'nonce_mismatch' ? 'wrong-nonce' : nonce
  const core = {
    type: type as ResourceConfirmationRef['type'],
    resource_transaction_id: `tx-${id}`,
    correlation_id: `corr-${id}`,
    gateway_nonce_echo,
    realized_effect_hash,
    realized_effect_provenance: provenance as ResourceConfirmationRef['realized_effect_provenance'],
    status: 'settled',
    timestamp_ms: SUB,
    signer_key_id,
  }
  const payload = `${RAPV0_TAG.resource}.${canonicalizeJCS(core)}`
  return { ...core, signature: sign(payload, signerPriv) }
}

function buildAnchor(receiptId: string, intentHash: string): { tref: TransparencyRef; root: string } {
  const leaf = canonicalHashJCS({ receipt_id: receiptId, intent_hash: intentHash, state: 'reserved' })
  const sibling = h(`sibling-${receiptId}`)
  const root = canonicalHashJCS({ l: leaf, r: sibling })
  return {
    tref: { type: 'enterprise_merkle_log', log_id: LOG_ID, inclusion_proof: [{ dir: 'R', hash: sibling }], anchored_at_state: 'reserved', tree_size: 2, leaf_hash: leaf },
    root,
  }
}

function build(id: string, o: Opts): { receipt: RegulatedActionReceiptV0; ctx: VerificationContext } {
  const action_class = o.action_class ?? 'financial_movement'
  const ar = (o.authority && o.authority !== 'none') ? buildAuthority(id, o.authority) : undefined
  const dbRoot = h(`db-${id}`)
  const ic = o.intent ? buildIntent(id, action_class, ar?.assertion_hash ?? '', dbRoot, o.intentValid !== false) : undefined
  const pd = (o.policy && o.policy !== 'none') ? buildPolicy(id, action_class, o.policy) : undefined
  const rc = (o.resource && o.resource !== 'none') ? buildResource(id, ic?.expected_effect_hash ?? h(`effect-${id}`), ic?.gateway_nonce ?? `nonce-${id}`, o.resource) : undefined

  // actor signature: split-identity uses op2 to model a faked second operator domain (V27).
  const actorSigner = o.separation === 'split' ? op2 : agent
  const actorCore = { profile: REGULATED_ACTION_PROFILE, receipt_id: `r-${id}`, action_class, key_id: actorSigner.id }
  let actorSig = sign(`${RAPV0_TAG.actor}.${canonicalizeJCS(actorCore)}`, actorSigner.priv)
  if (o.tamperOperator) actorSig = actorSig.slice(0, -2) + (actorSig.endsWith('00') ? '11' : '00')

  let anchor: { tref: TransparencyRef; root: string } | undefined
  if (o.anchor && o.anchor !== 'none') anchor = buildAnchor(`r-${id}`, ic?.intent_hash ?? h(`nointent-${id}`))

  const receipt: RegulatedActionReceiptV0 = {
    profile: REGULATED_ACTION_PROFILE,
    receipt_id: `r-${id}`,
    action_class,
    actor_signature: { alg: 'ed25519', key_id: actorSigner.id, sig: actorSig },
    ...(ar ? { authority_ref: ar } : {}),
    ...(ic ? { intent_commitment: ic, decision_basis_commitment: { root_hash: dbRoot, leaves_schema: ['input_artifact_hashes', 'policy_version_hash'], raw_chain_of_thought_included: false } } : {}),
    ...(pd ? { gateway_policy_decision: pd } : {}),
    ...(rc ? { resource_confirmation_ref: rc } : {}),
    ...(anchor ? { transparency_ref: anchor.tref } : {}),
  }

  const submitted = o.windowExceeded ? RES + 16 * 60000 : SUB
  const ctx: VerificationContext = {
    idp_keyset: { [ISSUER]: idpPub },
    operator_anchored_idp_copy: { [ISSUER]: idpCopyPub },
    registered_resource_keys: {
      [resIndep.id]: { publicKey: resIndepPub, registered_by_operator: false },
      [resGw.id]: { publicKey: resGwPub, registered_by_operator: true },
    },
    operator_domain_registry: {
      [agent.id]: { publicKey: agentPub, identity: agent.identity },
      [gw.id]: { publicKey: gwPub, identity: gw.identity },
      [op2.id]: { publicKey: op2Pub, identity: op2.identity },
    },
    operator_identity_id: 'op-1',
    gateway_key_id: gw.id,
    registered_log_roots: anchor ? { [LOG_ID]: anchor.root } : {},
    allowed_clock_skew_ms: 5000,
    reserved_ts: RES,
    submitted_ts: submitted,
    max_authority_execution_window_ms: MAX_WINDOW,
    anchor_orders_intent_before_resource: o.anchor === 'after' ? false : o.anchor === 'before' ? true : undefined,
    ...(o.noneq === false ? { non_equivocation_ok: false } : {}),
    ...(o.perClass ? { per_class_required_fields: { [action_class]: ['authority_ref', 'intent_commitment', 'gateway_policy_decision', 'resource_confirmation_ref', 'transparency_ref', 'decision_basis_commitment'] } } : {}),
    ...(o.perClassMissing ? { per_class_required_fields: { [action_class]: ['aps_delegation_ref'] } } : {}),
  }
  return { receipt, ctx }
}

// ── the 33 vectors ──
interface Spec { id: string; scenario: string; opts?: Opts; expect: string; reason?: string; authority_basis?: string }
const HONEST: Opts = { authority: 'valid', intent: true, policy: 'allow', resource: 'valid', anchor: 'before' }

const SPECS: Spec[] = [
  { id: 'V01', scenario: 'operator-only (agent sig only), no authority, no resource', opts: { authority: 'none', intent: false, policy: 'none', resource: 'none', anchor: 'none' }, expect: 'self_attested' },
  { id: 'V02', scenario: 'authority_ref present, signature invalid, no resource', opts: { authority: 'forged', intent: false, policy: 'none', resource: 'none', anchor: 'none' }, expect: 'authority_invalid' },
  { id: 'V03', scenario: 'authority expired before reserved, no resource', opts: { authority: 'expired', intent: false, policy: 'none', resource: 'none', anchor: 'none' }, expect: 'authority_invalid' },
  { id: 'V04', scenario: 'authority valid, no intent', opts: { authority: 'valid', intent: false, policy: 'none', resource: 'none', anchor: 'none' }, expect: 'authority_bound' },
  { id: 'V05', scenario: 'authority+intent+policy_allow, no resource confirmation', opts: { authority: 'valid', intent: true, policy: 'allow', resource: 'none', anchor: 'before' }, expect: 'intent_precommitted' },
  { id: 'V06', scenario: 'honest path: two domains, anchor consistent', opts: HONEST, expect: 'reconciled' },
  { id: 'V07', scenario: 'honest path + all per-class fields + noneq', opts: { ...HONEST, perClass: true, separation: 'ok', noneq: true }, expect: 'regulator_grade_for_class' },
  { id: 'V08', scenario: 'resource present+valid+matches, anchor MISSING', opts: { ...HONEST, anchor: 'none' }, expect: 'incomplete_for_class', reason: 'missing_transparency_anchor' },
  { id: 'V09', scenario: 'forged execution: resource signed by gateway-held / non-registered key', opts: { ...HONEST, resource: 'unregistered' }, expect: 'intent_precommitted' },
  { id: 'V10', scenario: 'boundary_attested_weak (same-process BAN)', opts: { ...HONEST, resource: 'weak' }, expect: 'intent_precommitted' },
  { id: 'V11', scenario: 'replay: valid sig + registered key, gateway_nonce_echo mismatch (intent ok)', opts: { ...HONEST, resource: 'nonce_mismatch' }, expect: 'void_reconciliation_mismatch' },
  { id: 'V12', scenario: 'bait-and-switch: realized_effect_hash != intent.expected_effect (intent ok)', opts: { ...HONEST, resource: 'effect_mismatch' }, expect: 'void_reconciliation_mismatch' },
  { id: 'V13', scenario: 'effect-echo trap: hashes equal but realized_effect_provenance==echoed', opts: { ...HONEST, resource: 'echoed' }, expect: 'intent_precommitted' },
  { id: 'V14', scenario: 'anchor present but orders intent AFTER the resource event', opts: { ...HONEST, anchor: 'after' }, expect: 'void_temporal_violation' },
  { id: 'V15', scenario: 'validly BAN-signed resource event with no intent at all', opts: { authority: 'none', intent: false, policy: 'none', resource: 'valid', anchor: 'none' }, expect: 'resource_unbound' },
  { id: 'V16', scenario: 'policy denied but a resource event exists (executed)', opts: { ...HONEST, policy: 'deny' }, expect: 'void_policy_violation' },
  { id: 'V17', scenario: 'BAN public key registered by the gateway itself', opts: { ...HONEST, resource: 'gwkey' }, expect: 'intent_precommitted' },
  { id: 'V18', scenario: 'IdP key rotated; only an operator-anchored key copy available', opts: { authority: 'weak', intent: true, policy: 'allow', resource: 'none', anchor: 'before' }, expect: 'incomplete_for_class', reason: 'missing_authority', authority_basis: 'operator_anchored_copy_weak' },
  { id: 'V19', scenario: 'small clock skew within tolerance, anchor order correct', opts: HONEST, expect: 'reconciled' },
  { id: 'V22', scenario: 'envelope crypto failure: tampered actor sig', opts: { ...HONEST, tamperOperator: true }, expect: 'void' },
  { id: 'V23', scenario: 'policy_deny AND NOT executed', opts: { authority: 'valid', intent: true, policy: 'deny', resource: 'none', anchor: 'before' }, expect: 'incomplete_for_class', reason: 'policy_denied_no_execution' },
  { id: 'V24', scenario: 'authority_ok+intent_ok+anchor present, policy absent, no resource', opts: { authority: 'valid', intent: true, policy: 'none', resource: 'none', anchor: 'before' }, expect: 'incomplete_for_class', reason: 'execution_unconfirmed' },
  { id: 'V25', scenario: 'resource present+valid+matches + intent ok + NO authority', opts: { authority: 'none', intent: true, policy: 'allow', resource: 'valid', anchor: 'before' }, expect: 'incomplete_for_class', reason: 'missing_authority' },
  { id: 'V26', scenario: 'authority_invalid (forged) AND resource_present_valid, otherwise clean', opts: { authority: 'forged', intent: true, policy: 'allow', resource: 'valid', anchor: 'before' }, expect: 'authority_invalid' },
  { id: 'V27', scenario: 'separation_ok false: two operator identities to fake domains>=2', opts: { ...HONEST, perClass: true, separation: 'split', noneq: true }, expect: 'reconciled' },
  { id: 'V28', scenario: 'per-class-required-fields missing, all else regulator-grade', opts: { ...HONEST, perClassMissing: true, separation: 'ok', noneq: true }, expect: 'reconciled' },
  { id: 'V29', scenario: 'noneq_ok false, all else regulator-grade', opts: { ...HONEST, perClass: true, separation: 'ok', noneq: false }, expect: 'reconciled' },
  { id: 'V30', scenario: 'authority valid-sig but submitted beyond max_authority_execution_window_ms', opts: { authority: 'window', intent: false, policy: 'none', resource: 'none', anchor: 'none', windowExceeded: true }, expect: 'authority_invalid' },
  { id: 'V31', scenario: 'simultaneous temporal_violation + reconciliation mismatch + policy_deny+executed', opts: { authority: 'valid', intent: true, policy: 'deny', resource: 'nonce_mismatch', anchor: 'after' }, expect: 'void_policy_violation' },
  { id: 'V32', scenario: 'self_attested basis carrying intent_ok+policy_allow (no authority, no resource)', opts: { authority: 'none', intent: true, policy: 'allow', resource: 'none', anchor: 'none' }, expect: 'self_attested' },
  { id: 'V33', scenario: 'boundary_attested_weak presented WITH two anchor-consistent domains', opts: { ...HONEST, resource: 'weak' }, expect: 'intent_precommitted' },
]

const out: unknown[] = []
const failures: string[] = []
for (const s of SPECS) {
  const { receipt, ctx } = build(s.id, s.opts ?? HONEST)
  const r = verifyRegulatedAction(receipt, ctx)
  const dispOk = r.disposition === s.expect
  const reasonOk = !s.reason || r.incomplete_reason === s.reason
  const basisOk = !s.authority_basis || r.authority_basis === s.authority_basis
  if (!dispOk || !reasonOk || !basisOk) {
    failures.push(`${s.id}: got ${r.disposition}${r.incomplete_reason ? ':' + r.incomplete_reason : ''} basis=${r.authority_basis ?? '-'} want ${s.expect}${s.reason ? ':' + s.reason : ''} basis=${s.authority_basis ?? '-'}`)
  }
  out.push({
    id: s.id, scenario: s.scenario, surface: 'verifier',
    input_receipt: receipt, verification_context: ctx,
    expected: {
      disposition: s.expect,
      ...(s.reason ? { incomplete_reason: s.reason } : {}),
      ...(s.authority_basis ? { authority_basis: s.authority_basis } : {}),
      violations: r.violations,
      trust_domain_separation: r.trust_domain_separation,
    },
  })
}

// completeness-layer vectors V20/V21 (gateway surface, not a verifier disposition)
out.splice(19, 0,
  {
    id: 'V20', scenario: 'resource event in coverage_scope with no receipt', surface: 'completeness',
    completeness_input: {
      coverage_scope: { resource: 'bank-api', tenant: 'tenant-1' },
      resource_events: [{ resource: 'bank-api', tenant: 'tenant-1', resource_transaction_id: 'tx-orphan-1', timestamp_ms: SUB }],
      reconciled_correlation_ids: [],
    },
    expected: { orphans: [{ resource_transaction_id: 'tx-orphan-1', timestamp_ms: SUB }] },
    notes: 'assertion is on expected.orphans; validated by the gateway completeness layer',
  },
  {
    id: 'V21', scenario: 'resource event OUTSIDE coverage_scope with no receipt', surface: 'completeness',
    completeness_input: {
      coverage_scope: { resource: 'bank-api', tenant: 'tenant-1' },
      resource_events: [{ resource: 'other-system', tenant: 'tenant-1', resource_transaction_id: 'tx-oob-1', timestamp_ms: SUB }],
      reconciled_correlation_ids: [],
    },
    expected: { orphans: [] },
    notes: 'scope filter shows no in-scope orphan; validated by the gateway completeness layer',
  },
)

if (failures.length) {
  console.error(`SELF-CHECK FAILED (${failures.length}):`)
  for (const f of failures) console.error('  ' + f)
  process.exit(1)
}

const doc = {
  profile: REGULATED_ACTION_PROFILE,
  description: 'APS Regulated Action Profile v0 conformance vectors. 31 verifier-surface vectors exercise the deterministic disposition function (A2); 2 completeness-surface vectors (V20/V21) are validated by the private gateway completeness layer. The set only grows.',
  canonical_truth_table: 'RAPV0-FROZEN-CONTRACT.md section B (amended guard order). The verifier returns judgment_correctness: not_claimed for every vector.',
  count: out.length,
  verifier_vector_count: out.filter((v) => (v as { surface: string }).surface === 'verifier').length,
  vectors: out,
}
const here = dirname(fileURLToPath(import.meta.url))
writeFileSync(join(here, 'vectors.json'), JSON.stringify(doc, null, 2) + '\n')
console.log(`OK: ${out.length} vectors written (${doc.verifier_vector_count} verifier, ${out.length - doc.verifier_vector_count} completeness); self-check passed.`)
