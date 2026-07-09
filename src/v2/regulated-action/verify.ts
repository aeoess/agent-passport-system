// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// APS Regulated Action Profile v0: the deterministic disposition verifier (A2).
//
// This is the canonical truth-table from RAPV0-FROZEN-CONTRACT.md section B (amended order).
// It is total, deterministic from explicit inputs, most-dangerous-first, first match wins.
// It is STATELESS and PURE: no network, no wall-clock read, no replay state. Every input
// comes from the caller via VerificationContext. Replay/jti/nonce uniqueness is reported as
// authority_replay: not_evaluated and is computed by the PRIVATE gateway, never here.
// judgment_correctness is always not_claimed: we never certify a discretionary judgment.

import { canonicalizeJCS, canonicalHashJCS } from '../../core/canonical-jcs.js'
import { verify as edVerify } from '../../crypto/keys.js'
import {
  REGULATED_ACTION_PROFILE,
  RAPV0_TAG,
  ACTION_CLASS_RANK,
} from './types.js'
import type {
  RegulatedActionReceiptV0,
  VerificationContext,
  RegulatedVerifyResult,
  Disposition,
  IncompleteReason,
  AuthorityBasis,
} from './types.js'

const RESOURCE_VALID_TYPES = new Set(['native_resource_signed', 'boundary_attested'])
const RESOURCE_VALID_STATUS = new Set(['accepted', 'settled'])

function sigOk(payload: string, sig: string | undefined, pubkey: string | undefined): boolean {
  if (!sig || !pubkey) return false
  try {
    return edVerify(payload, sig, pubkey)
  } catch {
    return false
  }
}

// Canonical signed payload for a domain-separated subobject: tag, then strict JCS of the
// subobject with its own signature field removed.
function signedPayload(tag: string, subobject: Record<string, unknown>, sigField: string): string {
  const copy: Record<string, unknown> = { ...subobject }
  delete copy[sigField]
  return `${tag}.${canonicalizeJCS(copy)}`
}

/**
 * Verify a RegulatedActionReceiptV0 against a VerificationContext. Returns the disposition,
 * every terminal condition that held (violations[]), missing evidence, the computed
 * trust-domain separation, the authority basis, and judgment_correctness: not_claimed.
 */
export function verifyRegulatedAction(
  receipt: RegulatedActionReceiptV0,
  ctx: VerificationContext,
): RegulatedVerifyResult {
  const missing: string[] = []

  // ── crypto_ok: operator-domain and resource-domain sigs only (NOT the authority sig). ──
  const opReg = ctx.operator_domain_registry || {}
  const actorKey = opReg[receipt.actor_signature?.key_id]?.publicKey
  let cryptoOk = sigOk(
    signedPayload(RAPV0_TAG.actor, { profile: receipt.profile, receipt_id: receipt.receipt_id, action_class: receipt.action_class, key_id: receipt.actor_signature?.key_id }, 'sig'),
    receipt.actor_signature?.sig,
    actorKey,
  )

  const intentPresent = !!receipt.intent_commitment
  if (intentPresent) {
    const ic = receipt.intent_commitment!
    const intentSignerId = receipt.gateway_policy_decision?.signer ?? ctx.gateway_key_id
    const intentKey = intentSignerId ? opReg[intentSignerId]?.publicKey : undefined
    const intentSigOk = sigOk(signedPayload(RAPV0_TAG.intent, ic as unknown as Record<string, unknown>, 'signature'), ic.signature, intentKey)
    cryptoOk = cryptoOk && intentSigOk
  }

  const policyPresent = !!receipt.gateway_policy_decision
  if (policyPresent) {
    const pd = receipt.gateway_policy_decision!
    const policyKey = opReg[pd.signer]?.publicKey
    const policySigOk = sigOk(signedPayload(RAPV0_TAG.policy, pd as unknown as Record<string, unknown>, 'signature'), pd.signature, policyKey)
    cryptoOk = cryptoOk && policySigOk
  }

  // crypto_ok covers ONLY the operator envelope (actor/intent/policy). It deliberately EXCLUDES
  // the resource sig and the authority sig: a forged/unverifiable EXTERNAL resource confirmation
  // must not void the operator's receipt, it must fail to establish the resource domain
  // (resource_present_valid=false), dropping below reconciled. Only a tampered OPERATOR sig voids.
  if (!cryptoOk) missing.push('crypto')

  // resource signature: evaluated for resource_present_valid / independence only.
  const rc = receipt.resource_confirmation_ref
  let resourceSigVerifies = false
  let resourceKeyIndependent = false
  if (rc) {
    const rk = ctx.registered_resource_keys?.[rc.signer_key_id]
    resourceSigVerifies = sigOk(signedPayload(RAPV0_TAG.resource, rc as unknown as Record<string, unknown>, 'signature'), rc.signature, rk?.publicKey)
    resourceKeyIndependent = !!rk && rk.registered_by_operator === false
  }

  // ── authority trichotomy: ok / weak_basis / invalid ──
  const ar = receipt.authority_ref
  const authorityPresent = !!ar
  let authorityOk = false
  let authorityWeakBasis = false
  let authorityInvalid = false
  let authorityBasis: AuthorityBasis | undefined
  if (ar) {
    const claims = { ...(ar as unknown as Record<string, unknown>) }
    delete claims.assertion_sig
    const authPayload = `${RAPV0_TAG.authority}.${canonicalizeJCS(claims)}`
    const extVerifies = sigOk(authPayload, ar.assertion_sig, ctx.idp_keyset?.[ar.issuer])
    const opVerifies = sigOk(authPayload, ar.assertion_sig, ctx.operator_anchored_idp_copy?.[ar.issuer])
    const issuedMs = Date.parse(ar.issued_at)
    const expiresMs = Date.parse(ar.expires_at)
    const validAcross =
      Number.isFinite(issuedMs) && Number.isFinite(expiresMs) &&
      issuedMs <= ctx.reserved_ts && expiresMs >= ctx.submitted_ts
    const withinWindow = ctx.submitted_ts - ctx.reserved_ts <= ctx.max_authority_execution_window_ms
    const freshnessOk = validAcross && withinWindow
    authorityOk = extVerifies && freshnessOk
    authorityWeakBasis = !authorityOk && !extVerifies && opVerifies && freshnessOk
    authorityInvalid = !authorityOk && !authorityWeakBasis
    authorityBasis = authorityOk ? 'external_idp' : authorityWeakBasis ? 'operator_anchored_copy_weak' : undefined
    if (authorityInvalid) missing.push('authority')
  } else {
    missing.push('authority')
  }

  // ── intent ──
  let intentOk = false
  if (receipt.intent_commitment) {
    const ic = receipt.intent_commitment
    const recomputed = canonicalHashJCS({
      action_class: receipt.action_class,
      scope: ic.scope,
      authority_assertion_hash: ar?.assertion_hash ?? '',
      decision_basis_root_hash: receipt.decision_basis_commitment?.root_hash ?? '',
      expected_effect_hash: ic.expected_effect_hash,
    })
    intentOk = ic.created_before_execution === true && recomputed === ic.intent_hash
  }

  // ── policy ──
  const pd = receipt.gateway_policy_decision
  const policyAllow = !!pd && pd.decision === 'allow' && pd.action_class_assigned === receipt.action_class
  const policyDeny = !!pd && (pd.decision === 'deny' || pd.decision === 'hold')

  // ── resource ──
  const resourcePresentValid =
    !!rc &&
    RESOURCE_VALID_TYPES.has(rc.type) &&
    rc.realized_effect_provenance === 'ban_derived' &&
    resourceSigVerifies &&
    resourceKeyIndependent &&
    RESOURCE_VALID_STATUS.has(rc.status)
  const resourceMatches =
    intentOk && !!rc && !!receipt.intent_commitment &&
    rc.gateway_nonce_echo === receipt.intent_commitment.gateway_nonce &&
    rc.realized_effect_hash === receipt.intent_commitment.expected_effect_hash
  const resourceOk = resourcePresentValid && resourceMatches
  const executed = resourcePresentValid || ctx.completeness_match === true

  // ── transparency anchor ──
  let anchorPresent = false
  if (receipt.transparency_ref) {
    const tr = receipt.transparency_ref
    const root = ctx.registered_log_roots?.[tr.log_id]
    let proofOk = false
    if (root) {
      // Recompute the Merkle root from leaf_hash + inclusion_proof; compare to registered root.
      let acc = tr.leaf_hash
      try {
        for (const step of tr.inclusion_proof) {
          acc = step.dir === 'L' ? canonicalHashJCS({ l: step.hash, r: acc }) : canonicalHashJCS({ l: acc, r: step.hash })
        }
        proofOk = acc === root
      } catch {
        proofOk = false
      }
    }
    anchorPresent = proofOk && tr.anchored_at_state === 'reserved'
  }
  if (!anchorPresent) missing.push('transparency_anchor')

  const temporalViolation = anchorPresent && ctx.anchor_orders_intent_before_resource === false
  const temporalConsistent = anchorPresent && ctx.anchor_orders_intent_before_resource === true
  const noneqOk = anchorPresent && ctx.non_equivocation_ok !== false

  // ── domains and separation ──
  const idpCounts = authorityOk
  const resourceCounts = resourceOk && resourceKeyIndependent
  const domains = (idpCounts ? 1 : 0) + (resourceCounts ? 1 : 0)

  const operatorKeyIds: string[] = []
  if (receipt.actor_signature?.key_id) operatorKeyIds.push(receipt.actor_signature.key_id)
  if (pd?.signer) operatorKeyIds.push(pd.signer)
  if (receipt.intent_commitment) {
    const intentSignerId = pd?.signer ?? ctx.gateway_key_id
    if (intentSignerId) operatorKeyIds.push(intentSignerId)
  }
  const separationOk = operatorKeyIds.every((kid) => opReg[kid]?.identity === ctx.operator_identity_id)

  // ── per-class required fields (regulator_grade tier) ──
  // regulator_grade_for_class is an opt-in STRICTER tier: reachable only when the caller
  // supplies a per-class bar (non-empty) AND every required field is present. Without a defined
  // bar for the class, the strongest honest claim is reconciled, never regulator_grade.
  const requiredFields = ctx.per_class_required_fields?.[receipt.action_class] ?? []
  const perClassOk =
    requiredFields.length > 0 &&
    requiredFields.every((f) => (receipt as unknown as Record<string, unknown>)[f] !== undefined)

  // ── terminal-condition flags (guards 1-7), most-dangerous-first ──
  const terminal: Array<[boolean, Disposition]> = [
    [!cryptoOk, 'void'],
    [policyDeny && executed, 'void_policy_violation'],
    [resourcePresentValid && intentPresent && temporalViolation, 'void_temporal_violation'],
    [resourcePresentValid && intentOk && !resourceMatches, 'void_reconciliation_mismatch'],
    [resourcePresentValid && !intentOk, 'resource_unbound'],
    [authorityInvalid, 'authority_invalid'],
    [!authorityPresent && !resourcePresentValid, 'self_attested'],
  ]
  const violations: Disposition[] = terminal.filter(([held]) => held).map(([, d]) => d)

  // ── first match wins ──
  let disposition: Disposition
  let incompleteReason: IncompleteReason | undefined
  const firstTerminal = terminal.find(([held]) => held)
  if (firstTerminal) {
    disposition = firstTerminal[1]
  } else if (
    authorityOk && intentOk && policyAllow && resourceOk && domains >= 2 &&
    temporalConsistent && noneqOk && perClassOk && separationOk
  ) {
    disposition = 'regulator_grade_for_class'
  } else if (authorityOk && intentOk && policyAllow && resourceOk && domains >= 2 && temporalConsistent) {
    disposition = 'reconciled'
  } else if (authorityOk && intentOk && policyAllow && !resourceOk) {
    disposition = 'intent_precommitted'
  } else if (authorityOk && !intentOk) {
    disposition = 'authority_bound'
  } else {
    disposition = 'incomplete_for_class'
    // deterministic reason precedence (AP-6)
    if (policyDeny) incompleteReason = 'policy_denied_no_execution'
    else if (!authorityOk) incompleteReason = 'missing_authority'
    else if (!anchorPresent) incompleteReason = 'missing_transparency_anchor'
    else incompleteReason = 'execution_unconfirmed'
  }

  // INVARIANT assertions (defense in depth; never reached if the table is correct).
  if ((disposition === 'reconciled' || disposition === 'regulator_grade_for_class') &&
      !(domains >= 2 && resourceOk && temporalConsistent)) {
    throw new Error('RAPV0 invariant breach: reconciled/regulator_grade without domains>=2 AND resource_ok AND temporal_consistent')
  }

  const result: RegulatedVerifyResult = {
    profile: REGULATED_ACTION_PROFILE,
    disposition,
    violations,
    missing_evidence: missing,
    trust_domain_separation: {
      computed_domains: domains,
      idp_counts: idpCounts,
      resource_counts: resourceCounts,
      operator_identity: ctx.operator_identity_id,
      separation_ok: separationOk,
    },
    authority_replay: 'not_evaluated',
    judgment_correctness: 'not_claimed',
  }
  if (incompleteReason) result.incomplete_reason = incompleteReason
  if (authorityBasis) result.authority_basis = authorityBasis
  return result
}

// Convenience: rank lookup for callers gating on class >= 3 (regulated).
export function actionClassRank(c: keyof typeof ACTION_CLASS_RANK): number {
  return ACTION_CLASS_RANK[c]
}
