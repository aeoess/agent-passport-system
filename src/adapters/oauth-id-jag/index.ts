// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// OAuth ID-JAG to APS delegation binding.
//
// Bridge and profile only. A caller-verified ID-JAG grant (the OAuth Identity
// Assertion JWT Authorization Grant) is imported as external authority, and APS
// adds the layer the draft leaves to profiles in section 9.7: scoped agent
// delegation, monotonic narrowing, evidence quality, and signed receipts for
// actions taken under it. APS maps onto ID-JAG at the edge; it does not become
// ID-JAG. This is a binding, not a dependency. Neither side requires the other.
//
// Pinned to draft-ietf-oauth-identity-assertion-authz-grant-04 (2026-05-21).
// Stable APS semantics; draft-pinned external protocol semantics.
//
// Proof box
// Specified and tested: a caller-verified grant projects to an APS descriptor
//   with two separate anchors (delegationChainRoot over chain content,
//   sourceGrantRef over grant provenance), a caller-signed verification
//   attestation, an externally anchored keyless root, scope projected with raw
//   authorization_details preserved, and no invented spend unit.
// Does NOT do: verify the ID-JAG signature, fetch JWKS, hold OAuth trust config,
//   check revocation, decide allow or deny, aggregate, or mint authority. The
//   input is a caller-verified grant; verification and enforcement stay with the
//   relying party. Soundness here is by accountability (a keyed caller on the
//   hook), not by construction.

import { canonicalHashJCS } from '../../core/canonical-jcs.js'
import { computeDelegationChainRoot } from '../../decisionReceipt.js'
import { createDelegationRef } from '../../core/reanchor.js'
import { sign, publicKeyFromPrivate } from '../../crypto/keys.js'
import type { Delegation } from '../../types/passport.js'
import {
  IDJAG_DRAFT, SOURCE_GRANT_REF_TAG, IdJagBindingError,
} from './types.js'
import type {
  IdJagClaims, IdJagAuthorizationDetail, VerifiedIdJagGrant, IdJagVerification,
  IdJagDescriptor, IdJagDiagnostic, IdJagOpaqueContext, IdJagActReconciliation,
  IdJagBindOptions, SourceGrantRefPreimage,
} from './types.js'

export * from './types.js'

const REQUIRED_CLAIMS: (keyof IdJagClaims)[] = ['iss', 'sub', 'aud', 'client_id', 'jti', 'exp', 'iat']

/**
 * Wrap a decoded grant the caller asserts it has verified. The only constructor
 * for VerifiedIdJagGrant, so an unverified grant cannot reach bindIdJagGrant.
 */
export function verifiedIdJagGrant(grant: IdJagClaims, verification: IdJagVerification): VerifiedIdJagGrant {
  return { grant, verification } as unknown as VerifiedIdJagGrant
}

function numericDateToIso(seconds: number): string {
  return new Date(seconds * 1000).toISOString()
}

/** Project the scope claim to APS scope tokens. Baseline only; RAR never widens it. */
function mapScopeBaseline(claims: IdJagClaims): string[] {
  const out: string[] = []
  if (typeof claims.scope === 'string') {
    for (const tok of claims.scope.split(/\s+/)) {
      if (tok.length > 0) out.push(tok)
    }
  }
  return out
}

/**
 * Project RAR against the scope baseline. RAR that would widen scope is flagged
 * and not applied. A recognized amount with a currency refines spend; an amount
 * without a currency is never stamped with a unit; anything else is carried raw
 * and immutable. The raw objects are always preserved by the caller separately.
 */
function projectRar(
  details: IdJagAuthorizationDetail[],
  scopeBaseline: string[],
): { diagnostics: IdJagDiagnostic[]; spendLimit?: number; spendLimitUnit?: 'currency' | 'invocations' } {
  const diagnostics: IdJagDiagnostic[] = []
  let spendLimit: number | undefined
  let spendLimitUnit: 'currency' | 'invocations' | undefined
  for (const detail of details) {
    const type = typeof detail.type === 'string' ? detail.type : ''
    if (!scopeBaseline.includes(type)) {
      diagnostics.push({ code: 'RAR_SCOPE_CONFLICT_NOT_APPLIED', detail: `RAR type "${type}" is not in the projected scope; not applied (would widen).` })
      continue
    }
    const amount = detail.amount
    if (typeof amount === 'number' && Number.isFinite(amount) && amount >= 0) {
      const currency = detail.currency
      if (typeof currency === 'string' && currency.length > 0) {
        if (spendLimit === undefined) {
          spendLimit = amount
          spendLimitUnit = 'currency'
        }
      } else {
        diagnostics.push({ code: 'UNITLESS_AMOUNT_NOT_STAMPED', detail: `RAR type "${type}" carries amount ${amount} with no currency; carried raw, no spend unit synthesized.` })
      }
    } else {
      diagnostics.push({ code: 'OPAQUE_RAR_CARRIED_IMMUTABLE', detail: `RAR type "${type}" has no recognized refinement; carried raw and immutable through the chain.` })
    }
  }
  const result: { diagnostics: IdJagDiagnostic[]; spendLimit?: number; spendLimitUnit?: 'currency' | 'invocations' } = { diagnostics }
  if (spendLimit !== undefined) {
    result.spendLimit = spendLimit
    result.spendLimitUnit = spendLimitUnit
  }
  return result
}

function buildOpaqueContext(claims: IdJagClaims, minimize: boolean): IdJagOpaqueContext {
  const ctx: IdJagOpaqueContext = {}
  if (claims.tenant !== undefined) ctx.tenant = claims.tenant
  if (claims.aud_tenant !== undefined) ctx.aud_tenant = claims.aud_tenant
  if (claims.acr !== undefined) ctx.acr = claims.acr
  if (claims.amr !== undefined) ctx.amr = claims.amr
  if (claims.auth_time !== undefined) ctx.auth_time = claims.auth_time
  if (!minimize) {
    if (claims.aud_sub !== undefined) ctx.aud_sub = claims.aud_sub
    if (claims.email !== undefined) ctx.email = claims.email
    if (claims.sub_id !== undefined) ctx.sub_id = claims.sub_id
  }
  return ctx
}

/** Literal-only reconciliation of the act claim against the APS chain leaf. Advisory; never authoritative; never claims cross-domain semantic conflict. */
function reconcileAct(act: Record<string, unknown> | undefined, chain: Delegation[]): IdJagActReconciliation {
  if (!act) return { status: 'absent', advisoryAct: null }
  const actActor = typeof act.sub === 'string' ? act.sub : undefined
  const chainActor = chain.length > 0 ? chain[chain.length - 1].delegatedTo : undefined
  if (actActor === undefined || chainActor === undefined) return { status: 'not_comparable', advisoryAct: act }
  if (actActor === chainActor) return { status: 'same_literal_identifier', advisoryAct: act }
  return { status: 'different_literal_identifier_not_enforced', advisoryAct: act }
}

/** Compute the source-grant-ref preimage. Provenance and binding target ONLY: resource is included only when present so absent and present do not hash ambiguously. */
function sourceGrantRefPreimage(claims: IdJagClaims): SourceGrantRefPreimage {
  const pre: SourceGrantRefPreimage = {
    tag: SOURCE_GRANT_REF_TAG,
    draft: IDJAG_DRAFT,
    iss: claims.iss,
    sub: claims.sub,
    jti: claims.jti,
    client_id: claims.client_id,
    aud: claims.aud,
    exp: claims.exp,
  }
  if (claims.resource !== undefined) pre.resource = claims.resource
  return pre
}

/**
 * Bind a caller-verified ID-JAG grant to an APS descriptor. Pure projection: it
 * signs the caller verification attestation and computes the two anchors, but it
 * makes no allow or deny decision, checks no signature on the grant, fetches
 * nothing, and invents no spend unit. The chain is the APS-signed hops the caller
 * built under the grant; this records them and hashes their content.
 *
 * Throws IdJagBindingError 'missing_required_claim' on an absent required claim,
 * or 'missing_verified_at' when no verifiedAt is supplied (it anchors the signed
 * attestation).
 */
export function bindIdJagGrant(
  verified: VerifiedIdJagGrant,
  chain: Delegation[],
  callerPrivateKey: string,
  options: IdJagBindOptions = {},
): IdJagDescriptor {
  const claims = verified.grant
  const verification = verified.verification

  for (const key of REQUIRED_CLAIMS) {
    const value = claims[key]
    if (value === undefined || value === null || value === '') {
      throw new IdJagBindingError('missing_required_claim', `ID-JAG grant is missing required claim: ${String(key)}`)
    }
  }
  const verifiedAt = verification.verifiedAt
  if (typeof verifiedAt !== 'string' || verifiedAt.length === 0) {
    throw new IdJagBindingError('missing_verified_at', 'caller verification must include verifiedAt to anchor the signed attestation')
  }

  const preimage = sourceGrantRefPreimage(claims)
  const sourceGrantRef = canonicalHashJCS(preimage as unknown as Record<string, unknown>)

  const message = `verified grant ${sourceGrantRef} at ${verifiedAt}`
  const signature = sign(message, callerPrivateKey)
  const signerPublicKey = publicKeyFromPrivate(callerPrivateKey)

  const scope = mapScopeBaseline(claims)
  const rawAuthorizationDetails = claims.authorization_details ?? []
  const rar = projectRar(rawAuthorizationDetails, scope)
  const resource = claims.resource
  const iatIso = numericDateToIso(claims.iat)

  const descriptor: IdJagDescriptor = {
    draft: IDJAG_DRAFT,
    sourceGrantRef,
    sourceGrantRefPreimage: preimage,
    delegationChainRoot: computeDelegationChainRoot(chain),
    chain,
    rootRef: createDelegationRef({ did: claims.sub }),
    externalRoot: { type: 'external_identity_assertion', protocol: 'id-jag', verifiedBy: 'caller' },
    delegatedTo: claims.client_id,
    scope,
    rawAuthorizationDetails,
    projectionLossy: true,
    diagnostics: rar.diagnostics,
    createdAt: iatIso,
    expiresAt: numericDateToIso(claims.exp),
    carriedAudience: {
      enforcement: 'not_enforced_by_binding',
      recipients: [claims.aud, ...(resource ? [resource] : [])],
    },
    externalState: { revocation: 'not_checked_by_binding' },
    actReconciliation: reconcileAct(claims.act, chain),
    callerVerification: {
      signal: {
        key: 'id_jag.grant_verified_by_caller',
        valueHash: sourceGrantRef,
        provenance: 'self_declared',
        verificationStatus: 'declared',
        stability: 'account',
        attester: signerPublicKey,
        observedAt: verifiedAt,
        evidenceRef: signature,
      },
      message,
      signature,
      signerPublicKey,
      verifiedAt,
      ...(verification.kid ? { kid: verification.kid } : {}),
    },
    opaqueContext: buildOpaqueContext(claims, options.minimizeSensitive === true),
    notCarried: { cnf: 'not_carried', dpop: 'not_carried' },
  }
  if (rar.spendLimit !== undefined) {
    descriptor.spendLimit = rar.spendLimit
    descriptor.spendLimitUnit = rar.spendLimitUnit
  }
  return descriptor
}
