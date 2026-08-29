// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════
// The Agent Social Contract — High-Level API
// ══════════════════════════════════════════════════════════════
//
// Everything below is one function call.
//
// To JOIN the social contract:
//   const agent = joinSocialContract({ name, mission, ... })
//
// To VERIFY another agent:
//   const trust = verifySocialContract(agent.passport)
//
// To RECORD work:
//   const receipt = recordWork(agent, { action, result })
//
// To PROVE your contributions:
//   const proof = proveContribution(agent, receipts)
//
// That's it. Four functions. The rest is implementation detail.

import { createPassport } from './core/passport.js'
import { verifyPassport } from './verification/verify.js'
import { attestFloor, verifyAttestation, loadFloor, evaluateCompliance } from './core/values.js'
import { createDelegation, createReceipt } from './core/delegation.js'
import {
  hashReceipt, traceBeneficiary,
  generateMerkleProof
} from './core/attribution.js'
import type {
  SignedPassport, KeyPair, FloorAttestation,
  ActionReceipt, Delegation, ValuesFloor, BeneficiaryInfo,
  MerkleProof, AttributionReport, ComplianceReport, BeneficiaryTrace
} from './types/passport.js'

// ══════════════════════════════════════
// JOIN — Create an agent in the social contract
// ══════════════════════════════════════

export interface JoinOptions {
  name: string
  mission: string
  owner: string
  capabilities: string[]
  platform: string
  models: string[]
  // Optional: attest to a values floor
  floor?: ValuesFloor | string   // ValuesFloor object or raw YAML/JSON string
  floorExtensions?: string[]
  // Optional: persistent passport with explicit validity window
  validityWindow?: { notBefore?: string, notAfter: string }
  // Optional: register a human beneficiary
  beneficiary?: {
    id: string
    relationship: 'creator' | 'employer' | 'delegator' | 'owner'
  }
}

export interface SocialContractAgent {
  passport: SignedPassport
  keyPair: KeyPair
  attestation: FloorAttestation | null
  agentId: string
  publicKey: string
}

/**
 * Join the Agent Social Contract.
 *
 * One call. Creates identity, attests to values, registers beneficiary.
 * Returns everything an agent needs to participate.
 */
export function joinSocialContract(opts: JoinOptions): SocialContractAgent {
  const agentId = `agent-${opts.name.toLowerCase().replace(/[^a-z0-9]/g, '-')}-${Date.now().toString(36)}`

  const { signedPassport, keyPair } = createPassport({
    agentId,
    agentName: opts.name,
    ownerAlias: opts.owner,
    mission: opts.mission,
    capabilities: opts.capabilities,
    runtime: {
      platform: opts.platform,
      models: opts.models,
      toolsCount: opts.capabilities.length,
      memoryType: 'persistent'
    },
    beneficiary: opts.beneficiary ? {
      principalId: opts.beneficiary.id,
      relationship: opts.beneficiary.relationship,
      registeredAt: new Date().toISOString()
    } : undefined,
    validityWindow: opts.validityWindow,
  })

  // Attest to floor if provided
  let attestation: FloorAttestation | null = null
  if (opts.floor) {
    const floor = typeof opts.floor === 'string' ? loadFloor(opts.floor) : opts.floor
    attestation = attestFloor(
      agentId,
      signedPassport.passport.publicKey,
      floor.version,
      opts.floorExtensions || [],
      keyPair.privateKey
    )
  }

  return {
    passport: signedPassport,
    keyPair,
    attestation,
    agentId,
    publicKey: signedPassport.passport.publicKey
  }
}

// ══════════════════════════════════════
// VERIFY — Check if an agent is trustworthy
// ══════════════════════════════════════

export interface TrustVerification {
  identity: { valid: boolean; errors: string[]; warnings: string[] }
  values: { attested: boolean; valid: boolean; errors: string[] } | null
  /** Whether an issuer countersignature from one of the caller's trusted
   *  issuers verified. False whenever no trusted issuers were supplied: a
   *  passport signature checks out under the key the passport itself
   *  carries, which establishes that the holder of that key wrote it and
   *  nothing about who vouches for the holder. */
  issuerTrusted: boolean
  /** Every check that RAN, passed: signature, validity window, the issuer
   *  countersignature when trusted issuers were supplied, and the values
   *  attestation when one was supplied. This is a structural verdict. It is
   *  NOT an authorization by a trust root; `issuerTrusted` is that. */
  structurallyValid: boolean
  /** Alias of `structurallyValid`, kept for callers reading `overall`.
   *  It never meant "trusted", which is why the honest name exists now. */
  overall: boolean
}

export interface VerifySocialContractOptions {
  /** Issuer public keys the caller trusts. When supplied and non-empty, the
   *  passport must carry a valid countersignature from one of them, and
   *  `issuerTrusted` reports whether it did. When omitted, no external
   *  trust root is consulted and `issuerTrusted` is false. */
  trustedIssuers?: string[]
}

/**
 * Verify another agent's standing in the social contract.
 *
 * Two separate questions, answered separately:
 *
 *   structurallyValid — the passport signature, its validity window, and
 *     the values attestation if one was supplied, all check out. This is a
 *     statement about the bytes.
 *   issuerTrusted     — an issuer the CALLER named countersigned this
 *     passport. This is the statement about standing.
 *
 * Without `trustedIssuers`, only the first question is answered and
 * `issuerTrusted` is false. The verifier's warnings, including 'No
 * trustedIssuers provided, self-signed passports are accepted', are
 * carried on `identity.warnings` rather than dropped, which is what used to
 * happen: the result was returned as a bare `overall` and rendered to
 * operators as TRUSTED.
 */
export function verifySocialContract(
  passport: SignedPassport,
  attestation?: FloorAttestation | null,
  opts?: VerifySocialContractOptions
): TrustVerification {
  const trustedIssuers = opts?.trustedIssuers ?? []
  const identity = verifyPassport(passport, { trustedIssuers })

  let values: TrustVerification['values'] = null
  if (attestation) {
    const attResult = verifyAttestation(attestation)
    values = {
      attested: true,
      valid: attResult.valid,
      errors: attResult.errors
    }
  }

  // Issuer trust is claimed only when a trust root was actually consulted
  // and the countersignature check that verifyPassport runs against it
  // produced no error.
  const issuerTrusted = trustedIssuers.length > 0 && identity.valid
  const structurallyValid = identity.valid && (!values || values.valid)

  return {
    identity: {
      valid: identity.valid,
      errors: identity.errors,
      warnings: identity.warnings ?? [],
    },
    values,
    issuerTrusted,
    structurallyValid,
    overall: structurallyValid,
  }
}

// ══════════════════════════════════════
// DELEGATE — Grant authority to another agent
// ══════════════════════════════════════

export interface DelegateOptions {
  from: SocialContractAgent          // or a keypair with publicKey
  toPublicKey: string
  scope: string[]
  spendLimit?: number
  maxDepth?: number
  expiresInHours?: number
}

/**
 * Delegate authority from one agent (or human) to another.
 */
export function delegate(opts: DelegateOptions): Delegation {
  return createDelegation({
    delegatedTo: opts.toPublicKey,
    delegatedBy: opts.from.publicKey,
    scope: opts.scope,
    spendLimit: opts.spendLimit,
    maxDepth: opts.maxDepth ?? 1,
    expiresInHours: opts.expiresInHours ?? 24,
    privateKey: opts.from.keyPair.privateKey
  })
}

// ══════════════════════════════════════
// WORK — Record an action
// ══════════════════════════════════════

export interface WorkOptions {
  type: string
  target: string
  scope: string
  spend?: number
  currency?: string
  result: 'success' | 'failure' | 'partial'
  summary: string
}

/**
 * Record a unit of work under a delegation.
 *
 * Returns a signed, verifiable receipt.
 */
export function recordWork(
  agent: SocialContractAgent,
  delegation: Delegation,
  delegationChain: string[],
  work: WorkOptions
): ActionReceipt {
  return createReceipt({
    agentId: agent.agentId,
    delegationId: delegation.delegationId,
    delegation,
    action: {
      type: work.type,
      target: work.target,
      scopeUsed: work.scope,
      spend: work.spend ? { amount: work.spend, currency: work.currency || 'USD' } : undefined
    },
    result: { status: work.result, summary: work.summary },
    delegationChain,
    privateKey: agent.keyPair.privateKey
  })
}

// ══════════════════════════════════════
// PROVE — Generate proof of contributions
// ══════════════════════════════════════

export interface ContributionProof {
  attribution: AttributionReport
  merkleRoot: string
  proofs: Map<string, MerkleProof>   // receiptId -> proof
  traces: BeneficiaryTrace[]
}

/**
 * Generate cryptographic proof of an agent's contributions.
 *
 * Moved to @aeoess/gateway (attribution-reports) because proof generation
 * depends on scope-weight product policy. See MIGRATION.md#attribution-reports.
 */
export function proveContributions(
  _agent: SocialContractAgent,
  _receipts: ActionReceipt[],
  _delegations: Delegation[],
  _beneficiary: string,
  _beneficiaryMap?: Map<string, BeneficiaryInfo>
): ContributionProof {
  throw new Error('Moved to @aeoess/gateway. See MIGRATION.md#attribution-reports')
}

// ══════════════════════════════════════
// AUDIT — Check compliance against the Floor
// ══════════════════════════════════════

/**
 * Audit an agent's compliance. Requires a verifier keypair
 * (the auditor signs the report).
 */
export function auditCompliance(
  agentId: string,
  receipts: ActionReceipt[],
  floor: ValuesFloor,
  delegations: Map<string, { scope: string[]; revoked: boolean }>,
  verifierKeyPair: KeyPair
): ComplianceReport {
  return evaluateCompliance(agentId, receipts, floor, delegations, verifierKeyPair.privateKey)
}
