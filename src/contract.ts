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
  /** Whether a trust root was consulted at all, i.e. whether the caller
   *  supplied a non-empty trustedIssuers list. */
  issuerChecked: boolean
  /** Whether an issuer countersignature from one of those trusted issuers
   *  verified. Always false when no trust root was consulted. */
  issuerTrusted: boolean
  /** Why the issuer check failed, when one ran. Kept out of
   *  identity.errors so that a missing trust root never reads as a defect
   *  in the passport itself. */
  issuerErrors: string[]
  /** The passport's own signature, its validity window, and the values
   *  attestation when one was supplied. A property of the BYTES: it does
   *  not move when the caller changes their trust configuration. It is not
   *  an authorization by a trust root; `issuerTrusted` is that. */
  structurallyValid: boolean
  /** @deprecated Reading this emits a runtime DeprecationWarning.
   *
   *  Equal to `structurallyValid && (!issuerChecked || issuerTrusted)`,
   *  which is exactly what this field always returned. The name says
   *  "overall" and was rendered to operators as TRUSTED, but with no
   *  trustedIssuers supplied it has only ever meant "the bytes check out".
   *  Read `structurallyValid` and `issuerTrusted` instead and decide
   *  explicitly which one your call site needs. */
  overall: boolean
}

export interface VerifySocialContractOptions {
  /** Issuer public keys the caller trusts. When supplied and non-empty, the
   *  passport must carry a valid countersignature from one of them for
   *  `issuerTrusted` to be true. When omitted, no external trust root is
   *  consulted, `issuerChecked` is false, and `issuerTrusted` is false. */
  trustedIssuers?: string[]
}

let overallDeprecationEmitted = false

/**
 * Verify another agent's standing in the social contract.
 *
 * Two independent questions, answered by two separate checks so that
 * neither can move the other:
 *
 *   structurallyValid — the passport signature, its validity window, and
 *     the values attestation if one was supplied, all check out. Computed
 *     WITHOUT the caller's anchors, so it is a statement about the bytes and
 *     is stable across trust configurations. Round 1 computed it from the
 *     anchored check, so a byte-identical passport flipped true to false
 *     purely because the caller passed a trustedIssuers list, and the CLI
 *     printed a failure over a passport that verified.
 *   issuerTrusted     — an issuer the CALLER named countersigned this
 *     passport. This is the statement about standing.
 *
 * Without `trustedIssuers`, only the first question is answered.
 * `issuerChecked` reports whether the second one was even asked, so "no
 * trust root consulted" is never indistinguishable from "trust root
 * consulted and failed".
 */
export function verifySocialContract(
  passport: SignedPassport,
  attestation?: FloorAttestation | null,
  opts?: VerifySocialContractOptions
): TrustVerification {
  const trustedIssuers = opts?.trustedIssuers ?? []
  const issuerChecked = trustedIssuers.length > 0

  // Structure first, deliberately WITHOUT anchors. verifyPassport folds the
  // issuer countersignature into its own `valid`, so passing anchors here
  // would make the structural verdict depend on the caller's configuration.
  const structural = verifyPassport(passport)

  // Trust root second, as a separate question. Only asked when the caller
  // named anchors to ask it against.
  const anchored = issuerChecked
    ? verifyPassport(passport, { trustedIssuers })
    : undefined

  let values: TrustVerification['values'] = null
  if (attestation) {
    const attResult = verifyAttestation(attestation)
    values = {
      attested: true,
      valid: attResult.valid,
      errors: attResult.errors
    }
  }

  const issuerTrusted = anchored !== undefined && anchored.valid
  // Errors the anchored check raised that the unanchored one did not: the
  // issuer-trust failures, isolated from the passport's own problems.
  const issuerErrors = anchored
    ? anchored.errors.filter(e => !structural.errors.includes(e))
    : []
  const structurallyValid = structural.valid && (!values || values.valid)

  const result = {
    identity: {
      valid: structural.valid,
      errors: structural.errors,
      warnings: structural.warnings ?? [],
    },
    values,
    issuerChecked,
    issuerTrusted,
    issuerErrors,
    structurallyValid,
  } as TrustVerification

  // `overall` is an accessor, not a stored field, so that reading it emits a
  // deprecation warning once per process. Enumerable so JSON.stringify of a
  // result still carries it for existing consumers. Its VALUE is unchanged
  // from before the split: structure AND whatever trust the caller demanded.
  Object.defineProperty(result, 'overall', {
    enumerable: true,
    configurable: true,
    get() {
      if (!overallDeprecationEmitted) {
        overallDeprecationEmitted = true
        process.emitWarning(
          'TrustVerification.overall is deprecated: it reads as a trust decision but with no trustedIssuers supplied it only means the bytes check out. Read structurallyValid and issuerTrusted instead.',
          'DeprecationWarning',
        )
      }
      return structurallyValid && (!issuerChecked || issuerTrusted)
    },
  })

  return result
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
