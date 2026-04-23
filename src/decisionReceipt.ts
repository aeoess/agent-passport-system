// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Decision Receipt (v2.3, Component A — dumb-sink hardening)
// ══════════════════════════════════════════════════════════════════
// Emits an in-toto Decision Receipt v0.1 predicate alongside the
// existing PolicyReceipt. The PolicyReceipt is the v2.x backward-
// compatible record; the DecisionReceiptEnvelope is the bilateral
// attestation target committed to in:
//   docs/ENFORCEMENT-TRUST-ANCHOR.md Component A
//   https://github.com/in-toto/attestation/pull/549
//
// The envelope is produced as a DSSE-style signed Statement:
//
//   { payloadType, payload: <JCS-canonical Statement string>,
//     signatures: [{ keyid, sig }] }
//
// so it verifies against @veritasacta/verify and composes with the
// parallel Python emission in aeoess/hermes-aps-delegation. This
// module is a pure primitive: no network, no mutable state, no
// gateway dependency. Gateway integration is the caller's choice.
// ══════════════════════════════════════════════════════════════════

import { createHash } from 'node:crypto'
import { sign } from './crypto/keys.js'
import { canonicalizeJCS } from './core/canonical-jcs.js'
import type { ActionIntent, PolicyDecision, EpistemicClaims } from './types/policy.js'
import type { Delegation, ActionReceipt } from './types/passport.js'

/** Canonical predicate identifier for the in-toto Decision Receipt v0.1.
 *  Matches the emission on the Hermes-APS delegation Python side. */
export const DECISION_RECEIPT_PREDICATE_TYPE =
  'https://veritasacta.com/attestation/decision-receipt/v0.1' as const

/** in-toto Statement envelope type. */
export const INTOTO_STATEMENT_V1 = 'https://in-toto.io/Statement/v1' as const

/** DSSE payloadType for in-toto Statements. */
export const INTOTO_PAYLOAD_TYPE = 'application/vnd.in-toto+json' as const

// ── in-toto Statement v1 types ──

export interface IntotoResourceDescriptor {
  name: string
  digest: { sha256: string }
}

export interface DecisionReceiptPredicate {
  decision: 'permit' | 'deny' | 'narrow'
  reason: string
  policyId: string
  policyDigest: { sha256: string }
  /** SHA-256 hex of the JCS canonicalization of the full delegation chain. */
  delegationChainRoot: { sha256: string }
  /** Hops from the root principal to the acting agent. */
  delegationDepth: number
  /** Typed epistemic labels — see PolicyReceipt.epistemic_claims. */
  epistemicClaims: EpistemicClaims
  issuerId: string
  issuedAt: string
  /** Digest of the ActionIntent the decision is attesting. */
  intentDigest: { sha256: string }
  /** Digest of the ActionReceipt that witnessed the executed effect. */
  receiptDigest: { sha256: string }
  metadata: {
    framework: 'aps'
    receiptKind: 'decision_receipt'
    apsVersion: string
    actionRef?: string
    [key: string]: unknown
  }
}

export interface IntotoStatement {
  _type: typeof INTOTO_STATEMENT_V1
  predicateType: typeof DECISION_RECEIPT_PREDICATE_TYPE
  subject: IntotoResourceDescriptor[]
  predicate: DecisionReceiptPredicate
}

export interface DSSESignature {
  keyid: string
  sig: string
}

/** DSSE-style signed envelope returned by emitDecisionReceipt.
 *  Verifies with @veritasacta/verify (Apache-2.0) and composes with
 *  the Python emission in aeoess/hermes-aps-delegation. */
export interface DecisionReceiptEnvelope {
  payloadType: typeof INTOTO_PAYLOAD_TYPE
  payload: string              // JCS-canonical JSON of IntotoStatement
  signatures: DSSESignature[]
  /** Convenience field (not part of DSSE) — SHA-256 of the payload bytes.
   *  Lets callers chain envelopes without re-canonicalizing. */
  _digest: { sha256: string }
}

// ── Input contract ──

export interface EmitDecisionReceiptInput {
  /** The agent's signed request. */
  intent: ActionIntent
  /** The evaluator's signed verdict. */
  decision: PolicyDecision
  /** The acting agent's signed receipt of what actually happened. */
  receipt: ActionReceipt
  /** Ordered root-to-leaf delegation chain that authorized the action.
   *  delegation_chain_root is SHA-256(JCS(chain)); delegation_depth is chain.length. */
  delegationChain: Delegation[]
  /** Typed epistemic labels the emitter asserts for this receipt. */
  epistemicClaims: EpistemicClaims
  /** Policy identifier (e.g. 'floor-validator-v1'). */
  policyId: string
  /** Ed25519 private key (hex) of the signer. */
  signerPrivateKey: string
  /** Stable identifier for the signing key. Defaults to `ed25519:<first-16-hex>`
   *  derived from the public key when not supplied. */
  signerKeyId: string
  /** Issuer DID or stable identifier for the signing party. */
  issuerId: string
  /** APS version string. Defaults to '2.3.0-alpha'. */
  apsVersion?: string
}

// ── Helpers ──

function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex')
}

function digestOf(obj: unknown): { sha256: string } {
  return { sha256: sha256Hex(canonicalizeJCS(obj)) }
}

/** Compute the delegation chain root digest used by v2.3 bilateral receipts.
 *  Deterministic across re-emissions: SHA-256 of the JCS serialization of the
 *  chain array. Exported so verifiers and cross-repo implementations (e.g. the
 *  Python hermes-aps-delegation emitter) can reproduce it byte-for-byte. */
export function computeDelegationChainRoot(chain: Delegation[]): string {
  return sha256Hex(canonicalizeJCS(chain))
}

// ── Main primitive ──

/** Emit an in-toto Decision Receipt v0.1 envelope.
 *
 *  Pure function. Given an intent/decision/receipt triple and the delegation
 *  chain that authorized it, produces a DSSE-style signed Statement whose
 *  predicate carries delegation_chain_root, delegation_depth, and the typed
 *  epistemic_claims. The caller retains the ordinary PolicyReceipt for v2.2.x
 *  consumers and emits this envelope in parallel for v2.3-aware verifiers.
 *
 *  The returned envelope's payload string is the JCS canonicalization of the
 *  in-toto Statement — signed bytes match the payload field exactly, so a
 *  verifier canonicalizes json.loads(envelope.payload) and checks equality
 *  before verifying the signature. Cross-repo interop requires nothing more
 *  than JCS and Ed25519. */
export function emitDecisionReceipt(input: EmitDecisionReceiptInput): DecisionReceiptEnvelope {
  const apsVersion = input.apsVersion ?? '2.3.0-alpha'

  const subject: IntotoResourceDescriptor[] = [
    {
      name: `aps-action:${input.intent.action.type}:${input.intent.intentId}`,
      digest: digestOf(input.intent),
    },
  ]

  const predicate: DecisionReceiptPredicate = {
    decision: input.decision.verdict,
    reason: input.decision.reason,
    policyId: input.policyId,
    policyDigest: digestOf({ version: input.decision.floorVersion, policyId: input.policyId }),
    delegationChainRoot: {
      sha256: computeDelegationChainRoot(input.delegationChain),
    },
    delegationDepth: input.delegationChain.length,
    epistemicClaims: input.epistemicClaims,
    issuerId: input.issuerId,
    issuedAt: new Date().toISOString(),
    intentDigest: digestOf(input.intent),
    receiptDigest: digestOf(input.receipt),
    metadata: {
      framework: 'aps',
      receiptKind: 'decision_receipt',
      apsVersion,
      actionRef: input.intent.actionRef,
    },
  }

  const statement: IntotoStatement = {
    _type: INTOTO_STATEMENT_V1,
    predicateType: DECISION_RECEIPT_PREDICATE_TYPE,
    subject,
    predicate,
  }

  const payload = canonicalizeJCS(statement)
  const signature = sign(payload, input.signerPrivateKey)

  return {
    payloadType: INTOTO_PAYLOAD_TYPE,
    payload,
    signatures: [{ keyid: input.signerKeyId, sig: signature }],
    _digest: { sha256: sha256Hex(payload) },
  }
}

/** Parse a DecisionReceiptEnvelope payload back into its in-toto Statement.
 *  Round-trip: canonicalizeJCS(parseDecisionReceiptStatement(env)) === env.payload. */
export function parseDecisionReceiptStatement(envelope: DecisionReceiptEnvelope): IntotoStatement {
  return JSON.parse(envelope.payload) as IntotoStatement
}
