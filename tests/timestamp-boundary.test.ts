// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// No exported verifier accepts an artifact it cannot read the time of.
// ══════════════════════════════════════════════════════════════════
// The contract, per surface: an artifact that is otherwise perfectly formed
// and correctly signed, but whose security-relevant timestamp is not an
// RFC 3339 instant, is REFUSED. Before the repair every one of these
// accepted it, because an Invalid Date compares false in both directions —
// so `expiresAt < now` said "not expired" and `now - evaluatedAt > maxAge`
// said "fresh".
//
// The table is written the same way for every surface: build a valid
// artifact with the SDK's own constructors, confirm the verifier accepts it,
// then replace one timestamp and confirm it does not. Each surface supplies
// its own `accepts` adapter because the result shapes differ — a boolean, an
// `{ valid, errors }`, a checks array, an is-expired predicate whose TRUE is
// the rejecting answer.
//
// The hostile values are the ones the audit used plus the forms a platform
// parser accepts as real instants: a day that does not exist in its month,
// and the hour-24 end-of-day spelling.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPair, sign } from '../src/crypto/keys.js'
import { canonicalizeForWrite } from '../src/core/canonical.js'
import { verifyPolicyDecision } from '../src/core/policy.js'
import { verifyAttestation } from '../src/core/values.js'
import {
  createSAO, createTaintLabel, createExecutionFrame, createCrossChainPermit,
  countersignPermit, verifyCrossChainPermit, isSAOExpired, isFrameExpired,
  createExecutionReceipt, verifyExecutionReceipt,
} from '../src/core/cross-chain.js'
import { verifyVC } from '../src/core/vc.js'
import { verifyVerifiableCredential } from '../src/core/vc-wrapper.js'
import { createMinimalEnvelope, verifyExecutionEnvelope } from '../src/core/execution-envelope.js'
import { createPassport, isPassportValid } from '../src/core/passport.js'
import { createDelegation, verifyDelegation } from '../src/core/delegation.js'
import { createDID } from '../src/core/did.js'
import { toDIDKey } from '../src/core/did-interop.js'
import type { PolicyDecision } from '../src/types/policy.js'
import type { FloorAttestation } from '../src/types/values.js'

/** Values that are PRESENT and are not instants. Every surface must refuse
 *  these, whether the field is required or optional. */
const MALFORMED: Array<[unknown, string]> = [
  ['not-a-date', 'an invalid string'],
  ['  2026-09-03T12:00:00Z  ', 'a whitespace-padded instant'],
  ['2026-09-03T12:00:00', 'an instant with no zone designator'],
  ['9999-99-99T99:99:99Z', 'every field overflowed'],
  ['2026-02-30T00:00:00Z', 'a day that does not exist in its month'],
  ['2026-01-01T24:00:00Z', 'the hour-24 end-of-day spelling'],
  [4102444800000, 'epoch milliseconds as a number'],
]

/** Values the SDK's canonical form cannot distinguish from an absent field:
 *  canonicalize() strips null and undefined, and every presence test in the
 *  repo is a truthiness test, so the empty string reads as absent too. For a
 *  REQUIRED timestamp these must still refuse — there is no instant. For an
 *  OPTIONAL one they mean the field was not set, and the pre-existing
 *  semantics (no expiry to check) are deliberately preserved. */
const ABSENT_SHAPED: Array<[unknown, string]> = [
  ['', 'the empty string'],
  [null, 'null'],
  [undefined, 'undefined'],
]

const agent = generateKeyPair()
const evaluator = generateKeyPair()
const other = generateKeyPair()

/** Replace one nested field, leaving the rest of the artifact intact. */
function withField<T>(artifact: T, path: string[], value: unknown): T {
  const copy: Record<string, unknown> = JSON.parse(JSON.stringify(artifact))
  let node: Record<string, unknown> = copy
  for (const key of path.slice(0, -1)) node = node[key] as Record<string, unknown>
  node[path[path.length - 1]] = value
  return copy as T
}

/** Sign an object the way the SDK signs it: over the canonical unsigned body. */
function signed<T extends Record<string, unknown>>(body: T, privateKey: string, field = 'signature'): T {
  return { ...body, [field]: sign(canonicalizeForWrite(body), privateKey) }
}

const FUTURE = new Date(Date.now() + 3_600_000).toISOString()
const PAST = new Date(Date.now() - 3_600_000).toISOString()

interface Fixture {
  /** A valid artifact the surface accepts. */
  artifact: Record<string, unknown>
  /** Re-sign after mutation, so a refusal is about the timestamp and not
   *  about a signature the mutation broke. Identity where the field under
   *  test is outside the signed bytes, or where the surface checks no
   *  signature at all — noted per surface. */
  resign: (mutated: Record<string, unknown>) => Record<string, unknown>
}

interface Surface {
  /** Exported function under test, named as a caller would write it. */
  name: string
  /** Field replaced, as a path into the artifact. */
  field: string[]
  /** The field is optional on its artifact, so an absent-shaped value means
   *  "not set" rather than "unreadable". Absent from a required field is
   *  still a refusal. */
  optionalField?: true
  /** Build a valid artifact together with the means to re-sign it. */
  build: () => Fixture
  /** True when the surface ACCEPTED the artifact. */
  accepts: (artifact: never) => boolean | Promise<boolean>
}

/** Re-sign the canonical unsigned body into `field`, the universal APS shape. */
function resigner(privateKey: string, field = 'signature') {
  return (obj: Record<string, unknown>): Record<string, unknown> => {
    const { [field]: _old, ...unsigned } = obj
    return { ...unsigned, [field]: sign(canonicalizeForWrite(unsigned), privateKey) }
  }
}

/** The artifact carries the field under test outside its signed bytes, or the
 *  surface verifies no signature. Stated per surface rather than defaulted, so
 *  a fixture cannot quietly stop re-signing. */
const NOT_SIGNED_OVER = (obj: Record<string, unknown>) => obj

const SURFACES: Surface[] = [
  {
    name: 'verifyPolicyDecision — decision.expiresAt',
    field: ['expiresAt'],
    build: () => ({
      artifact: resigner(evaluator.privateKey)({
        decisionId: 'pdec_ts_0001',
        intentId: 'intent_ts_0001',
        evaluatorId: 'evaluator-ts',
        evaluatorPublicKey: evaluator.publicKey,
        verdict: 'permit',
        principlesEvaluated: [],
        reason: 'within floor',
        floorVersion: 'floor-v0.2',
        evaluatedAt: PAST,
        expiresAt: FUTURE,
      }),
      resign: resigner(evaluator.privateKey),
    }),
    accepts: (d: never) => verifyPolicyDecision(d).valid,
  },
  {
    name: 'verifyAttestation — attestation.expiresAt',
    field: ['expiresAt'],
    build: () => ({
      artifact: resigner(agent.privateKey)({
        attestationId: 'att_ts_0001',
        agentId: 'agent-ts',
        publicKey: agent.publicKey,
        floorVersion: 'floor-v0.2',
        extensions: [],
        attestedAt: PAST,
        expiresAt: FUTURE,
        commitment: 'I accept the floor',
      }),
      resign: resigner(agent.privateKey),
    }),
    accepts: (a: never) => verifyAttestation(a).valid,
  },
  {
    name: 'verifyCrossChainPermit — permit.expiresAt',
    field: ['expiresAt'],
    build: () => {
      const source = generateKeyPair()
      const dest = generateKeyPair()
      const permit = countersignPermit(
        createCrossChainPermit({
          sourcePrincipalId: 'principal-a',
          sourcePrincipalPublicKey: source.publicKey,
          sourceDataClasses: ['pii'],
          destPrincipalId: 'principal-b',
          destPrincipalPublicKey: dest.publicKey,
          destAllowedScopes: ['read:*'],
          purpose: 'timestamp boundary fixture',
          sourcePrivateKey: source.privateKey,
        }),
        dest.privateKey,
      )
      // Both principals sign the same body, which includes expiresAt.
      const resign = (p: Record<string, unknown>): Record<string, unknown> => {
        const body = {
          sourceContext: p.sourceContext,
          destinationContext: p.destinationContext,
          purpose: p.purpose,
          destinationConstraints: p.destinationConstraints,
          createdAt: p.createdAt,
          expiresAt: p.expiresAt,
        }
        const payload = canonicalizeForWrite(body)
        return {
          ...p,
          sourceSignature: sign(payload, source.privateKey),
          destinationSignature: sign(payload, dest.privateKey),
        }
      }
      return { artifact: permit as unknown as Record<string, unknown>, resign }
    },
    accepts: (p: never) => verifyCrossChainPermit(p),
  },
  {
    name: 'isSAOExpired — sao.expiresAt (accepted = not expired)',
    field: ['expiresAt'],
    build: () => ({
      // expiresAt is outside the monitor-signed payload, and isSAOExpired
      // verifies no signature — it answers only the expiry question.
      artifact: createSAO(
        { record: 1 },
        createTaintLabel('principal-a', 'chain-a', 'del-a', 'internal'),
        agent.privateKey,
        agent.publicKey,
      ) as unknown as Record<string, unknown>,
      resign: NOT_SIGNED_OVER,
    }),
    accepts: (s: never) => !isSAOExpired(s),
  },
  {
    name: 'isFrameExpired — frame.startedAt (accepted = not expired)',
    field: ['startedAt'],
    build: () => ({
      // An ExecutionFrame carries no signature.
      artifact: createExecutionFrame('agent-ts', { ttlMinutes: 60 }) as unknown as Record<string, unknown>,
      resign: NOT_SIGNED_OVER,
    }),
    accepts: (f: never) => !isFrameExpired(f),
  },
  {
    name: 'verifyExecutionReceipt — receipt.expiresAt',
    field: ['expiresAt'],
    build: () => ({
      artifact: createExecutionReceipt({
        frame: createExecutionFrame('agent-ts', { ttlMinutes: 60 }),
        requestHash: 'sha256:fixture',
        tool: 'search',
        params: { q: 'x' },
        delegationId: 'del-ts',
        policyVersion: 'v1',
        flowResult: { verdict: 'permitted', blockingLabels: [], reason: 'ok', taintSet: [], checkedAt: PAST },
        gatewayId: 'gateway-ts',
        gatewayPrivateKey: evaluator.privateKey,
      }) as unknown as Record<string, unknown>,
      resign: resigner(evaluator.privateKey, 'gatewaySignature'),
    }),
    accepts: (r: never) => verifyExecutionReceipt(r, evaluator.publicKey).valid,
  },
  {
    name: 'isPassportValid — passport.expiresAt',
    field: ['expiresAt'],
    build: () => ({
      // isPassportValid answers the window question only; the passport
      // signature is verified by verifyPassport, not here.
      artifact: createPassport({
        agentName: 'ts-agent', ownerAlias: 'ts-owner', mission: 'fixture',
        capabilities: ['read'], runtime: { platform: 'node', models: ['none'] },
      }).signedPassport.passport as unknown as Record<string, unknown>,
      resign: NOT_SIGNED_OVER,
    }),
    accepts: (p: never) => isPassportValid(p).valid,
  },
  {
    name: 'verifyDelegation — delegation.expiresAt',
    field: ['expiresAt'],
    build: () => ({
      artifact: createDelegation({
        delegatedTo: agent.publicKey,
        delegatedBy: other.publicKey,
        scope: ['read:*'],
        privateKey: other.privateKey,
      }) as unknown as Record<string, unknown>,
      resign: resigner(other.privateKey),
    }),
    accepts: (d: never) => verifyDelegation(d).valid,
  },
  {
    name: 'verifyExecutionEnvelope — decision.evaluated_at under a freshness window',
    field: ['decision', 'evaluated_at'],
    build: () => ({
      artifact: createMinimalEnvelope({
        agentDid: 'did:aps:agent', runId: 'run-ts', actionId: 'action-ts',
        scope: ['read:*'], revocationStatus: 'active',
        decisionHash: 'sha256:fixture', policyRef: 'floor-v0.2',
        evaluationMethod: 'deterministic', verdict: 'permit',
        evaluatedAt: new Date().toISOString(),
        evaluatorDid: 'did:aps:evaluator',
        evaluatorSignature: sign('fixture', evaluator.privateKey),
        receiptHash: 'sha256:fixture',
        signerPrivateKey: evaluator.privateKey, signerPublicKey: evaluator.publicKey,
      }) as unknown as Record<string, unknown>,
      // Only the freshness axis is asserted, and decisionFresh does not
      // depend on the envelope signature. F-01's own negatives live in
      // tests/execution-envelope.test.ts.
      resign: NOT_SIGNED_OVER,
    }),
    accepts: (e: never) =>
      verifyExecutionEnvelope(e, { maxDecisionAgeMs: 3_600_000 }).decisionFresh,
  },
  {
    name: 'verifyVC — credential.expirationDate',
    field: ['expirationDate'],
    optionalField: true,
    build: () => ({ artifact: vcFixture(FUTURE, 'did:aps'), resign: resignCredential('did:aps') }),
    accepts: async (c: never) => (await verifyVC(c)).valid,
  },
  {
    name: 'verifyVerifiableCredential — vc.expirationDate',
    field: ['expirationDate'],
    optionalField: true,
    build: () => ({ artifact: vcFixture(FUTURE, 'did:key'), resign: resignCredential('did:key') }),
    accepts: async (c: never) => (await verifyVerifiableCredential(c)).valid,
  },
]

/** Rebuild a credential's proof over the mutated body, so the negatives test
 *  the expiry check and not a signature the mutation invalidated. */
function resignCredential(method: 'did:aps' | 'did:key') {
  return (c: Record<string, unknown>): Record<string, unknown> => {
    const { proof, ...body } = c
    const did = method === 'did:key' ? toDIDKey(agent.publicKey) : createDID(agent.publicKey)
    return {
      ...body,
      proof: {
        type: 'Ed25519Signature2020',
        created: PAST,
        verificationMethod: `${did}#key-1`,
        proofPurpose: 'assertionMethod',
        proofValue: Buffer.from(sign(canonicalizeForWrite(body), agent.privateKey), 'hex').toString('base64url'),
      },
    }
  }
}

/** A credential whose expiry is the only variable. Built by hand rather than
 *  through passportToVC so the expiry can be set directly; the proof is real. */
function vcFixture(expirationDate: string, method: 'did:aps' | 'did:key' = 'did:aps'): Record<string, unknown> {
  // vc.ts resolves a did:aps identifier, vc-wrapper.ts a did:key one. The
  // fixture uses each module's own DID constructor so it cannot drift from
  // the form that module accepts.
  const did = method === 'did:key' ? toDIDKey(agent.publicKey) : createDID(agent.publicKey)
  const body = {
    '@context': ['https://www.w3.org/ns/credentials/v2'],
    id: 'urn:aps:credential:timestamp-fixture',
    type: ['VerifiableCredential'],
    issuer: did,
    issuanceDate: PAST,
    expirationDate,
    credentialSubject: { id: did, role: 'fixture' },
  }
  return {
    ...body,
    proof: {
      type: 'Ed25519Signature2020',
      created: PAST,
      verificationMethod: `${did}#key-1`,
      proofPurpose: 'assertionMethod',
      proofValue: Buffer.from(sign(canonicalizeForWrite(body), agent.privateKey), 'hex').toString('base64url'),
    },
  }
}

describe('every exported verifier refuses an unreadable security timestamp', () => {
  for (const surface of SURFACES) {
    describe(surface.name, () => {
      it('accepts the artifact when the timestamp is a real instant', async () => {
        const ok = await surface.accepts(surface.build().artifact as never)
        assert.equal(ok, true, 'the fixture itself must be accepted, or the negatives prove nothing')
      })

      for (const [value, why] of MALFORMED) {
        it(`refuses ${why}`, async () => {
          const { artifact, resign } = surface.build()
          const mutated = resign(withField(artifact, surface.field, value))
          const accepted = await surface.accepts(mutated as never)
          assert.equal(accepted, false,
            `${surface.name} accepted ${JSON.stringify(value)} as ${surface.field.join('.')}`)
        })
      }

      for (const [value, why] of ABSENT_SHAPED) {
        const expectAccept = surface.optionalField === true
        it(`${expectAccept ? 'reads as absent' : 'refuses'}: ${why}`, async () => {
          const { artifact, resign } = surface.build()
          const mutated = resign(withField(artifact, surface.field, value))
          const accepted = await surface.accepts(mutated as never)
          assert.equal(accepted, expectAccept,
            expectAccept
              ? `${surface.name} must treat ${JSON.stringify(value)} as an unset optional field`
              : `${surface.name} accepted ${JSON.stringify(value)} as ${surface.field.join('.')}`)
        })
      }
    })
  }
})

describe('the refusal is about the timestamp, not about the harness', () => {
  // A guard on the guard. Mutating a signed field and re-signing is exactly
  // what the negatives do; if that path corrupted the artifact by itself,
  // every negative above would pass for the wrong reason. Writing the
  // artifact's OWN value back through the same path must still be accepted.
  for (const surface of SURFACES) {
    it(`${surface.name}: the same value written back is still accepted`, async () => {
      const { artifact, resign } = surface.build()
      let node: Record<string, unknown> = artifact
      for (const key of surface.field.slice(0, -1)) node = node[key] as Record<string, unknown>
      const value = node[surface.field[surface.field.length - 1]]
      const rebuilt = resign(withField(artifact, surface.field, value))
      assert.equal(await surface.accepts(rebuilt as never), true)
    })
  }
})
