// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// AUD-145-APS-01 — bare-verifier null / non-object input guards
// ══════════════════════════════════════════════════════════════════
// Every exported bare verifier takes attacker-deliverable input. The JSON
// literal `null`, a bare `undefined`, or any non-object must return the
// verifier's normal reject verdict — NOT throw a TypeError. A thrown
// verifier is a denial-of-service and a fail-open trap: the caller's
// catch path is not the verifier's `{ valid: false }` path.
//
// This suite iterates every fixed verifier over the hostile input set and
// asserts (a) NONE throw, and (b) each returns a reject / invalid verdict.
// Before the Day-145 fix, the null and undefined cases threw a TypeError.
// ══════════════════════════════════════════════════════════════════

import { describe, it } from 'node:test'
import assert from 'node:assert/strict'

import {
  verifyActionReceipt,
  verifyCustodyReceipt,
  verifyContestabilityReceipt,
  verifyAPSBundle,
} from '../../src/v2/accountability/index.js'
import {
  verifyReceiptContext,
  verifyOffline,
  type ReceiptContext,
} from '../../src/v2/offline-verifier/index.js'
import { verifyPassport } from '../../src/verification/verify.js'
import { verifyDelegation, verifyRevocation } from '../../src/core/delegation.js'
import { verifyBilateralReceipt } from '../../src/core/bilateral-receipt.js'

// The hostile input set: the two that used to throw (null / undefined) plus
// the wrong-typed inputs that already rejected correctly (must keep rejecting).
const HOSTILE_INPUTS: readonly unknown[] = [null, undefined, 123, 'x', true, [], {}]

// A minimal, well-formed context so verifyReceiptContext reaches its receipt
// guard rather than failing on a malformed ctx. The receipt is what is under
// test here, not the context.
const MINIMAL_CTX: ReceiptContext = {
  now: '2026-07-11T00:00:00.000Z',
  active_delegation_root: 'root',
  delegation_expires_at: '2030-01-01T00:00:00.000Z',
  revoked_delegation_roots: [],
  budget_base_units: 0n,
  action_cost_base_units: 0n,
  expected_principal_did: 'did:example:principal',
  active_policy_version: 1,
  evaluated_policy_version: 1,
  seen_receipt_ids: [],
  presented_as_claim_type: 'aps:action:v1',
  execution_attested: true,
}

// Each verifier: how to run it on one hostile input, and how to read "reject"
// out of its (verifier-specific) result shape.
interface VerifierCase {
  name: string
  run: (input: unknown) => unknown
  isReject: (result: unknown) => boolean
}

const CASES: readonly VerifierCase[] = [
  {
    name: 'verifyActionReceipt',
    run: input => verifyActionReceipt(input as never),
    isReject: r => (r as { valid: boolean }).valid === false,
  },
  {
    name: 'verifyCustodyReceipt',
    run: input => verifyCustodyReceipt(input as never),
    isReject: r => (r as { valid: boolean }).valid === false,
  },
  {
    name: 'verifyContestabilityReceipt',
    run: input => verifyContestabilityReceipt(input as never),
    isReject: r => (r as { valid: boolean }).valid === false,
  },
  {
    name: 'verifyAPSBundle',
    run: input => verifyAPSBundle(input as never),
    isReject: r => (r as { valid: boolean }).valid === false,
  },
  {
    name: 'verifyReceiptContext',
    run: input => verifyReceiptContext(input as never, MINIMAL_CTX),
    isReject: r => (r as { valid: boolean }).valid === false,
  },
  {
    name: 'verifyOffline',
    run: input => verifyOffline(input as never),
    isReject: r => (r as { verdict: string }).verdict === 'reject',
  },
  {
    name: 'verifyBilateralReceipt',
    run: input =>
      verifyBilateralReceipt(input as never, 'requesting-pk', 'serving-pk'),
    isReject: r => (r as { valid: boolean }).valid === false,
  },
  {
    name: 'verifyPassport',
    run: input => verifyPassport(input as never),
    isReject: r => (r as { valid: boolean }).valid === false,
  },
  {
    name: 'verifyDelegation',
    run: input => verifyDelegation(input as never),
    isReject: r => (r as { valid: boolean }).valid === false,
  },
  {
    name: 'verifyRevocation',
    run: input => verifyRevocation(input as never),
    isReject: r => r === false, // returns a bare boolean
  },
]

describe('AUD-145-APS-01: bare verifiers reject null / non-object without throwing', () => {
  for (const c of CASES) {
    for (const input of HOSTILE_INPUTS) {
      const label = input === undefined ? 'undefined' : JSON.stringify(input)
      it(`${c.name}(${label}) rejects and does not throw`, () => {
        let result: unknown
        assert.doesNotThrow(() => {
          result = c.run(input)
        }, `${c.name} threw on ${label} instead of returning a reject verdict`)
        assert.equal(
          c.isReject(result),
          true,
          `${c.name} did not reject ${label}`,
        )
      })
    }
  }
})
