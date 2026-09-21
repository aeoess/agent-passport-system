// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { snapshotPlainData } from '../authority-delegation/plain-data.js'
import type { AuthorityDelegationV1 } from '../authority-delegation/types.js'
import { verifyAuthorityRevocation } from './verify.js'
import type { AuthorityRevocationVerificationOptions } from './verify.js'
import type {
  AuthorityRevocationStore,
  AuthorityRevocationV1,
  AuthorityRevocationVerificationResult,
} from './types.js'

/**
 * What recordAuthorityRevocation() answers. Discriminated on `recorded`, so a caller
 * cannot read `stored` without having decided which case it is in.
 *
 *  - `recorded: true` — the candidate verified against its target. `stored` is what the
 *    store holds for that delegation now, and `inserted` says whether this call is the
 *    one that wrote it. `inserted: false` with `recorded: true` is the ordinary
 *    first-wins case: a valid revocation arrived second and the earlier record stands.
 *  - `recorded: false` — the candidate did not verify. `stored` is `undefined`, always,
 *    including when the store already holds a valid record for the same delegation. A
 *    rejected request is never handed somebody else's record as though it were its own
 *    result; `verification` carries the failures that rejected it.
 *
 * `verification` is the candidate's own result in both cases, never a result borrowed
 * from a record already held.
 */
export type AuthorityRevocationRecordResult =
  | {
      recorded: true
      inserted: boolean
      stored: AuthorityRevocationV1
      verification: AuthorityRevocationVerificationResult
    }
  | {
      recorded: false
      inserted: false
      stored: undefined
      verification: AuthorityRevocationVerificationResult
    }

/**
 * Verify one candidate revocation against the delegation it names and, only then, offer
 * it to `store` for the delegation's first-wins slot. The one supported way a revocation
 * enters a store.
 *
 * The defect this closes: a store's write primitive takes a record and a record alone,
 * and a store can verify nothing, because verification needs the target delegation and a
 * key resolver and a store holds neither. A write path reachable with an arbitrary object
 * therefore lets any object take the first-wins slot for a delegation, and because that
 * slot is irreversible (INV-5), the delegation can never afterwards record the valid
 * revocation that would have revoked it. The resolver's own re-verification keeps such a
 * record from ever reading as 'revoked', so the damage is not a false revocation; it is a
 * permanently blocked real one. Verification belongs before the write, which is here.
 *
 * Order of operations:
 *
 *  1. snapshot the candidate as plain JSON data, once
 *  2. verify that snapshot against `delegation` under `options`
 *  3. on anything but `valid`, return `recorded: false` with that verification result and
 *     no record, having touched the store not at all
 *  4. on `valid`, hand the SNAPSHOT to store.insertVerifiedRevocation() and report what
 *     the store says it now holds
 *
 * Step 1 and step 4 use the same snapshot, so the bytes the store keeps are exactly the
 * bytes that were verified. Passing the caller's original value instead would let a
 * getter or a Proxy trap answer one way for the verifier and another for the store.
 *
 * `options` is the same key resolution the resolver takes; the key is resolved under the
 * TARGET delegation's issuer, at the revocation's own `revoked_at`. See
 * verifyAuthorityRevocation().
 *
 * Does not throw on a bad candidate: an unusable candidate, an unusable target and an
 * unusable resolver are all verification results, and verifyAuthorityRevocation() does
 * not throw. An exception raised by `store` itself is not caught. A store that cannot
 * complete a write has not produced a verification outcome, and reporting its failure as
 * one would be a lie about the record rather than about the store.
 */
export function recordAuthorityRevocation(
  store: AuthorityRevocationStore,
  delegation: AuthorityDelegationV1,
  candidate: unknown,
  options: AuthorityRevocationVerificationOptions,
): AuthorityRevocationRecordResult {
  const snapshot = snapshotPlainData(candidate)
  const verification = verifyAuthorityRevocation(snapshot, delegation, options)
  if (!verification.valid) {
    return { recorded: false, inserted: false, stored: undefined, verification }
  }
  const { inserted, stored } = store.insertVerifiedRevocation(snapshot as AuthorityRevocationV1)
  return { recorded: true, inserted, stored, verification }
}
