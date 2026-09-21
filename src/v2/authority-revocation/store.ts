// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import type {
  AuthorityRevocationInsertion,
  AuthorityRevocationStore,
  AuthorityRevocationV1,
} from './types.js'

/**
 * Reference AuthorityRevocationStore holding every record in this process's heap.
 *
 * For tests, fixtures and local reference use. It is not a persistence layer and does not
 * become one: the records live in two Maps and are gone when the process exits, when the
 * object is garbage collected, or when a second process asks the same question. Draft
 * section 3.5.1 makes cascade completion depend on a descendant's revocation being
 * PERSISTENT, and nothing here can establish that, which is why this module emits no
 * completion record.
 *
 * Behavior this class fixes, none of it settled by draft text:
 *
 *  - First verified revocation for a delegation wins. INV-5 makes revocation
 *    irreversible, and a store that let a second record displace the first would make the
 *    recorded revocation time, reason and revoker mutable after the fact.
 *  - insertVerifiedRevocation() for a delegation that already has a record reports
 *    `inserted: false` and returns the record already held, and the caller's record is
 *    discarded. A repeated request is therefore idempotent in what the store reports, not
 *    in the bytes the caller minted: two calls with different nonces mint two different
 *    valid records, and the store keeps the first.
 *  - insertVerifiedRevocation() brings its target into the tracked view. Recording a
 *    revocation for a delegation is a statement that this store has an opinion about that
 *    delegation.
 *
 * insertVerifiedRevocation() is a persistence primitive and not an entry point. It does
 * not verify, and a store cannot: verification needs the target delegation and a key
 * resolver, neither of which is here. recordAuthorityRevocation() in record.ts is the
 * one supported way in; it verifies against the target and calls this method only on a
 * `valid` result. Nothing about that split relaxes the resolver, which still verifies on
 * the way out, so a record that reached this store by some other route still cannot
 * produce a 'revoked' answer.
 */
export class InMemoryAuthorityRevocationStore implements AuthorityRevocationStore {
  private readonly tracked = new Set<string>()
  private readonly records = new Map<string, AuthorityRevocationV1>()

  /** Bring `delegationId` into this store's view with no revocation recorded for it.
   *
   *  Not part of AuthorityRevocationStore: how a store learns which delegations it covers
   *  is an implementation's own business, and a database-backed store would answer
   *  tracks() from its own rows rather than from a method like this one. */
  track(delegationId: string): void {
    this.tracked.add(delegationId)
  }

  tracks(delegationId: string): boolean {
    return this.tracked.has(delegationId)
  }

  get(delegationId: string): AuthorityRevocationV1 | undefined {
    return this.records.get(delegationId)
  }

  /** See AuthorityRevocationStore.insertVerifiedRevocation for the contract, including
   *  that `revocation` must already have been verified against its target delegation by
   *  recordAuthorityRevocation().
   *
   *  The read of the existing record and the write are one synchronous statement sequence
   *  with no await and no callback between them, so on this single-threaded runtime no
   *  other caller can interleave and no second caller can observe `inserted: true` for a
   *  delegation whose slot is already taken. */
  insertVerifiedRevocation(revocation: AuthorityRevocationV1): AuthorityRevocationInsertion {
    const existing = this.records.get(revocation.delegation_id)
    if (existing) return { inserted: false, stored: existing }
    this.records.set(revocation.delegation_id, revocation)
    this.tracked.add(revocation.delegation_id)
    return { inserted: true, stored: revocation }
  }
}
