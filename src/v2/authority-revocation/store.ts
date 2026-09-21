// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import type { AuthorityRevocationStore, AuthorityRevocationV1 } from './types.js'

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
 *  - First recorded revocation for a delegation wins. INV-5 makes revocation
 *    irreversible, and a store that let a second record displace the first would make the
 *    recorded revocation time, reason and revoker mutable after the fact.
 *  - put() for a delegation that already has a record returns the record already held,
 *    and the caller's record is discarded. A repeated request is therefore idempotent in
 *    what the store reports, not in the bytes the caller minted: two calls with different
 *    nonces mint two different valid records, and the store keeps the first.
 *  - put() does not verify. Verification needs the target delegation and a key resolver,
 *    neither of which a store has. Callers put records they have verified, and the
 *    resolver in resolver.ts verifies again on the way out, so a record that reached this
 *    store unverified still cannot produce a 'revoked' answer.
 *  - put() brings its target into the tracked view. Recording a revocation for a
 *    delegation is a statement that this store has an opinion about that delegation.
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

  put(revocation: AuthorityRevocationV1): AuthorityRevocationV1 {
    const existing = this.records.get(revocation.delegation_id)
    if (existing) return existing
    this.records.set(revocation.delegation_id, revocation)
    this.tracked.add(revocation.delegation_id)
    return revocation
  }
}
