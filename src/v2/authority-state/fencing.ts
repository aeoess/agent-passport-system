// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// PROPOSED, OPT-IN. Fencing on the authority-state WRITE path.
// See ./types.ts for the specification position. Proposed.
//
// WHY THIS IS A SEPARATE AXIS FROM THE READ PATH. A read-side high-water mark protects one
// verifier that has already seen the newer state. It does nothing for a verifier that has
// seen nothing, reading a published view that a stale writer republished underneath it. A
// partition that resolves the wrong way rolls authority back with no restore involved, and
// the read path never sees a regression because the published state simply IS the old
// state. So the check has to exist where the write lands.
//
// The rule implemented here is the one Kleppmann's "How to do distributed locking" states:
// the storage server takes an active role in checking tokens and rejects any write on which
// the token has gone backwards. `OPEN-QUESTIONS.md` names authority rollback as open and
// names an append-only revocation log a restore must replay as the other candidate
// mechanism in the same sentence. That one is NOT modelled here. Neither is specified.

import { compareStateMarker, sameScope } from './marker.js'
import type { FencedWrite, FencedWriteOutcome, StateMarker } from './types.js'

/**
 * An authority-state publication log with a fencing gate on every write.
 *
 * Generic in the payload on purpose: this class orders writes and stores nothing about
 * authority itself. The payload is whatever the deployment publishes as a state view, a
 * store handle, a snapshot identifier or a record set. The SDK has no opinion about it.
 *
 * The gate, in one line each:
 *
 *  - a token BELOW the highest already accepted is refused, `stale_fencing_token`
 *  - a token EQUAL to it is accepted, because equal has not gone backwards: the same holder
 *    is retrying, and the retry is idempotent
 *  - a token ABOVE it is accepted, and so is a token the log has never seen before, as long
 *    as it does not go backwards. The gate fences state that is behind, not state that
 *    merely differs
 *  - a token counted in a DIFFERENT SCOPE from the log's is refused,
 *    `fencing_scope_mismatch`, and an absent or malformed token is refused
 *    `fencing_token_unreadable`. Two markers from different scopes order nothing, and a
 *    write path that cannot order a token is not fenced. Neither refusal is in any source;
 *    both are this module's choice, and they are kept apart because an unreadable token is
 *    a different finding from a backwards one
 *
 * A refused write changes nothing: not the published payload, not the highest token. That
 * is the property the whole class exists for, and a caller reads `accepted` to learn which
 * of the two happened rather than comparing payloads.
 *
 * NOT DURABLE, NOT CONCURRENT, NOT A LOCK SERVICE. This holds one token and one payload in
 * this process's heap. It acquires no lock, contacts no lock service, and its check-then-set
 * is one synchronous statement sequence, which is safe on this runtime and is a property of
 * the runtime rather than a pattern a durable store may copy. The same warning
 * `InMemoryAuthorityRevocationStore` carries applies here for the same reason.
 */
export class FencedAuthorityStateLog<T> {
  private highest: StateMarker | null = null
  private payload: T | undefined = undefined
  private written = false

  /** The highest token accepted so far, or `null` when nothing has been published. */
  highestToken(): StateMarker | null {
    return this.highest
  }

  /** What is published now. `undefined` when no write has landed, which a caller must tell
   *  apart from a write that landed carrying `undefined`; `hasPublished()` is how. */
  published(): T | undefined {
    return this.payload
  }

  hasPublished(): boolean {
    return this.written
  }

  /** Submit a write. See the class doc for the four outcomes. Never throws for a malformed
   *  token: an unreadable token is one that cannot be shown to have moved forward, so it is
   *  refused. */
  write(write: FencedWrite<T>): FencedWriteOutcome<T> {
    const token = write?.token
    // Read the token on its own first. An unreadable token is a different finding from a
    // stale one, and collapsing them would report a backwards move that never happened.
    if (compareStateMarker(token, token) !== 'forward') {
      return { accepted: false, code: 'fencing_token_unreadable', published: this.highest }
    }
    if (this.highest !== null) {
      if (!sameScope(this.highest, token)) {
        return { accepted: false, code: 'fencing_scope_mismatch', published: this.highest }
      }
      if (compareStateMarker(this.highest, token) !== 'forward') {
        return { accepted: false, code: 'stale_fencing_token', published: this.highest }
      }
    }
    this.highest = token
    this.payload = write.payload
    this.written = true
    return { accepted: true, published: token, payload: write.payload }
  }
}
