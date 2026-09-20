// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { isCanonicalQuantity, validateAuthorityDelegationShape } from './schema.js'
import { authorityDelegationBody, computeAuthorityDelegationId } from './canonical.js'
import { readPlainDataChainContainer, snapshotPlainData } from './plain-data.js'
import type {
  AuthorityDelegationV1,
  BudgetOperationResult,
  BudgetReservationState,
} from './types.js'

interface Counter {
  reserved: bigint
  committed: bigint
}

interface Reservation {
  actionRef: string
  unit: string
  amount: bigint
  delegationIds: string[]
  state: BudgetReservationState
}

const ACTION_REF = /^[0-9a-f]{64}$/

/**
 * Reference linearizable ledger for one JavaScript process. Each mutation is a
 * single synchronous critical section. Distributed deployments must replace it
 * with a store providing the same all-ancestors atomicity and idempotency.
 */
export class InMemoryAuthorityBudgetLedger {
  private readonly counters = new Map<string, Counter>()
  private readonly reservations = new Map<string, Reservation>()

  /**
   * Each chain member is snapshotted to plain JSON data (see plain-data.ts) before any
   * other read of it; a member that is not plain gives CONFLICT here, before any
   * counter changes, the same as a malformed member does today. Every later read in
   * this method comes from the snapshot rather than from the caller's original chain
   * array: the shape check, the delegation_id recomputation, chain continuity
   * (parent_delegation_id and issuer against the parent's subject), and, for each
   * bounded delegation, its authority.spend fields and its delegation_id used to key
   * the reservation counters. This method makes no attenuation reads of its own;
   * verifyAuthorityDelegationChain is what compares a child's authority against its
   * parent's.
   */
  reserve(
    verifiedChain: readonly AuthorityDelegationV1[],
    actionRef: string,
    unit: string,
    amountString: string,
  ): BudgetOperationResult {
    if (
      typeof actionRef !== 'string' || !ACTION_REF.test(actionRef) ||
      typeof unit !== 'string' || !isCanonicalQuantity(amountString)
    ) {
      return { ok: false, code: 'CONFLICT' }
    }
    // Provisional: the same 256-record limit the chain verifier applies, and the same
    // choice of this SDK's own, pending a protocol ruling.
    const container = readPlainDataChainContainer(verifiedChain, 1, 256)
    if (!container) {
      return { ok: false, code: 'CONFLICT' }
    }
    const chain: AuthorityDelegationV1[] = new Array(container.length)
    const seen = new Set<string>()
    for (let i = 0; i < container.length; i++) {
      const current = snapshotPlainData(container[i]) as AuthorityDelegationV1
      if (validateAuthorityDelegationShape(current).length > 0 ||
          computeAuthorityDelegationId(authorityDelegationBody(current)) !== current.delegation_id ||
          seen.has(current.delegation_id)) {
        return { ok: false, code: 'CONFLICT' }
      }
      seen.add(current.delegation_id)
      if (i === 0) {
        if (current.parent_delegation_id !== null) return { ok: false, code: 'CONFLICT' }
      } else {
        const parent = chain[i - 1]
        if (current.parent_delegation_id !== parent.delegation_id || current.issuer !== parent.subject) {
          return { ok: false, code: 'CONFLICT' }
        }
      }
      chain[i] = current
    }
    const amount = BigInt(amountString)
    const bounded = chain.filter(item => item.authority.spend.mode === 'bounded')
    const ids = bounded.map(item => item.delegation_id)
    // A cancelled reservation holds nothing: its amount was released from every
    // bounded ancestor's counter. Reporting a retry of it as idempotent would tell a
    // boundary that q is reserved when no counter holds it, and two such calls could
    // dispatch twice against one signed cumulative ceiling, which draft
    // draft-pidlisnyi-aps-03 lines 602-607 require to be reserved "against every
    // bounded ancestor or against none". A call naming a cancelled action_ref is
    // therefore treated as the fresh reservation it is: every limit is checked again
    // and the cancelled record is replaced. Provisional: the draft says only that an
    // identical retry is idempotent and conflicting reuse is rejected (lines 621-622),
    // and does not say which of those a retry after cancellation is, so refusing it
    // outright would be defensible too. This choice keeps a boundary able to retry
    // after releasing, and it can never report a reservation it does not hold. Pending
    // a protocol ruling.
    const prior = this.reservations.get(actionRef)
    if (prior && prior.state !== 'cancelled') {
      const identical = prior.unit === unit && prior.amount === amount &&
        prior.delegationIds.length === ids.length &&
        prior.delegationIds.every((id, index) => id === ids[index])
      return identical
        ? { ok: true, code: 'IDEMPOTENT', state: prior.state }
        : { ok: false, code: 'CONFLICT', state: prior.state }
    }

    for (const delegation of bounded) {
      const spend = delegation.authority.spend
      if (spend.mode !== 'bounded') continue
      if (spend.unit !== unit) return { ok: false, code: 'UNIT_MISMATCH' }
      if (amount > BigInt(spend.per_action)) return { ok: false, code: 'PER_ACTION_EXCEEDED' }
      const counter = this.counters.get(delegation.delegation_id) ?? { reserved: 0n, committed: 0n }
      if (counter.reserved + counter.committed + amount > BigInt(spend.cumulative)) {
        return { ok: false, code: 'CUMULATIVE_EXCEEDED' }
      }
    }

    // All checks completed before any counter is changed.
    for (const delegation of bounded) {
      const counter = this.counters.get(delegation.delegation_id) ?? { reserved: 0n, committed: 0n }
      counter.reserved += amount
      this.counters.set(delegation.delegation_id, counter)
    }
    this.reservations.set(actionRef, {
      actionRef,
      unit,
      amount,
      delegationIds: ids,
      state: 'reserved',
    })
    return { ok: true, code: 'RESERVED', state: 'reserved' }
  }

  markDispatched(actionRef: string): BudgetOperationResult {
    const reservation = this.reservations.get(actionRef)
    if (!reservation) return { ok: false, code: 'NOT_FOUND' }
    if (reservation.state === 'dispatched') return { ok: true, code: 'IDEMPOTENT', state: 'dispatched' }
    if (reservation.state !== 'reserved') return { ok: false, code: 'INVALID_STATE', state: reservation.state }
    reservation.state = 'dispatched'
    return { ok: true, code: 'DISPATCHED', state: 'dispatched' }
  }

  commit(actionRef: string): BudgetOperationResult {
    const reservation = this.reservations.get(actionRef)
    if (!reservation) return { ok: false, code: 'NOT_FOUND' }
    if (reservation.state === 'committed') return { ok: true, code: 'IDEMPOTENT', state: 'committed' }
    if (reservation.state !== 'reserved' && reservation.state !== 'dispatched') {
      return { ok: false, code: 'INVALID_STATE', state: reservation.state }
    }
    for (const id of reservation.delegationIds) {
      const counter = this.counters.get(id)
      if (!counter || counter.reserved < reservation.amount) {
        return { ok: false, code: 'INVALID_STATE', state: reservation.state }
      }
    }
    for (const id of reservation.delegationIds) {
      const counter = this.counters.get(id)!
      counter.reserved -= reservation.amount
      counter.committed += reservation.amount
    }
    reservation.state = 'committed'
    return { ok: true, code: 'COMMITTED', state: 'committed' }
  }

  /** Cancellation is allowed only before dispatch. */
  cancel(actionRef: string): BudgetOperationResult {
    const reservation = this.reservations.get(actionRef)
    if (!reservation) return { ok: false, code: 'NOT_FOUND' }
    if (reservation.state === 'cancelled') return { ok: true, code: 'IDEMPOTENT', state: 'cancelled' }
    if (reservation.state !== 'reserved') return { ok: false, code: 'INVALID_STATE', state: reservation.state }
    for (const id of reservation.delegationIds) {
      const counter = this.counters.get(id)
      if (!counter || counter.reserved < reservation.amount) {
        return { ok: false, code: 'INVALID_STATE', state: reservation.state }
      }
    }
    for (const id of reservation.delegationIds) {
      this.counters.get(id)!.reserved -= reservation.amount
    }
    reservation.state = 'cancelled'
    return { ok: true, code: 'CANCELLED', state: 'cancelled' }
  }

  counter(delegationId: string): { reserved: string; committed: string } {
    const counter = this.counters.get(delegationId) ?? { reserved: 0n, committed: 0n }
    return { reserved: counter.reserved.toString(), committed: counter.committed.toString() }
  }
}
