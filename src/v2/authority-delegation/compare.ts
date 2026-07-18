// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { scopeNarrows } from './scope.js'
import type { AuthorityFailure, AuthorityVectorV1, ReversibilityClassV1 } from './types.js'

const REVERSIBILITY_RANK: Record<ReversibilityClassV1, number> = {
  tentative: 0,
  compensable: 1,
  irreversible: 2,
}

function fail(
  failures: AuthorityFailure[],
  code: AuthorityFailure['code'],
  facet: keyof AuthorityVectorV1,
  message: string,
): void {
  failures.push({ code, facet, message })
}

/** Compare a child against its immediate parent in the seven-facet partial order. */
export function compareAuthority(
  parent: AuthorityVectorV1,
  child: AuthorityVectorV1,
): AuthorityFailure[] {
  const failures: AuthorityFailure[] = []

  if (child.scope.profile !== parent.scope.profile) {
    fail(failures, 'UNSUPPORTED_PROFILE', 'scope', 'scope profile changes are incomparable')
  } else if (!scopeNarrows(parent.scope.grants, child.scope.grants)) {
    fail(failures, 'SCOPE_WIDENING', 'scope', 'child scope is not covered by parent scope')
  }

  if (parent.spend.mode === 'bounded') {
    if (child.spend.mode === 'unbounded') {
      fail(failures, 'SPEND_WIDENING', 'spend', 'bounded parent cannot produce unbounded child')
    } else if (child.spend.unit !== parent.spend.unit) {
      fail(failures, 'SPEND_UNIT_CHANGE', 'spend', 'bounded spend unit must remain exact')
    } else if (BigInt(child.spend.per_action) > BigInt(parent.spend.per_action) ||
               BigInt(child.spend.cumulative) > BigInt(parent.spend.cumulative)) {
      fail(failures, 'SPEND_WIDENING', 'spend', 'child spend limits exceed parent limits')
    }
  }

  if (parent.depth.remaining === 0) {
    fail(failures, 'DEPTH_EXHAUSTED', 'depth', 'parent has no remaining delegation hop')
  } else if (child.depth.remaining > parent.depth.remaining - 1) {
    fail(failures, 'DEPTH_WIDENING', 'depth', 'child remaining depth must consume at least one hop')
  }

  if (Date.parse(child.time.not_before) < Date.parse(parent.time.not_before) ||
      Date.parse(child.time.not_after) > Date.parse(parent.time.not_after)) {
    fail(failures, 'TIME_WIDENING', 'time', 'child validity window is not contained in parent window')
  }

  if (child.reputation.profile !== parent.reputation.profile) {
    fail(failures, 'UNSUPPORTED_PROFILE', 'reputation', 'reputation profile changes are incomparable')
  } else if (child.reputation.ceiling > parent.reputation.ceiling) {
    fail(failures, 'REPUTATION_WIDENING', 'reputation', 'child reputation ceiling exceeds parent')
  }

  if (child.values.profile !== parent.values.profile) {
    fail(failures, 'UNSUPPORTED_PROFILE', 'values', 'values profile changes are incomparable')
  } else {
    const childRequired = new Set(child.values.required)
    if (parent.values.required.some(identifier => !childRequired.has(identifier))) {
      fail(failures, 'VALUES_WEAKENING', 'values', 'child removed an ancestor-required value identifier')
    }
  }

  if (child.reversibility.profile !== parent.reversibility.profile) {
    fail(failures, 'UNSUPPORTED_PROFILE', 'reversibility', 'reversibility profile changes are incomparable')
  } else if (REVERSIBILITY_RANK[child.reversibility.ceiling] >
             REVERSIBILITY_RANK[parent.reversibility.ceiling]) {
    fail(failures, 'REVERSIBILITY_WIDENING', 'reversibility', 'child reversibility ceiling exceeds parent')
  }

  return failures
}
