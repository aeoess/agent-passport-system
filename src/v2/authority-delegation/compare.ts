// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { scopeNarrows } from './scope.js'
import type { AuthorityFailure, AuthorityVectorV1, ReversibilityClassV1 } from './types.js'

// draft-pidlisnyi-aps-03 lines 553-565 order reversibility from narrowest to widest as
// tentative, compensable, irreversible, and require a child ceiling not to move to the
// right. The order is defined over exactly those three values, so a ceiling outside it
// is not in the order and cannot be shown to be no wider: reversibilityRank() returns
// null for it and the comparison below reports REVERSIBILITY_WIDENING rather than
// silently passing. A validated record never reaches this, because the closed schema
// refuses such a ceiling first; a caller of the exported comparison can.
const REVERSIBILITY_RANK: Record<ReversibilityClassV1, number> = {
  tentative: 0,
  compensable: 1,
  irreversible: 2,
}

function reversibilityRank(ceiling: unknown): number | null {
  if (typeof ceiling !== 'string') return null
  const rank = (REVERSIBILITY_RANK as Record<string, number | undefined>)[ceiling]
  return rank === undefined ? null : rank
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

  if (child.time.not_before < parent.time.not_before ||
      child.time.not_after > parent.time.not_after) {
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
  } else {
    const childRank = reversibilityRank(child.reversibility.ceiling)
    const parentRank = reversibilityRank(parent.reversibility.ceiling)
    if (childRank === null || parentRank === null || childRank > parentRank) {
      fail(failures, 'REVERSIBILITY_WIDENING', 'reversibility', 'child reversibility ceiling exceeds parent')
    }
  }

  return failures
}
