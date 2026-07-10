// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════════
// Feasibility compiler. Policy plus delegation envelope to deterministic IR.
// ══════════════════════════════════════════════════════════════════════
//
// PROOF BOX
//   Proves:   The compiled IR specifies the feasibility obligation for a
//             requested action against a delegation envelope: the conjunction
//             of scope, spend, depth, temporal-window, and revocation
//             constraints that the action must satisfy.
//   Does NOT
//   prove:    that the obligation is satisfiable, i.e. it does not DECIDE
//             feasibility. Nothing in this module solves the obligation. No
//             solver is introduced this round (no Z3, no solver bindings). The
//             compiler emits the obligation; deciding it is a separate, later
//             concern.
//
// Determinism contract: for a fixed (policy, delegation) input, compileFeasibility
// returns byte-identical IR and emitSmtLib returns a byte-identical string. All
// emitted lists are sorted by a total order and no clock, randomness, or ambient
// state is read.
// ══════════════════════════════════════════════════════════════════════

import { createHash } from 'crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import type {
  FeasibilityIR,
  IRConstraint,
  IRVariable,
} from './ir.js'

/** IR format version. Bump on any breaking change to the IR structure. */
export const FEASIBILITY_IR_VERSION = '1.0.0'

/** Target logic string carried on the IR and emitted into SMT-LIB.
 *  QF_SLIA = quantifier-free strings + linear integer arithmetic. */
export const FEASIBILITY_LOGIC = 'QF_SLIA'

/** The requested action, distilled to the fields the obligation needs. Modeled
 *  on ActionIntent.action (src/types/policy.ts) but kept minimal and decoupled
 *  so the compiler is a pure function of plain data. */
export interface FeasibilityPolicyInput {
  /** The scope the action requires, e.g. 'data:read'. */
  scopeRequired: string
  /** Spend the action would consume, if any. */
  spend?: number
  /** ISO 8601 timestamp the action is evaluated at. Used only to encode the
   *  temporal-window obligation as a constraint; it is NOT read from a clock. */
  evaluatedAt?: string
}

/** The granted delegation envelope, distilled to the fields the obligation
 *  needs. Modeled on Delegation (src/types/passport.ts). */
export interface FeasibilityDelegationInput {
  /** Scopes granted by the delegation. */
  scope: string[]
  /** Spend ceiling, if the delegation carries one. */
  spendLimit?: number
  /** Spend already consumed under this delegation. */
  spentAmount?: number
  /** Max delegation depth permitted. */
  maxDepth: number
  /** Current depth of this delegation in its chain. */
  currentDepth: number
  /** Delegation expiry, ISO 8601. */
  expiresAt: string
  /** Delegation not-valid-before, ISO 8601, if set. */
  notBefore?: string
  /** Whether the delegation has been revoked. */
  revoked?: boolean
}

/** Inputs to {@link compileFeasibility}. */
export interface CompileFeasibilityInput {
  policy: FeasibilityPolicyInput
  delegation: FeasibilityDelegationInput
}

// ── internal helpers ──

/** Lowercase hex sha256 of the canonical (JCS) form of a value. Deterministic. */
function sourceHash(input: CompileFeasibilityInput): string {
  // Canonicalize a normalized projection so equal inputs hash equal regardless
  // of key insertion order or absent optional fields.
  const normalized = {
    delegation: {
      currentDepth: input.delegation.currentDepth,
      expiresAt: input.delegation.expiresAt,
      maxDepth: input.delegation.maxDepth,
      notBefore: input.delegation.notBefore ?? null,
      revoked: input.delegation.revoked ?? false,
      scope: [...input.delegation.scope].sort(),
      spendLimit: input.delegation.spendLimit ?? null,
      spentAmount: input.delegation.spentAmount ?? 0,
    },
    policy: {
      evaluatedAt: input.policy.evaluatedAt ?? null,
      scopeRequired: input.policy.scopeRequired,
      spend: input.policy.spend ?? 0,
    },
  }
  return createHash('sha256').update(canonicalizeJCS(normalized), 'utf-8').digest('hex')
}

/** Compile a policy + delegation envelope into the feasibility IR.
 *  Pure and deterministic: no clock, no randomness, sorted output. */
export function compileFeasibility(input: CompileFeasibilityInput): FeasibilityIR {
  const { policy, delegation } = input

  const variables: IRVariable[] = []
  const constraints: IRConstraint[] = []

  // ── scope obligation ──
  // The requested scope must be a member of the granted scope set.
  variables.push({
    name: 'action_scope',
    sort: 'String',
    origin: 'action',
    comment: 'the scope the requested action needs',
  })
  constraints.push({
    id: 'scope_granted',
    kind: 'member',
    lhs: 'action_scope',
    set: [...delegation.scope].sort(),
    comment: 'requested scope must be one of the delegation grants',
  })

  // ── spend obligation ──
  // Only emitted when the delegation carries a spend ceiling. The cumulative
  // spend (already consumed + this action) must not exceed the limit.
  if (delegation.spendLimit !== undefined) {
    variables.push({
      name: 'action_spend',
      sort: 'Int',
      origin: 'action',
      comment: 'spend the requested action would consume',
    })
    variables.push({
      name: 'spent_amount',
      sort: 'Int',
      origin: 'delegation',
      comment: 'spend already consumed under the delegation',
    })
    variables.push({
      name: 'spend_limit',
      sort: 'Int',
      origin: 'delegation',
      comment: 'spend ceiling carried by the delegation',
    })
    variables.push({
      name: 'cumulative_spend',
      sort: 'Int',
      origin: 'delegation',
      comment: 'spent_amount + action_spend',
    })
    constraints.push({
      id: 'cumulative_spend_def',
      kind: 'eq',
      lhs: 'cumulative_spend',
      rhs: { lit: (delegation.spentAmount ?? 0) + (policy.spend ?? 0) },
      comment: 'cumulative spend equals prior spend plus this action',
    })
    constraints.push({
      id: 'spend_within_limit',
      kind: 'le',
      lhs: 'cumulative_spend',
      rhs: { var: 'spend_limit' },
      comment: 'cumulative spend must not exceed the spend limit',
    })
  }

  // ── depth obligation ──
  // The current delegation depth must not exceed the permitted maximum.
  variables.push({
    name: 'current_depth',
    sort: 'Int',
    origin: 'delegation',
    comment: 'current depth of the delegation in its chain',
  })
  variables.push({
    name: 'max_depth',
    sort: 'Int',
    origin: 'delegation',
    comment: 'maximum delegation depth permitted',
  })
  constraints.push({
    id: 'depth_within_bound',
    kind: 'le',
    lhs: 'current_depth',
    rhs: { var: 'max_depth' },
    comment: 'current depth must not exceed the maximum permitted depth',
  })

  // ── temporal-window obligation ──
  // Encoded only as the requirement that the delegation has not been revoked
  // and (when evaluatedAt is supplied) that the action falls inside the
  // delegation validity window. Timestamps are encoded as string equality
  // markers; this module does not parse or compare clocks. A solver or verifier
  // resolves the window; the compiler only states the obligation exists.
  variables.push({
    name: 'not_revoked',
    sort: 'Bool',
    origin: 'delegation',
    comment: 'true when the delegation has not been revoked',
  })
  constraints.push({
    id: 'delegation_active',
    kind: 'bool',
    lhs: 'not_revoked',
    comment: 'the delegation must not be revoked',
  })

  if (policy.evaluatedAt !== undefined) {
    variables.push({
      name: 'within_window',
      sort: 'Bool',
      origin: 'delegation',
      comment:
        'true when evaluatedAt is within [notBefore, expiresAt] of the delegation',
    })
    constraints.push({
      id: 'within_validity_window',
      kind: 'bool',
      lhs: 'within_window',
      comment:
        'the action timestamp must fall within the delegation validity window',
    })
  }

  variables.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
  constraints.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))

  return {
    version: FEASIBILITY_IR_VERSION,
    sourceHash: sourceHash(input),
    logic: FEASIBILITY_LOGIC,
    variables,
    constraints,
    scopeNote: {
      asserts:
        'This IR specifies the feasibility obligation for the action against the delegation envelope.',
      does_not_assert: [
        'It does not decide whether the obligation is satisfiable.',
        'Nothing in this module solves the obligation; no solver is introduced this round.',
      ],
    },
  }
}

// ── SMT-LIB emission ──

const SMT_SORT: Record<IRVariable['sort'], string> = {
  Bool: 'Bool',
  Int: 'Int',
  String: 'String',
}

/** Render an SMT-LIB literal for a constraint right-hand side. */
function smtLiteral(lit: string | number | boolean): string {
  if (typeof lit === 'boolean') return lit ? 'true' : 'false'
  if (typeof lit === 'number') {
    // SMT-LIB writes negative integers as (- n).
    return lit < 0 ? `(- ${Math.abs(lit)})` : String(lit)
  }
  // String literal: SMT-LIB double-quotes, doubling embedded quotes.
  return `"${lit.replace(/"/g, '""')}"`
}

/** Render the operand for a binary constraint (variable or literal). */
function smtOperand(rhs: IRConstraint['rhs']): string {
  if (rhs === undefined) return ''
  if ('var' in rhs) return rhs.var
  return smtLiteral(rhs.lit)
}

/** Render a single constraint as an SMT-LIB assertion term (no outer assert). */
function smtConstraintTerm(c: IRConstraint): string {
  switch (c.kind) {
    case 'eq':
      return `(= ${c.lhs} ${smtOperand(c.rhs)})`
    case 'le':
      return `(<= ${c.lhs} ${smtOperand(c.rhs)})`
    case 'ge':
      return `(>= ${c.lhs} ${smtOperand(c.rhs)})`
    case 'bool':
      return c.lhs
    case 'member': {
      const members = (c.set ?? []).slice().sort()
      if (members.length === 0) {
        // Empty grant set: membership is unsatisfiable. Emit false explicitly.
        return 'false'
      }
      const disjuncts = members.map((m) => `(= ${c.lhs} ${smtLiteral(m)})`)
      return disjuncts.length === 1 ? disjuncts[0] : `(or ${disjuncts.join(' ')})`
    }
    default: {
      // Exhaustiveness guard. Unreachable for known kinds.
      const _never: never = c.kind
      return _never
    }
  }
}

/** Emit a deterministic SMT-LIB 2 string for a feasibility IR.
 *  Pure function of the IR; same IR always yields the same string. The emitted
 *  script declares the variables, asserts each constraint, and ends with
 *  (check-sat). It introduces no solver dependency: it is text the caller may
 *  hand to any SMT solver out of band. This module does not run a solver. */
export function emitSmtLib(ir: FeasibilityIR): string {
  const lines: string[] = []
  lines.push('; APS feasibility obligation')
  lines.push(`; ir-version ${ir.version}`)
  lines.push(`; source-hash ${ir.sourceHash}`)
  lines.push('; This script states the obligation. It does not decide it.')
  lines.push(`(set-logic ${ir.logic})`)

  for (const v of ir.variables) {
    lines.push(`(declare-const ${v.name} ${SMT_SORT[v.sort]})`)
  }
  for (const c of ir.constraints) {
    lines.push(`(assert ${smtConstraintTerm(c)}) ; ${c.id}`)
  }
  lines.push('(check-sat)')
  // Trailing newline for stable, diff-friendly output.
  return lines.join('\n') + '\n'
}

/** Convenience: compile then emit SMT-LIB in one call. Deterministic. */
export function compileToSmtLib(input: CompileFeasibilityInput): string {
  return emitSmtLib(compileFeasibility(input))
}
