// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════════
// Feasibility IR. The intermediate representation a policy plus delegation
// envelope compiles into.
// ══════════════════════════════════════════════════════════════════════
//
// The IR is a clean, deterministic description of the feasibility
// obligation: the set of declared variables and the constraints that an
// action must satisfy to be authorized by a delegation. It is a flat,
// solver-agnostic structure. Nothing in this module solves it. The IR is
// the obligation; deciding feasibility is a separate concern that is out of
// scope this round (no solver dependency is introduced).
//
// Determinism: every list this module emits is sorted by a total order, so a
// fixed (policy, delegation) input always produces byte-identical IR.
// ══════════════════════════════════════════════════════════════════════

/** Sorts of the variables the IR can declare. Kept minimal and concrete so the
 *  obligation maps cleanly onto a quantifier-free SMT theory. */
export type IRSort = 'Bool' | 'Int' | 'String'

/** A declared variable in the feasibility obligation. */
export interface IRVariable {
  name: string
  sort: IRSort
  /** Where this variable comes from: the requested action or the granted
   *  delegation envelope. Advisory metadata; does not affect the obligation. */
  origin: 'action' | 'delegation'
  /** Human-readable note on what the variable models. */
  comment: string
}

/** The relational/logical operators the IR constraint language supports.
 *  Deliberately small: equality, integer comparison, set membership, boolean. */
export type IRConstraintKind =
  | 'eq'           // lhs == rhs
  | 'le'           // lhs <= rhs   (integers)
  | 'ge'           // lhs >= rhs   (integers)
  | 'member'       // value is a member of a fixed set
  | 'bool'         // a boolean variable must be true

/** A single feasibility constraint. */
export interface IRConstraint {
  /** Stable identifier for this constraint, e.g. 'scope_granted'. Used to sort
   *  constraints into a deterministic order and to label SMT assertions. */
  id: string
  kind: IRConstraintKind
  /** Left operand: a declared variable name. */
  lhs: string
  /** Right operand for eq/le/ge: a variable name or a literal. Absent for
   *  'bool' (the lhs boolean must hold) and for 'member' (see set). */
  rhs?: { var: string } | { lit: string | number | boolean }
  /** Membership set for 'member' constraints. Sorted strings. */
  set?: string[]
  /** Human-readable explanation of the obligation this constraint encodes. */
  comment: string
}

/** A compiled feasibility obligation. This is the IR. */
export interface FeasibilityIR {
  /** IR format version. Bump on any breaking change to the structure. */
  version: string
  /** sha256 hex of the canonical inputs this IR was compiled from. Lets a
   *  consumer tie an IR back to its (policy, delegation) source without
   *  replaying the compile. */
  sourceHash: string
  /** Logic the obligation targets, e.g. 'QF_SLIA' (quantifier-free strings +
   *  linear integer arithmetic). Advisory; this module emits but never solves. */
  logic: string
  /** Declared variables, sorted by name. */
  variables: IRVariable[]
  /** Constraints, sorted by id. The obligation is the conjunction of these. */
  constraints: IRConstraint[]
  /** Honest-scope note: what compiling this IR establishes and what it does not. */
  scopeNote: {
    asserts: string
    does_not_assert: string[]
  }
}
