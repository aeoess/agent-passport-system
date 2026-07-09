// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════════
// Scope Dimension Registry. Types.
// ══════════════════════════════════════════════════════════════════════
//
// A delegation scope is a product of dimensions (time, spend, scope,
// data_class, destination, purpose, ...). Each dimension declares:
//   - its type (what kind of value it ranges over),
//   - whether it is decidable (a mechanical predicate settles it), and
//   - its enforcement_strength: 'strict' or 'advisory'.
//
// Strict decidable dimensions are routed into the M6 feasibility partial
// order check (src/v2/feasibility): they become part of the hard
// obligation. Advisory dimensions (free-text purpose, self-declared
// intent) are REMOVED from the hard check and carried as honest-scope
// 'does_not_assert' lines. An advisory dimension can never be the basis
// of a hard deny.
//
// This registry classifies and describes dimensions. It does not decide
// the obligation: deciding is the solver's job, downstream of M6.
// ══════════════════════════════════════════════════════════════════════

import type { AssuranceClass } from '../types.js'
import type { ConstraintFacet, ConstraintStatus } from '../../types/gateway.js'

/** The value-type a dimension ranges over. Kept small and concrete so a
 *  decidable dimension maps onto a quantifier-free predicate. A free-text
 *  string ('text') is the canonical non-decidable shape. */
export type DimensionValueType =
  | 'enum_set' // membership/exclusion over a fixed vocabulary (decidable)
  | 'string_set' // membership over an open set of opaque labels (decidable)
  | 'numeric' // an integer/real bound (decidable)
  | 'boolean' // a flag (decidable)
  | 'timestamp' // an ISO-8601 instant compared to a window (decidable)
  | 'text' // free-form human text (NOT decidable)

/** How strongly a dimension is enforced.
 *  - 'strict'   : decidable; routes into the M6 hard obligation. May deny.
 *  - 'advisory' : excluded from the hard check; audit/honest-scope only.
 *                 An advisory dimension MUST NOT be the basis of a hard deny. */
export type EnforcementStrength = 'strict' | 'advisory'

/** A declared delegation dimension. */
export interface DimensionDeclaration {
  /** Stable identifier, e.g. 'scope', 'spend', 'data_class', 'destination'. */
  id: string
  /** The constraint facet this dimension narrows. Reuses the canonical
   *  product-lattice facet vocabulary (src/types/gateway.ts). */
  facet: ConstraintFacet
  /** The value-type the dimension ranges over. */
  valueType: DimensionValueType
  /** True when a mechanical predicate settles the dimension. A 'text' value
   *  type is never decidable. */
  decidable: boolean
  /** How strongly the dimension is enforced. A non-decidable dimension is
   *  always 'advisory'; a decidable dimension MAY be 'strict'. */
  enforcement_strength: EnforcementStrength
  /** The assurance class. Reuses the existing taxonomy (src/v2/types.ts):
   *  'mechanically_enforceable' for strict decidable dimensions; an advisory
   *  dimension carries 'evidentially_auditable' or 'socially_adjudicated'. */
  assurance_class: AssuranceClass
  /** When the dimension routes into the M6 obligation, the IR variable the
   *  M6 compiler declares for it (e.g. 'action_scope'). Absent for advisory
   *  dimensions and for dimensions the registry narrows in place rather than
   *  handing to the compiler. */
  m6Variable?: string
  /** Closed vocabulary for an 'enum_set' dimension. When present, a declared
   *  value outside this set is rejected. Sorted for deterministic output. */
  vocabulary?: string[]
  /** Human-readable note. No claims of effect; mechanical description only. */
  comment: string
  /** For an advisory dimension, the honest-scope line stating what the
   *  registry does NOT decide about it. Mirrors the
   *  scope_of_claim.does_not_assert convention. */
  does_not_assert?: string
  /** Documented path to make a currently-advisory dimension decidable, e.g.
   *  'replace free-text purpose with a controlled DataPurpose code'. Advisory
   *  only; informational. */
  decidablePath?: string
}

/** A dimension value declared on a delegation, paired with its declaration. */
export interface DimensionAssignment {
  /** The dimension this value belongs to. Must match a registered id. */
  dimensionId: string
  /** The declared value. For set-valued dimensions this is the granted set. */
  value: string[] | number | boolean | string
}

/** The classification of a registry's dimensions into strict-vs-advisory.
 *  Strict decidable dimensions are the ones routed into the M6 hard check;
 *  advisory dimensions are explicitly excluded and reported, never silently
 *  dropped. Mirrors the checks_run / checks_skipped convention in
 *  src/core/feasibility.ts. */
export interface DimensionClassification {
  /** Ids of dimensions routed into the M6 hard obligation. Sorted. */
  strict_decidable: string[]
  /** Ids of advisory dimensions excluded from the hard check. Sorted. */
  advisory_excluded: string[]
  /** Per-advisory-dimension reason it was excluded. Keyed by dimension id. */
  excluded_reasons: Record<string, string>
  /** Honest-scope note: what classifying establishes and what it does not. */
  scopeNote: {
    asserts: string
    does_not_assert: string[]
  }
}

/** Result of checking whether a child dimension value narrows a parent value.
 *  Reuses the four-valued Belnap ConstraintStatus for the per-dimension
 *  status so the result composes with the gateway constraint vector. */
export interface DimensionNarrowingResult {
  /** The dimension checked. */
  dimensionId: string
  /** True when the child value is a subset of (or equal to) the parent value
   *  for a decidable dimension. Undefined semantics for advisory dimensions:
   *  status is reported 'not_applicable', narrows is false, and the dimension
   *  cannot be the basis of a hard deny. */
  narrows: boolean
  /** Four-valued status. 'pass' = child narrows; 'fail' = child widened;
   *  'not_applicable' = advisory dimension, not decided here. */
  status: ConstraintStatus
  /** Members the child added that the parent did not grant (a widening).
   *  Sorted. Empty for a valid narrowing. */
  widened: string[]
  /** Human-readable explanation. No truth claims about advisory dimensions. */
  message: string
}
