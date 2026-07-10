// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════════
// Scope Dimension Registry. Classification, narrowing, and M6 routing.
// ══════════════════════════════════════════════════════════════════════
//
// PROOF BOX
//   Proves:   Which delegation dimensions are decidably enforced (strict,
//             routed into the M6 feasibility hard obligation) versus
//             advisory (excluded from the hard check). For a strict
//             decidable dimension, that a declared child value is a subset
//             of the parent value (set narrowing), or is rejected.
//   Does NOT
//   prove:    that an advisory free-text purpose was honored. An advisory
//             dimension is self-declared and not mechanically checkable,
//             which is exactly why it is excluded from the hard check and
//             can never be the basis of a hard deny. This module also does
//             not DECIDE the M6 obligation: it emits the obligation via the
//             M6 compiler and classifies the dimensions; no solver runs.
//
// Determinism: every emitted list is sorted by a total order; the module
// reads no clock, randomness, or ambient state. A fixed registry plus a
// fixed assignment set always yields byte-identical output.
// ══════════════════════════════════════════════════════════════════════

import { createHash } from 'crypto'
import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import {
  compileFeasibility,
  type CompileFeasibilityInput,
  type FeasibilityIR,
} from '../feasibility/index.js'
import type { ConstraintStatus } from '../../types/gateway.js'
import type {
  DimensionDeclaration,
  DimensionClassification,
  DimensionNarrowingResult,
} from './types.js'

/** Registry format version. Bump on any breaking change to the declarations. */
export const SCOPE_REGISTRY_VERSION = '1.0.0'

// ── canonical dimension declarations ──
//
// The four dimensions M6 already hard-encodes (scope, spend, depth,
// temporal/revocation) are declared here as strict decidable and tagged
// with the IR variable the M6 compiler emits for them. The registry does
// NOT re-implement their constraint emission; it routes to compileFeasibility.
//
// data_class and destination are NEW strict decidable dimensions modeled as
// set membership/exclusion: a child grant must be a subset of the parent
// grant. purpose is the canonical advisory free-text dimension: it is removed
// from the hard check and carried as honest-scope only.

/** scope: the M6 'scope_granted' membership obligation. Strict decidable. */
const DIM_SCOPE: DimensionDeclaration = {
  id: 'scope',
  facet: 'scope',
  valueType: 'string_set',
  decidable: true,
  enforcement_strength: 'strict',
  assurance_class: 'mechanically_enforceable',
  m6Variable: 'action_scope',
  comment: 'requested scope must be a member of the granted scope set (M6 scope_granted)',
}

/** spend: the M6 cumulative-spend bound. Strict decidable. */
const DIM_SPEND: DimensionDeclaration = {
  id: 'spend',
  facet: 'spend',
  valueType: 'numeric',
  decidable: true,
  enforcement_strength: 'strict',
  assurance_class: 'mechanically_enforceable',
  m6Variable: 'cumulative_spend',
  comment: 'cumulative spend must not exceed the delegation limit (M6 spend_within_limit)',
}

/** depth: the M6 delegation-depth bound. Strict decidable. */
const DIM_DEPTH: DimensionDeclaration = {
  id: 'depth',
  facet: 'scope',
  valueType: 'numeric',
  decidable: true,
  enforcement_strength: 'strict',
  assurance_class: 'mechanically_enforceable',
  m6Variable: 'current_depth',
  comment: 'current delegation depth must not exceed the maximum (M6 depth_within_bound)',
}

/** temporal: the M6 validity-window / revocation obligation. Strict decidable. */
const DIM_TEMPORAL: DimensionDeclaration = {
  id: 'temporal',
  facet: 'time',
  valueType: 'timestamp',
  decidable: true,
  enforcement_strength: 'strict',
  assurance_class: 'mechanically_enforceable',
  m6Variable: 'within_window',
  comment: 'action must fall within the delegation validity window and the delegation must not be revoked (M6 delegation_active, within_validity_window)',
}

/** data_class: NEW strict decidable dimension. Set membership over data
 *  classifications (e.g. 'public', 'internal', 'confidential', 'pii'). A
 *  child grant must be a subset of the parent grant: narrowing only. */
const DIM_DATA_CLASS: DimensionDeclaration = {
  id: 'data_class',
  facet: 'data',
  valueType: 'enum_set',
  decidable: true,
  enforcement_strength: 'strict',
  assurance_class: 'mechanically_enforceable',
  m6Variable: 'action_data_class',
  vocabulary: ['confidential', 'internal', 'pii', 'public', 'restricted'],
  comment: 'the data classes a child may touch must be a subset of the parent grant (set narrowing)',
}

/** destination: NEW strict decidable dimension. Set membership over allowed
 *  egress destinations (opaque labels, e.g. an allow-listed domain or chain
 *  id). A child grant must be a subset of the parent grant. This is the
 *  decidable allow-list slot, NOT a taint analytic; it does not score or
 *  prevent confused-deputy flows, it only narrows the permitted set. */
const DIM_DESTINATION: DimensionDeclaration = {
  id: 'destination',
  facet: 'cross_chain',
  valueType: 'string_set',
  decidable: true,
  enforcement_strength: 'strict',
  assurance_class: 'mechanically_enforceable',
  m6Variable: 'action_destination',
  comment: 'the egress destinations a child may reach must be a subset of the parent allow-list (set narrowing)',
}

/** purpose: the canonical ADVISORY free-text dimension. Self-declared agent
 *  intent. NOT decidable, so removed from the hard check. Carried as
 *  honest-scope only; can never be the basis of a hard deny. */
const DIM_PURPOSE: DimensionDeclaration = {
  id: 'purpose',
  facet: 'scope',
  valueType: 'text',
  decidable: false,
  enforcement_strength: 'advisory',
  assurance_class: 'evidentially_auditable',
  comment: 'free-text declared purpose; self-declared agent intent, not mechanically checkable',
  does_not_assert: 'The registry does not decide whether a declared free-text purpose was honored; advisory dimensions cannot be the basis of a hard deny.',
  decidablePath: 'replace free-text purpose with a controlled DataPurpose code (src/types/data-source.ts) to make it a decidable enum_set dimension.',
}

/** The canonical dimension set this registry ships, sorted by id. */
export const CANONICAL_DIMENSIONS: readonly DimensionDeclaration[] = [
  DIM_DATA_CLASS,
  DIM_DEPTH,
  DIM_DESTINATION,
  DIM_PURPOSE,
  DIM_SCOPE,
  DIM_SPEND,
  DIM_TEMPORAL,
].slice().sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))

// ── registry construction ──

/** A scope dimension registry: a sorted, de-duplicated set of declarations. */
export interface ScopeDimensionRegistry {
  version: string
  /** Declarations, sorted by id. */
  dimensions: DimensionDeclaration[]
  /** sha256 hex of the canonical declarations. Lets a consumer pin a registry. */
  registryHash: string
}

/** Build a registry from a set of declarations. Defaults to CANONICAL_DIMENSIONS.
 *  Rejects duplicate ids and any non-decidable dimension marked 'strict'
 *  (a 'text' value type can never be strictly enforced). Deterministic. */
export function buildRegistry(
  dimensions: readonly DimensionDeclaration[] = CANONICAL_DIMENSIONS,
): ScopeDimensionRegistry {
  const seen = new Set<string>()
  for (const d of dimensions) {
    if (seen.has(d.id)) {
      throw new Error(`Duplicate dimension id in registry: ${d.id}`)
    }
    seen.add(d.id)
    if (!d.decidable && d.enforcement_strength === 'strict') {
      throw new Error(
        `Dimension ${d.id} is not decidable and cannot be 'strict'; non-decidable dimensions must be 'advisory'.`,
      )
    }
    if (d.valueType === 'text' && d.decidable) {
      throw new Error(
        `Dimension ${d.id} has a free-text value type and cannot be marked decidable.`,
      )
    }
  }
  const sorted = dimensions
    .slice()
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
    .map((d) => normalizeDeclaration(d))
  const registryHash = createHash('sha256')
    .update(canonicalizeJCS(sorted), 'utf-8')
    .digest('hex')
  return { version: SCOPE_REGISTRY_VERSION, dimensions: sorted, registryHash }
}

/** Sort a declaration's internal lists so equal declarations hash equal. */
function normalizeDeclaration(d: DimensionDeclaration): DimensionDeclaration {
  const out: DimensionDeclaration = { ...d }
  if (d.vocabulary) out.vocabulary = [...d.vocabulary].sort()
  return out
}

// ── classification: strict-vs-advisory ──

/** Partition a registry into the strict decidable dimensions (routed into the
 *  M6 hard check) and the advisory dimensions (excluded, reported, never
 *  silently dropped). Mirrors the checks_run / checks_skipped convention. */
export function classifyDimensions(
  registry: ScopeDimensionRegistry,
): DimensionClassification {
  const strict_decidable: string[] = []
  const advisory_excluded: string[] = []
  const excluded_reasons: Record<string, string> = {}

  for (const d of registry.dimensions) {
    if (d.decidable && d.enforcement_strength === 'strict') {
      strict_decidable.push(d.id)
    } else {
      advisory_excluded.push(d.id)
      excluded_reasons[d.id] = d.decidable
        ? 'declared advisory; excluded from the hard check by policy'
        : 'not decidable (free-text); excluded from the hard check and carried as honest-scope only'
    }
  }

  strict_decidable.sort()
  advisory_excluded.sort()

  return {
    strict_decidable,
    advisory_excluded,
    excluded_reasons,
    scopeNote: {
      asserts:
        'These strict decidable dimensions are routed into the M6 feasibility hard obligation; advisory dimensions are excluded from it.',
      does_not_assert: [
        'It does not decide the M6 obligation; no solver runs in this module.',
        'It does not assert that any advisory free-text dimension was honored; advisory dimensions cannot be the basis of a hard deny.',
      ],
    },
  }
}

// ── M6 routing ──

/** Compile the strict decidable dimensions into the M6 feasibility obligation.
 *  This is a thin pass-through to compileFeasibility: the registry classifies
 *  and routes, M6 emits the obligation. The advisory dimensions are NOT part
 *  of the returned IR; the classification reports them separately. */
export function compileStrictDimensions(
  input: CompileFeasibilityInput,
): FeasibilityIR {
  return compileFeasibility(input)
}

// ── set-narrowing partial order (data_class, destination, scope, ...) ──

/** Sort and de-duplicate a string set. */
function normSet(values: string[]): string[] {
  return [...new Set(values)].sort()
}

/** Check that a child set-valued dimension value is a subset of the parent
 *  value: the partial order all strict set-valued dimensions narrow under.
 *  Authority may only narrow. A child member the parent did not grant is a
 *  widening and fails the check.
 *
 *  Advisory dimensions return status 'not_applicable' and narrows=false: they
 *  are not decided here and cannot be the basis of a hard deny. */
export function checkSetNarrowing(
  declaration: DimensionDeclaration,
  parentValue: string[],
  childValue: string[],
): DimensionNarrowingResult {
  // Advisory dimensions are not decided here.
  if (!declaration.decidable || declaration.enforcement_strength === 'advisory') {
    return {
      dimensionId: declaration.id,
      narrows: false,
      status: 'not_applicable',
      widened: [],
      message: `Dimension ${declaration.id} is advisory; narrowing is not decided here and cannot hard-deny.`,
    }
  }

  const parent = normSet(parentValue)
  const child = normSet(childValue)
  const parentMembers = new Set(parent)

  // For an enum_set dimension, members outside the closed vocabulary are
  // rejected as a malformed widening.
  const vocabularyViolations =
    declaration.valueType === 'enum_set' && declaration.vocabulary
      ? child.filter((c) => !declaration.vocabulary!.includes(c))
      : []

  const widened = child.filter((c) => !parentMembers.has(c)).sort()

  if (vocabularyViolations.length > 0) {
    const status: ConstraintStatus = 'fail'
    return {
      dimensionId: declaration.id,
      narrows: false,
      status,
      widened: normSet([...widened, ...vocabularyViolations]),
      message: `Dimension ${declaration.id} child declares values outside the closed vocabulary: ${normSet(vocabularyViolations).join(', ')}`,
    }
  }

  if (widened.length > 0) {
    return {
      dimensionId: declaration.id,
      narrows: false,
      status: 'fail',
      widened,
      message: `Dimension ${declaration.id} child widened authority; values not granted by parent: ${widened.join(', ')}`,
    }
  }

  return {
    dimensionId: declaration.id,
    narrows: true,
    status: 'pass',
    widened: [],
    message: `Dimension ${declaration.id} child is a subset of the parent grant (narrowing).`,
  }
}

/** Whether an advisory dimension may be the basis of a hard deny.
 *  Always false. This is the registry's central invariant: advisory
 *  dimensions never hard-deny. Strict decidable dimensions deny through the
 *  M6 obligation, not through this predicate. */
export function canHardDeny(declaration: DimensionDeclaration): boolean {
  return declaration.decidable && declaration.enforcement_strength === 'strict'
}
