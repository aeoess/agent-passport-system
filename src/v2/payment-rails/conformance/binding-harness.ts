// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Payment Rails: Tier-2 binding-adapter conformance harness
// ══════════════════════════════════════════════════════════════════
// The Tier-1 harness in `./harness.ts` exercises the foundation
// `PaymentRail` interface against the Nano reference. Tier-2 covers
// the five binding adapters (AP2, x402, Stripe-Issuing, ACP, MPP)
// that are NOT a uniform PaymentRail. They bind APS V2 governance
// to external wire protocols. Each ships its own surface; this
// harness pins the cross-rail invariants any sixth adapter must hold.
//
// Three invariants are asserted, each documented inline below:
//
//   (a) Field-name resolution is byte-parity across rails.
//       resolveSpendLimitCents() is the single source of truth.
//       Same V2Delegation → same numeric cap → same canonical bytes
//       across every wrapper. A rail that diverges produces non-
//       interoperable receipts.
//
//   (b) Denial vocabulary round-trips through the foundation enum.
//       Each rail's per-rail denial taxonomy MUST map back to one of
//       the closed foundation DenialReason values (no_commerce_scope,
//       spend_limit_exceeded, wallet_revoked, time_window_violation,
//       rail_error, requires_owner_confirmation). Audit consumers
//       reading Tier-1 stay correct even when rails surface richer
//       per-rail reasons.
//
//   (c) Resolution is deterministic. Two calls on the same input
//       produce byte-identical JSON. This catches non-determinism
//       bugs (timestamp leakage, hashmap iteration order, BigInt
//       coercion drift) that would silently break byte-parity.
//
// The harness defines `BindingRailAdapter` as the minimal common
// surface. The five built-in wrappers in BUILTIN_BINDING_ADAPTERS
// adapt the existing rail exports to that shape; adapter sources are
// not modified. A contributor implementing a sixth binding adapter
// against the spec writes their own BindingRailAdapter wrapper and
// runs runBindingConformance() against it.
//
// Public test vectors live alongside the harness at
// ./binding-fixtures/<rail>.fixture.json so third parties can
// validate their own implementations against the same scenarios.
// ══════════════════════════════════════════════════════════════════

import { canonicalizeJCS } from '../../../core/canonical-jcs.js'
import { mapAcpDenialToFoundation, delegationToAcpAllowed } from '../acp/index.js'
import { mapMppDenialToFoundation, delegationToMppAllowed } from '../mpp/index.js'
import { defaultMapDelegationToSpendingControls } from '../stripe-issuing/primitives.js'
import { resolveSpendLimitCents } from '../scope-resolution.js'
import type { V2Delegation } from '../../types.js'
import type { DenialReason } from '../types.js'

// ── Public types ──────────────────────────────────────────────────

export type BindingRailName =
  | 'ap2'
  | 'x402'
  | 'stripe-issuing'
  | 'acp'
  | 'mpp'

/**
 * The minimal common surface every binding adapter exposes for
 * Tier-2 conformance. `resolveSpendCap` returns the spend cap a
 * V2Delegation imposes in minor currency units, or null when no cap
 * is configured. `mapDenialToFoundation` projects a rail-specific
 * denial reason string into the closed foundation taxonomy, returning
 * null for unrecognized inputs.
 *
 * Wrappers are thin shims over the rail's existing exports. The
 * harness ships built-in wrappers in BUILTIN_BINDING_ADAPTERS; rail
 * sources stay unchanged.
 */
export interface BindingRailAdapter {
  name: BindingRailName
  resolveSpendCap(delegation: V2Delegation): number | null
  mapDenialToFoundation(railSpecificReason: string): DenialReason | null
}

export interface ConformanceFixtureScenario {
  id: string
  description: string
  /** A V2Delegation. Each rail's resolveSpendCap is invoked against
   *  this; the result must equal expected_cap_minor_units. */
  delegation: V2Delegation
  expected_cap_minor_units: number | null
}

export interface DenialFixtureScenario {
  id: string
  description: string
  /** Rail-specific code the rail's mapping function consumes. */
  rail_specific_reason: string
  /** The closed-taxonomy foundation reason the rail-specific code
   *  must project to. */
  expected_foundation_reason: DenialReason
}

export interface DeterminismFixtureScenario {
  id: string
  description: string
  delegation: V2Delegation
  expected_cap_minor_units: number | null
}

export interface BindingFixtureSet {
  rail_name: BindingRailName
  schema_version: string
  conformance: ConformanceFixtureScenario[]
  denials: DenialFixtureScenario[]
  determinism: DeterminismFixtureScenario[]
}

export type Tier2Invariant =
  | 'field_name_resolution'
  | 'denial_round_trip'
  | 'resolver_determinism'
  | 'cross_rail_byte_parity'

export interface BindingScenarioReport {
  rail_name: BindingRailName
  scenario_id: string
  invariant: Tier2Invariant
  pass: boolean
  detail?: string
}

export interface BindingConformanceReport {
  schema_version: string
  started_at: string
  finished_at: string
  total: number
  passed: number
  failed: number
  all_pass: boolean
  scenarios: BindingScenarioReport[]
}

export interface RunBindingConformanceOpts {
  /** Throw on first byte-parity violation. Default false (audit mode
   *  collects every result). Tests pass true to fail fast. */
  strict?: boolean
}

// ── Built-in wrappers (do NOT modify adapter sources) ────────────

/** AP2 reads via resolveSpendLimitCents with canonicalKey
 *  'commerce.spend_limit'. AP2 has no per-rail denial taxonomy of
 *  its own (mandates either construct or fail with verify reasons),
 *  so foundation reasons pass through identity. */
const ap2Adapter: BindingRailAdapter = {
  name: 'ap2',
  resolveSpendCap(delegation) {
    return resolveSpendLimitCents(delegation, { canonicalKey: 'commerce.spend_limit' })
  },
  mapDenialToFoundation(reason) {
    return _isFoundationReason(reason) ? reason : null
  },
}

/** x402 is a wire protocol; its rail does not consume V2Delegation
 *  directly. The wrapper invokes the canonical resolver so a future
 *  V2Delegation→x402 invoice path stays byte-parity with the others.
 *  Denials are emitted by the caller as foundation reason 'rail_error'
 *  with reason_detail carrying the facilitator's invalidReason or
 *  errorReason; the mapping function projects every rail-specific
 *  code to 'rail_error'. */
const x402Adapter: BindingRailAdapter = {
  name: 'x402',
  resolveSpendCap(delegation) {
    return resolveSpendLimitCents(delegation)
  },
  mapDenialToFoundation(_reason) {
    return 'rail_error'
  },
}

/** Stripe-Issuing routes through defaultMapDelegationToSpendingControls,
 *  which throws for absent / non-positive caps. The wrapper catches
 *  that and returns null so the harness can express the "no cap"
 *  scenario uniformly. Stripe authorization decisions surface as
 *  foundation reasons directly; identity mapping. */
const stripeIssuingAdapter: BindingRailAdapter = {
  name: 'stripe-issuing',
  resolveSpendCap(delegation) {
    try {
      const sc = defaultMapDelegationToSpendingControls(delegation)
      const limit = sc.spending_limits?.[0]
      if (limit === undefined) return null
      return limit.amount
    } catch {
      // Stripe-Issuing rejects delegations with no positive cap by throwing.
      // Fall back to the canonical resolver's null so the harness sees the
      // same "no cap" signal as the other wrappers.
      return resolveSpendLimitCents(delegation)
    }
  },
  mapDenialToFoundation(reason) {
    return _isFoundationReason(reason) ? reason : null
  },
}

const acpAdapter: BindingRailAdapter = {
  name: 'acp',
  resolveSpendCap(delegation) {
    return delegationToAcpAllowed(delegation).max_total
  },
  mapDenialToFoundation(reason) {
    if (_isFoundationReason(reason)) return reason
    if (_isAcpReason(reason)) return mapAcpDenialToFoundation(reason)
    return null
  },
}

const mppAdapter: BindingRailAdapter = {
  name: 'mpp',
  resolveSpendCap(delegation) {
    return delegationToMppAllowed(delegation).max_amount_per_charge
  },
  mapDenialToFoundation(reason) {
    if (_isFoundationReason(reason)) return reason
    if (_isMppReason(reason)) return mapMppDenialToFoundation(reason)
    return null
  },
}

/** All five built-in wrappers in fixed order. Tests typically pass
 *  this list verbatim to runBindingConformance(). */
export const BUILTIN_BINDING_ADAPTERS: readonly BindingRailAdapter[] = Object.freeze([
  ap2Adapter,
  x402Adapter,
  stripeIssuingAdapter,
  acpAdapter,
  mppAdapter,
])

// ── Closed-taxonomy guards ────────────────────────────────────────

const FOUNDATION_REASONS: ReadonlySet<string> = new Set<DenialReason>([
  'no_commerce_scope',
  'spend_limit_exceeded',
  'wallet_revoked',
  'time_window_violation',
  'rail_error',
  'requires_owner_confirmation',
])

function _isFoundationReason(s: string): s is DenialReason {
  return FOUNDATION_REASONS.has(s)
}

const ACP_REASONS: ReadonlySet<string> = new Set([
  'spend_limit_exceeded',
  'merchant_not_allowed',
  'delegation_expired',
  'currency_mismatch',
  'wallet_revoked',
  'no_commerce_scope',
  'idempotency_conflict',
  'invalid_session_state',
  'api_version_mismatch',
  'requires_owner_confirmation',
])

function _isAcpReason(s: string): s is Parameters<typeof mapAcpDenialToFoundation>[0] {
  return ACP_REASONS.has(s)
}

const MPP_REASONS: ReadonlySet<string> = new Set([
  'spend_limit_exceeded',
  'method_not_allowed',
  'currency_not_allowed',
  'delegation_expired',
  'no_payment_scope',
  'challenge_expired',
  'invalid_authorization',
  'session_replay',
  'wallet_revoked',
  'mpp_version_mismatch',
  'requires_owner_confirmation',
])

function _isMppReason(s: string): s is Parameters<typeof mapMppDenialToFoundation>[0] {
  return MPP_REASONS.has(s)
}

// ── Runner ────────────────────────────────────────────────────────

/**
 * Run the Tier-2 binding-adapter conformance harness.
 *
 * For each rail's fixture set:
 *   - Conformance scenarios: invoke resolveSpendCap, assert numeric
 *     equality with expected_cap_minor_units, and record canonical
 *     JSON bytes for the cross-rail byte-parity pass.
 *   - Denial scenarios: invoke mapDenialToFoundation, assert the
 *     result equals expected_foundation_reason and lies in the closed
 *     foundation taxonomy.
 *   - Determinism scenarios: invoke resolveSpendCap twice and assert
 *     byte-identical canonical JSON across the two calls.
 *
 * After per-rail passes, the harness folds the conformance results
 * into a cross-rail byte-parity check: for each conformance scenario
 * id present in every rail's fixture set, the canonical JSON of the
 * resolved cap MUST be byte-identical across all rails.
 *
 * @param adapters       Wrappers to test. Pass BUILTIN_BINDING_ADAPTERS
 *                       to cover the five shipped rails.
 * @param fixtures       Map keyed by rail_name; each value is the
 *                       rail's fixture set.
 * @param opts.strict    Throw on first failure. Default false.
 */
export function runBindingConformance(
  adapters: readonly BindingRailAdapter[],
  fixtures: Readonly<Record<BindingRailName, BindingFixtureSet>>,
  opts: RunBindingConformanceOpts = {},
): BindingConformanceReport {
  const started = new Date()
  const reports: BindingScenarioReport[] = []
  const schema_version = _consensusSchemaVersion(fixtures)

  // Per-rail passes first. perRailCanonical[rail][scenario_id] = JSON bytes
  // of the resolved cap; used by the cross-rail byte-parity pass below.
  const perRailCanonical: Partial<Record<BindingRailName, Record<string, string>>> = {}

  for (const adapter of adapters) {
    const set = fixtures[adapter.name]
    if (!set) {
      reports.push({
        rail_name: adapter.name,
        scenario_id: '<missing>',
        invariant: 'field_name_resolution',
        pass: false,
        detail: `no fixture set provided for rail ${adapter.name}`,
      })
      if (opts.strict) throw new Error(`missing fixture set for rail ${adapter.name}`)
      continue
    }

    const railCanonical: Record<string, string> = {}
    perRailCanonical[adapter.name] = railCanonical

    // (a) field-name resolution
    for (const scn of set.conformance) {
      const got = adapter.resolveSpendCap(scn.delegation)
      const pass = got === scn.expected_cap_minor_units
      railCanonical[scn.id] = canonicalizeJCS(got)
      reports.push({
        rail_name: adapter.name,
        scenario_id: scn.id,
        invariant: 'field_name_resolution',
        pass,
        detail: pass ? undefined : `expected ${scn.expected_cap_minor_units}, got ${got}`,
      })
      if (!pass && opts.strict) {
        throw new Error(
          `[${adapter.name}/${scn.id}] field_name_resolution: expected ${scn.expected_cap_minor_units}, got ${got}`,
        )
      }
    }

    // (b) denial round-trip
    for (const scn of set.denials) {
      const got = adapter.mapDenialToFoundation(scn.rail_specific_reason)
      const inEnum = got !== null && FOUNDATION_REASONS.has(got)
      const matches = got === scn.expected_foundation_reason
      const pass = inEnum && matches
      let detail: string | undefined
      if (!inEnum) {
        detail = `mapped reason '${got}' not in foundation taxonomy`
      } else if (!matches) {
        detail = `expected ${scn.expected_foundation_reason}, got ${got}`
      }
      reports.push({
        rail_name: adapter.name,
        scenario_id: scn.id,
        invariant: 'denial_round_trip',
        pass,
        detail,
      })
      if (!pass && opts.strict) {
        throw new Error(
          `[${adapter.name}/${scn.id}] denial_round_trip: ${detail}`,
        )
      }
    }

    // (c) determinism
    for (const scn of set.determinism) {
      const a = adapter.resolveSpendCap(scn.delegation)
      const b = adapter.resolveSpendCap(scn.delegation)
      const aBytes = canonicalizeJCS(a)
      const bBytes = canonicalizeJCS(b)
      const numericMatches = a === scn.expected_cap_minor_units
      const byteParityMatches = aBytes === bBytes
      const pass = numericMatches && byteParityMatches
      let detail: string | undefined
      if (!numericMatches) {
        detail = `expected ${scn.expected_cap_minor_units}, got ${a}`
      } else if (!byteParityMatches) {
        detail = `byte drift between two calls: '${aBytes}' vs '${bBytes}'`
      }
      reports.push({
        rail_name: adapter.name,
        scenario_id: scn.id,
        invariant: 'resolver_determinism',
        pass,
        detail,
      })
      if (!pass && opts.strict) {
        throw new Error(
          `[${adapter.name}/${scn.id}] resolver_determinism: ${detail}`,
        )
      }
    }
  }

  // Cross-rail byte-parity. For every scenario id present in EVERY
  // rail's fixture set, the canonical JSON of the resolved cap MUST
  // be byte-identical across all rails.
  const railNames = adapters.map((a) => a.name)
  const sharedScenarioIds = _intersectScenarioIds(railNames, perRailCanonical)
  for (const scenarioId of sharedScenarioIds) {
    const seen: Record<string, BindingRailName[]> = {}
    for (const rail of railNames) {
      const bytes = perRailCanonical[rail]?.[scenarioId]
      if (bytes === undefined) continue
      ;(seen[bytes] ??= []).push(rail)
    }
    const groups = Object.entries(seen)
    const pass = groups.length === 1
    const detail = pass
      ? undefined
      : `byte divergence: ${groups.map(([b, rs]) => `${rs.join('+')}=${b}`).join(' | ')}`
    reports.push({
      // synthetic rail_name for the cross-rail pass; the fixture id
      // identifies which scenario diverged.
      rail_name: railNames[0] ?? 'ap2',
      scenario_id: scenarioId,
      invariant: 'cross_rail_byte_parity',
      pass,
      detail,
    })
    if (!pass && opts.strict) {
      throw new Error(
        `cross_rail_byte_parity[${scenarioId}]: ${detail}`,
      )
    }
  }

  const finished = new Date()
  const passed = reports.filter((r) => r.pass).length
  const failed = reports.length - passed
  return {
    schema_version,
    started_at: started.toISOString(),
    finished_at: finished.toISOString(),
    total: reports.length,
    passed,
    failed,
    all_pass: failed === 0,
    scenarios: reports,
  }
}

// ── Helpers ───────────────────────────────────────────────────────

function _intersectScenarioIds(
  rails: readonly BindingRailName[],
  perRail: Partial<Record<BindingRailName, Record<string, string>>>,
): string[] {
  const present = rails
    .map((r) => perRail[r])
    .filter((m): m is Record<string, string> => m !== undefined)
  if (present.length === 0) return []
  const [first, ...rest] = present
  return Object.keys(first).filter((id) => rest.every((m) => id in m))
}

function _consensusSchemaVersion(
  fixtures: Readonly<Record<BindingRailName, BindingFixtureSet>>,
): string {
  const versions = new Set(Object.values(fixtures).map((f) => f.schema_version))
  if (versions.size === 1) return [...versions][0] as string
  return `mixed:${[...versions].sort().join(',')}`
}
