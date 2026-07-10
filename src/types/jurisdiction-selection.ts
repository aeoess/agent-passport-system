// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════
// Jurisdiction Selection Provenance, Types
// ══════════════════════════════════════════════════════════════════
// Records which policy packs were selected for a set of jurisdiction
// facts, and surfaces disagreements between them. A selection record,
// not a router and not a compliance engine. Packs are opaque
// references; the protocol carries context, no legal content.
// ══════════════════════════════════════════════════════════════════

/**
 * The jurisdiction facts of one execution context. Each dimension is
 * an ISO 3166-1 alpha-2 code, the same vocabulary JurisdictionEnvelope
 * uses. subject_jurisdiction is optional because many actions have no
 * identifiable data subject.
 */
export interface JurisdictionFacts {
  /** Jurisdiction of the principal on whose behalf the agent acts */
  principal_jurisdiction: string
  /** Jurisdiction where execution happens */
  execution_jurisdiction: string
  /** Jurisdiction of the resource being acted on */
  resource_jurisdiction: string
  /** Jurisdiction of the data subject, when one exists */
  subject_jurisdiction?: string
}

/**
 * An opaque reference to an externally issued policy pack. The SDK
 * never inspects pack content; constraints is an opaque key/value
 * surface used only to detect disagreement between packs.
 */
export interface PolicyPackRef {
  /** Pack identifier, unique per issuer */
  id: string
  /** Pack version string */
  version: string
  /** Issuer identifier */
  issuer: string
  /** Jurisdiction the pack declares itself for (ISO 3166-1 alpha-2) */
  jurisdiction: string
  /** Content digest of the pack, for pinning */
  digest: string
  /** Opaque declared constraint surface, compared key by key */
  constraints?: Record<string, string>
}

/**
 * One disagreement between selected packs: two or more packs declare
 * different values for the same constraints key. Never auto-resolved.
 */
export interface PackConflict {
  /** The constraints key the packs disagree on */
  dimension: string
  /** Packs declaring this key, as id@version, in selected order */
  packs: string[]
  /** Declared values, index-aligned with packs */
  values: string[]
  /** Human-readable note; no resolution is implied */
  note: string
}

/** Options for selectJurisdictionPacks */
export interface SelectionOptions {
  /**
   * Explicit precedence, highest first, by pack id. A conflict is
   * resolved by precedence only when every pack declaring the
   * conflicting key is listed here. Absent or partial coverage means
   * the conflict is surfaced, never auto-resolved.
   */
  precedence?: string[]
  /** RFC 3339 timestamp for the record; pass for reproducible output */
  selected_at?: string
}

/**
 * Provenance record of one pack selection. Invariants: selected_packs
 * is deterministically ordered (jurisdiction match count descending,
 * then id, then version); resolution is 'conflict-surfaced' whenever
 * conflicts is non-empty; precedence_used is present exactly when a
 * precedence list was supplied to the resolver.
 */
export interface SelectionRecord {
  facts: JurisdictionFacts
  selected_packs: PolicyPackRef[]
  conflicts: PackConflict[]
  resolution: 'selected' | 'conflict-surfaced'
  resolver_version: '0.1.0'
  /** The precedence list that was in effect, when one was supplied */
  precedence_used?: string[]
  selected_at: string
}
