// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// Reversibility fold - foundation (spec v2, reversibility-fold-design-v2.md)
//
// A new primitive that reuses the trust-domain-counting and provisional/final
// lifecycle patterns already established in APS, applied to reversibility.
//
// This module is the FOUNDATION only: the two-axis output types and their
// projection (step 1), and the versioned mapping-profile registry (step 2).
// It touches no receipt envelope, no gateway, and no existing wire shape.
// The effect-instantiation block, lifecycle records, fold, divergence, and
// admission checkpoint are later steps and are not implemented here.

// ══════════════════════════════════════
// STEP 1 - Two-axis output (spec section 0)
// ══════════════════════════════════════
//
// v1 used ONE value to answer TWO different questions: "what may I admit" (a
// policy limit) and "what actually happened" (an execution outcome needing
// evidence). The fix is two projections.
//
//  - realized_class: honest about what evidence establishes. May say "not
//    known yet" (unresolved).
//  - enforcement_class: conservative. Admission and the gateway act on this.
//    unresolved maps to irreversible ONLY in this projection.
//
// Receipts and audits report realized_class truthfully; enforcement acts on
// enforcement_class. Keeping the two separate is what makes the async-pending
// case honest (enforcement_class = irreversible while realized_class =
// unresolved), instead of a false terminal "irreversible".

/** What evidence actually establishes about an effect's reversibility.
 *  `unresolved` is an honest "not known yet", never silently upgraded. */
export type RealizedClass = 'tentative' | 'compensable' | 'irreversible' | 'unresolved'

/** The conservative class admission and the gateway act on. There is no
 *  `unresolved` here: the projection below folds it to `irreversible`. */
export type EnforcementClass = 'tentative' | 'compensable' | 'irreversible'

/** Pure projection realized -> enforcement (spec section 0).
 *  `unresolved` becomes `irreversible` (conservative, fail-closed). Every
 *  other value is the identity. This is the ONLY place `unresolved` is
 *  mapped to `irreversible`; realized truth is never rewritten. */
export function enforcementFrom(realized: RealizedClass): EnforcementClass {
  return realized === 'unresolved' ? 'irreversible' : realized
}
