// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

// Draft lines 516-518 state the whole rule: "Scope grants use ASCII colon-separated
// segments. '*' covers all grants; a wildcard is otherwise permitted only as the
// terminal segment ':*'." Nothing more is a protocol requirement. This SDK previously
// also imposed a segment character class, a 16-segment cap and a 255-character cap;
// none of the three is in the draft, and a grant this SDK rejected for one of them was
// rejected by an SDK grammar rather than by the protocol.
const ASCII_ONLY = /^[\x00-\x7f]*$/

export function isValidScopeGrant(grant: string): boolean {
  if (typeof grant !== 'string' || grant.length === 0) return false
  if (!ASCII_ONLY.test(grant)) return false
  if (grant === '*') return true
  const parts = grant.split(':')
  // A terminal ":*" is the one permitted wildcard segment; it is dropped before the
  // remaining segments are checked, so no other segment may be a wildcard.
  if (parts.at(-1) === '*') parts.pop()
  // Colon-separated segments: a segment is what lies between two colons, so an empty
  // one is not a segment. Every remaining segment must also be free of the wildcard.
  return parts.length > 0 && parts.every(part => part.length > 0 && !part.includes('*'))
}

/** Exact grants cover only themselves. A terminal :* grant covers its prefix and descendants. */
export function scopeGrantCovers(parent: string, child: string): boolean {
  if (parent === '*') return true
  if (parent.endsWith(':*')) {
    const prefix = parent.slice(0, -2)
    const childPrefix = child.endsWith(':*') ? child.slice(0, -2) : child
    return childPrefix === prefix || childPrefix.startsWith(prefix + ':')
  }
  return parent === child
}

// Validity and strict order below are still one O(n) pass. Redundancy (no grant
// covered by any other grant in the list) used to be the pairwise O(n^2) scan the
// antichain definition suggests; a 16,000-grant list took over three seconds.
//
// Once every grant is valid and the list strictly sorted (so every grant is
// distinct), whether some OTHER grant covers a given grant g reduces to two cheap
// tests: is the bare wildcard "*" present (it covers everything), or is "Q:*"
// present for a Q that is a whole-segment prefix of g's own prefix (g itself with a
// trailing ":*" removed, if it has one)? scopeGrantCovers's definition is: an exact
// grant covers only itself, and a grant ending in ":*" with prefix P covers a grant
// with prefix C exactly when C equals P or C starts with P + ":". Because a colon
// only ever falls on a segment boundary in a valid grant, "C starts with P + ':'"
// for a valid P is exactly "P equals the join of some whole number of C's leading
// segments" (and "C equals P" is that same statement for all of C's segments), so
// some other grant covers g exactly when one of the at-most-16 candidate strings
// built by joining g's leading segments and appending ":*" is itself a grant in the
// list, other than g. Building those candidates and doing a set lookup for each
// replaces comparing g against every other grant: O(n * segments) instead of O(n^2).
export function grantsAreCanonical(grants: readonly string[]): boolean {
  if (!Array.isArray(grants)) return false
  for (let i = 0; i < grants.length; i++) {
    const grant = grants[i]
    if (!isValidScopeGrant(grant)) return false
    if (i > 0 && grants[i - 1] >= grant) return false
  }

  const grantSet = new Set(grants)
  for (const grant of grants) {
    if (grant === '*') continue
    if (grantSet.has('*')) return false
    const prefix = grant.endsWith(':*') ? grant.slice(0, -2) : grant
    const segments = prefix.split(':')
    for (let m = 1; m <= segments.length; m++) {
      const candidate = segments.slice(0, m).join(':') + ':*'
      if (candidate !== grant && grantSet.has(candidate)) return false
    }
  }
  return true
}

// Linear in len(parent) + len(child) * segments, instead of the pairwise
// O(len(parent) * len(child)) scan the definition above suggests: parent goes into
// a set once, and a child grant is covered by the same reasoning grantsAreCanonical
// uses above, applied to two different lists instead of one list against itself.
//
// This equals the pairwise scopeGrantCovers definition only for a parent and a
// child list that have each already passed grantsAreCanonical (valid, strictly
// sorted, irredundant). compareAuthority, the only caller that reaches this
// function from the chain verifier, never calls it before both authority vectors'
// scope facets have passed schema validation, so that precondition always holds on
// that path. Called directly with an unvalidated or malformed grant list, this
// function is not specified to agree with the pairwise definition.
export function scopeNarrows(parent: readonly string[], child: readonly string[]): boolean {
  const parentSet = new Set(parent)
  if (parentSet.has('*')) return true
  for (const grant of child) {
    if (parentSet.has(grant)) continue
    const prefix = grant.endsWith(':*') ? grant.slice(0, -2) : grant
    const segments = prefix.split(':')
    let covered = false
    for (let m = 1; m <= segments.length; m++) {
      const candidate = segments.slice(0, m).join(':') + ':*'
      if (parentSet.has(candidate)) { covered = true; break }
    }
    if (!covered) return false
  }
  return true
}
