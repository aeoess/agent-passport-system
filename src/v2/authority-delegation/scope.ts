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

export function grantsAreCanonical(grants: readonly string[]): boolean {
  if (!Array.isArray(grants)) return false
  for (let i = 0; i < grants.length; i++) {
    const grant = grants[i]
    if (!isValidScopeGrant(grant)) return false
    if (i > 0 && grants[i - 1] >= grant) return false
    // A canonical set is an antichain: no entry is redundant under another entry.
    for (let j = 0; j < grants.length; j++) {
      if (i !== j && scopeGrantCovers(grants[j], grant)) return false
    }
  }
  return true
}

export function scopeNarrows(parent: readonly string[], child: readonly string[]): boolean {
  return child.every(grant => parent.some(parentGrant => scopeGrantCovers(parentGrant, grant)))
}
