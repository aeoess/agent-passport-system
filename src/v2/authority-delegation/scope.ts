// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/

export function isValidScopeGrant(grant: string): boolean {
  if (grant === '*') return true
  if (typeof grant !== 'string' || grant.length === 0 || grant.length > 255) return false
  const parts = grant.split(':')
  if (parts.length > 16) return false
  const wildcard = parts.at(-1) === '*'
  if (wildcard) parts.pop()
  if (parts.length === 0 || parts.some(part => !SEGMENT.test(part))) return false
  return !parts.includes('*')
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
