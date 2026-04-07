// Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// Scope Version Hash — bilateral receipt pre-commitment (MCP#1763)
// Both sides commit to a hash of the scope state before evaluation begins,
// preventing divergent state in bilateral receipts.

import { createHash } from 'node:crypto'
import { canonicalize } from './canonical.js'

/** Compute a deterministic hash of the scope state at a point in time */
export function computeScopeVersionHash(opts: {
  delegationId: string
  scope: string[]
  spendLimit: number
  spendUsed: number
  depth: number
  maxDepth: number
  expiresAt?: string
}): string {
  const canonical = canonicalize({
    delegationId: opts.delegationId,
    scope: [...opts.scope].sort(),
    spendLimit: opts.spendLimit,
    spendUsed: opts.spendUsed,
    depth: opts.depth,
    maxDepth: opts.maxDepth,
    expiresAt: opts.expiresAt || null,
  })
  return createHash('sha256').update(canonical).digest('hex')
}

/** Verify that two scope version hashes match (pre-commitment check) */
export function verifyScopeVersionMatch(
  requestHash: string,
  responseHash: string
): { match: boolean; reason?: string } {
  if (!requestHash || !responseHash) {
    return { match: false, reason: 'Missing scope version hash' }
  }
  if (requestHash === responseHash) {
    return { match: true }
  }
  return { match: false, reason: 'Scope state changed between request and response signing' }
}
