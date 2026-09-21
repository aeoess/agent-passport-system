// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import {
  authorityDelegationBody,
  computeAuthorityDelegationId,
} from '../authority-delegation/canonical.js'
import type {
  AuthorityDelegationV1,
  RevocationResolution,
} from '../authority-delegation/types.js'
import { verifyAuthorityRevocation } from './verify.js'
import type { AuthorityRevocationVerificationOptions } from './verify.js'
import type { AuthorityRevocationStore } from './types.js'

/**
 * Adapt an AuthorityRevocationStore to the resolver verifyAuthorityDelegationChain and
 * issueSubAuthorityDelegation already take.
 *
 * The three answers, and what each one costs to earn:
 *
 *  - 'revoked' only when the store holds a record for this delegation AND that record
 *    verifies against this delegation under verifyAuthorityRevocation(). A stored record
 *    that does not verify yields 'unknown', not 'revoked' and not 'active': the store has
 *    an opinion this resolver cannot confirm, which is exactly indeterminate.
 *  - 'active' only when the store says it tracks this delegation and holds no revocation
 *    for it. Absence from a store is never 'active' on its own. A store that has never
 *    heard of a delegation has not said the delegation is unrevoked.
 *  - 'unknown' for everything else, including a store that throws and a delegation whose
 *    `delegation_id` does not recompute from its own body.
 *
 * The chain verifier treats 'unknown' as indeterminate (REVOCATION_UNKNOWN) and
 * issueSubAuthorityDelegation refuses to mint under anything but 'active', so the
 * fail-closed direction is already theirs; this resolver only has to avoid manufacturing
 * an 'active' it cannot support.
 *
 * Never throws. A resolver that threw would be caught by both callers and read as
 * 'unknown' anyway, so it returns 'unknown' in the open rather than through a catch in
 * somebody else's code.
 */
export function createAuthorityRevocationResolver(
  store: AuthorityRevocationStore,
  options: AuthorityRevocationVerificationOptions,
): (delegation: AuthorityDelegationV1) => RevocationResolution {
  return (delegation: AuthorityDelegationV1): RevocationResolution => {
    try {
      // A claimed delegation_id sits outside the delegation's own identifier preimage.
      // Looking a revocation up by an unauthenticated label would let a caller ask about
      // one delegation while presenting another.
      const delegationId = computeAuthorityDelegationId(authorityDelegationBody(delegation))
      if (delegationId !== delegation.delegation_id) return 'unknown'

      const record = store.get(delegationId)
      if (record !== undefined) {
        return verifyAuthorityRevocation(record, delegation, options).state === 'valid'
          ? 'revoked'
          : 'unknown'
      }
      return store.tracks(delegationId) ? 'active' : 'unknown'
    } catch {
      return 'unknown'
    }
  }
}
