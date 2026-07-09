// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// IdentityCompositionError — A2A composition-contract §5 error shape
// ══════════════════════════════════════════════════════════════════
// Aligned with edisonduran/agent-did spec/a2a-composition-contract.
// The four-reason enum matches the strings named in the RFC §5 so the
// error shape is interoperable with any verifier reading the spec.
// ══════════════════════════════════════════════════════════════════

/**
 * Reasons emitted when identity composition verification fails.
 * Aligned with the A2A composition-contract RFC §5 error shape
 * (edisonduran/agent-did spec/a2a-composition-contract).
 */
export type IdentityCompositionErrorReason =
  | 'rotation_window_closed'   // signature under prior key after planned overlap closed (§4.3 / scenario 3c)
  | 'emergency_revoked'        // signature under emergency-revoked prior key (§4.4 / scenario 3d)
  | 'key_purpose_violation'    // per-request signature key resolves to wrong verification relationship (§6.3)
  | 'tampered'                 // signature does not verify against any published key under any rotation scenario

export interface IdentityCompositionErrorContext {
  keyId?: string
  expectedPurpose?: 'assertionMethod' | 'authentication' | 'capabilityDelegation' | 'keyAgreement' | 'capabilityInvocation'
  foundIn?: ReadonlyArray<string>   // which verification relationships the keyId was actually found in
  [key: string]: unknown
}

export class IdentityCompositionError extends Error {
  constructor(
    public readonly reason: IdentityCompositionErrorReason,
    message: string,
    public readonly context?: IdentityCompositionErrorContext
  ) {
    super(message)
    this.name = 'IdentityCompositionError'
    Object.setPrototypeOf(this, IdentityCompositionError.prototype)
  }
}

/**
 * Asserts that the given keyId is authorized for the required verification
 * relationship in the resolved DID document. Throws IdentityCompositionError
 * with reason='key_purpose_violation' if not.
 *
 * Implements the §6.3 normative requirement that the per-request signature key
 * MUST resolve to a verification method whose verification relationship in the
 * resolved DID document matches the operation context (typically assertionMethod).
 */
export function assertKeyPurpose(
  keyId: string,
  didDoc: {
    assertionMethod?: ReadonlyArray<string>
    authentication?: ReadonlyArray<string>
    capabilityDelegation?: ReadonlyArray<string>
    keyAgreement?: ReadonlyArray<string>
    capabilityInvocation?: ReadonlyArray<string>
  },
  requiredPurpose: NonNullable<IdentityCompositionErrorContext['expectedPurpose']>
): void {
  const list = didDoc[requiredPurpose] ?? []
  if (!list.includes(keyId)) {
    const foundIn: string[] = []
    for (const p of ['assertionMethod','authentication','capabilityDelegation','keyAgreement','capabilityInvocation'] as const) {
      if ((didDoc[p] ?? []).includes(keyId)) foundIn.push(p)
    }
    throw new IdentityCompositionError(
      'key_purpose_violation',
      `Key ${keyId} is not authorized for ${requiredPurpose}` +
        (foundIn.length ? ` (found in: ${foundIn.join(', ')})` : ' (not present in DID document)'),
      { keyId, expectedPurpose: requiredPurpose, foundIn }
    )
  }
}
