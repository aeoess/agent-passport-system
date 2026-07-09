// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// Verification source, how a verifying key was obtained
// ══════════════════════════════════════════════════════════════════
// The position this module ships: HOW a verifying key was obtained must
// travel in signed evidence, not in verifier logs. A relying party reading
// a receipt months later can then see, inside the signed bytes, whether the
// signature check behind a commitment ran against an inline-presented key,
// a previously stored pin, or a key fetched from a resolver, and judge the
// acquisition posture with its own policy.
//
// This is a RECORD of what the verifier did at verification time. It is
// not a trust score, it is not aggregated, and nothing here rates sources.
// ══════════════════════════════════════════════════════════════════

/**
 * How the verifying key was obtained for one signature check.
 *
 * Methods:
 *   - 'inline': the key material was presented with the artifact itself
 *     (for example a pubkey field inside the signed object). The check
 *     binds the artifact to that key; it says nothing about who holds it.
 *   - 'pinned': the key was previously obtained through one of the other
 *     two methods and stored. A pin is not a third kind of trust: its
 *     posture is the posture of whatever populated it, which is why a
 *     pinned source MUST carry pin_populated_at_ms and pin_populated_via.
 *   - 'resolver': the key was fetched at verification time from a resolver
 *     endpoint. A resolver source MUST carry resolver_origin, the
 *     allowlisted HTTPS origin that was actually used.
 *
 * Crosswalk: external ecosystems that record a 'cache' acquisition method
 * map onto APS 'pinned'; the population provenance fields carry what the
 * external form leaves implicit.
 */
export interface VerificationSource {
  /** How the key was obtained. */
  method: 'inline' | 'pinned' | 'resolver'
  /** Epoch milliseconds when the verifier performed the check. */
  verified_at_ms: number
  /** Resolver only: the allowlisted HTTPS origin used for the fetch. */
  resolver_origin?: string
  /** Pinned only: epoch milliseconds when the pin was populated. */
  pin_populated_at_ms?: number
  /** Pinned only: which method originally populated the pin. A pin's trust
   *  posture is the posture of what populated it. */
  pin_populated_via?: 'inline' | 'resolver'
}

/** Validation outcome for a VerificationSource. Fail closed: any rule
 *  violation makes the source invalid; nothing is coerced or defaulted. */
export interface VerificationSourceValidation {
  valid: boolean
  /** Human-readable rule violations, empty iff valid. */
  reasons: string[]
}
