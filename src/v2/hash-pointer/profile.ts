// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
// ══════════════════════════════════════════════════════════════════════
// Hash-and-Pointer Payloads + Field-Disclosure Profile - Implementation
// ══════════════════════════════════════════════════════════════════════
//
// ============================ PROOF BOX ============================
// Specified, tested, validated.
//
// PROVES: A field-disclosure profile commits a receipt to a payload by hash
//   plus a pointer (URI) without embedding the raw payload, and binds each
//   field by hash so that a redacted or hidden field still leaves the receipt
//   signature verifiable. The builder rejects a raw value for any field marked
//   sensitive, so raw PII cannot reach the signed body through a 'public'
//   policy.
//
// DOES NOT PROVE:
//   - That the payload at the URI is available or unchanged. That requires
//     resolving the URI and re-hashing (compose the resolver, W2-A2). A
//     present URI is not an availability claim.
//   - That a hidden field's value is narrow or harmless. A hash binding hides
//     the value; it says nothing about what the value is.
//   - That an 'encrypted' field is actually encrypted, or with what key. This
//     module never encrypts; it carries caller-supplied ciphertext opaquely.
//   - Any truth about the field values themselves. A binding is a commitment to
//     a value, not a statement that the value is true.
// ==================================================================
//
// This file is solver-free, service-free, and does not fetch any URI.
// ══════════════════════════════════════════════════════════════════════

import { canonicalize, canonicalHash, canonicalHashForWrite } from '../../core/canonical.js'
import type {
  BuildFieldDisclosureProfileInput,
  DisclosedField,
  FieldDisclosurePolicy,
  FieldDisclosureProfile,
  FieldDisclosureVerification,
  HashPointerPayload,
} from './types.js'
import { REDACTED_SENTINEL } from './types.js'

/** Hash a single field VALUE deterministically. Reuses the core canonical hash
 *  so a field hash is stable across SDK, gateway, and Python. The value is
 *  wrapped under a fixed key so primitives and objects hash through the same
 *  path. */
function hashFieldValue(value: unknown): string {
  return canonicalHash({ v: value })
}

/** Write-boundary twin of hashFieldValue().
 *
 *  buildFieldDisclosureProfile() commits field hashes into a NEW profile while
 *  verifyFieldDisclosureProfile() recomputes the identical hashes to check an existing
 *  one, so the helper is shared and cannot be guarded in place. */
function hashFieldValueForWrite(value: unknown): string {
  return canonicalHashForWrite({ v: value })
}

const VALID_POLICIES: ReadonlySet<FieldDisclosurePolicy> = new Set([
  'public',
  'hash_only',
  'encrypted',
  'redacted',
])

/**
 * Build a field-disclosure profile from a source payload and a per-field
 * policy map. The builder NEVER embeds a raw sensitive value:
 *
 *   - A field named in `sensitive_fields` MUST NOT have policy 'public'. If it
 *     does, the build is rejected. This is the guard against raw PII reaching
 *     the signed body.
 *   - For 'hash_only' and 'redacted', only the hash binding is kept; the value
 *     is absent ('redacted' additionally records the '[REDACTED]' sentinel as
 *     the visible placeholder, matching the storage tombstone convention).
 *   - For 'encrypted', the caller-supplied ciphertext is kept; the value is
 *     absent. A missing ciphertext for an 'encrypted' field is rejected.
 *   - Every field carries a hash binding regardless of policy, so a hidden or
 *     redacted field still leaves the signature verifiable.
 *
 * The optional whole-payload commitment hashes the canonical payload and pairs
 * it with the supplied URI.
 */
export function buildFieldDisclosureProfile(
  input: BuildFieldDisclosureProfileInput
): FieldDisclosureProfile {
  const sensitive = new Set(input.sensitive_fields ?? [])
  const fields: DisclosedField[] = []

  // Validate policies and the sensitive-field guard up front, before any value
  // is touched, so a raw PII leak is a hard build-time rejection.
  for (const name of Object.keys(input.payload)) {
    const policy: FieldDisclosurePolicy = input.policies[name] ?? 'public'
    if (!VALID_POLICIES.has(policy)) {
      throw new Error(
        `buildFieldDisclosureProfile: unknown disclosure policy "${policy}" for field "${name}"`
      )
    }
    if (sensitive.has(name) && policy === 'public') {
      throw new Error(
        `buildFieldDisclosureProfile: field "${name}" is marked sensitive and cannot use the 'public' disclosure policy; ` +
          `use 'hash_only', 'encrypted', or 'redacted'`
      )
    }
  }

  // Any sensitive field named in the policy map but absent from the payload is
  // not a leak, but a sensitive field present with no policy entry would have
  // defaulted to 'public' and been caught above. Now materialize each field.
  for (const name of Object.keys(input.payload)) {
    const policy: FieldDisclosurePolicy = input.policies[name] ?? 'public'
    const rawValue = input.payload[name]
    const hash = hashFieldValueForWrite(rawValue)

    const field: DisclosedField = { name, policy, hash }

    switch (policy) {
      case 'public':
        field.value = rawValue
        break
      case 'hash_only':
        field.transform = 'hashing'
        // value intentionally absent - only the hash binding survives
        break
      case 'encrypted': {
        const ct = input.ciphertexts?.[name]
        if (ct === undefined) {
          throw new Error(
            `buildFieldDisclosureProfile: field "${name}" has policy 'encrypted' but no ciphertext was supplied`
          )
        }
        field.ciphertext = ct
        break
      }
      case 'redacted':
        field.transform = 'redaction'
        // The visible placeholder matches the storage tombstone sentinel. The
        // value is removed; the hash binding is preserved so the signature
        // still verifies - "hash chain and signature preserved".
        field.value = REDACTED_SENTINEL
        break
    }

    fields.push(field)
  }

  let payload: HashPointerPayload | undefined
  if (input.uri !== undefined) {
    payload = {
      algorithm: 'sha256',
      payload_sha256: canonicalHashForWrite(input.payload),
      uri: input.uri,
      content_type: input.content_type,
      committed_at: new Date().toISOString(),
    }
  }

  return {
    version: '1.0',
    payload,
    fields,
    bbs_proof: input.bbs_proof,
  }
}

/**
 * Verify a field-disclosure profile.
 *
 * With no second argument this checks INTERNAL consistency only: every field
 * carries a hash, public/redacted fields are shaped correctly, encrypted fields
 * carry ciphertext. With a `disclosed` map of field name to claimed cleartext
 * value, each supplied value is re-hashed and checked against the bound hash:
 * a match proves the discloser knew the committed value; a mismatch is flagged.
 * With a `payload` it re-hashes the canonical payload against the whole-payload
 * commitment.
 *
 * This reports mechanical facts. It does not fetch the URI and makes no
 * availability claim.
 */
export function verifyFieldDisclosureProfile(
  profile: FieldDisclosureProfile,
  opts?: {
    /** Claimed cleartext values for hidden fields, to test against bindings. */
    disclosed?: Record<string, unknown>
    /** A full payload to test against the whole-payload commitment. */
    payload?: Record<string, unknown>
  }
): FieldDisclosureVerification {
  const errors: string[] = []
  const fieldResults: FieldDisclosureVerification['fields'] = {}

  for (const field of profile.fields) {
    if (typeof field.hash !== 'string' || field.hash.length === 0) {
      errors.push(`Field "${field.name}" has no hash binding`)
      fieldResults[field.name] = { policy: field.policy, status: 'mismatch' }
      continue
    }

    // Structural checks per policy.
    if (field.policy === 'public') {
      // A public field must carry its value, and the value must hash to the
      // binding (the binding is over the same value the signature covers).
      const recomputed = hashFieldValue(field.value)
      if (recomputed !== field.hash) {
        errors.push(`Field "${field.name}" public value does not match its hash binding`)
        fieldResults[field.name] = { policy: field.policy, status: 'mismatch' }
        continue
      }
    } else if (field.policy === 'encrypted') {
      if (field.ciphertext === undefined) {
        errors.push(`Field "${field.name}" is 'encrypted' but carries no ciphertext`)
        fieldResults[field.name] = { policy: field.policy, status: 'mismatch' }
        continue
      }
    } else if (field.policy === 'redacted') {
      if (field.value !== REDACTED_SENTINEL) {
        errors.push(`Field "${field.name}" is 'redacted' but value is not the ${REDACTED_SENTINEL} sentinel`)
        fieldResults[field.name] = { policy: field.policy, status: 'mismatch' }
        continue
      }
    }
    // 'hash_only' needs no structural check beyond the hash presence above.

    // Optional value check against a supplied disclosure.
    const claimed = opts?.disclosed
      ? Object.prototype.hasOwnProperty.call(opts.disclosed, field.name)
      : false
    if (claimed) {
      const recomputed = hashFieldValue((opts!.disclosed as Record<string, unknown>)[field.name])
      if (recomputed === field.hash) {
        fieldResults[field.name] = { policy: field.policy, status: 'matched' }
      } else {
        errors.push(`Disclosed value for "${field.name}" does not match its hash binding`)
        fieldResults[field.name] = { policy: field.policy, status: 'mismatch' }
      }
    } else if (field.policy === 'public') {
      fieldResults[field.name] = { policy: field.policy, status: 'matched' }
    } else {
      // Hidden field with no supplied value: binding is present and consistent
      // but the value itself is not revealed, so it is 'unchecked' here unless
      // the binding self-check above failed.
      fieldResults[field.name] = { policy: field.policy, status: 'bound' }
    }
  }

  // Whole-payload commitment check.
  let payloadMatched: boolean | null = null
  if (profile.payload) {
    if (opts?.payload) {
      const recomputed = canonicalHash(opts.payload)
      payloadMatched = recomputed === profile.payload.payload_sha256
      if (!payloadMatched) {
        errors.push('Supplied payload does not match the hash-and-pointer commitment')
      }
    }
    // No supplied payload: commitment present, availability NOT claimed.
  }

  return {
    valid: errors.length === 0,
    fields: fieldResults,
    payloadMatched,
    errors,
  }
}

/**
 * Canonical bytes a receipt signs when it carries a field-disclosure profile.
 * Exposed so a receipt builder can fold the profile into its signed body using
 * the same canonicalization every other builder uses, without this module
 * owning a signing key. Adding this to a body changes nothing for receipts that
 * omit the profile.
 */
export function canonicalProfileBytes(profile: FieldDisclosureProfile): string {
  return canonicalize(profile as unknown as Record<string, unknown>)
}
