// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
// ══════════════════════════════════════════════════════════════════
// base64url decode (RFC 7515 §2 / RFC 4648 §5), no dependencies.
// ══════════════════════════════════════════════════════════════════
// JWK `x` for an Ed25519 key is base64url (no padding) of the raw
// 32-byte public key. We decode it strictly: only the URL-safe
// alphabet, no padding characters, no whitespace. Anything else is a
// malformed JWK and is rejected by the caller (fail-closed).
// ══════════════════════════════════════════════════════════════════

const B64URL_RE = /^[A-Za-z0-9_-]+$/

/**
 * Decode a base64url string (unpadded, URL-safe alphabet) to bytes.
 * Returns null on any malformed input rather than throwing, so callers
 * can route the failure to a 'malformed' resolution status.
 *
 * Strictness:
 *  - rejects standard-base64 chars (`+`, `/`) and padding (`=`).
 *  - rejects empty input and whitespace.
 *  - the trailing partial group is validated: stray high bits in the
 *    final sextet (which would make the encoding non-canonical) are
 *    rejected so two distinct strings can never decode to the same key.
 */
export function decodeBase64Url(input: string): Uint8Array | null {
  if (typeof input !== 'string' || input.length === 0) return null
  if (!B64URL_RE.test(input)) return null
  // base64url length % 4 === 1 is structurally impossible (a single
  // leftover char cannot encode any byte).
  if (input.length % 4 === 1) return null

  const lookup = (c: string): number => {
    if (c >= 'A' && c <= 'Z') return c.charCodeAt(0) - 65
    if (c >= 'a' && c <= 'z') return c.charCodeAt(0) - 71
    if (c >= '0' && c <= '9') return c.charCodeAt(0) + 4
    if (c === '-') return 62
    if (c === '_') return 63
    return -1
  }

  const out: number[] = []
  let buffer = 0
  let bits = 0
  for (let i = 0; i < input.length; i++) {
    const v = lookup(input[i])
    if (v < 0) return null
    buffer = (buffer << 6) | v
    bits += 6
    if (bits >= 8) {
      bits -= 8
      out.push((buffer >> bits) & 0xff)
    }
  }
  // Reject non-canonical trailing bits: any leftover bits MUST be zero,
  // otherwise the encoding is not the canonical encoding of the bytes.
  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) return null

  return Uint8Array.from(out)
}

/** Lowercase hex of a byte array. */
export function bytesToHex(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i++) {
    s += bytes[i].toString(16).padStart(2, '0')
  }
  return s
}
