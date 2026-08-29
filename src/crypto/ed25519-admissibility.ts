// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//
// Ed25519 admissibility for APS.
//
// Node's crypto.verify implements the RFC 8032 verification equation. It
// accepts a public key or an R that decodes to a small-order point. With the
// Edwards identity as the public key and R = the identity with S = 0, the
// equation [S]B = R + [k]A degenerates to identity = identity, so one
// signature verifies under every message. A signature that does not depend on
// the message proves nothing about the artifact carrying it, so such key
// material is refused before the artifact is believed.
//
// The rule enforced here is the behaviour on which the two strict
// implementations in the APS family agree: libsodium (agent-passport-python
// src/agent_passport/crypto.py) and ed25519-dalek verify_strict
// (agent-passport-system crates/aps-verifier-core). They were run over a corpus
// of 2534 vectors, including the Wycheproof Ed25519 suite, all eight
// small-order points in every encoding, small-order R under honest keys,
// non-canonical encodings, s >= L, and 2048 ordinary generated keys, and
// agreed on every one. A public key or an R is admissible only when its 32
// bytes are the canonical encoding of a point that is not of small order.
//
// The third strict condition, a scalar S reduced modulo the group order, is
// already enforced by Node over OpenSSL. tests/ed25519-admissibility.test.ts
// pins it so the delegation would be caught if it ever stopped holding.
//
// This module decides rejection only. It never causes a signature to be
// accepted that Node would otherwise reject, and it is not on any signing
// path. The arithmetic is the standard edwards25519 group law over BigInt;
// tests/ed25519-admissibility.test.ts checks it against every small-order
// encoding and against 128 ordinary keys.

/** Field prime of edwards25519: 2^255 - 19. */
const P = (1n << 255n) - 19n
/** Curve parameter d = -121665/121666 mod p. */
const D =
  37095705934669439343138083508754565189542113879843219016388785533085940283555n
/** A square root of -1 mod p, used to recover x. */
const SQRT_M1 =
  19681161376707505956807079304988542015446066515923890162744021073123829784752n

const LOW_255 = (1n << 255n) - 1n
/** (p - 5) / 8, the exponent of the single-exponentiation square root. */
const SQRT_EXP = (P - 5n) / 8n

function mod(a: bigint): bigint {
  const r = a % P
  return r < 0n ? r + P : r
}

function powMod(base: bigint, exponent: bigint): bigint {
  let result = 1n
  let b = mod(base)
  let e = exponent
  while (e > 0n) {
    if (e & 1n) result = mod(result * b)
    b = mod(b * b)
    e >>= 1n
  }
  return result
}

/** Affine point. */
interface Point {
  x: bigint
  y: bigint
}

function bytesToLittleEndian(bytes: Uint8Array): bigint {
  let n = 0n
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]!)
  return n
}

/**
 * RFC 8032 point decompression using the recommended single-exponentiation
 * square root: x = (u * v^3) * (u * v^7)^((p-5)/8), corrected by sqrt(-1) when
 * needed. Returns null when the 32 bytes do not decode to a curve point.
 *
 * A y coordinate that is not reduced modulo p is decoded here and refused by
 * `isCanonicalEncoding`, which is what makes two byte strings for the same key
 * distinguishable.
 */
function decodePoint(bytes: Uint8Array): Point | null {
  const n = bytesToLittleEndian(bytes)
  const sign = (n >> 255n) & 1n
  const y = mod(n & LOW_255)

  const yy = mod(y * y)
  const u = mod(yy - 1n)
  const v = mod(D * yy + 1n)
  // v == 0 has no solution. Without this guard the square-root check below
  // would pass for a point that does not exist.
  if (v === 0n) return null

  const v2 = mod(v * v)
  const v3 = mod(v2 * v)
  const v7 = mod(mod(v3 * v3) * v)
  let x = mod(mod(u * v3) * powMod(mod(u * v7), SQRT_EXP))

  const check = mod(v * mod(x * x))
  if (check !== u) {
    if (check === mod(-u)) x = mod(x * SQRT_M1)
    else return null
  }
  if (x % 2n !== sign) x = mod(P - x)
  return { x, y }
}

/**
 * Whether these bytes are the one encoding RFC 8032 allows for the point they
 * decode to: the y coordinate reduced modulo p, and the sign bit clear when
 * x is zero. Two byte strings must never name the same key.
 */
function isCanonicalEncoding(bytes: Uint8Array, point: Point): boolean {
  const n = bytesToLittleEndian(bytes)
  if ((n & LOW_255) >= P) return false
  if (point.x === 0n && (n >> 255n) === 1n) return false
  return true
}

/**
 * A point has small order exactly when multiplying it by the cofactor 8 gives
 * the identity, which is three doublings. Projective coordinates are used so
 * no modular inversion is needed: (X : Y : Z) means (X/Z, Y/Z), and the
 * identity is any (0 : Z : Z).
 *
 * The doubling is the standard twisted Edwards projective doubling with
 * a = -1. The group law is complete on edwards25519 because d is not a square,
 * so there are no exceptional cases.
 */
function hasSmallOrder(point: Point): boolean {
  let X = point.x
  let Y = point.y
  let Z = 1n
  for (let i = 0; i < 3; i++) {
    const B = mod((X + Y) * (X + Y))
    const C = mod(X * X)
    const Dd = mod(Y * Y)
    const Ee = mod(-C)
    const F = mod(Ee + Dd)
    const H = mod(Z * Z)
    const J = mod(F - 2n * H)
    X = mod(mod(B - C - Dd) * J)
    Y = mod(F * mod(Ee - Dd))
    Z = mod(F * J)
  }
  if (Z === 0n) return true // cannot happen with a complete law; fail closed
  return X === 0n && Y === Z
}

/**
 * Whether these 32 bytes may carry an APS signature: the canonical encoding of
 * an edwards25519 point that is not of small order. Used for the public key
 * and for the signature's R.
 */
export function isAdmissiblePoint(bytes: Uint8Array): boolean {
  if (bytes.length !== 32) return false
  const point = decodePoint(bytes)
  if (point === null) return false
  if (!isCanonicalEncoding(bytes, point)) return false
  return !hasSmallOrder(point)
}

/**
 * Whether a raw 32-byte public key and a raw 64-byte signature carry
 * admissible key material. Both the public key and the signature's R must
 * pass.
 */
export function isAdmissibleKeyMaterial(
  publicKey: Uint8Array,
  signature: Uint8Array,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) return false
  return isAdmissiblePoint(publicKey) && isAdmissiblePoint(signature.subarray(0, 32))
}
