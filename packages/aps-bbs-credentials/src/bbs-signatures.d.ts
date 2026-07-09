// Copyright 2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
/**
 * Ambient declarations for @grottonetworking/bbs-signatures@0.1.5.
 *
 * The library ships as untyped ESM (single export "./lib/BBS.js"). These
 * declarations cover only the surface this isolated package uses. They are
 * derived from the JSDoc in the library source and pinned to the 0.1.5 API
 * (IETF draft-irtf-cfrg-bbs-signatures draft-05).
 */
declare module '@grottonetworking/bbs-signatures' {
  /** api_id for the BLS12-381-SHA-256 ciphersuite. */
  export const API_ID_BBS_SHA: string
  /** api_id for the BLS12-381-SHAKE-256 ciphersuite. */
  export const API_ID_BBS_SHAKE: string

  /** Opaque generator material produced by prepareGenerators. */
  export interface Generators {
    P1: unknown
    Q1: unknown
    H: unknown[]
  }

  /** Derive a secret key (32-byte scalar) from key material. */
  export function keyGen(
    key_material: Uint8Array,
    key_info: Uint8Array,
    key_dst?: string,
    api_id?: string
  ): Promise<Uint8Array>

  /** Derive the compressed G2 public key (96 bytes) from a 32-byte SK. */
  export function publicFromPrivate(privateBytes: Uint8Array): Uint8Array

  /** Map message octets to BBS message scalars. */
  export function messages_to_scalars(
    messages: Uint8Array[],
    api_id?: string
  ): Promise<bigint[]>

  /** Prepare L group generators for sign/verify/proof. */
  export function prepareGenerators(
    L: number,
    api_id: string
  ): Promise<Generators>

  /** Create an 80-byte BBS signature over message scalars. */
  export function sign(
    SK: Uint8Array | bigint,
    PK: Uint8Array,
    header: Uint8Array,
    messages: bigint[],
    generators: Generators,
    api_id: string
  ): Promise<Uint8Array>

  /** Verify a BBS signature over message scalars. */
  export function verify(
    PK: Uint8Array,
    signature: Uint8Array,
    header: Uint8Array,
    messages: bigint[],
    generators: Generators,
    api_id: string
  ): Promise<boolean>

  /** Generate a selective-disclosure proof revealing disclosed_indexes. */
  export function proofGen(
    PK: Uint8Array,
    signature: Uint8Array,
    header: Uint8Array,
    ph: Uint8Array,
    messages: bigint[],
    disclosed_indexes: number[],
    generators: Generators,
    api_id: string,
    rand_scalars?: (count: number) => Promise<bigint[]> | bigint[]
  ): Promise<Uint8Array>

  /** Verify a selective-disclosure proof. */
  export function proofVerify(
    PK: Uint8Array,
    proof: Uint8Array,
    header: Uint8Array,
    ph: Uint8Array,
    disclosed_messages: bigint[],
    disclosed_indexes: number[],
    generators: Generators,
    api_id: string
  ): Promise<boolean>
}
