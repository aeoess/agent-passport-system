// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { canonicalizeJCS } from '../../core/canonical-jcs.js'
import type { JsonValue } from './types.js'

export class IJsonValidationError extends TypeError {
  constructor(message: string) {
    super(message)
    this.name = 'IJsonValidationError'
  }
}

function assertUnicodeScalarString(value: string, path: string): void {
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i)
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < value.length ? value.charCodeAt(i + 1) : -1
      if (next >= 0xdc00 && next <= 0xdfff) {
        i++
        continue
      }
      throw new IJsonValidationError(`${path}: unpaired high surrogate`)
    }
    if (unit >= 0xdc00 && unit <= 0xdfff) {
      throw new IJsonValidationError(`${path}: unpaired low surrogate`)
    }
  }
}

/** Validate the in-memory new-write input before RFC 8785 processing.
 *  No coercion is performed. In particular, undefined is not converted to null
 *  and Date is not converted to a string. */
export function assertIJson(value: unknown, path = '$', ancestors = new WeakSet<object>()): asserts value is JsonValue {
  if (value === null || typeof value === 'boolean') return
  if (typeof value === 'string') {
    assertUnicodeScalarString(value, path)
    return
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new IJsonValidationError(`${path}: non-finite number`)
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new IJsonValidationError(`${path}: integer exceeds the interoperable IEEE 754 range`)
    }
    return
  }
  if (typeof value !== 'object') {
    throw new IJsonValidationError(`${path}: unsupported ${typeof value}`)
  }
  if (value instanceof Date) throw new IJsonValidationError(`${path}: Date must be converted explicitly`)
  if (ancestors.has(value)) throw new IJsonValidationError(`${path}: cyclic value`)
  ancestors.add(value)
  if (Array.isArray(value)) {
    value.forEach((item, i) => assertIJson(item, `${path}[${i}]`, ancestors))
  } else {
    const proto = Object.getPrototypeOf(value)
    if (proto !== Object.prototype && proto !== null) {
      throw new IJsonValidationError(`${path}: non-plain object`)
    }
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      assertUnicodeScalarString(key, `${path} key`)
      assertIJson(item, `${path}.${key}`, ancestors)
    }
  }
  ancestors.delete(value)
}

export function strictJCS(value: unknown): string {
  assertIJson(value)
  return canonicalizeJCS(value)
}

/** Parse bounded raw JSON without losing duplicate object names.
 *  Duplicate comparison is performed after JSON string decoding, so aliases
 *  such as "a" and "\u0061" are the same member name and are rejected. */
export function parseStrictIJson(raw: string, maxUtf8Bytes = 1_048_576, maxDepth = 128): JsonValue {
  if (typeof raw !== 'string') throw new IJsonValidationError('$: raw JSON string required')
  if (!Number.isSafeInteger(maxUtf8Bytes) || maxUtf8Bytes < 1 || Buffer.byteLength(raw, 'utf8') > maxUtf8Bytes) {
    throw new IJsonValidationError('$: raw JSON size limit exceeded')
  }
  if (!Number.isSafeInteger(maxDepth) || maxDepth < 1) throw new IJsonValidationError('$: invalid depth limit')
  let offset = 0
  const skipWhitespace = (): void => { while (offset < raw.length && /[\x20\t\r\n]/.test(raw[offset])) offset++ }
  const parseString = (): string => {
    const start = offset++
    let escaped = false
    while (offset < raw.length) {
      const code = raw.charCodeAt(offset)
      if (!escaped && code === 0x22) {
        offset++
        let decoded: unknown
        try { decoded = JSON.parse(raw.slice(start, offset)) } catch { throw new IJsonValidationError('$: invalid JSON string') }
        assertIJson(decoded)
        return decoded as string
      }
      if (!escaped && code < 0x20) throw new IJsonValidationError('$: unescaped control character')
      if (!escaped && code === 0x5c) escaped = true
      else escaped = false
      offset++
    }
    throw new IJsonValidationError('$: unterminated JSON string')
  }
  const parseValue = (depth: number): JsonValue => {
    if (depth > maxDepth) throw new IJsonValidationError('$: JSON nesting limit exceeded')
    skipWhitespace()
    const token = raw[offset]
    if (token === '"') return parseString()
    if (token === '{') {
      offset++
      const value: { [key: string]: JsonValue } = Object.create(null)
      const names = new Set<string>()
      skipWhitespace()
      if (raw[offset] === '}') { offset++; return value }
      while (true) {
        skipWhitespace()
        if (raw[offset] !== '"') throw new IJsonValidationError('$: object member name required')
        const name = parseString()
        if (names.has(name)) throw new IJsonValidationError('$: duplicate object member')
        names.add(name)
        skipWhitespace()
        if (raw[offset++] !== ':') throw new IJsonValidationError('$: colon required')
        value[name] = parseValue(depth + 1)
        skipWhitespace()
        const separator = raw[offset++]
        if (separator === '}') return value
        if (separator !== ',') throw new IJsonValidationError('$: comma or object end required')
      }
    }
    if (token === '[') {
      offset++
      const value: JsonValue[] = []
      skipWhitespace()
      if (raw[offset] === ']') { offset++; return value }
      while (true) {
        value.push(parseValue(depth + 1))
        skipWhitespace()
        const separator = raw[offset++]
        if (separator === ']') return value
        if (separator !== ',') throw new IJsonValidationError('$: comma or array end required')
      }
    }
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]] as const) {
      if (raw.startsWith(literal, offset)) { offset += literal.length; return value }
    }
    const number = raw.slice(offset).match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/)
    if (!number) throw new IJsonValidationError('$: JSON value required')
    offset += number[0].length
    const value: unknown = JSON.parse(number[0])
    assertIJson(value)
    return value as number
  }
  const value = parseValue(1)
  skipWhitespace()
  if (offset !== raw.length) throw new IJsonValidationError('$: trailing JSON data')
  assertIJson(value)
  return value
}

export function assertExactKeys(value: Record<string, unknown>, allowed: readonly string[], required: readonly string[], name: string): void {
  const allow = new Set(allowed)
  for (const key of Object.keys(value)) {
    if (!allow.has(key)) throw new IJsonValidationError(`${name}: unknown field ${key}`)
  }
  for (const key of required) {
    if (!(key in value)) throw new IJsonValidationError(`${name}: missing field ${key}`)
  }
}
