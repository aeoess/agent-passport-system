// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

const UTC_MILLISECONDS = /^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d\.\d{3}Z$/

export function assertPlainRecord(value: unknown, name: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${name}: expected object`)
  }
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) {
    throw new Error(`${name}: non-JSON object`)
  }
}

export function assertExactKeys(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = [],
  name = 'object',
): void {
  const allowed = new Set([...required, ...optional])
  for (const key of required) {
    if (!Object.hasOwn(value, key)) throw new Error(`${name}: missing ${key}`)
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new Error(`${name}: unknown field ${key}`)
  }
}

export function assertIJson(value: unknown, path = '$', ancestors = new WeakSet<object>()): void {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    if (typeof value === 'string') assertUnicodeScalarString(value, path)
    return
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || (Number.isInteger(value) && !Number.isSafeInteger(value))) {
      throw new Error(`${path}: non-I-JSON number`)
    }
    return
  }
  if (typeof value !== 'object' || value === undefined || value instanceof Date) {
    throw new Error(`${path}: unsupported I-JSON value`)
  }
  if (ancestors.has(value)) throw new Error(`${path}: cyclic value`)
  ancestors.add(value)
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertIJson(entry, `${path}[${index}]`, ancestors))
  } else {
    assertPlainRecord(value, path)
    for (const [key, entry] of Object.entries(value)) {
      assertUnicodeScalarString(key, `${path} key`)
      if (entry === undefined) throw new Error(`${path}.${key}: undefined is not I-JSON`)
      assertIJson(entry, `${path}.${key}`, ancestors)
    }
  }
  ancestors.delete(value)
}

export function assertUnicodeScalarString(value: string, path: string): void {
  for (let index = 0; index < value.length; index++) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (next < 0xdc00 || next > 0xdfff) throw new Error(`${path}: lone surrogate`)
      index++
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new Error(`${path}: lone surrogate`)
    }
  }
}

export function assertUtcMilliseconds(value: string, name: string): void {
  if (!UTC_MILLISECONDS.test(value)) throw new Error(`${name}: expected canonical UTC milliseconds`)
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error(`${name}: invalid calendar timestamp`)
  }
}

export function assertHex(value: string, length: number, name: string): void {
  if (!new RegExp(`^[0-9a-f]{${length}}$`).test(value)) {
    throw new Error(`${name}: expected ${length} lowercase hexadecimal characters`)
  }
}

export function assertSortedUnique(values: string[], name: string): void {
  for (const value of values) {
    if (typeof value !== 'string' || value.length === 0) throw new Error(`${name}: empty or non-string value`)
    assertUnicodeScalarString(value, name)
  }
  for (let index = 1; index < values.length; index++) {
    if (compareUtf8(values[index - 1], values[index]) >= 0) {
      throw new Error(`${name}: values must be sorted and unique by UTF-8 bytes`)
    }
  }
}

export function sortedUnique(values: readonly string[], name: string): string[] {
  const result = [...values]
  result.sort(compareUtf8)
  assertSortedUnique(result, name)
  return result
}

function compareUtf8(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'))
}
