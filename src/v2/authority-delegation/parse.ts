// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { validateAuthorityDelegationShape } from './schema.js'
import type { AuthorityDelegationV1 } from './types.js'

const MAX_WIRE_BYTES = 1_048_576

/**
 * JSON.parse silently keeps the last occurrence of a duplicate member. RFC
 * 8785 operates on I-JSON, so scan the already-syntax-checked source and reject
 * repeated names at every object depth before accepting a signed record.
 */
function rejectDuplicateMembers(source: string): void {
  let cursor = 0

  const skipWhitespace = (): void => {
    while (cursor < source.length && /[\u0009\u000a\u000d\u0020]/.test(source[cursor])) cursor++
  }
  const readString = (): string => {
    const start = cursor
    cursor++ // opening quote; whole-document JSON.parse already proved syntax
    while (cursor < source.length) {
      if (source[cursor] === '\\') {
        cursor += 2
      } else if (source[cursor++] === '"') {
        return JSON.parse(source.slice(start, cursor)) as string
      }
    }
    throw new SyntaxError('unterminated JSON string')
  }
  const value = (): void => {
    skipWhitespace()
    const first = source[cursor]
    if (first === '{') {
      cursor++
      skipWhitespace()
      const names = new Set<string>()
      if (source[cursor] === '}') { cursor++; return }
      while (cursor < source.length) {
        const name = readString()
        if (names.has(name)) throw new SyntaxError('duplicate JSON object member')
        names.add(name)
        skipWhitespace()
        cursor++ // colon
        value()
        skipWhitespace()
        if (source[cursor++] === '}') return
        skipWhitespace() // comma was consumed
      }
    } else if (first === '[') {
      cursor++
      skipWhitespace()
      if (source[cursor] === ']') { cursor++; return }
      while (cursor < source.length) {
        value()
        skipWhitespace()
        if (source[cursor++] === ']') return
      }
    } else if (first === '"') {
      readString()
    } else {
      const start = cursor
      while (cursor < source.length && !/[\u0009\u000a\u000d\u0020,}\]]/.test(source[cursor])) cursor++
      const token = source.slice(start, cursor)
      if (/^[-0-9]/.test(token) && !/^-?(0|[1-9][0-9]*)$/.test(token)) {
        throw new SyntaxError('non-integer JSON numbers are not permitted')
      }
    }
  }

  value()
}

/** Strict untrusted-wire entry point: valid JSON, I-JSON names, and closed v1 schema. */
export function parseAuthorityDelegationJson(source: string): AuthorityDelegationV1 {
  if (typeof source !== 'string' || Buffer.byteLength(source, 'utf8') > MAX_WIRE_BYTES) {
    throw new TypeError('authority delegation JSON must be a string no larger than 1 MiB')
  }
  const decoded: unknown = JSON.parse(source)
  rejectDuplicateMembers(source)
  const failures = validateAuthorityDelegationShape(decoded)
  if (failures.length > 0) {
    throw new TypeError(`authority delegation wire invalid: ${failures.map(item => item.code).join(', ')}`)
  }
  return decoded as AuthorityDelegationV1
}
