// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { validateAuthorityDelegationShape } from './schema.js'
import type { AuthorityDelegationV1 } from './types.js'

// The draft states no maximum wire size. This 1 MiB limit is this implementation's own
// ceiling, not a protocol rule: crossing it means this parser declines to read the
// document, which is why it throws rather than reporting a conformance failure. The
// chain verifier reports its equivalent ceiling as RESOURCE_LIMIT and indeterminate.
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
      // No spelling rule here. An integral-valued I-JSON number is admissible on the
      // wire however it is written, and RFC 8785 canonicalises the spelling, so "2.0"
      // and "2e0" are the same value as "2" and produce the same canonical bytes. This
      // parser used to refuse the spelling, which made an SDK rule into a wire
      // rejection. A token whose VALUE is not an integer where the schema requires one
      // is still refused, by the schema, which is where value rules belong.
      void source.slice(start, cursor) // token boundaries consumed above; nothing to judge
    }
  }

  value()
}

/** Strict untrusted-wire entry point: valid JSON, I-JSON names, and closed v1 schema. */
export function parseAuthorityDelegationJson(source: string): AuthorityDelegationV1 {
  if (typeof source !== 'string' || Buffer.byteLength(source, 'utf8') > MAX_WIRE_BYTES) {
    throw new TypeError("authority delegation JSON must be a string within this implementation's 1 MiB ceiling")
  }
  const decoded: unknown = JSON.parse(source)
  rejectDuplicateMembers(source)
  const failures = validateAuthorityDelegationShape(decoded)
  if (failures.length > 0) {
    throw new TypeError(`authority delegation wire invalid: ${failures.map(item => item.code).join(', ')}`)
  }
  return decoded as AuthorityDelegationV1
}
