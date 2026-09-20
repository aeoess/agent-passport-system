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
 *
 * The walk is iterative, with an explicit stack of open containers, rather than
 * one function call per nesting level. A recursive-descent version of this same
 * walk overflowed the native call stack (an uncaught RangeError) on a deeply
 * nested but otherwise valid document, before this check ever reached the
 * schema. This walk's depth is bounded only by the caller's MAX_WIRE_BYTES
 * ceiling below and by the heap the open-container stack uses, never by the
 * JS call stack, so it reaches the same accept-or-reject answer for every
 * document this parser already accepted or rejected, and now also answers a
 * document that used to crash it.
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

  type Frame = { object: true; names: Set<string> } | { object: false }
  const stack: Frame[] = []

  // Consumes one JSON value at the cursor (leading whitespace already skipped
  // by the caller). Returns true when the value is a non-empty container, now
  // pushed on the stack, still awaiting its first member or element. Returns
  // false when the value is already complete (a scalar, or an empty object or
  // array), in which case the caller runs the "a value just completed" step
  // below for whichever frame that value belongs to.
  const openValue = (): boolean => {
    const first = source[cursor]
    if (first === '{') {
      cursor++
      skipWhitespace()
      if (source[cursor] === '}') { cursor++; return false }
      stack.push({ object: true, names: new Set() })
      return true
    }
    if (first === '[') {
      cursor++
      skipWhitespace()
      if (source[cursor] === ']') { cursor++; return false }
      stack.push({ object: false })
      return true
    }
    if (first === '"') {
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
    return false
  }

  skipWhitespace()
  let awaitingValue = true
  for (;;) {
    if (awaitingValue) {
      const top = stack.at(-1)
      if (top && top.object) {
        skipWhitespace()
        const name = readString()
        if (top.names.has(name)) throw new SyntaxError('duplicate JSON object member')
        top.names.add(name)
        skipWhitespace()
        cursor++ // colon
        skipWhitespace()
      }
      if (openValue()) continue // a new container was pushed; its first key or element is next
      awaitingValue = false
    } else {
      const top = stack.at(-1)
      if (!top) return // the whole document is one complete value
      skipWhitespace()
      if (source[cursor] === (top.object ? '}' : ']')) {
        cursor++
        stack.pop()
        continue // that container just completed as a value for its own parent frame
      }
      cursor++ // comma
      skipWhitespace()
      awaitingValue = true
    }
  }
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
