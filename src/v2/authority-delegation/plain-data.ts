// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

/**
 * Plain-JSON-data snapshot shared by every authority-delegation entry point.
 *
 * The public draft (draft-pidlisnyi-aps-03) computes an identifier or a signature with
 * JCS, RFC 8785, over validated I-JSON (line 204), and treats a cryptographic or
 * attenuation failure as invalid (section 3.3, line 591). Every artifact a verifier
 * receives is untrusted input, and a verification interface should turn a structurally
 * malformed artifact into a defined result rather than an unhandled failure (lines
 * 1652-1660). A value with no JSON form is exactly that kind of malformed artifact: it
 * cannot be canonicalized, so it cannot be the value that was actually validated,
 * hashed and signed unless something first strips it out.
 *
 * A record handed to any entry point is plain JSON data when it, and everything inside
 * it, is one of: null; a boolean; a finite number; a string; an exact plain array
 * (Array.isArray and Object.getPrototypeOf equal to Array.prototype, own string keys
 * exactly the indices 0 through length-1 plus "length", and every index an enumerable
 * data property, no hole, no accessor, no extra member); or an exact plain object
 * (a non-array object whose prototype is Object.prototype or null, and every own
 * string-keyed property of which is an enumerable data property; symbol-keyed
 * properties are ignored, since JSON and RFC 8785 never see them). A container that
 * contains itself at any depth is not plain JSON data; a container reachable twice
 * without a cycle is fine.
 *
 * snapshotPlainData() reads every property of its argument exactly once, through
 * Object.getOwnPropertyDescriptor, never through ordinary property access, and never
 * calls a getter or a Proxy "get" trap. It copies plain values into fresh plain arrays
 * and objects and puts NOT_PLAIN_DATA in place of anything that is not plain,
 * including a container found on its own current path. isIJSONValue() in schema.ts
 * already treats any value of type symbol as not I-JSON, so the record-wide I-JSON walk
 * rejects the marker with no change of its own. For a top-level argument that is not
 * itself a plain object or plain array, the marker is the whole snapshot.
 *
 * The walk keeps an explicit stack instead of recursing, so pathological nesting depth
 * in an attacker-supplied argument cannot overflow the call stack. Every entry point
 * below calls this once per record argument, before any other read of that argument,
 * and every later read in that entry point, including a read passed on to a
 * caller-supplied callback, must come from the returned snapshot rather than from the
 * original value, so a getter or a Proxy trap can never be read a second time with a
 * different answer.
 */

/** Module-private: stands in for any value this SDK's I-JSON walk must reject. */
const NOT_PLAIN_DATA: unique symbol = Symbol('aps:not-plain-json-data')

function isPlainScalar(value: unknown): value is null | boolean | number | string {
  if (value === null) return true
  switch (typeof value) {
    case 'boolean':
    case 'string':
      return true
    case 'number':
      return Number.isFinite(value)
    default:
      return false
  }
}

interface PlainArrayShape {
  length: number
  descriptors: PropertyDescriptor[]
}

/** Reads every own property descriptor of `value` exactly once. Returns null when
 *  `value` is not an exact plain array: wrong prototype, a hole, an accessor, a
 *  non-enumerable member, or an extra named member. Callers pass only values for
 *  which Array.isArray(value) is already true. */
function plainArrayShape(value: object): PlainArrayShape | null {
  if (Object.getPrototypeOf(value) !== Array.prototype) return null
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length')
  const length = lengthDescriptor ? lengthDescriptor.value : undefined
  if (typeof length !== 'number' || !Number.isInteger(length) || length < 0) return null
  const names = Object.getOwnPropertyNames(value)
  if (names.length !== length + 1) return null
  const nameSet = new Set(names)
  if (!nameSet.has('length')) return null
  const descriptors: PropertyDescriptor[] = new Array(length)
  for (let i = 0; i < length; i++) {
    const key = String(i)
    if (!nameSet.has(key)) return null // a hole
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) return null
    descriptors[i] = descriptor
  }
  return { length, descriptors }
}

/** Reads every own string-keyed property descriptor of `value` exactly once. Returns
 *  null when `value` is not an exact plain object: wrong prototype, an accessor, or a
 *  non-enumerable member. Symbol-keyed properties are ignored. Callers pass only
 *  values for which Array.isArray(value) is already false. */
function plainObjectShape(value: object): Map<string, PropertyDescriptor> | null {
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return null
  const shape = new Map<string, PropertyDescriptor>()
  for (const key of Object.getOwnPropertyNames(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key)
    if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) return null
    shape.set(key, descriptor)
  }
  return shape
}

interface PendingValue {
  kind: 'value'
  value: unknown
  place: (result: unknown) => void
}

interface PendingExit {
  kind: 'exit'
  container: object
}

/**
 * Deep snapshot of `root` under the plain-JSON-data rule documented above. Every
 * authority-delegation entry point calls this once per record argument, before any
 * other read of that argument, and runs all later logic on the snapshot only.
 */
export function snapshotPlainData(root: unknown): unknown {
  let output: unknown
  const onPath = new Set<object>()
  const stack: (PendingValue | PendingExit)[] = [
    { kind: 'value', value: root, place: result => { output = result } },
  ]
  while (stack.length > 0) {
    const task = stack.pop()!
    if (task.kind === 'exit') {
      onPath.delete(task.container)
      continue
    }
    const { value, place } = task
    if (isPlainScalar(value)) {
      place(value)
      continue
    }
    if (typeof value !== 'object' || value === null) {
      place(NOT_PLAIN_DATA) // undefined, bigint, function, symbol, or a non-finite number
      continue
    }
    if (onPath.has(value)) {
      place(NOT_PLAIN_DATA) // a container on its own current path: a cycle
      continue
    }
    if (Array.isArray(value)) {
      const shape = plainArrayShape(value)
      if (!shape) { place(NOT_PLAIN_DATA); continue }
      const copy: unknown[] = new Array(shape.length)
      place(copy)
      onPath.add(value)
      stack.push({ kind: 'exit', container: value })
      // Pushed last-first so that they are popped, and placed, in their original order.
      for (let i = shape.length - 1; i >= 0; i--) {
        const index = i
        stack.push({
          kind: 'value',
          value: shape.descriptors[index].value,
          place: result => { copy[index] = result },
        })
      }
    } else {
      const shape = plainObjectShape(value)
      if (!shape) { place(NOT_PLAIN_DATA); continue }
      const copy: Record<string, unknown> = {}
      place(copy)
      onPath.add(value)
      stack.push({ kind: 'exit', container: value })
      // Pushed last-first so that the copy's members are defined in the original
      // member order: the snapshot then serializes, and is returned to callers,
      // exactly as the original would be.
      for (const [key, descriptor] of [...shape].reverse()) {
        stack.push({
          kind: 'value',
          value: descriptor.value,
          // defineProperty, not assignment: assigning to a member named "__proto__"
          // would set the copy's prototype instead of creating the member, and the
          // member would silently disappear from the snapshot.
          place: result => {
            Object.defineProperty(copy, key, { value: result, writable: true, enumerable: true, configurable: true })
          },
        })
      }
    }
  }
  return output
}

/**
 * True when `value` is itself an exact plain array (not a subclass, not a value with a
 * hole, an accessor, or an extra member). Used at the boundary of a whole chain, which
 * is not itself record content and so is checked for shape without being copied.
 */
export function isPlainDataArray(value: unknown): value is unknown[] {
  return Array.isArray(value) && plainArrayShape(value) !== null
}
