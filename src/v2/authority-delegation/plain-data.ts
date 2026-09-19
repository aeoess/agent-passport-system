// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { types } from 'node:util'

/** Function.prototype.toString captured when this module loaded. isIntrinsicPrototype()
 *  below calls this reference rather than a candidate function's own toString, so a
 *  script that replaces Function.prototype.toString, or a constructor that overrides its
 *  own toString, after this module has already loaded cannot make a forged constructor
 *  read back as native code. */
const functionToString = Function.prototype.toString

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
 * it, is one of: null; a boolean; a finite number; a string; an exact plain array; or an
 * exact plain object. A Proxy is never plain data, at any depth, including a revoked
 * Proxy: this is decided with Node's own internal proxy check, which never invokes a
 * trap, so a Proxy is rejected before anything belonging to it, its prototype, its own
 * keys, or any of its descriptors, is read. An exact plain array is a value for which
 * Array.isArray is true, that is not itself a Proxy, whose prototype is the
 * Array.prototype of some JavaScript realm, whose own string keys are exactly the
 * indices 0 through length-1 plus "length", every index of which is an enumerable data
 * property, no hole, no accessor, no extra member, and which carries no own
 * symbol-keyed property. An exact plain object is a non-array, non-Proxy object whose
 * prototype is null, or whose prototype is the Object.prototype of some realm, every
 * own string-keyed property of which is an enumerable data property, and which carries
 * no own symbol-keyed property either: a symbol such as Symbol.iterator changes what
 * JavaScript code reads from the value, even though JSON.parse never produces one.
 * "The Array.prototype of some JavaScript realm" and "the Object.prototype of some
 * realm" are decided by isIntrinsicPrototype() below through realm-intrinsic identity,
 * an own "constructor" property leading back to a function whose own "prototype"
 * property is that same object and whose captured Function.prototype.toString text is
 * exactly the native-code form for Object or Array, never by prototype-chain shape: a
 * plain array JSON.parse decoded in another realm, such as node:vm, a worker, or an
 * iframe, qualifies exactly as one JSON.parse decoded in this realm does, while a
 * forged prototype whose own [[Prototype]] chain merely looks right, including a
 * look-alike built from another realm's real Object or Array function, never does. A
 * container that contains itself at any depth is not plain JSON data; a container
 * reachable twice without a cycle is fine.
 *
 * snapshotPlainData() reads every property of its argument exactly once, through
 * Object.getOwnPropertyDescriptor, never through ordinary property access, and never
 * calls a getter or a Proxy "get" trap. It copies plain values into fresh plain arrays
 * and objects and puts NOT_PLAIN_DATA in place of anything that is not plain, including
 * a container found on its own current path. isIJSONValue() in schema.ts already treats
 * any value of type symbol as not I-JSON, so the record-wide I-JSON walk rejects the
 * marker with no change of its own. For a top-level argument that is not itself a plain
 * object or plain array, the marker is the whole snapshot. Any exception raised while
 * one value is inspected, a throwing Proxy trap among them, makes that one value
 * NOT_PLAIN_DATA rather than an exception out of the walk, so an exception never
 * escapes any authority-delegation entry point on this account.
 *
 * The walk keeps an explicit stack instead of recursing, so pathological nesting depth
 * in an attacker-supplied argument cannot overflow the call stack. It also keeps a map
 * from each container object it has already finished (or already rejected) to that
 * result, keyed by object identity, so a container reached again through another
 * reference, while it is not on the current path, is not walked a second time: the copy
 * already made (or the NOT_PLAIN_DATA already found) is placed again instead. A
 * container reached again while it is still on the current path is a cycle and is
 * unaffected by this map, since the cycle check runs first; only once that container
 * has fully exited does a later reference to it read the map. This keeps the walk's
 * cost linear in the number of distinct containers plus their members even when an
 * input built from shared references, such as node_i = [node_(i-1), node_(i-1)], would
 * otherwise multiply the work by the number of paths to each container. Object identity
 * is enough here: a container the input references twice appears once, shared, in the
 * snapshot, so both positions hold the identical copy rather than two separately copied
 * but equal containers, and that shared copy is what appears at both positions in an
 * issued record's body and in whatever a caller-supplied callback receives.
 *
 * Every entry point below calls this once per record argument, before any other read of
 * that argument, and every later read in that entry point, including a read passed on
 * to a caller-supplied callback, must come from the returned snapshot rather than from
 * the original value, so a getter or a Proxy trap can never be read a second time with a
 * different answer.
 *
 * The entry points that snapshot this way are validateAuthorityDelegationShape (and
 * isAuthorityDelegationV1, which calls it), verifyAuthorityDelegationChain,
 * InMemoryAuthorityBudgetLedger.reserve, issueAuthorityDelegation, and
 * issueSubAuthorityDelegation. The raw canonical helpers computeAuthorityDelegationId,
 * computeAuthorityDelegationIdForWrite, signAuthorityDelegation,
 * verifyAuthorityDelegationSignature, authorityDelegationBody, and the id and signature
 * input builders (authorityDelegationIdInput, authorityDelegationIdInputForWrite, and
 * authorityDelegationSignatureInput) do not snapshot: each of them is called only with a
 * value some entry point above has already snapshotted, or a value assembled from one,
 * so walking it again here would only repeat work already done.
 *
 * The chain container passed to verifyAuthorityDelegationChain and to
 * InMemoryAuthorityBudgetLedger.reserve is not itself record content, so
 * readPlainDataChainContainer() below checks its shape and reads it without copying it
 * through this walk. A Proxy there, including as the container itself, is rejected the
 * same way and at the same point as anywhere else: before any of its properties are
 * read. Its length is read once through its own descriptor, and the length bound is
 * checked before any index of the container is read; each index is then read exactly
 * once, through its own descriptor, and every entry point snapshots each returned
 * member through this same walk before any other read of that member. A container that
 * fails this check gives exactly the result a non-array chain gives.
 */

/** Module-private: stands in for any value this SDK's I-JSON walk must reject. */
const NOT_PLAIN_DATA: unique symbol = Symbol('aps:not-plain-json-data')

/**
 * True when `value` is a Proxy, including a revoked one. Backed by Node's own internal
 * proxy check (node:util's types.isProxy), which never invokes a trap on `value` and
 * never touches its target or handler, so this can be asked before any other operation
 * on `value`. A revoked Proxy throws on almost every other operation this module would
 * otherwise perform first, Array.isArray and Object.getPrototypeOf among them; asking
 * `typeof value` first does not, so isPlainScalar() above this in the walk is safe to
 * run before this check.
 */
function isProxy(value: unknown): boolean {
  return (typeof value === 'object' || typeof value === 'function') && value !== null && types.isProxy(value)
}

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

/**
 * True when `candidate` is "the Object.prototype of some realm" or "the Array.prototype
 * of some realm", decided by realm-intrinsic identity rather than by prototype-chain
 * shape: `candidate` is an object and not a Proxy; it carries an own data property
 * "constructor" whose value F is a function and not a Proxy; F carries an own data
 * property "prototype" that is non-writable, non-configurable, and holds exactly
 * `candidate`; and functionToString.call(F), using the Function.prototype.toString
 * reference captured when this module loaded, is exactly `function Object() { [native
 * code] }` or `function Array() { [native code] }`. Any exception raised while checking
 * makes this false. A structurally array- or object-shaped prototype whose own
 * [[Prototype]] chain merely looks right, a class instance whose class prototype's own
 * prototype is null, and a look-alike whose "constructor" names a real Object or Array
 * function but whose own "prototype" is not that function's actual prototype, all fail
 * this check; a cross-realm Object.prototype or Array.prototype, reached through
 * node:vm, a worker, or an iframe, still passes it, since it is checked by this same
 * identity, never by comparison against this realm's own Object.prototype or
 * Array.prototype.
 */
function isIntrinsicPrototype(candidate: object, name: 'Object' | 'Array'): boolean {
  try {
    if (isProxy(candidate)) return false
    const constructorDescriptor = Object.getOwnPropertyDescriptor(candidate, 'constructor')
    if (!constructorDescriptor || !('value' in constructorDescriptor)) return false
    const constructor = constructorDescriptor.value
    if (typeof constructor !== 'function' || isProxy(constructor)) return false
    const prototypeDescriptor = Object.getOwnPropertyDescriptor(constructor, 'prototype')
    if (
      !prototypeDescriptor ||
      !('value' in prototypeDescriptor) ||
      prototypeDescriptor.value !== candidate ||
      prototypeDescriptor.writable !== false ||
      prototypeDescriptor.configurable !== false
    ) {
      return false
    }
    return functionToString.call(constructor) === `function ${name}() { [native code] }`
  } catch {
    return false
  }
}

/**
 * Per-call memoization for isIntrinsicPrototype(), keyed by prototype object identity
 * and split by which intrinsic (Object or Array) is being asked about, since the same
 * object could otherwise be asked about both and must never share one cached verdict
 * between them. Scoped to a single call to snapshotPlainData() or to
 * readPlainDataChainContainer(): a fresh cache is created at the start of each such
 * call and threaded through it, never kept past that call, so this changes nothing
 * about the result, only how many times the check underneath is repeated when one
 * realm's Object.prototype or Array.prototype, or one forged look-alike, backs many
 * containers in the same argument.
 */
interface PrototypeIntrinsicCache {
  readonly objectPrototypes: Map<object, boolean>
  readonly arrayPrototypes: Map<object, boolean>
}

function newPrototypeIntrinsicCache(): PrototypeIntrinsicCache {
  return { objectPrototypes: new Map(), arrayPrototypes: new Map() }
}

/**
 * True when `candidate` is the Array.prototype of some JavaScript realm: see
 * isIntrinsicPrototype() above for exactly what that means and why a structurally
 * array-shaped forgery does not qualify. False, with no exception, for null, for
 * anything that is not an object, and for a Proxy.
 */
function isArrayPrototypeOfSomeRealm(candidate: unknown, cache: PrototypeIntrinsicCache): boolean {
  if (candidate === null || typeof candidate !== 'object') return false
  const cached = cache.arrayPrototypes.get(candidate)
  if (cached !== undefined) return cached
  const verdict = isIntrinsicPrototype(candidate, 'Array')
  cache.arrayPrototypes.set(candidate, verdict)
  return verdict
}

/**
 * True when `prototype` is a value an exact plain object may carry: null, or the
 * Object.prototype of some realm as decided by isIntrinsicPrototype() above.
 */
function isPlainObjectPrototype(prototype: unknown, cache: PrototypeIntrinsicCache): boolean {
  if (prototype === null) return true
  if (typeof prototype !== 'object') return false
  const cached = cache.objectPrototypes.get(prototype)
  if (cached !== undefined) return cached
  const verdict = isIntrinsicPrototype(prototype, 'Object')
  cache.objectPrototypes.set(prototype, verdict)
  return verdict
}

interface PlainArrayShape {
  length: number
  descriptors: PropertyDescriptor[]
}

/** Reads every own property descriptor of `value` exactly once. Returns null when
 *  `value` is not an exact plain array: wrong prototype, an own symbol-keyed property,
 *  a hole, an accessor, a non-enumerable member, or an extra named member. Callers pass
 *  only values for which Array.isArray(value) is already true and isProxy(value) is
 *  already false. */
function plainArrayShape(value: object, cache: PrototypeIntrinsicCache): PlainArrayShape | null {
  if (!isArrayPrototypeOfSomeRealm(Object.getPrototypeOf(value), cache)) return null
  if (Object.getOwnPropertySymbols(value).length > 0) return null
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
 *  null when `value` is not an exact plain object: wrong prototype, an own
 *  symbol-keyed property, an accessor, or a non-enumerable member. Callers pass only
 *  values for which Array.isArray(value) is already false and isProxy(value) is
 *  already false. */
function plainObjectShape(value: object, cache: PrototypeIntrinsicCache): Map<string, PropertyDescriptor> | null {
  if (!isPlainObjectPrototype(Object.getPrototypeOf(value), cache)) return null
  if (Object.getOwnPropertySymbols(value).length > 0) return null
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
  // Every container this walk has already finished, or already rejected for its own
  // shape, keyed by its object identity: see the doc comment above. Never consulted for
  // a container still on the current path, since the cycle check above it runs first.
  const done = new Map<object, unknown>()
  // Realm-intrinsic prototype verdicts already computed during this one call: see
  // PrototypeIntrinsicCache above.
  const prototypeCache = newPrototypeIntrinsicCache()
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
    try {
      if (isPlainScalar(value)) {
        place(value)
        continue
      }
      if (isProxy(value)) {
        place(NOT_PLAIN_DATA) // a Proxy, including a revoked one, is never plain data
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
      if (done.has(value)) {
        place(done.get(value)) // reached again, off its own path: reuse the result already found
        continue
      }
      if (Array.isArray(value)) {
        const shape = plainArrayShape(value, prototypeCache)
        if (!shape) { done.set(value, NOT_PLAIN_DATA); place(NOT_PLAIN_DATA); continue }
        const copy: unknown[] = new Array(shape.length)
        done.set(value, copy)
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
        const shape = plainObjectShape(value, prototypeCache)
        if (!shape) { done.set(value, NOT_PLAIN_DATA); place(NOT_PLAIN_DATA); continue }
        const copy: Record<string, unknown> = {}
        done.set(value, copy)
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
    } catch {
      // Any exception raised while this one value was inspected, a throwing Proxy trap
      // among them, makes this value NOT_PLAIN_DATA rather than an exception out of the
      // walk.
      place(NOT_PLAIN_DATA)
    }
  }
  return output
}

/**
 * Checked, descriptor-only read of a chain container: the argument to
 * verifyAuthorityDelegationChain and to InMemoryAuthorityBudgetLedger.reserve. The
 * container itself is not record content, so it is checked for shape and read here
 * without being copied through snapshotPlainData; every entry point still snapshots
 * each member this returns, on its own, through snapshotPlainData, before any other
 * read of that member.
 *
 * Returns the container's own members, in their original order, each read exactly once
 * through its own property descriptor, when `value` is an exact plain array (never a
 * Proxy, at any point this function inspects, including as `value` itself, whose
 * prototype is the Array.prototype of some realm by the same realm-intrinsic identity
 * plainArrayShape() uses, and which carries no own symbol-keyed property) whose length,
 * read once through its own descriptor, is between `minLength` and `maxLength`
 * inclusive: the length bound is checked before any index of `value` is read. Returns
 * null on any other shape, and on any exception raised while inspecting `value`; the
 * caller then gives exactly the result a non-array chain gives.
 */
export function readPlainDataChainContainer(
  value: unknown,
  minLength: number,
  maxLength: number,
): unknown[] | null {
  try {
    if (isProxy(value) || typeof value !== 'object' || value === null) return null
    if (!Array.isArray(value)) return null
    const cache = newPrototypeIntrinsicCache()
    if (!isArrayPrototypeOfSomeRealm(Object.getPrototypeOf(value), cache)) return null
    if (Object.getOwnPropertySymbols(value).length > 0) return null
    const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length')
    const length = lengthDescriptor ? lengthDescriptor.value : undefined
    if (typeof length !== 'number' || !Number.isInteger(length) || length < minLength || length > maxLength) {
      return null
    }
    const names = Object.getOwnPropertyNames(value)
    if (names.length !== length + 1) return null
    const nameSet = new Set(names)
    if (!nameSet.has('length')) return null
    const members: unknown[] = new Array(length)
    for (let i = 0; i < length; i++) {
      const key = String(i)
      if (!nameSet.has(key)) return null // a hole
      const descriptor = Object.getOwnPropertyDescriptor(value, key)
      if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) return null
      members[i] = descriptor.value
    }
    return members
  } catch {
    return null
  }
}
