// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0

import { types } from 'node:util'

/** Function.prototype.toString captured when this module loaded. isIntrinsicPrototype()
 *  below calls this reference rather than a candidate function's own toString, so a
 *  constructor that overrides its own toString, or a script that replaces
 *  Function.prototype.toString after this module has loaded, cannot make a forged
 *  constructor read back as native code. That is all capturing it defends against: a
 *  script that replaces some other built-in after load, Function.prototype.call among
 *  them, is the modified-process case the doc comment below places outside what this
 *  module can defend. */
const functionToString = Function.prototype.toString

/** JSON.isRawJSON where the runtime has it. A runtime without it has no JSON.rawJSON
 *  either, so no raw JSON object can exist there and the answer is always false. */
const isRawJSON: (value: object) => boolean =
  typeof (JSON as unknown as { isRawJSON?: unknown }).isRawJSON === 'function'
    ? (JSON as unknown as { isRawJSON: (value: object) => boolean }).isRawJSON
    : () => false

/**
 * Plain-JSON-data snapshot shared by the authority-delegation entry points named below.
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
 * Array.prototype of some JavaScript realm, whose length is a non-negative integer read
 * from its own descriptor, every index 0 through length-1 of which is an enumerable data
 * property, no hole and no accessor, and which carries neither an own symbol-keyed
 * property nor an own callable "toJSON" or "toJSON" accessor. An own property of an array that is neither an
 * index nor "length" is left out of the snapshot rather than refused: JSON.stringify
 * serializes an array by its length and its indices, so such a property is invisible to
 * the JSON form as well. The one own name that can change that form is "toJSON", which
 * JSON.stringify calls in place of serializing the members when it is callable, so an
 * own callable "toJSON", and an own "toJSON" accessor, whose getter this module must not
 * call and which could return a callable, are refused; an own "toJSON" holding any other
 * value is data JSON.stringify ignores on an array, and the snapshot ignores it too. Refusing the others instead would mean enumerating the array's own property
 * names, which this engine cannot do at 2**23 members or more. A read of the caller's
 * own array still shows such a property, directly, or through
 * Object.getOwnPropertyNames, or, when it is enumerable, through Object.keys, for-in or
 * object spread; the snapshot, the validated content, the signed bytes and
 * JSON.stringify do not.
 *
 * An object's own property names are enumerated, because every one of them is copied,
 * and an object is the one input shape this module cannot judge at every size: this
 * engine returns at most 2**23 own property names and throws RangeError beyond that, so
 * an object with 2**23 + 1 or more own members is not plain data here, where the Python
 * SDK judges the same object by its content. What that costs is one extra failure code
 * on a record the v1 body schema does not judge: a record whose version is unknown and
 * which carries such an object is SCHEMA_INVALID and UNSUPPORTED_VERSION here and
 * UNSUPPORTED_VERSION there, and neither SDK reports it valid. A record the v1 schema
 * does judge is SCHEMA_INVALID in both, since a member holding that object is not a
 * member of the closed schema. An object with exactly 2**23 own members is fine, and so
 * is an array of any length, since an array's names are no longer enumerated. Reading
 * the names of only the enumerable members would lift that ceiling, but it would also
 * stop this module from refusing an own non-enumerable member, which a JSON serializer
 * drops silently. Whether an implementation may impose a record-size limit, and with
 * which result state, is not something the draft states, so the ceiling is recorded here
 * and left as it is, pending a protocol ruling, rather than answered with a rule of this
 * module's own.
 *
 * An exact plain object is a non-array, non-Proxy object whose
 * prototype is null, or whose prototype is the Object.prototype of some realm, which
 * holds no primitive value of its own (it is not a Boolean, Number, String, BigInt or
 * Symbol wrapper object, as node:util's types.isBoxedPrimitive decides) and is not a
 * JSON.rawJSON object (as JSON.isRawJSON decides, where the runtime has it), every own
 * string-keyed property of which is an enumerable data property, and which carries no
 * own symbol-keyed property either: a symbol such as Symbol.iterator changes what
 * JavaScript code reads from the value, even though JSON.parse never produces one.
 * No JSON parser produces a wrapper object or a raw JSON object, so neither is JSON
 * data to begin with. For four of the five wrapper kinds the two views also disagree:
 * JSON.stringify serializes a Boolean, Number, String or BigInt wrapper by the primitive
 * it holds, or throws, and a raw JSON object by its raw text, never by its own members,
 * so such a value would otherwise be validated, hashed and signed by members that
 * JSON.stringify never shows the caller. A Symbol wrapper has no such case in
 * JSON.stringify and does serialize by its own members; it is refused with the others
 * because it is still not a value a JSON parser can produce.
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
 * A realm whose own Object.prototype or Array.prototype has itself been modified, by
 * adding members to it or by changing its own [[Prototype]], is outside what this
 * module defends: that intrinsic is still identified as itself, but JSON.stringify in
 * that realm no longer serializes plain data by its own members alone, and a value from
 * such a realm may be accepted or refused. The same holds for a process whose
 * built-ins, such as Function.prototype.call, Object.getOwnPropertyDescriptor or
 * node:util's types, are replaced after this module loads: a check running inside that
 * process cannot defend against the process itself.
 *
 * snapshotPlainData() reads every property of its argument exactly once, through
 * Object.getOwnPropertyDescriptor, never through ordinary property access, and never
 * calls a getter or a Proxy "get" trap. It copies plain values into fresh plain arrays
 * and objects and puts NOT_PLAIN_DATA in place of anything that is not plain, including
 * a container found on its own current path. isIJSONValue() in schema.ts already treats
 * any value of type symbol as not I-JSON, so the record-wide I-JSON walk rejects the
 * marker with no change of its own. A top-level argument that is a plain scalar is
 * returned as it is; for any other top-level argument that is not a plain object or
 * plain array, the marker is the whole snapshot. Any exception raised while
 * one value is inspected, a throwing Proxy trap among them, makes that one value
 * NOT_PLAIN_DATA rather than an exception out of the walk, so an exception never
 * escapes any authority-delegation entry point on this account.
 *
 * The walk keeps an explicit stack instead of recursing, so pathological nesting depth
 * in an attacker-supplied argument cannot overflow the call stack. That stack holds one
 * frame per container on the current path, never one entry per member: each frame keeps
 * its container, the copy standing in for it, and the cursor of the member being copied,
 * and each member's descriptor is read only when the cursor reaches it and is dropped
 * once its value has been copied. What the walk needs at any moment is therefore the
 * snapshot it is building plus the depth of the input, not a task and a descriptor per
 * decoded member: a 28 MB decoded record used to exhaust the heap and abort the process
 * where the same record now verifies. One consequence of reading a member's descriptor
 * only when the cursor reaches it: a container whose last member is the one that is not
 * an enumerable data property has already had every member before it copied when that is
 * found, and those copies stay in the map below for the rest of the call. The refusal
 * therefore costs what the accepted part of that container costs, rather than nothing,
 * on input no JSON parser can produce, since a hole, an accessor and a non-enumerable
 * member all come from a caller building the value by hand. It also keeps a map
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
 * Each entry point named below calls this on each record argument, before any other
 * read of that argument, and every later read in that entry point, including a read
 * passed on to a caller-supplied callback, must come from the returned snapshot rather
 * than from the original value, so a getter or a Proxy trap can never be read a second
 * time with a different answer. validateAuthorityDelegationShape snapshots its own
 * argument too, so a record another entry point has already snapshotted is copied a
 * second time; that second copy reads only plain data and changes nothing but the work
 * done.
 *
 * The entry points that snapshot this way are validateAuthorityDelegationShape (and
 * isAuthorityDelegationV1, which calls it), verifyAuthorityDelegationChain (and
 * verifyAuthorityDelegation, which calls it with a one-record chain),
 * InMemoryAuthorityBudgetLedger.reserve, issueAuthorityDelegation, and
 * issueSubAuthorityDelegation. The raw canonical helpers computeAuthorityDelegationId,
 * computeAuthorityDelegationIdForWrite, signAuthorityDelegation,
 * verifyAuthorityDelegationSignature, authorityDelegationBody, and the id and signature
 * input builders (authorityDelegationIdInput, authorityDelegationIdInputForWrite, and
 * authorityDelegationSignatureInput) do not snapshot. The entry points above call them
 * only with a value they have already snapshotted, or a value assembled from one. Several
 * of them are also exported from the package root, and a caller who calls one directly
 * passes its own value, which is then read through ordinary property access, getters
 * and Proxy traps included, exactly as given: these helpers compute or check the id or
 * signature of whatever value they receive and make no plain-data decision of their
 * own.
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

/** Checks `value`'s prototype, its own symbols, its own "toJSON" descriptor and its
 *  length, each read exactly once, and returns its length. Returns null when `value` is
 *  not an exact plain array: wrong prototype, an own symbol-keyed property, an own
 *  callable "toJSON" or "toJSON" accessor, or a length that is not a
 *  non-negative integer. Each index is checked as the walk below reaches it: it must be
 *  an own enumerable data property, so a hole, an accessor or a non-enumerable index
 *  makes the array not plain data. An own property that is neither an index nor "length"
 *  is left out of the snapshot rather than refused, which is what a JSON serializer does
 *  with it too.
 *
 *  This never enumerates the array's own property names. Object.getOwnPropertyNames and
 *  Object.getOwnPropertyDescriptors throw RangeError("Too many properties to enumerate")
 *  on an array of 2**23 members or more, whose names are its indices plus "length", and
 *  that exception, caught by the walk below,
 *  used to turn a correctly signed record that the Python SDK verifies valid into
 *  SCHEMA_INVALID. Callers pass only values for which Array.isArray(value) is already
 *  true and isProxy(value) is already false. */
function plainArrayLength(value: object, cache: PrototypeIntrinsicCache): number | null {
  if (!isArrayPrototypeOfSomeRealm(Object.getPrototypeOf(value), cache)) return null
  if (Object.getOwnPropertySymbols(value).length > 0) return null
  // The one own named property that can change what JSON.stringify reads from an array.
  // JSON.stringify gets "toJSON" and calls it in place of serializing the members when
  // it is callable, so an own callable toJSON, and an own accessor, whose getter this
  // module must not call and which could return one, make the array not plain data. An
  // own toJSON holding any other value is data JSON.stringify ignores, exactly like any
  // other own named property of an array.
  const toJSONDescriptor = Object.getOwnPropertyDescriptor(value, 'toJSON')
  if (toJSONDescriptor && (!('value' in toJSONDescriptor) || typeof toJSONDescriptor.value === 'function')) return null
  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, 'length')
  const length = lengthDescriptor ? lengthDescriptor.value : undefined
  if (typeof length !== 'number' || !Number.isInteger(length) || length < 0) return null
  return length
}

/** Returns `value`'s own string-keyed property names, read exactly once. Returns null
 *  when `value` is not an exact plain object: a wrapper object holding a primitive, a
 *  raw JSON object, wrong prototype, or an own symbol-keyed property. Each named
 *  property is checked as the walk below reaches it: it must be an enumerable data
 *  property, so an accessor or a non-enumerable member makes the object not plain data.
 *  Object.getOwnPropertyNames throws RangeError("Too many properties to enumerate") when
 *  it would return more than 2**23 names, so at 2**23 + 1 or more own properties, and
 *  the walk below turns that into the marker: see the module doc comment. Callers pass only values for which Array.isArray(value) is
 *  already false and isProxy(value) is already false. */
function plainObjectKeys(value: object, cache: PrototypeIntrinsicCache): string[] | null {
  if (types.isBoxedPrimitive(value) || isRawJSON(value)) return null
  if (!isPlainObjectPrototype(Object.getPrototypeOf(value), cache)) return null
  if (Object.getOwnPropertySymbols(value).length > 0) return null
  return Object.getOwnPropertyNames(value)
}

/** One container the walk below has entered and not yet left: its source, the copy
 *  standing in for it in the snapshot, and the cursor of the member being copied. The
 *  walk holds one of these per level of the current path, never one per member, so the
 *  memory it needs is bounded by the snapshot it is building plus the depth of the
 *  input, not by the input's member count. */
interface ArrayFrame {
  kind: 'array'
  source: object
  copy: unknown[]
  length: number
  index: number
}

interface ObjectFrame {
  kind: 'object'
  source: object
  copy: Record<string, unknown>
  keys: string[]
  index: number
}

type Frame = ArrayFrame | ObjectFrame

/**
 * Deep snapshot of `root` under the plain-JSON-data rule documented above. Each entry
 * point named in that doc comment calls this on each record argument, before any other
 * read of that argument, and runs all later logic on the snapshot only.
 */
export function snapshotPlainData(root: unknown): unknown {
  let output: unknown
  // Every container the walk has entered and not yet left, by object identity: a
  // container reached again while it is still here contains itself and is a cycle.
  const onPath = new Set<object>()
  // Every container this walk has already finished, or already rejected for its own
  // shape, keyed by its object identity: see the doc comment above. Never consulted for
  // a container still on the current path, since the cycle check above it runs first.
  const done = new Map<object, unknown>()
  // Realm-intrinsic prototype verdicts already computed during this one call: see
  // PrototypeIntrinsicCache above.
  const prototypeCache = newPrototypeIntrinsicCache()
  const frames: Frame[] = []

  /** Puts one finished value in the member slot the innermost open container is at, or
   *  makes it the whole snapshot when no container is open. */
  const place = (result: unknown): void => {
    if (frames.length === 0) {
      output = result
      return
    }
    const frame = frames[frames.length - 1]
    if (frame.kind === 'array') {
      frame.copy[frame.index] = result
      return
    }
    // defineProperty, not assignment: assigning to a member named "__proto__" would set
    // the copy's prototype instead of creating the member, and the member would silently
    // disappear from the snapshot.
    Object.defineProperty(frame.copy, frame.keys[frame.index], {
      value: result,
      writable: true,
      enumerable: true,
      configurable: true,
    })
  }

  /** Rejects the innermost open container, once one of its members turns out not to be
   *  an enumerable data property or cannot be read at all. Its copy has already been put
   *  in its own parent's slot and in the memo, and both are replaced by the marker. No
   *  other reference can be holding that copy: a second reference reached while this
   *  container is open is a cycle, and the memo is only read for containers that have
   *  already been left. */
  const rejectOpenContainer = (): void => {
    const frame = frames.pop()!
    onPath.delete(frame.source)
    done.set(frame.source, NOT_PLAIN_DATA)
    place(NOT_PLAIN_DATA)
  }

  let member: unknown = root
  let hasMember = true
  while (hasMember) {
    try {
      if (isPlainScalar(member)) {
        place(member)
      } else if (isProxy(member)) {
        place(NOT_PLAIN_DATA) // a Proxy, including a revoked one, is never plain data
      } else if (typeof member !== 'object' || member === null) {
        place(NOT_PLAIN_DATA) // undefined, bigint, function, symbol, or a non-finite number
      } else if (onPath.has(member)) {
        place(NOT_PLAIN_DATA) // a container on its own current path: a cycle
      } else if (done.has(member)) {
        place(done.get(member)) // reached again, off its own path: reuse the result already found
      } else if (Array.isArray(member)) {
        const length = plainArrayLength(member, prototypeCache)
        if (length === null) {
          done.set(member, NOT_PLAIN_DATA)
          place(NOT_PLAIN_DATA)
        } else {
          // Not new Array(length): a declared length is the caller's number, not a count
          // of members this walk has seen, and an array carrying one member at index
          // 30,000,000 would otherwise cost that whole length before index 0 is read.
          // Filling from index 0 upward gives the copy exactly the length its members
          // reach, which for an array that is plain data is that same length.
          const copy: unknown[] = []
          done.set(member, copy)
          place(copy)
          onPath.add(member)
          frames.push({ kind: 'array', source: member, copy, length, index: -1 })
        }
      } else {
        const keys = plainObjectKeys(member, prototypeCache)
        if (keys === null) {
          done.set(member, NOT_PLAIN_DATA)
          place(NOT_PLAIN_DATA)
        } else {
          const copy: Record<string, unknown> = {}
          done.set(member, copy)
          place(copy)
          onPath.add(member)
          frames.push({ kind: 'object', source: member, copy, keys, index: -1 })
        }
      }
    } catch {
      // Any exception raised while this one value was inspected, a throwing Proxy trap
      // among them, makes this value NOT_PLAIN_DATA rather than an exception out of the
      // walk.
      place(NOT_PLAIN_DATA)
    }

    // Move to the next member of the innermost open container, leaving containers whose
    // members are all copied. Members are read, and placed, in their original order, so
    // the snapshot serializes exactly as the original would.
    hasMember = false
    while (frames.length > 0) {
      const frame = frames[frames.length - 1]
      const next = frame.index + 1
      if (next >= (frame.kind === 'array' ? frame.length : frame.keys.length)) {
        onPath.delete(frame.source)
        frames.pop()
        continue
      }
      frame.index = next
      let descriptor: PropertyDescriptor | undefined
      try {
        descriptor = Object.getOwnPropertyDescriptor(
          frame.source,
          frame.kind === 'array' ? String(next) : frame.keys[next],
        )
      } catch {
        descriptor = undefined
      }
      if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) {
        // a hole, an accessor, or a non-enumerable member
        rejectOpenContainer()
        continue
      }
      member = descriptor.value
      hasMember = true
      break
    }
  }
  return output
}

/**
 * Checked, descriptor-only read of a chain container: the argument to
 * verifyAuthorityDelegationChain and to InMemoryAuthorityBudgetLedger.reserve. The
 * container itself is not record content, so it is checked for shape and read here
 * without being copied through snapshotPlainData; both of those entry points still
 * snapshot each member this returns, on its own, through snapshotPlainData, before any
 * other read of that member.
 *
 * Returns the container's own members, in their original order, each read exactly once
 * through its own property descriptor, when `value` is an exact plain array by the same
 * rule plainArrayLength() applies to an array inside a record: never a Proxy, at any
 * point this function inspects, including as `value` itself; its prototype is the
 * Array.prototype of some realm by the same realm-intrinsic identity; it carries no own
 * symbol-keyed property and no own callable or accessor "toJSON"; its length, read once
 * through its own descriptor, is between `minLength` and `maxLength` inclusive, and that
 * bound is checked before any index of `value` is read; and every index is an own
 * enumerable data property. An own property that is neither an index nor "length" is
 * ignored here as it is left out of the snapshot there. Returns null on any other shape,
 * and on any exception raised while inspecting `value`; the caller then gives exactly
 * the result a non-array chain gives.
 */
export function readPlainDataChainContainer(
  value: unknown,
  minLength: number,
  maxLength: number,
): unknown[] | null {
  try {
    if (isProxy(value) || typeof value !== 'object' || value === null) return null
    if (!Array.isArray(value)) return null
    const length = plainArrayLength(value, newPrototypeIntrinsicCache())
    if (length === null || length < minLength || length > maxLength) return null
    const members: unknown[] = new Array(length)
    for (let i = 0; i < length; i++) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(i))
      if (!descriptor || !('value' in descriptor) || descriptor.enumerable !== true) return null // a hole, an accessor, or a non-enumerable index
      members[i] = descriptor.value
    }
    return members
  } catch {
    return null
  }
}
