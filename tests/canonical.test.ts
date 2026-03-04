import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { canonicalize } from '../src/core/canonical.js'

describe('Canonical Serialization — Cross-Language Compatibility', () => {
  // These test vectors MUST match the Python implementation in docs/canonical.py
  // If you change canonicalize(), run the Python tests too.

  it('sorts keys and omits null', () => {
    const input = { z: 1, a: 'hello', m: null, b: [3, 1, 2] }
    assert.equal(canonicalize(input), '{"a":"hello","b":[3,1,2],"z":1}')
  })

  it('handles nested objects recursively', () => {
    const input = { outer: { z: true, a: 1 }, list: [{ b: 2, a: 1 }] }
    assert.equal(canonicalize(input), '{"list":[{"a":1,"b":2}],"outer":{"a":1,"z":true}}')
  })

  it('handles empty containers', () => {
    assert.equal(canonicalize({}), '{}')
    assert.equal(canonicalize([]), '[]')
  })

  it('handles null and undefined', () => {
    assert.equal(canonicalize(null), 'null')
    assert.equal(canonicalize(undefined), 'null')
  })

  it('handles null in arrays (F-PX2-001)', () => {
    // Must produce valid JSON — not '[1,,3]'
    assert.equal(canonicalize([1, null, 3]), '[1,null,3]')
    assert.equal(canonicalize([null]), '[null]')
    assert.equal(canonicalize([null, null]), '[null,null]')
    // Verify the result is parseable JSON
    JSON.parse(canonicalize([1, null, 3]))
  })

  it('handles Date objects (F-PX2-004)', () => {
    const d = new Date('2026-03-01T00:00:00.000Z')
    assert.equal(canonicalize(d), '"2026-03-01T00:00:00.000Z"')
    // Date inside object
    const obj = { date: d, name: 'test' }
    assert.equal(canonicalize(obj), '{"date":"2026-03-01T00:00:00.000Z","name":"test"}')
  })

  it('handles primitives', () => {
    assert.equal(canonicalize('hello'), '"hello"')
    assert.equal(canonicalize(42), '42')
    assert.equal(canonicalize(true), 'true')
    assert.equal(canonicalize(false), 'false')
  })

  it('omits undefined values in objects', () => {
    const input = { a: 1, b: undefined, c: 3 }
    assert.equal(canonicalize(input), '{"a":1,"c":3}')
  })

  it('handles deeply nested structures', () => {
    const input = {
      z: { y: { x: { w: 'deep' } } },
      a: [{ c: 3, a: 1, b: 2 }]
    }
    assert.equal(
      canonicalize(input),
      '{"a":[{"a":1,"b":2,"c":3}],"z":{"y":{"x":{"w":"deep"}}}}'
    )
  })

  it('handles evidence packet structure (real-world)', () => {
    // Simulates signing an evidence packet — the structure that broke cross-lang
    const packet = {
      packetId: 'evid-test-001',
      taskId: 'task-test-001',
      submittedBy: 'abc123',
      claims: [
        { dimension: 'repo', claim: 'test claim', confidence: 'high' }
      ],
      metadata: { sourcesSearched: 3, totalClaims: 1 }
    }
    const canonical = canonicalize(packet)
    
    // Verify determinism
    assert.equal(canonicalize(packet), canonical)
    
    // Verify no whitespace
    assert.ok(!canonical.includes(': '))
    assert.ok(!canonical.includes(', '))
    
    // Verify sorted keys at all levels
    assert.ok(canonical.indexOf('"claims"') < canonical.indexOf('"metadata"'))
    assert.ok(canonical.indexOf('"metadata"') < canonical.indexOf('"packetId"'))
  })

  it('produces no whitespace for any input', () => {
    const complex = {
      arr: [1, 'two', { three: 3 }],
      nested: { deep: { deeper: [true, false, null] } },
      str: 'hello world'
    }
    const result = canonicalize(complex)
    // Only whitespace should be inside string values
    const withoutStrings = result.replace(/"[^"]*"/g, '""')
    assert.ok(!withoutStrings.includes(' '), `Unexpected whitespace: ${withoutStrings}`)
  })
})
