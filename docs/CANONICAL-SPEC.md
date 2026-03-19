# Canonical Serialization Spec — Agent Passport System

## Version: 1.0 (2026-02-27)
## Status: Required for all cross-agent signature operations

## Problem

Ed25519 signatures are over **exact bytes**. If two implementations serialize
the same JSON object differently (key order, whitespace, null handling), 
signatures produced by one cannot be verified by the other.

This was discovered in the first coordination task (task-mm446e9v-980a2713)
when PortalX2's Python `json.dumps()` produced different bytes than the 
Node.js SDK's `canonicalize()`, making the analysis packet signature 
non-verifiable from disk.

## Canonical Form Rules

All JSON objects MUST be serialized using these rules before signing:

1. **Sort keys alphabetically** (Unicode code point order)
2. **No whitespace** — no spaces after `:` or `,`
3. **Omit null and undefined values** — keys with null/undefined are excluded
4. **Recursive** — nested objects follow the same rules
5. **Arrays preserve order** — array elements are canonicalized but not reordered
6. **Strings use JSON escaping** — standard `JSON.stringify()` escaping
7. **Numbers use JSON format** — no trailing zeros, no leading zeros except `0.x`

## Examples

Input:
```json
{ "z": 1, "a": "hello", "m": null, "b": [3, 1, 2] }
```

Canonical form:
```
{"a":"hello","b":[3,1,2],"z":1}
```

Note: `"m"` is omitted (null value), keys sorted, no whitespace.

## Delegation Canonical Form

All delegations (root and subdelegation) sign the same field set.
The `signature` field is excluded. Fields with `null`/`undefined` values are omitted.

**Root delegation example** (spendLimit set):
```
{"createdAt":"2026-03-18T00:00:00.000Z","currentDepth":0,"delegatedBy":"abc123","delegatedTo":"def456","delegationId":"del_a1b2c3","expiresAt":"2026-03-19T00:00:00.000Z","maxDepth":2,"scope":["search","memory.read","memory.write","analysis"],"spendLimit":1000,"spentAmount":0}
```

**Subdelegation example** (same fields — `parentId` is NOT in the signed payload):
```
{"createdAt":"2026-03-18T01:00:00.000Z","currentDepth":1,"delegatedBy":"def456","delegatedTo":"ghi789","delegationId":"del_d4e5f6","expiresAt":"2026-03-19T00:00:00.000Z","maxDepth":2,"scope":["search","memory.read"],"spendLimit":500,"spentAmount":0}
```

**Key interop notes:**
- `parentId` / `parent_id` is tracked in the chain registry, NOT in the signed object
- If `spendLimit` is `undefined` (not set), it is **omitted entirely** from the canonical form
- `spentAmount` defaults to `0` and IS included (it is not null/undefined)
- `currentDepth` and `maxDepth` are always present (default `0` and `1` respectively)
- Scope array elements are NOT sorted — order is preserved as provided

## Signing Flow

```
1. Construct your data object (e.g., evidence packet)
2. Remove the "signature" field if present
3. Canonicalize the remaining object
4. Sign the canonical string as UTF-8 bytes with Ed25519
5. Hex-encode the 64-byte signature
6. Add "signature" field back to the object
```

## Verification Flow

```
1. Parse the JSON object
2. Extract and remove the "signature" field
3. Canonicalize the remaining object  
4. Verify: Ed25519.verify(canonical_bytes, signature_bytes, public_key_bytes)
```