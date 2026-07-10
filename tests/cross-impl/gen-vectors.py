# Copyright (c) 2026 Tymofii Pidlisnyi
# SPDX-License-Identifier: Apache-2.0
"""Generate pinned expected canonical bytes + SHA-256 from rfc8785@0.1.4.

This produces a JSON manifest that the SDK's cross-impl test asserts against
in BOTH TypeScript and Python. The Node-side reference (canonicalize@3.0.0)
must produce byte-identical output; the SDK's strict-JCS impl
(canonicalHashJCS in TS, canonicalize_jcs in Python) must too.
"""
import hashlib
import json
import sys

import rfc8785

VECTORS = [
    {
        "id": "v01-simple",
        "description": "Simple object, no nulls — variants identical (sanity baseline).",
        "input": {"agentId": "agent-001", "scope": "read"},
    },
    {
        "id": "v02-null-preserved",
        "description": "Null value at top level — JCS preserves, legacy strips. Divergence vector.",
        "input": {"agentId": "agent-001", "metadata": None, "scope": "read"},
    },
    {
        "id": "v03-key-order",
        "description": "Keys MUST be sorted by Unicode code point.",
        "input": {"zebra": 1, "alpha": 2, "middle": 3},
    },
    {
        "id": "v04-nested-null",
        "description": "Null at depth inside nested object.",
        "input": {"outer": {"inner": None, "value": 42}, "top": "ok"},
    },
    {
        "id": "v05-array-null",
        "description": "Null elements inside arrays. Both variants preserve array nulls.",
        "input": {"items": [1, None, 3]},
    },
    {
        "id": "v06-numbers",
        "description": "Mixed integer + signed + fractional + zero numeric serialization.",
        "input": {"integer": 42, "negative": -7, "float": 3.14, "zero": 0},
    },
    {
        "id": "v07-empties",
        "description": "Empty object and empty array.",
        "input": {"emptyArr": [], "emptyObj": {}},
    },
    {
        "id": "v08-unicode",
        "description": "Non-ASCII content in keys and values; UTF-8 bytes emitted literally per RFC 8785 §3.2.2.2.",
        "input": {"name": "Тимофій", "emoji": "🔐"},
    },
    {
        "id": "v09-action-ref-tuple",
        "description": "I-D §4.1 action_ref pre-image shape — production-like input.",
        "input": {
            "agentId": "did:aps:z6Mkfoo",
            "actionType": "code_execution",
            "scopeRequired": ["commerce:read", "commerce:write"],
            "timestamp": "2026-05-21T00:00:00Z",
        },
    },
    {
        "id": "v10-attribution-tuple",
        "description": "ATTRIBUTION-PRIMITIVE-v1.1 §1.6 four-tuple shape with null in params.",
        "input": {
            "agentId": "a",
            "actionType": "t",
            "params": {"k": None, "v": 1},
            "nonce": "n0",
        },
    },
    {
        "id": "v11-string-escapes",
        "description": "Tab (U+0009) and newline (U+000A) escapes per RFC 8785 §3.2.2.2.",
        "input": {"raw": "line1\tcol2\nline3"},
    },
    {
        "id": "v12-booleans",
        "description": "Boolean values are serialized as 'true' / 'false'.",
        "input": {"active": True, "revoked": False},
    },
]


def main():
    out = {
        "generator": "rfc8785@0.1.4 (Python)",
        "spec": "RFC 8785 JSON Canonicalization Scheme (JCS)",
        "hash": "SHA-256, lowercase hex",
        "vectors": [],
    }
    for v in VECTORS:
        canon_bytes = rfc8785.dumps(v["input"])
        canon_str = canon_bytes.decode("utf-8") if isinstance(canon_bytes, bytes) else canon_bytes
        digest = hashlib.sha256(canon_str.encode("utf-8")).hexdigest()
        out["vectors"].append({
            "id": v["id"],
            "description": v["description"],
            "input": v["input"],
            "expected_canonical_bytes": canon_str,
            "expected_sha256": digest,
        })
    json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
