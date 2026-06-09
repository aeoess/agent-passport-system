#!/usr/bin/env python3
"""Conformance verifier for action_ref v1 (action-ref-v1-jcs-sha256).

Standalone: Python 3 stdlib only. A minimal RFC 8785 (JCS) serializer is
vendored below, scoped to the action_ref preimage domain (a flat JSON object
whose values are all strings). It is an independent recomputation, not a
wrapper around the SDK, so a pass here cross-checks the SDK-pinned hashes in
vectors.json against a second implementation.

Exit 0 on full pass. Nonzero with a per-vector diff on any failure.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

# The exact timestamp grammar from the specification and the SDK
# implementation (src/core/external-action-ref.ts): RFC 3339 UTC, uppercase T
# and Z, exactly three fractional digits.
TIMESTAMP_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$")

PREIMAGE_KEYS = ("action_type", "agent_id", "scope", "timestamp")


def jcs_escape_string(s: str) -> str:
    """Serialize one string per RFC 8785 (ECMA-262 JSON.stringify rules):
    shortest form, two-character escapes for the named controls, \\u00xx for
    the rest of the C0 range, everything else literal."""
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\r":
            out.append("\\r")
        elif cp < 0x20:
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def jcs_canonicalize_flat_strings(obj: dict) -> str:
    """RFC 8785 canonicalization for the action_ref preimage domain: a flat
    object whose values are all strings. Keys are sorted by UTF-16 code units
    (RFC 8785 section 3.2.3); for these preimage keys that equals ASCII
    order, but the comparator is implemented properly anyway."""
    for k, v in obj.items():
        if not isinstance(v, str):
            raise TypeError(f"preimage value for {k!r} must be a string, got {type(v).__name__}")
    keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be"))
    pairs = [f"{jcs_escape_string(k)}:{jcs_escape_string(obj[k])}" for k in keys]
    return "{" + ",".join(pairs) + "}"


def compute_action_ref_v1(preimage: dict) -> str:
    ts = preimage["timestamp"]
    if not TIMESTAMP_RE.match(ts):
        raise ValueError(
            "timestamp must be RFC 3339 UTC with three fractional digits and "
            f"a Z suffix (YYYY-MM-DDTHH:MM:SS.mmmZ), got {ts!r}"
        )
    canonical = jcs_canonicalize_flat_strings(preimage)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def preimage_from_input(inp: dict) -> dict:
    return {k: inp[k] for k in PREIMAGE_KEYS}


def main() -> int:
    vectors_path = Path(__file__).resolve().parent / "vectors.json"
    suite = json.loads(vectors_path.read_text(encoding="utf-8"))
    failures = []
    accepted = rejected = 0

    for vec in suite["vectors"]:
        vid = vec["id"]
        if vec.get("reject"):
            ts = vec["input"]["timestamp"]
            if TIMESTAMP_RE.match(ts):
                failures.append(f"{vid}: timestamp {ts!r} PASSED the grammar but must be rejected ({vec['reason']})")
                continue
            try:
                compute_action_ref_v1(preimage_from_input(vec["input"]))
                failures.append(f"{vid}: compute_action_ref_v1 did not raise on invalid timestamp {ts!r}")
            except ValueError:
                rejected += 1
            continue

        preimage = preimage_from_input(vec["input"])
        canonical = jcs_canonicalize_flat_strings(preimage)
        if "canonical" in vec and canonical != vec["canonical"]:
            failures.append(
                f"{vid}: canonical form mismatch\n  expected: {vec['canonical']}\n  computed: {canonical}"
            )
            continue
        got = compute_action_ref_v1(preimage)
        if got != vec["expected"]:
            failures.append(
                f"{vid}: hash mismatch\n  expected: {vec['expected']}\n  computed: {got}\n  canonical: {canonical}"
            )
            continue
        ok = True
        for i, raw in enumerate(vec.get("input_json_variants", [])):
            variant = json.loads(raw)
            vgot = compute_action_ref_v1(preimage_from_input(variant))
            if vgot != vec["expected"]:
                failures.append(
                    f"{vid}: key-order variant {i} hash mismatch\n  expected: {vec['expected']}\n  computed: {vgot}\n  variant: {raw}"
                )
                ok = False
        if ok:
            accepted += 1

    total = len(suite["vectors"])
    if failures:
        print(f"FAIL: {len(failures)} failure(s) across {total} vectors\n")
        for f in failures:
            print(f"- {f}")
        return 1
    print(f"PASS: {total} vectors ({accepted} accept recomputed byte-identical, {rejected} reject correctly refused)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
