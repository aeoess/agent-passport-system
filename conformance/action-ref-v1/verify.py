#!/usr/bin/env python3
"""Conformance verifier for action_ref v1 (action-ref-v1-jcs-sha256).

Standalone: Python 3 stdlib only. A minimal RFC 8785 (JCS) serializer is
vendored below, scoped to the action_ref preimage domain (a flat JSON object
whose values are all strings). It is an independent recomputation, not a
wrapper around the SDK, so a pass here cross-checks the SDK-pinned hashes in
vectors.json against a second implementation.

The profile's input domain is enforced here too (validate_domain below), and a
vector stating its preimage as raw JSON text goes through a duplicate-rejecting
parser (parse_preimage_json), since a duplicate preimage key is
OUT_OF_PROFILE_DOMAIN and plain json.loads would discard the evidence.

Every rejection raised here names OUT_OF_PROFILE_DOMAIN, matching the SDK
implementation: one marker for every domain failure, so a caller never has to
pattern-match prose to tell "outside the profile" from any other error.

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
            raise TypeError(
                f"OUT_OF_PROFILE_DOMAIN: preimage value for {k!r} must be a string, "
                f"got {type(v).__name__}"
            )
    keys = sorted(obj.keys(), key=lambda k: k.encode("utf-16-be"))
    pairs = [f"{jcs_escape_string(k)}:{jcs_escape_string(obj[k])}" for k in keys]
    return "{" + ",".join(pairs) + "}"


def validate_domain(preimage: dict) -> None:
    """Enforce the profile's input domain before any digest is computed.

    The Domain paragraph of giskard09/argentum-core docs/spec/action-ref.md
    (commit 6ceecf5442fb9a573fdc87a0559755437a7f379f) pins one
    closed input domain and requires a verifier to return
    OUT_OF_PROFILE_DOMAIN and stop, never to canonicalize an
    out-of-domain preimage by best effort: agent_id, action_type and scope are
    ASCII only (every code point <= 0x7F, which also subsumes surrogate pairs
    and closes the NFC/NFD ambiguity), and scope is non-empty (the ""
    not-applicable exception was removed on 2026-08-15 to match
    draft-etcheverry-action-ref-02 section 6). Field order matches the
    reference validator's _validate_domain.
    """
    for key in ("agent_id", "action_type", "scope"):
        value = preimage[key]
        if not isinstance(value, str):
            raise TypeError(f"OUT_OF_PROFILE_DOMAIN: {key} must be a string, got {type(value).__name__}")
        if not value.isascii():
            raise ValueError(f"OUT_OF_PROFILE_DOMAIN: {key} carries a non-ASCII code point: {value!r}")
    if preimage["scope"] == "":
        raise ValueError(
            'OUT_OF_PROFILE_DOMAIN: scope must be a non-empty string -- no "not applicable" exception'
        )


def parse_preimage_json(raw: str) -> dict:
    """Parse a raw preimage document, rejecting a duplicate preimage key.

    A duplicate key is OUT_OF_PROFILE_DOMAIN, and the fact only exists in the
    bytes: plain json.loads keeps the last occurrence, so by the time there is
    a dict to validate the evidence is gone. The object_pairs_hook sees every
    pair, and its keys are already JSON-decoded, so a plain "scope" and a
    "scope" written with an escaped s are the same name and collide.
    """

    def reject_duplicates(pairs):
        members: dict = {}
        for key, value in pairs:
            if key in members:
                raise ValueError(f"OUT_OF_PROFILE_DOMAIN: duplicate preimage key {key!r}")
            members[key] = value
        return members

    parsed = json.loads(raw, object_pairs_hook=reject_duplicates)
    if not isinstance(parsed, dict):
        raise ValueError(
            f"OUT_OF_PROFILE_DOMAIN: the preimage must be a JSON object, got {type(parsed).__name__}"
        )
    missing = [k for k in PREIMAGE_KEYS if k not in parsed]
    if missing:
        raise ValueError(
            f"OUT_OF_PROFILE_DOMAIN: preimage is missing required field(s): {', '.join(missing)}"
        )
    return {k: parsed[k] for k in PREIMAGE_KEYS}


def compute_action_ref_v1(preimage: dict) -> str:
    validate_domain(preimage)
    ts = preimage["timestamp"]
    if not isinstance(ts, str) or not TIMESTAMP_RE.match(ts):
        raise ValueError(
            "OUT_OF_PROFILE_DOMAIN: timestamp must be RFC 3339 UTC with three "
            f"fractional digits and a Z suffix (YYYY-MM-DDTHH:MM:SS.mmmZ), got {ts!r}"
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
            # The parse is inside the try on purpose: for an input_json vector
            # the rejection belongs to the parser (a duplicate preimage key),
            # and it is still a correct refusal before any digest.
            try:
                if "input_json" in vec:
                    preimage = parse_preimage_json(vec["input_json"])
                else:
                    preimage = preimage_from_input(vec["input"])
                compute_action_ref_v1(preimage)
            except (ValueError, TypeError, KeyError):
                rejected += 1
            else:
                failures.append(
                    f"{vid}: compute_action_ref_v1 ACCEPTED a preimage that must be refused ({vec['reason']})"
                )
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
            vgot = compute_action_ref_v1(parse_preimage_json(raw))
            if vgot != vec["expected"]:
                failures.append(
                    f"{vid}: key-order variant {i} hash mismatch\n  expected: {vec['expected']}\n  computed: {vgot}\n  variant: {raw}"
                )
                ok = False
        if ok:
            accepted += 1

    total = len(suite["vectors"])
    # Surface the conformance verification_mode tally (enforced vs asserted).
    # Default to enforced when a vector omits the field (backward compatible).
    mode_counts: dict = {}
    for vec in suite["vectors"]:
        m = vec.get("verification_mode", "enforced")
        mode_counts[m] = mode_counts.get(m, 0) + 1
    mode_summary = ", ".join(f"{m}={c}" for m, c in sorted(mode_counts.items()))
    if failures:
        print(f"FAIL: {len(failures)} failure(s) across {total} vectors\n")
        for f in failures:
            print(f"- {f}")
        return 1
    print(f"PASS: {total} vectors ({accepted} accept recomputed byte-identical, {rejected} reject correctly refused) | verification_mode: {mode_summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
