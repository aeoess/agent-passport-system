#!/usr/bin/env python3
# Copyright 2024-2026 Tymofii Pidlisnyi. Apache-2.0 license. See LICENSE.
#
# INDEPENDENT, SDK-FREE conformance runner for the APS Regulated Action Profile v0.
# Pure Python standard library only: a vendored RFC 8032 Ed25519 verify, an RFC 8785
# (JCS) canonicalizer, and a from-scratch reimplementation of the deterministic
# disposition function (RAPV0-FROZEN-CONTRACT.md section B, amended guard order).
# It re-derives crypto_ok / authority / intent / resource / anchor and the 12 guards
# from the same vectors.json the TypeScript verifier consumes, giving a cross-language
# conformance check. judgment_correctness is structurally always not_claimed.
#
# Run: python3 conformance/regulated-action/v0/verify.py

import json, hashlib, os, sys
from datetime import datetime

# ── vendored Ed25519 verify (RFC 8032 reference, public domain) ──
_p = 2 ** 255 - 19
_d = (-121665 * pow(121666, _p - 2, _p)) % _p
_I = pow(2, (_p - 1) // 4, _p)

def _xrecover(y):
    xx = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p) % _p
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = (x * _I) % _p
    if x % 2 != 0:
        x = _p - x
    return x

_By = 4 * pow(5, _p - 2, _p) % _p
_Bx = _xrecover(_By)
_B = (_Bx % _p, _By % _p)

def _edwards(P, Q):
    x1, y1 = P
    x2, y2 = Q
    x3 = (x1 * y2 + x2 * y1) * pow(1 + _d * x1 * x2 * y1 * y2, _p - 2, _p) % _p
    y3 = (y1 * y2 + x1 * x2) * pow(1 - _d * x1 * x2 * y1 * y2, _p - 2, _p) % _p
    return (x3 % _p, y3 % _p)

def _scalarmult(P, e):
    if e == 0:
        return (0, 1)
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q

def _bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1

def _Hint(m):
    h = hashlib.sha512(m).digest()
    return sum(2 ** i * _bit(h, i) for i in range(512))

def _isoncurve(P):
    x, y = P
    return (-x * x + y * y - 1 - _d * x * x * y * y) % _p == 0

def _decodeint(s):
    return sum(2 ** i * _bit(s, i) for i in range(256))

def _decodepoint(s):
    y = sum(2 ** i * _bit(s, i) for i in range(255))
    x = _xrecover(y)
    if x & 1 != _bit(s, 255):
        x = _p - x
    P = (x, y)
    if not _isoncurve(P):
        raise ValueError("point not on curve")
    return P

def ed25519_verify(sig, msg, pk):
    if len(sig) != 64 or len(pk) != 32:
        return False
    try:
        R = _decodepoint(sig[:32])
        A = _decodepoint(pk)
    except Exception:
        return False
    S = _decodeint(sig[32:])
    h = _Hint(sig[:32] + pk + msg)
    return _scalarmult(_B, S) == _edwards(R, _scalarmult(A, h))

# ── RFC 8785 JCS canonicalization (matches src/core/canonical-jcs.ts for this data) ──
def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def jcs_hash(obj):
    return hashlib.sha256(jcs(obj).encode("utf-8")).hexdigest()

def sig_ok(payload, sig_hex, pub_hex):
    if not sig_hex or not pub_hex:
        return False
    if len(pub_hex) != 64 or len(sig_hex) != 128:
        return False
    try:
        return ed25519_verify(bytes.fromhex(sig_hex), payload.encode("utf-8"), bytes.fromhex(pub_hex))
    except Exception:
        return False

def signed_payload(tag, subobj, sig_field):
    copy = {k: v for k, v in subobj.items() if k != sig_field}
    return tag + "." + jcs(copy)

TAG = {
    "actor": "APS-RAPV0-ACTOR", "intent": "APS-RAPV0-INTENT", "policy": "APS-RAPV0-POLICY",
    "resource": "APS-RAPV0-RESOURCE-CONFIRMATION", "authority": "APS-RAPV0-AUTHORITY",
}
RES_VALID_TYPES = {"native_resource_signed", "boundary_attested"}
RES_VALID_STATUS = {"accepted", "settled"}

def iso_ms(s):
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000.0
    except Exception:
        return None

def disposition(receipt, ctx):
    op_reg = ctx.get("operator_domain_registry", {})
    actor = receipt.get("actor_signature", {})
    actor_key = op_reg.get(actor.get("key_id"), {}).get("publicKey")
    crypto_ok = sig_ok(
        signed_payload(TAG["actor"], {"profile": receipt["profile"], "receipt_id": receipt["receipt_id"], "action_class": receipt["action_class"], "key_id": actor.get("key_id")}, "sig"),
        actor.get("sig"), actor_key)

    ic = receipt.get("intent_commitment")
    pd = receipt.get("gateway_policy_decision")
    if ic is not None:
        intent_signer = (pd or {}).get("signer") or ctx.get("gateway_key_id")
        ikey = op_reg.get(intent_signer, {}).get("publicKey") if intent_signer else None
        crypto_ok = crypto_ok and sig_ok(signed_payload(TAG["intent"], ic, "signature"), ic.get("signature"), ikey)
    if pd is not None:
        pkey = op_reg.get(pd.get("signer"), {}).get("publicKey")
        crypto_ok = crypto_ok and sig_ok(signed_payload(TAG["policy"], pd, "signature"), pd.get("signature"), pkey)

    rc = receipt.get("resource_confirmation_ref")
    res_sig_ok = False
    res_independent = False
    if rc is not None:
        rk = ctx.get("registered_resource_keys", {}).get(rc.get("signer_key_id"))
        res_sig_ok = sig_ok(signed_payload(TAG["resource"], rc, "signature"), rc.get("signature"), (rk or {}).get("publicKey"))
        res_independent = bool(rk) and rk.get("registered_by_operator") is False

    ar = receipt.get("authority_ref")
    authority_present = ar is not None
    authority_ok = authority_weak = authority_invalid = False
    authority_basis = None
    if ar is not None:
        claims = {k: v for k, v in ar.items() if k != "assertion_sig"}
        auth_payload = TAG["authority"] + "." + jcs(claims)
        ext = sig_ok(auth_payload, ar.get("assertion_sig"), ctx.get("idp_keyset", {}).get(ar["issuer"]))
        opv = sig_ok(auth_payload, ar.get("assertion_sig"), ctx.get("operator_anchored_idp_copy", {}).get(ar["issuer"]))
        issued = iso_ms(ar["issued_at"]); expires = iso_ms(ar["expires_at"])
        valid_across = issued is not None and expires is not None and issued <= ctx["reserved_ts"] and expires >= ctx["submitted_ts"]
        within = ctx["submitted_ts"] - ctx["reserved_ts"] <= ctx["max_authority_execution_window_ms"]
        fresh = valid_across and within
        authority_ok = ext and fresh
        authority_weak = (not authority_ok) and (not ext) and opv and fresh
        authority_invalid = (not authority_ok) and (not authority_weak)
        authority_basis = "external_idp" if authority_ok else ("operator_anchored_copy_weak" if authority_weak else None)

    intent_ok = False
    if ic is not None:
        recomputed = jcs_hash({
            "action_class": receipt["action_class"], "scope": ic["scope"],
            "authority_assertion_hash": ar["assertion_hash"] if ar else "",
            "decision_basis_root_hash": receipt.get("decision_basis_commitment", {}).get("root_hash", ""),
            "expected_effect_hash": ic["expected_effect_hash"],
        })
        intent_ok = ic.get("created_before_execution") is True and recomputed == ic["intent_hash"]

    policy_allow = bool(pd) and pd.get("decision") == "allow" and pd.get("action_class_assigned") == receipt["action_class"]
    policy_deny = bool(pd) and pd.get("decision") in ("deny", "hold")

    res_present_valid = (rc is not None and rc.get("type") in RES_VALID_TYPES and rc.get("realized_effect_provenance") == "ban_derived"
                         and res_sig_ok and res_independent and rc.get("status") in RES_VALID_STATUS)
    res_matches = (intent_ok and rc is not None and ic is not None
                   and rc.get("gateway_nonce_echo") == ic.get("gateway_nonce")
                   and rc.get("realized_effect_hash") == ic.get("expected_effect_hash"))
    res_ok = res_present_valid and res_matches
    executed = res_present_valid or ctx.get("completeness_match") is True

    anchor_present = False
    tr = receipt.get("transparency_ref")
    if tr is not None:
        root = ctx.get("registered_log_roots", {}).get(tr["log_id"])
        proof_ok = False
        if root:
            acc = tr["leaf_hash"]
            for step in tr["inclusion_proof"]:
                acc = jcs_hash({"l": step["hash"], "r": acc}) if step["dir"] == "L" else jcs_hash({"l": acc, "r": step["hash"]})
            proof_ok = acc == root
        anchor_present = proof_ok and tr.get("anchored_at_state") == "reserved"

    order = ctx.get("anchor_orders_intent_before_resource")
    temporal_violation = anchor_present and order is False
    temporal_consistent = anchor_present and order is True
    noneq_ok = anchor_present and ctx.get("non_equivocation_ok") is not False

    idp_counts = authority_ok
    resource_counts = res_ok and res_independent
    domains = (1 if idp_counts else 0) + (1 if resource_counts else 0)

    op_keys = []
    if actor.get("key_id"):
        op_keys.append(actor["key_id"])
    if pd and pd.get("signer"):
        op_keys.append(pd["signer"])
    if ic is not None:
        isigner = (pd or {}).get("signer") or ctx.get("gateway_key_id")
        if isigner:
            op_keys.append(isigner)
    separation_ok = all(op_reg.get(k, {}).get("identity") == ctx["operator_identity_id"] for k in op_keys)

    req = (ctx.get("per_class_required_fields") or {}).get(receipt["action_class"], [])
    per_class_ok = len(req) > 0 and all(receipt.get(f) is not None for f in req)

    terminal = [
        (not crypto_ok, "void"),
        (policy_deny and executed, "void_policy_violation"),
        (res_present_valid and ic is not None and temporal_violation, "void_temporal_violation"),
        (res_present_valid and intent_ok and not res_matches, "void_reconciliation_mismatch"),
        (res_present_valid and not intent_ok, "resource_unbound"),
        (authority_invalid, "authority_invalid"),
        ((not authority_present) and (not res_present_valid), "self_attested"),
    ]
    violations = [d for held, d in terminal if held]
    reason = None
    first = next((d for held, d in terminal if held), None)
    if first:
        disp = first
    elif authority_ok and intent_ok and policy_allow and res_ok and domains >= 2 and temporal_consistent and noneq_ok and per_class_ok and separation_ok:
        disp = "regulator_grade_for_class"
    elif authority_ok and intent_ok and policy_allow and res_ok and domains >= 2 and temporal_consistent:
        disp = "reconciled"
    elif authority_ok and intent_ok and policy_allow and not res_ok:
        disp = "intent_precommitted"
    elif authority_ok and not intent_ok:
        disp = "authority_bound"
    else:
        disp = "incomplete_for_class"
        if policy_deny:
            reason = "policy_denied_no_execution"
        elif not authority_ok:
            reason = "missing_authority"
        elif not anchor_present:
            reason = "missing_transparency_anchor"
        else:
            reason = "execution_unconfirmed"
    return disp, reason, authority_basis, violations, domains


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    doc = json.load(open(os.path.join(here, "vectors.json"), encoding="utf-8"))
    npass = nfail = 0
    for v in doc["vectors"]:
        if v.get("surface") != "verifier":
            continue
        disp, reason, basis, violations, domains = disposition(v["input_receipt"], v["verification_context"])
        exp = v["expected"]
        ok = (disp == exp["disposition"]
              and (("incomplete_reason" not in exp) or reason == exp["incomplete_reason"])
              and (("authority_basis" not in exp) or basis == exp["authority_basis"]))
        if ok:
            npass += 1
        else:
            nfail += 1
            print(f"FAIL {v['id']}: got {disp}:{reason} basis={basis} want {exp['disposition']}:{exp.get('incomplete_reason')} basis={exp.get('authority_basis')}")
    completeness = sum(1 for v in doc["vectors"] if v.get("surface") == "completeness")
    print(f"verify.py (independent): {npass}/{npass + nfail} verifier vectors pass. {completeness} completeness-surface vectors validated by the gateway.")
    sys.exit(1 if nfail else 0)


if __name__ == "__main__":
    main()
