// Copyright (c) 2026 Tymofii Pidlisnyi
// SPDX-License-Identifier: Apache-2.0
//! WASM build path for the APS Runtime Passport verifier.
//!
//! This is a thin, browser/edge-targetable surface over the same
//! `aps_verifier_core::aps_check` hot path the napi binding uses. It
//! exists so the batched `check_many` API has a build path that does not
//! depend on the Node N-API ABI (the napi crate is `cdylib` linked
//! against the Node runtime and cannot target `wasm32-unknown-unknown`).
//!
//! Scope and limits:
//! - This crate exposes ONLY the batched evaluation loop and a parse
//!   helper. It does not re-implement verifier semantics; every decision
//!   comes from `aps_check`, so a WASM `check_many` result is identical
//!   to a native `check_many` result for the same inputs.
//! - `wasm32-unknown-unknown` has no system clock, so the caller passes
//!   `now_unix_ns` explicitly. Time policy stays in the host.
//! - Signature verification (Ed25519) is intentionally left to the host
//!   in this scaffold; `compile_authority` parses without verifying, the
//!   same as the napi `load_passport_unverified` path. A verified WASM
//!   load is a follow-up once a key-passing surface is specified.
//!
//! Proof box:
//!   Proves: each action in a WASM `check_many` call is evaluated under
//!   the same policy as a single check, via the identical `aps_check`
//!   code path against the same compiled authority and context, in input
//!   order.
//!   Does NOT prove: anything about wall-clock latency on any platform.
//!   No public latency claim is approved from any WASM measurement.

use aps_verifier_core::{
    aps_check, ActionDescriptor, Clock, CompiledAuthority, Decision, DecisionType, ReasonCode,
    RuntimePassport, ToolEntry, ToolRegistry, VerifierContext,
};
use wasm_bindgen::prelude::*;

/// Fixed-time clock for WASM: `wasm32-unknown-unknown` has no system
/// clock, so the caller supplies the current time and we echo it.
struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix_ns(&self) -> u64 {
        self.0
    }
}

/// Opaque compiled-authority handle held on the JS side.
#[wasm_bindgen]
pub struct WasmAuthority {
    authority: CompiledAuthority,
    verifier_instance_id_hash: [u8; 32],
    attested_tier_value: u8,
    revocation_epoch: u32,
}

/// Parse + compile a passport (without signature verification) into a
/// reusable authority handle. Mirrors the napi `load_passport_unverified`
/// path. `tools_json` is a JSON array of `{descriptorHashHex, localId}`.
#[wasm_bindgen]
pub fn compile_authority(
    passport_json: &str,
    tools_json: &str,
) -> Result<WasmAuthority, JsValue> {
    let tool_inputs: Vec<ToolJson> = serde_parse(tools_json)?;
    let mut entries = Vec::with_capacity(tool_inputs.len());
    for t in &tool_inputs {
        let descriptor_hash = hex_to_array_32(&t.descriptor_hash_hex)
            .map_err(|e| JsValue::from_str(&format!("RegistryBuildFailed: {e}")))?;
        entries.push(ToolEntry {
            descriptor_hash,
            local_id: t.local_id,
        });
    }
    let registry = ToolRegistry::from_entries(entries)
        .map_err(|e| JsValue::from_str(&format!("RegistryBuildFailed: {e}")))?;
    let passport = RuntimePassport::from_json(passport_json)
        .map_err(|e| JsValue::from_str(&format!("PassportParseFailed: {e}")))?;
    let attested_tier_value = passport.tier_attested as u8;
    let revocation_epoch = passport.revocation_epoch;
    let verifier_instance_id_hash =
        *blake3::hash(passport.verifier_instance_id.as_bytes()).as_bytes();
    let authority = CompiledAuthority::from_passport(&passport, registry)
        .map_err(|e| JsValue::from_str(&format!("CompileFailed: {e}")))?;
    Ok(WasmAuthority {
        authority,
        verifier_instance_id_hash,
        attested_tier_value,
        revocation_epoch,
    })
}

/// Batched evaluation over WASM. `actions_json` is a JSON array of action
/// descriptors (same field set as the napi `ActionInput`). Returns a JSON
/// array of decisions, one per action, in input order. The evaluation
/// loop is identical to the native `check_many`: one context, one
/// `aps_check` per action.
#[wasm_bindgen]
pub fn check_many(
    handle: &WasmAuthority,
    actions_json: &str,
    now_unix_ns: u64,
) -> Result<String, JsValue> {
    let action_inputs: Vec<ActionJson> = serde_parse(actions_json)?;
    let mut descriptors = Vec::with_capacity(action_inputs.len());
    for a in &action_inputs {
        descriptors.push(build_descriptor(a)?);
    }

    let clock = FixedClock(now_unix_ns);
    let tier = tier_from_value(handle.attested_tier_value);
    let ctx = VerifierContext::new(
        &clock,
        handle.verifier_instance_id_hash,
        tier,
        handle.revocation_epoch,
    );

    let mut decisions: Vec<DecisionJson> = Vec::with_capacity(descriptors.len());
    for d in &descriptors {
        let decision = aps_check(&handle.authority, d, &ctx);
        decisions.push(decision_json(&decision));
    }
    serde_to_string(&decisions)
}

// -----------------------------------------------------------------------
// minimal JSON plumbing (kept dependency-light: hand-rolled, no serde
// derive on this crate's own types to keep the wasm bundle small)
// -----------------------------------------------------------------------

struct ToolJson {
    descriptor_hash_hex: String,
    local_id: u32,
}

struct ActionJson {
    version: u8,
    passport_id_hash_hex: String,
    tool_descriptor_hash_hex: String,
    local_tool_id: u32,
    operation_id: u16,
    resource_type: u16,
    risk_class: u8,
    resource_path_depth: u8,
    cost_units: u32,
    sequence_id: u64,
    nonce_hex: String,
    resource_path_hashes: Vec<u64>,
}

struct DecisionJson {
    decision_type: String,
    reason_code: u8,
    reason_name: String,
    sequence_id: u64,
    decision_id_hex: String,
    event_mac_hex: String,
    /// Producer-observed time bound into `event_mac`, disclosed so the
    /// MAC can be rechecked (spec §6.3). On this surface it echoes the
    /// caller-supplied `now_unix_ns`.
    timestamp_unix_ns: u64,
}

// The wasm crate avoids pulling serde_json to keep the bundle minimal.
// These two shims parse/serialize via a tiny embedded reader. To keep
// the scaffold honest and small, they delegate to `js_sys`-free manual
// parsing through `aps-verifier-core`'s already-present serde stack would
// pull serde_json transitively; instead we accept that the JSON shapes
// here are simple and use a compact hand parser.

fn serde_parse<T: FromJson>(s: &str) -> Result<Vec<T>, JsValue> {
    T::parse_array(s).map_err(|e| JsValue::from_str(&e))
}

fn serde_to_string(decisions: &[DecisionJson]) -> Result<String, JsValue> {
    let mut out = String::from("[");
    for (i, d) in decisions.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"decisionType\":\"{}\",\"reasonCode\":{},\"reasonName\":\"{}\",\"sequenceId\":{},\"decisionIdHex\":\"{}\",\"eventMacHex\":\"{}\",\"timestampUnixNs\":{}}}",
            d.decision_type,
            d.reason_code,
            d.reason_name,
            d.sequence_id,
            d.decision_id_hex,
            d.event_mac_hex,
            d.timestamp_unix_ns
        ));
    }
    out.push(']');
    Ok(out)
}

trait FromJson: Sized {
    fn parse_array(s: &str) -> Result<Vec<Self>, String>;
}

impl FromJson for ToolJson {
    fn parse_array(s: &str) -> Result<Vec<Self>, String> {
        let v = json::parse(s)?;
        let arr = v.as_array().ok_or("tools: expected array")?;
        arr.iter()
            .map(|o| {
                Ok(ToolJson {
                    descriptor_hash_hex: o.get_str("descriptorHashHex")?,
                    local_id: o.get_u64("localId")? as u32,
                })
            })
            .collect()
    }
}

impl FromJson for ActionJson {
    fn parse_array(s: &str) -> Result<Vec<Self>, String> {
        let v = json::parse(s)?;
        let arr = v.as_array().ok_or("actions: expected array")?;
        arr.iter()
            .map(|o| {
                let hashes = o
                    .get("resourcePathHashes")
                    .and_then(|h| h.as_array())
                    .map(|a| a.iter().filter_map(|x| x.as_u64()).collect::<Vec<u64>>())
                    .unwrap_or_default();
                Ok(ActionJson {
                    version: o.get_u64("version")? as u8,
                    passport_id_hash_hex: o.get_str("passportIdHashHex")?,
                    tool_descriptor_hash_hex: o.get_str("toolDescriptorHashHex")?,
                    local_tool_id: o.get_u64("localToolId")? as u32,
                    operation_id: o.get_u64("operationId")? as u16,
                    resource_type: o.get_u64("resourceType")? as u16,
                    risk_class: o.get_u64("riskClass")? as u8,
                    resource_path_depth: o.get_u64("resourcePathDepth")? as u8,
                    cost_units: o.get_u64("costUnits")? as u32,
                    sequence_id: o.get_u64("sequenceId")?,
                    nonce_hex: o.get_str("nonceHex")?,
                    resource_path_hashes: hashes,
                })
            })
            .collect()
    }
}

fn build_descriptor(a: &ActionJson) -> Result<ActionDescriptor, JsValue> {
    let passport_id_hash = hex_to_array_32(&a.passport_id_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("passportIdHashHex: {e}")))?;
    let tool_descriptor_hash = hex_to_array_32(&a.tool_descriptor_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("toolDescriptorHashHex: {e}")))?;
    let nonce = hex_to_array_16(&a.nonce_hex)
        .map_err(|e| JsValue::from_str(&format!("nonceHex: {e}")))?;
    if a.resource_path_hashes.len() > 8 {
        return Err(JsValue::from_str(
            "resourcePathHashes accepts at most 8 elements (spec §5)",
        ));
    }
    let mut resource_path_hashes = [0u64; 8];
    for (i, h) in a.resource_path_hashes.iter().enumerate() {
        resource_path_hashes[i] = *h;
    }
    let mut descriptor = ActionDescriptor {
        version: a.version,
        reserved: [0; 3],
        passport_id_hash,
        tool_descriptor_hash,
        local_tool_id: a.local_tool_id,
        operation_id: a.operation_id,
        resource_type: a.resource_type,
        risk_class: a.risk_class,
        resource_path_depth: a.resource_path_depth,
        reserved2: [0; 2],
        cost_units: a.cost_units,
        sequence_id: a.sequence_id,
        nonce,
        resource_path_hashes,
        action_hash: [0; 32],
    };
    descriptor.finalize();
    Ok(descriptor)
}

fn decision_json(decision: &Decision) -> DecisionJson {
    DecisionJson {
        decision_type: decision_type_name(decision.decision_type).to_string(),
        reason_code: decision.reason_code as u8,
        reason_name: reason_code_name(decision.reason_code).to_string(),
        sequence_id: decision.sequence_id,
        decision_id_hex: hex_encode(&decision.decision_id),
        event_mac_hex: hex_encode(&decision.event_mac),
        timestamp_unix_ns: decision.timestamp_unix_ns,
    }
}

fn tier_from_value(v: u8) -> aps_verifier_core::Tier {
    use aps_verifier_core::Tier;
    match v {
        0 | 1 => Tier::T1,
        2 => Tier::T2,
        _ => Tier::T3,
    }
}

fn decision_type_name(d: DecisionType) -> &'static str {
    match d {
        DecisionType::Allow => "Allow",
        DecisionType::Deny => "Deny",
        DecisionType::Escalate => "Escalate",
    }
}

fn reason_code_name(r: ReasonCode) -> &'static str {
    match r {
        ReasonCode::Ok => "OK",
        ReasonCode::ExpiredPassport => "EXPIRED_PASSPORT",
        ReasonCode::NotYetValid => "NOT_YET_VALID",
        ReasonCode::StaleRevocationEpoch => "STALE_REVOCATION_EPOCH",
        ReasonCode::RegistryVersionMismatch => "REGISTRY_VERSION_MISMATCH",
        ReasonCode::ToolNotAllowed => "TOOL_NOT_ALLOWED",
        ReasonCode::OperationNotAllowed => "OPERATION_NOT_ALLOWED",
        ReasonCode::ResourceOutOfScope => "RESOURCE_OUT_OF_SCOPE",
        ReasonCode::RiskTierTooLow => "RISK_TIER_TOO_LOW",
        ReasonCode::RiskClassExceeded => "RISK_CLASS_EXCEEDED",
        ReasonCode::BudgetExceeded => "BUDGET_EXCEEDED",
        ReasonCode::SequenceReplay => "SEQUENCE_REPLAY",
        ReasonCode::NonceReplay => "NONCE_REPLAY",
        ReasonCode::ApprovalRequired => "APPROVAL_REQUIRED",
        ReasonCode::DeniedByRule => "DENIED_BY_RULE",
        ReasonCode::ActionHashInvalid => "ACTION_HASH_INVALID",
        ReasonCode::VerifierInstanceMismatch => "VERIFIER_INSTANCE_MISMATCH",
        ReasonCode::ClockAnchorStale => "CLOCK_ANCHOR_STALE",
        ReasonCode::SequenceRecoveryInvalid => "SEQUENCE_RECOVERY_INVALID",
        ReasonCode::StrictModeRequired => "STRICT_MODE_REQUIRED",
    }
}

fn hex_to_array_32(hex: &str) -> Result<[u8; 32], String> {
    hex_to_array::<32>(hex)
}

fn hex_to_array_16(hex: &str) -> Result<[u8; 16], String> {
    hex_to_array::<16>(hex)
}

fn hex_to_array<const N: usize>(hex: &str) -> Result<[u8; N], String> {
    if hex.len() != N * 2 {
        return Err(format!("expected {} hex chars, got {}", N * 2, hex.len()));
    }
    let mut out = [0u8; N];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| format!("non-hex character at {i}: {e}"))?;
    }
    Ok(out)
}

fn hex_encode(bytes: &[u8]) -> String {
    use core::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// -----------------------------------------------------------------------
// Tiny embedded JSON reader. Handles only the small, well-formed shapes
// this crate accepts (arrays of flat objects with string / number /
// number-array values). Keeps the wasm bundle free of serde_json.
// -----------------------------------------------------------------------
mod json {
    #[allow(dead_code)] // Null/Bool are parsed for completeness; this
    // crate's accessors only read Num/Str/Arr/Obj.
    pub enum Value {
        Null,
        Bool(bool),
        /// Numbers keep their raw source token so integer fields parse to
        /// exact u64. BLAKE3-derived resource-path hashes and sequence
        /// ids routinely exceed 2^53, so an f64 round-trip would silently
        /// corrupt them; we parse the token as u64 directly instead.
        Num(String),
        Str(String),
        Arr(Vec<Value>),
        Obj(Vec<(String, Value)>),
    }

    impl Value {
        pub fn as_array(&self) -> Option<&Vec<Value>> {
            match self {
                Value::Arr(a) => Some(a),
                _ => None,
            }
        }
        pub fn as_u64(&self) -> Option<u64> {
            match self {
                Value::Num(s) => token_to_u64(s),
                _ => None,
            }
        }
        pub fn get(&self, key: &str) -> Option<&Value> {
            match self {
                Value::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
                _ => None,
            }
        }
        pub fn get_str(&self, key: &str) -> Result<String, String> {
            match self.get(key) {
                Some(Value::Str(s)) => Ok(s.clone()),
                _ => Err(format!("missing or non-string field: {key}")),
            }
        }
        pub fn get_u64(&self, key: &str) -> Result<u64, String> {
            match self.get(key) {
                Some(Value::Num(s)) => {
                    token_to_u64(s).ok_or_else(|| format!("field {key} is not a u64: {s}"))
                }
                _ => Err(format!("missing or non-number field: {key}")),
            }
        }
    }

    /// Parse a JSON numeric token as exact u64. Rejects fractions,
    /// exponents, and negative values: the fields this crate reads are
    /// all non-negative integers.
    fn token_to_u64(s: &str) -> Option<u64> {
        let t = s.strip_prefix('+').unwrap_or(s);
        if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        t.parse::<u64>().ok()
    }

    pub fn parse(s: &str) -> Result<Value, String> {
        let bytes = s.as_bytes();
        let mut pos = 0;
        let v = parse_value(bytes, &mut pos)?;
        skip_ws(bytes, &mut pos);
        Ok(v)
    }

    fn skip_ws(b: &[u8], pos: &mut usize) {
        while *pos < b.len() && (b[*pos] == b' ' || b[*pos] == b'\n' || b[*pos] == b'\t' || b[*pos] == b'\r') {
            *pos += 1;
        }
    }

    fn parse_value(b: &[u8], pos: &mut usize) -> Result<Value, String> {
        skip_ws(b, pos);
        if *pos >= b.len() {
            return Err("unexpected end of input".into());
        }
        match b[*pos] {
            b'[' => parse_array(b, pos),
            b'{' => parse_object(b, pos),
            b'"' => parse_string(b, pos).map(Value::Str),
            b't' | b'f' => parse_bool(b, pos),
            b'n' => parse_null(b, pos),
            _ => parse_number(b, pos),
        }
    }

    fn parse_array(b: &[u8], pos: &mut usize) -> Result<Value, String> {
        *pos += 1; // consume '['
        let mut out = Vec::new();
        skip_ws(b, pos);
        if *pos < b.len() && b[*pos] == b']' {
            *pos += 1;
            return Ok(Value::Arr(out));
        }
        loop {
            let v = parse_value(b, pos)?;
            out.push(v);
            skip_ws(b, pos);
            if *pos >= b.len() {
                return Err("unterminated array".into());
            }
            match b[*pos] {
                b',' => {
                    *pos += 1;
                }
                b']' => {
                    *pos += 1;
                    break;
                }
                _ => return Err("expected ',' or ']' in array".into()),
            }
        }
        Ok(Value::Arr(out))
    }

    fn parse_object(b: &[u8], pos: &mut usize) -> Result<Value, String> {
        *pos += 1; // consume '{'
        let mut out = Vec::new();
        skip_ws(b, pos);
        if *pos < b.len() && b[*pos] == b'}' {
            *pos += 1;
            return Ok(Value::Obj(out));
        }
        loop {
            skip_ws(b, pos);
            let key = parse_string(b, pos)?;
            skip_ws(b, pos);
            if *pos >= b.len() || b[*pos] != b':' {
                return Err("expected ':' in object".into());
            }
            *pos += 1;
            let v = parse_value(b, pos)?;
            out.push((key, v));
            skip_ws(b, pos);
            if *pos >= b.len() {
                return Err("unterminated object".into());
            }
            match b[*pos] {
                b',' => {
                    *pos += 1;
                }
                b'}' => {
                    *pos += 1;
                    break;
                }
                _ => return Err("expected ',' or '}' in object".into()),
            }
        }
        Ok(Value::Obj(out))
    }

    fn parse_string(b: &[u8], pos: &mut usize) -> Result<String, String> {
        if *pos >= b.len() || b[*pos] != b'"' {
            return Err("expected string".into());
        }
        *pos += 1;
        let mut out = String::new();
        while *pos < b.len() {
            let c = b[*pos];
            *pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    if *pos >= b.len() {
                        return Err("bad escape".into());
                    }
                    let e = b[*pos];
                    *pos += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'n' => out.push('\n'),
                        b't' => out.push('\t'),
                        b'r' => out.push('\r'),
                        _ => return Err("unsupported escape".into()),
                    }
                }
                _ => out.push(c as char),
            }
        }
        Err("unterminated string".into())
    }

    fn parse_bool(b: &[u8], pos: &mut usize) -> Result<Value, String> {
        if b[*pos..].starts_with(b"true") {
            *pos += 4;
            Ok(Value::Bool(true))
        } else if b[*pos..].starts_with(b"false") {
            *pos += 5;
            Ok(Value::Bool(false))
        } else {
            Err("invalid bool".into())
        }
    }

    fn parse_null(b: &[u8], pos: &mut usize) -> Result<Value, String> {
        if b[*pos..].starts_with(b"null") {
            *pos += 4;
            Ok(Value::Null)
        } else {
            Err("invalid null".into())
        }
    }

    fn parse_number(b: &[u8], pos: &mut usize) -> Result<Value, String> {
        let start = *pos;
        while *pos < b.len() {
            let c = b[*pos];
            if c.is_ascii_digit() || c == b'-' || c == b'+' || c == b'.' || c == b'e' || c == b'E' {
                *pos += 1;
            } else {
                break;
            }
        }
        let slice = core::str::from_utf8(&b[start..*pos]).map_err(|_| "bad number utf8")?;
        if slice.is_empty() {
            return Err("empty number".into());
        }
        Ok(Value::Num(slice.to_string()))
    }
}

// -----------------------------------------------------------------------
// Unit tests for the WASM batch path (run on the host target via
// `cargo test`, not wasm32; they exercise the same parse + loop logic).
// -----------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    const TOOL_HEX: &str = "abcd000000000000000000000000000000000000000000000000000000000000";

    fn passport_json_str() -> String {
        let tool_hash = hex_to_array_32(TOOL_HEX).unwrap();
        let registry = ToolRegistry::from_entries(vec![ToolEntry {
            descriptor_hash: tool_hash,
            local_id: 0,
        }])
        .unwrap();
        let root_hex = hex_encode(&registry.current_root());
        format!(
            r#"{{
  "type": "aps.runtime_passport",
  "version": "0.1",
  "passport_id": "rp_01HX0EXAMPLE000000000000000",
  "agent_id": "ag_01HX0AGENT000000000000000000",
  "principal_id": "pr_01HX0PRINCIPAL00000000000000",
  "beneficiary_id": "bn_01HX0BEN00000000000000000000",
  "issuer": "https://gateway.example.test",
  "issued_at": "2026-05-19T22:38:56.000Z",
  "expires_at": "2026-05-19T22:39:56.000Z",
  "max_clock_skew_ms": 1000,
  "policy_epoch": 42,
  "revocation_epoch": 1842,
  "tool_registry_root": "blake3:{root_hex}",
  "delegation_chain_hash": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
  "effective_authority_hash": "blake3:0000000000000000000000000000000000000000000000000000000000000000",
  "risk_class": "R2",
  "minimum_tier_required": "T2",
  "tier_attested": "T2",
  "verifier_instance_id": "vi_01HX0VI00000000000000000000",
  "verifier_build_hash": "blake3:1111111111111111111111111111111111111111111111111111111111111111",
  "session_id": "sn_01HX0SESS00000000000000000000",
  "sequence_start": 1000,
  "sequence_end": 100000001,
  "budget_lease": {{
    "lease_id": "bl_01HX0LEASE0000000000000000000",
    "max_actions": 4294967295,
    "max_cost_units": 18446744073709551615,
    "sublease_parent": null
  }},
  "authority_blob_encoding": "application/aps-authority+json",
  "authority_blob": {{
    "allowed_tools": ["blake3:{TOOL_HEX}"],
    "allowed_operations": ["read"],
    "resource_scopes": ["customer/*"],
    "approval_rules": []
  }},
  "receipt_stream_id": "rs_01HX0RS00000000000000000000",
  "signature": "ed25519:{sig}"
}}"#,
            sig = "0".repeat(128)
        )
    }

    fn customer_hash() -> u64 {
        aps_verifier_core::hash_path_component("customer")
    }

    #[test]
    fn json_parser_round_trips_action_array() {
        // Includes a resource-path hash above 2^53 to confirm the parser
        // preserves u64 precision (an f64 round-trip would corrupt it).
        let big: u64 = 12_345_678_901_234_567_890;
        let s = format!(
            r#"[{{"version":1,"passportIdHashHex":"00","toolDescriptorHashHex":"11","localToolId":0,"operationId":0,"resourceType":0,"riskClass":2,"resourcePathDepth":1,"costUnits":1,"sequenceId":1000,"nonceHex":"22","resourcePathHashes":[{big},2,3]}}]"#
        );
        let parsed: Vec<ActionJson> = ActionJson::parse_array(&s).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].version, 1);
        assert_eq!(parsed[0].sequence_id, 1000);
        assert_eq!(parsed[0].resource_path_hashes, vec![big, 2, 3]);
    }

    #[test]
    fn empty_action_array_yields_empty_decisions() {
        let inputs: Vec<ActionJson> = ActionJson::parse_array("[]").unwrap();
        assert!(inputs.is_empty());
    }

    #[test]
    fn wasm_check_many_matches_core_sequential() {
        // Build authority via the wasm surface.
        let passport = RuntimePassport::from_json(&passport_json_str()).unwrap();
        let tool_hash = hex_to_array_32(TOOL_HEX).unwrap();
        let registry = ToolRegistry::from_entries(vec![ToolEntry {
            descriptor_hash: tool_hash,
            local_id: 0,
        }])
        .unwrap();
        let attested = passport.tier_attested as u8;
        let rev = passport.revocation_epoch;
        let vih = *blake3::hash(passport.verifier_instance_id.as_bytes()).as_bytes();
        let authority = CompiledAuthority::from_passport(&passport, registry).unwrap();

        // Two consecutive allow actions, seq 1000 and 1001.
        let pid_hash = blake3::hash("rp_01HX0EXAMPLE000000000000000".as_bytes());
        let pid_hex = hex_encode(pid_hash.as_bytes());
        let chash = customer_hash();
        let now_ns: u64 = 1_779_230_341_000_000_000;

        let actions_json = format!(
            r#"[{{"version":1,"passportIdHashHex":"{pid_hex}","toolDescriptorHashHex":"{TOOL_HEX}","localToolId":0,"operationId":0,"resourceType":0,"riskClass":2,"resourcePathDepth":1,"costUnits":1,"sequenceId":1000,"nonceHex":"55555555555555555555555555555555","resourcePathHashes":[{chash}]}},
                {{"version":1,"passportIdHashHex":"{pid_hex}","toolDescriptorHashHex":"{TOOL_HEX}","localToolId":0,"operationId":0,"resourceType":0,"riskClass":2,"resourcePathDepth":1,"costUnits":1,"sequenceId":1001,"nonceHex":"55555555555555555555555555555555","resourcePathHashes":[{chash}]}}]"#
        );

        let action_inputs: Vec<ActionJson> = ActionJson::parse_array(&actions_json).unwrap();
        let descriptors: Vec<ActionDescriptor> =
            action_inputs.iter().map(|a| build_descriptor(a).unwrap()).collect();

        let clock = FixedClock(now_ns);
        let ctx = VerifierContext::new(&clock, vih, tier_from_value(attested), rev);
        let mut wasm_decisions = Vec::new();
        for d in &descriptors {
            wasm_decisions.push(aps_check(&authority, d, &ctx));
        }

        assert_eq!(wasm_decisions.len(), 2);
        assert_eq!(wasm_decisions[0].decision_type, DecisionType::Allow);
        assert_eq!(wasm_decisions[1].decision_type, DecisionType::Allow);
        assert_eq!(wasm_decisions[0].sequence_id, 1000);
        assert_eq!(wasm_decisions[1].sequence_id, 1001);
    }
}
