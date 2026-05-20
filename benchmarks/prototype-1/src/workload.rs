//! Fixtures and harness setup for the L0 / L1 measurements.
//!
//! Spec §13 (benchmark environments) + spec §9 (hot path). The L0
//! fixture builds a happy-path passport, action, and verifier
//! context once at startup; L1 uses the same fixtures but tampers
//! the action to trigger the spec §9 step 0 `ACTION_HASH_INVALID`
//! short-circuit. Tampering happens at fixture-build time, NOT in
//! the timed loop.

use aps_verifier_core::{
    aps_check, hash_path_component, ActionDescriptor, CompiledAuthority, Decision, ManualClock,
    NullSink, PassportError, RuntimePassport, Tier, ToolEntry, ToolRegistry, VerifierContext,
};

const TOOL_HEX: &str = "abcd000000000000000000000000000000000000000000000000000000000000";

pub struct Fixture {
    pub authority: CompiledAuthority,
    pub action_allow: ActionDescriptor,
    pub action_deny_action_hash_invalid: ActionDescriptor,
    pub clock: ManualClock,
    pub instance_id_hash: [u8; 32],
    pub revocation_epoch: u32,
    pub sink: NullSink,
}

impl Fixture {
    pub fn build() -> Result<Self, BuildError> {
        let tool_hash = hash_from_hex(TOOL_HEX);
        let registry = ToolRegistry::from_entries(vec![ToolEntry {
            descriptor_hash: tool_hash,
            local_id: 0,
        }])
        .map_err(|e| BuildError(format!("registry: {e}")))?;
        let registry_for_authority = registry.clone();
        let root_hex = hex_encode(&registry.current_root());

        let json = build_passport_json(&root_hex, &hex_encode(&tool_hash));
        let passport = RuntimePassport::from_json(&json).map_err(BuildError::from_passport)?;
        let authority = CompiledAuthority::from_passport(&passport, registry_for_authority)
            .map_err(|e| BuildError(format!("compile: {e}")))?;

        // Build the allow-path action: passport_id_hash matches, tool
        // matches, operation_id = 0 (read), risk_class = 2, resource
        // matches "customer/*", sequence_id = 1000 (the window start).
        let mut allow = blank_action();
        allow.passport_id_hash = blake3_32_str("rp_01HX0EXAMPLE000000000000000");
        allow.tool_descriptor_hash = tool_hash;
        allow.local_tool_id = 0;
        allow.operation_id = 0;
        allow.risk_class = 2;
        allow.resource_path_depth = 1;
        allow.resource_path_hashes[0] = hash_path_component("customer");
        allow.sequence_id = 1000;
        allow.cost_units = 1;
        allow.nonce = [0x55; 16];
        allow.finalize();

        // Deny-path action: same as allow but tamper one field AFTER
        // finalize so action_hash mismatches. Triggers step 0 short-
        // circuit (cheapest deny).
        let mut deny = allow.clone();
        deny.sequence_id = deny.sequence_id.wrapping_add(1);
        // action_hash NOT recomputed → step 0 fails.

        let clock = ManualClock::new(default_clock_ns());
        let instance_id_hash = blake3_32_str("vi_01HX0VI00000000000000000000");

        Ok(Fixture {
            authority,
            action_allow: allow,
            action_deny_action_hash_invalid: deny,
            clock,
            instance_id_hash,
            revocation_epoch: 1842,
            sink: NullSink,
        })
    }

    pub fn context<'a>(&'a self) -> VerifierContext<'a> {
        VerifierContext::with_sink(
            &self.clock,
            self.instance_id_hash,
            Tier::T2,
            self.revocation_epoch,
            &self.sink,
        )
    }
}

#[derive(Debug)]
pub struct BuildError(pub String);

impl BuildError {
    fn from_passport(e: PassportError) -> Self {
        BuildError(format!("passport: {e}"))
    }
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for BuildError {}

/// Single hot-path call for benchmarking. Re-exported here so the
/// timed-loop in main.rs doesn't need to import from the verifier
/// crate directly.
#[inline(always)]
pub fn run_check(authority: &CompiledAuthority, action: &ActionDescriptor, ctx: &VerifierContext) -> Decision {
    aps_check(authority, action, ctx)
}

// -----------------------------------------------------------------------
// Helpers (kept here so main.rs stays focused on dispatch + timing).
// -----------------------------------------------------------------------

fn blank_action() -> ActionDescriptor {
    ActionDescriptor {
        version: 1,
        reserved: [0; 3],
        passport_id_hash: [0; 32],
        tool_descriptor_hash: [0; 32],
        local_tool_id: 0,
        operation_id: 0,
        resource_type: 0,
        risk_class: 0,
        resource_path_depth: 0,
        reserved2: [0; 2],
        cost_units: 0,
        sequence_id: 0,
        nonce: [0; 16],
        resource_path_hashes: [0; 8],
        action_hash: [0; 32],
    }
}

fn hash_from_hex(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).expect("hex");
    }
    out
}

fn hex_encode(bytes: &[u8; 32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn blake3_32_str(s: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(s.as_bytes());
    *hasher.finalize().as_bytes()
}

fn default_clock_ns() -> u64 {
    // Midway through the 60-second issued_at..expires_at window the
    // happy passport uses ("2026-05-19T22:38:56.000Z" + 5s).
    1_779_230_341_000_000_000
}

fn build_passport_json(root_hex: &str, tool_hex: &str) -> String {
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
    "allowed_tools": ["blake3:{tool_hex}"],
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

