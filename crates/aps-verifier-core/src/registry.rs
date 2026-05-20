//! Section 11.1: tool registry consistency.
//!
//! Wire carries descriptor hashes only; local integer IDs are
//! resolved at passport load and validated on every action by a
//! single cache-line compare of
//! `registry[local_tool_id].descriptor_hash == action.tool_descriptor_hash`.
//! Mismatch surfaces as `REGISTRY_VERSION_MISMATCH` (reason 0x04).
//!
//! TODO: load-time descriptor-hash to integer mapping, HTTPS poll-based
//! registry refresh when `tool_registry_root` does not match local.

/// Single entry in the local tool registry. Layout matches Appendix A
/// `ToolEntry`; `descriptor_ptr` is omitted in this skeleton.
#[repr(C)]
pub struct ToolEntry {
    pub descriptor_hash: [u8; 32],
}
