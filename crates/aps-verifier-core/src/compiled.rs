//! Section 8 and Appendix A: CompiledAuthority in-memory representation.
//!
//! Hot-path properties (Section 8) MUST hold:
//!   1. No heap allocations during `aps_check`.
//!   2. No string operations or JSON parsing during `aps_check`.
//!   3. Constant-time or near-constant-time evaluation per check.
//!   4. Atomic decrement for budget counters.
//!   5. Atomic CAS for sequence advancement.
//!   6. Cache-aligned layout of frequently-accessed fields.
//!
//! TODO: full layout per Appendix A, alternative resource-scope
//! structures benchmarked per Section 8 (radix trie, perfect hash,
//! bloom + fallback).

use core::sync::atomic::{AtomicU32, AtomicU64};

use crate::durability::DurabilityMode;

/// Reference CompiledAuthority layout (Appendix A). Non-normative; the
/// hot path may pick a faster shape provided Section 8 properties hold.
#[repr(C, align(64))]
pub struct CompiledAuthority {
    // Cache line 1: hot fields touched every action.
    pub expires_at_unix_ns: u64,
    pub issued_at_unix_ns: u64,
    pub max_clock_skew_ns: u64,
    pub revocation_epoch: u32,
    pub risk_class: u8,
    pub minimum_tier_required: u8,
    pub flags: u16,
    pub sequence_next: AtomicU64,
    pub sequence_end: u64,
    pub budget_remaining_actions: AtomicU32,
    pub budget_remaining_cost_units: AtomicU64,
    pub allowed_op_mask: u32,
    pub last_time_anchor_ns: AtomicU64,

    // Cache line 2: identity hashes.
    pub passport_id_hash: [u8; 32],
    pub verifier_instance_id_hash: [u8; 32],

    // Receipt stream.
    pub receipt_stream_key: [u8; 32],
    pub durability_mode: DurabilityMode,
}
