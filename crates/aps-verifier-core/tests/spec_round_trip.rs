//! Round-trip + adversarial-case test stubs, per Section 14 acceptance
//! criteria of `specs/PROTOTYPE-1-RUNTIME-PASSPORT.md`.
//!
//! Adversarial cases to cover (Section 14.4):
//!   - Registry drift attack: stale local registry against a fresh
//!     passport. Expect `REGISTRY_VERSION_MISMATCH` (0x04).
//!   - Clock partition attack: R0..R2 actions continue to execute,
//!     R3 actions halt with `CLOCK_ANCHOR_STALE` (0x11).
//!   - Crash-replay attack: after restart, any action with
//!     `sequence_id <= last_committed_sequence_id` returns
//!     `SEQUENCE_RECOVERY_INVALID` (0x12).
//!
//! Round-trip coverage (Section 14.1):
//!   - Wire formats from Sections 4, 5, 6 are stable across the Rust
//!     core and (once shipped) the TS SDK.

#[test]
#[ignore = "acceptance-criteria coverage lands once aps_check (chunk 6) is online"]
fn spec_round_trip_skeleton() {
    unimplemented!(
        "acceptance-criteria coverage lands once aps_check (chunk 6) is online"
    );
}
