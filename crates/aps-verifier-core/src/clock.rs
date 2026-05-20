//! Section 11.2: clock-skew tolerance with risk-class-aware soft
//! degradation.
//!
//! R0..R2 actions execute against a valid passport even without fresh
//! time anchors, bounded by `expires_at + max_clock_skew_ms`. R3 actions
//! require a time anchor fresher than 30 seconds or return
//! `CLOCK_ANCHOR_STALE` (reason 0x11). R4 is out of Prototype 1 scope.
//!
//! TODO: periodic gateway poll, `last_time_anchor_ns` atomic update,
//! monotonic vs wall-clock reconciliation.

/// Update the verifier's `last_gateway_time_anchor_received`.
pub fn update_time_anchor(_now_unix_ns: u64) {
    unimplemented!("Section 11.2 time-anchor handler: implementation pending")
}
