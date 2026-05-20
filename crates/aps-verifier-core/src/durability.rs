//! Section 11.3: event durability modes.
//!
//! - Mode A (memory-buffered):     R0..R1, async flush, return immediate.
//! - Mode B1 (blocking commit):    R2..R3 conservative, fsync at batch
//!                                 boundary (default 1ms or 64 events).
//! - Mode B2 (queued commit):      R2..R3 fast, admit to batch then
//!                                 return; batch ID carries crash-window
//!                                 reconciliation.
//! - Mode C (strict):              R4, out of Prototype 1 scope; the
//!                                 hot path returns `STRICT_MODE_REQUIRED`.
//!
//! TODO: ring buffer, group-commit scheduler, batch-ID allocation.

/// Per-passport durability mode selector. Discriminants are not normative
/// (the wire format encodes risk_class, not mode).
#[repr(u8)]
pub enum DurabilityMode {
    MemoryBuffered = 0,
    BlockingGroupCommit = 1,
    QueuedGroupCommit = 2,
}
