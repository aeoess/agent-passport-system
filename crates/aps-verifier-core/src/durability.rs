//! Section 11.3: event durability modes.
//!
//! The canonical type lives in [`crate::passport::DurabilityMode`] and is
//! re-exported here so the compiled-authority side of the crate (which
//! treats durability as a hot-path field) imports it from a stable
//! address.
//!
//! Modes:
//!
//! - Mode A (memory-buffered). R0..R1. Async flush, return immediate.
//! - Mode B1 (blocking commit). R2..R3 conservative. fsync at batch
//!   boundary (default 1ms or 64 events).
//! - Mode B2 (queued commit). R2..R3 fast. Admit to batch then return;
//!   batch ID carries crash-window reconciliation.
//! - Mode C (strict). R4. Out of Prototype 1 scope; the hot path returns
//!   `STRICT_MODE_REQUIRED`.
//!
//! TODO: ring buffer, group-commit scheduler, batch-ID allocation.

pub use crate::passport::DurabilityMode;
