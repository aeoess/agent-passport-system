//! Section 11.4: crash recovery floor.
//!
//! On verifier restart, before accepting any new action:
//!   1. Read the local durable log for the active passport.
//!   2. Verify the rolling keyed BLAKE3 over the log.
//!   3. Recover `last_committed_sequence_id`.
//!   4. Set `sequence_next = last_committed_sequence_id + 1`.
//!
//! Any incoming action with `sequence_id <= last_committed_sequence_id`
//! returns `SEQUENCE_RECOVERY_INVALID` (reason 0x12).
//!
//! TODO: log reader, rolling-MAC verifier, recovered floor publication
//! to the CompiledAuthority `sequence_next` atomic.

/// Result of a recovery sweep: the highest committed `sequence_id`
/// found in the durable log, or `None` if the log is empty / new.
pub fn recover_sequence_floor() -> Option<u64> {
    unimplemented!("Section 11.4 crash recovery: implementation pending")
}
