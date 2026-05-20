//! Section 11.4: crash recovery floor.
//!
//! On verifier restart the durable log is walked entry by entry, the
//! rolling MAC chain is validated, and `last_committed_sequence_id`
//! is recovered. The verifier then sets `sequence_next =
//! last_committed_sequence_id + 1`. Any incoming action with
//! `sequence_id <= last_committed_sequence_id` denies with
//! `SEQUENCE_RECOVERY_INVALID` (reason 0x12).
//!
//! Tamper-resistance per spec §11.5: chain validation is Tier 1
//! protection against accidental corruption and crash replay. A
//! malicious host with `mac_key` can forge a log that validates
//! cleanly. Tier 2 (signed verifier build) and Tier 3 (TEE) are
//! deferred to Phase 2/3.
//!
//! The "log for the active passport" question is out of scope here:
//! `recover_log` takes an explicit path. Callers pin one log file per
//! passport session; mapping passport_id → log_path is a
//! configuration concern outside this crate.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use thiserror::Error;

use crate::decision::{Decision, DECISION_SIZE};
use crate::receipt_log::{compute_rolling_mac, LOG_ENTRY_PAYLOAD};

const ENTRY_FRAME_HEADER: usize = 4;

#[derive(Debug, Clone)]
pub struct RecoveryReport {
    /// Highest sequence_id in any validated log entry. Zero if no
    /// entries were recoverable (fresh start).
    pub last_committed_sequence_id: u64,
    /// Rolling MAC at the last valid entry; chain-continuation point
    /// for a [`crate::receipt_log::LogWriter`] resuming writes.
    pub last_rolling_mac: [u8; 32],
    /// Count of entries validated.
    pub entries_recovered: u64,
    /// File offset of the byte after the last valid entry. The file
    /// suffix beyond this offset is corrupt or truncated and must be
    /// discarded before resuming writes.
    pub valid_through_offset: u64,
    pub status: RecoveryStatus,
}

impl RecoveryReport {
    fn fresh_start() -> Self {
        RecoveryReport {
            last_committed_sequence_id: 0,
            last_rolling_mac: [0u8; 32],
            entries_recovered: 0,
            valid_through_offset: 0,
            status: RecoveryStatus::FreshStart,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryStatus {
    /// Log file did not exist or was empty.
    FreshStart,
    /// Chain validated to end of file.
    CleanRecovery,
    /// Chain validated up to some entry; the suffix beyond
    /// `truncated_at_offset` was corrupt or truncated. Recovered state
    /// is valid for the validated prefix.
    PartialRecovery {
        truncated_at_offset: u64,
        reason: TruncationReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TruncationReason {
    /// File ended mid-entry (incomplete length prefix or payload).
    IncompleteEntry,
    /// Stored rolling_mac did not match the recomputed value.
    MacMismatch { at_entry: u64 },
    /// Length prefix did not equal the spec-defined payload size (96).
    InvalidLength { at_entry: u64, length: u32 },
}

#[derive(Debug, Error)]
pub enum RecoveryError {
    /// First entry could not be validated — log is unusable. The chain
    /// starts with prev_mac = [0;32] so a first-entry failure means the
    /// file is fundamentally wrong (corrupt, wrong key, or wrong log
    /// for this session), not just truncated.
    #[error("first entry MAC validation failed")]
    InitialMacFailure,
    #[error("io error during recovery: {0}")]
    Io(#[from] std::io::Error),
}

/// Walk the durable log at `log_path`, validating each entry's
/// rolling MAC against the chain. Returns the recovery report.
///
/// - Missing file → `FreshStart`.
/// - Empty file → `FreshStart`.
/// - First-entry MAC mismatch → `Err(InitialMacFailure)`.
/// - Mid-chain MAC mismatch → `PartialRecovery { MacMismatch }`.
/// - Truncated suffix → `PartialRecovery { IncompleteEntry }`.
/// - Bad length prefix → `PartialRecovery { InvalidLength }`.
/// - Clean walk to EOF → `CleanRecovery`.
pub fn recover_log(
    log_path: &Path,
    mac_key: [u8; 32],
) -> Result<RecoveryReport, RecoveryError> {
    if !log_path.exists() {
        return Ok(RecoveryReport::fresh_start());
    }
    let mut file = File::open(log_path)?;
    let file_len = file.metadata()?.len();
    if file_len == 0 {
        return Ok(RecoveryReport::fresh_start());
    }

    let mut prev_mac = [0u8; 32];
    let mut last_seq_id = 0u64;
    let mut entries = 0u64;
    let mut offset: u64 = 0;

    loop {
        let entry_start_offset = offset;

        // Length prefix.
        let mut length_buf = [0u8; ENTRY_FRAME_HEADER];
        let n = read_partial(&mut file, &mut length_buf)?;
        if n == 0 {
            // Clean EOF at entry boundary.
            return Ok(RecoveryReport {
                last_committed_sequence_id: last_seq_id,
                last_rolling_mac: prev_mac,
                entries_recovered: entries,
                valid_through_offset: offset,
                status: RecoveryStatus::CleanRecovery,
            });
        }
        if n < ENTRY_FRAME_HEADER {
            return Ok(RecoveryReport {
                last_committed_sequence_id: last_seq_id,
                last_rolling_mac: prev_mac,
                entries_recovered: entries,
                valid_through_offset: offset,
                status: RecoveryStatus::PartialRecovery {
                    truncated_at_offset: entry_start_offset,
                    reason: TruncationReason::IncompleteEntry,
                },
            });
        }
        let length = u32::from_le_bytes(length_buf);
        offset += ENTRY_FRAME_HEADER as u64;

        if length as usize != LOG_ENTRY_PAYLOAD {
            return Ok(RecoveryReport {
                last_committed_sequence_id: last_seq_id,
                last_rolling_mac: prev_mac,
                entries_recovered: entries,
                valid_through_offset: entry_start_offset,
                status: RecoveryStatus::PartialRecovery {
                    truncated_at_offset: entry_start_offset,
                    reason: TruncationReason::InvalidLength {
                        at_entry: entries,
                        length,
                    },
                },
            });
        }

        // Payload.
        let mut payload = [0u8; LOG_ENTRY_PAYLOAD];
        let n = read_partial(&mut file, &mut payload)?;
        if n < LOG_ENTRY_PAYLOAD {
            return Ok(RecoveryReport {
                last_committed_sequence_id: last_seq_id,
                last_rolling_mac: prev_mac,
                entries_recovered: entries,
                valid_through_offset: entry_start_offset,
                status: RecoveryStatus::PartialRecovery {
                    truncated_at_offset: entry_start_offset,
                    reason: TruncationReason::IncompleteEntry,
                },
            });
        }

        let decision_bytes: [u8; DECISION_SIZE] = payload[..DECISION_SIZE]
            .try_into()
            .expect("slice len asserted by payload size");
        let stored_mac: [u8; 32] = payload[DECISION_SIZE..]
            .try_into()
            .expect("slice len asserted by payload size");

        // Recompute MAC over (prev_mac || decision_bytes).
        let expected_mac = compute_rolling_mac(&mac_key, &prev_mac, &decision_bytes);
        if expected_mac != stored_mac {
            if entries == 0 {
                return Err(RecoveryError::InitialMacFailure);
            }
            return Ok(RecoveryReport {
                last_committed_sequence_id: last_seq_id,
                last_rolling_mac: prev_mac,
                entries_recovered: entries,
                valid_through_offset: entry_start_offset,
                status: RecoveryStatus::PartialRecovery {
                    truncated_at_offset: entry_start_offset,
                    reason: TruncationReason::MacMismatch { at_entry: entries },
                },
            });
        }

        // Parse Decision. If the MAC validated, parse should also
        // succeed; treat parse failure as the first-entry case for
        // defense in depth (a parse failure on a MAC-validated entry
        // is a wire-format mismatch the writer should never produce).
        match Decision::from_bytes(&decision_bytes) {
            Ok(d) => {
                last_seq_id = d.sequence_id;
            }
            Err(_) => {
                if entries == 0 {
                    return Err(RecoveryError::InitialMacFailure);
                }
                return Ok(RecoveryReport {
                    last_committed_sequence_id: last_seq_id,
                    last_rolling_mac: prev_mac,
                    entries_recovered: entries,
                    valid_through_offset: entry_start_offset,
                    status: RecoveryStatus::PartialRecovery {
                        truncated_at_offset: entry_start_offset,
                        reason: TruncationReason::MacMismatch { at_entry: entries },
                    },
                });
            }
        }

        prev_mac = stored_mac;
        entries += 1;
        offset += LOG_ENTRY_PAYLOAD as u64;
    }
}

/// Read into `buf`, retrying on `Interrupted`. Returns the number of
/// bytes actually read; 0 means clean EOF before any bytes were read,
/// less than `buf.len()` means partial.
fn read_partial<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let n = buf.len();
    let mut total = 0;
    while total < n {
        match r.read(&mut buf[total..]) {
            Ok(0) => return Ok(total),
            Ok(k) => total += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}
