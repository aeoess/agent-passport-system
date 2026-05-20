//! Spec §11.4 durable log format.
//!
//! Append-only framed entries, shared by all durability modes:
//!
//! ```text
//! [4 bytes: entry_length u32 LE = 96]
//! [64 bytes: Decision wire form (spec §6)]
//! [32 bytes: rolling_mac]
//! ```
//!
//! Rolling MAC chain:
//!
//! ```text
//! rolling_mac = BLAKE3_keyed(mac_key, prev_mac || decision_bytes)
//! ```
//!
//! where `prev_mac` is `[0u8; 32]` for the first entry. The chain is
//! tamper-evident at Tier 1 against accidental corruption and crash
//! replay (spec §11.5); a malicious host with `mac_key` can rewrite
//! the chain at will, so Tier 1 is bounded to R0-R1 (§18 tier matrix).
//!
//! Chunk 8 produces a recoverable log format. Chunk 9 implements the
//! crash-recovery scan that walks and validates this chain to recover
//! `last_committed_sequence_id` per spec §11.4.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Read, Write};
use std::path::Path;

use thiserror::Error;

use crate::decision::{Decision, DECISION_SIZE};

const ENTRY_FRAME_HEADER: usize = 4;
const ROLLING_MAC_SIZE: usize = 32;

/// Full on-disk entry size: 4-byte length prefix + 64-byte Decision +
/// 32-byte rolling MAC.
pub const LOG_ENTRY_BYTES: usize = ENTRY_FRAME_HEADER + DECISION_SIZE + ROLLING_MAC_SIZE;

/// Value the 4-byte length prefix carries (payload size, not full
/// frame). 64 + 32 = 96.
pub const LOG_ENTRY_PAYLOAD: usize = DECISION_SIZE + ROLLING_MAC_SIZE;

#[derive(Debug, Error)]
pub enum LogError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid entry frame: {0}")]
    InvalidFrame(String),
    #[error("rolling MAC mismatch at entry {0}")]
    MacMismatch(u64),
}

/// Append-only writer over the receipt log. Each `append` advances the
/// rolling MAC chain. Modes choose whether to `flush` (push to OS
/// buffer) or `sync` (fsync to durable storage).
pub struct LogWriter {
    file: BufWriter<File>,
    prev_mac: [u8; 32],
    mac_key: [u8; 32],
    entries_written: u64,
}

impl LogWriter {
    /// Open or create the log at `path`. If the file already exists
    /// and contains entries, walks the chain to set `prev_mac` and
    /// `entries_written` to the file's tail state. If chain validation
    /// fails midway, returns `LogError::MacMismatch` (a tampered log is
    /// not appended to; chunk 9 will replace this with formal recovery).
    pub fn open(path: &Path, mac_key: [u8; 32]) -> Result<Self, LogError> {
        let already_exists = path.exists();
        let (prev_mac, entries_written) = if already_exists {
            scan_existing(path, &mac_key)?
        } else {
            ([0u8; 32], 0u64)
        };
        let file = OpenOptions::new()
            .read(true)
            .append(true)
            .create(true)
            .open(path)?;
        Ok(LogWriter {
            file: BufWriter::new(file),
            prev_mac,
            mac_key,
            entries_written,
        })
    }

    /// Append a decision. Computes the rolling MAC, writes the framed
    /// entry to the underlying buffered file, advances `prev_mac`.
    /// Does NOT fsync; caller chooses via `flush` or `sync`.
    pub fn append(&mut self, decision: &Decision) -> Result<(), LogError> {
        let decision_bytes = decision.to_bytes();
        let rolling_mac = compute_rolling_mac(&self.mac_key, &self.prev_mac, &decision_bytes);
        let length: u32 = LOG_ENTRY_PAYLOAD as u32;
        self.file.write_all(&length.to_le_bytes())?;
        self.file.write_all(&decision_bytes)?;
        self.file.write_all(&rolling_mac)?;
        self.prev_mac = rolling_mac;
        self.entries_written += 1;
        Ok(())
    }

    /// Flush the BufWriter to the OS (no fsync). Mode A uses this.
    pub fn flush(&mut self) -> Result<(), LogError> {
        self.file.flush()?;
        Ok(())
    }

    /// Flush + fsync_data the underlying file. Modes B1/B2 use this at
    /// batch boundaries.
    pub fn sync(&mut self) -> Result<(), LogError> {
        self.file.flush()?;
        self.file.get_ref().sync_data()?;
        Ok(())
    }

    /// Most recent rolling MAC value. Useful for crash-recovery checks
    /// (chunk 9).
    pub fn current_mac(&self) -> &[u8; 32] {
        &self.prev_mac
    }

    /// Number of entries appended since open.
    pub fn entries_written(&self) -> u64 {
        self.entries_written
    }
}

/// `BLAKE3_keyed(mac_key, prev_mac || decision_bytes)`.
pub(crate) fn compute_rolling_mac(
    mac_key: &[u8; 32],
    prev_mac: &[u8; 32],
    decision_bytes: &[u8; DECISION_SIZE],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(mac_key);
    hasher.update(prev_mac);
    hasher.update(decision_bytes);
    *hasher.finalize().as_bytes()
}

fn scan_existing(path: &Path, mac_key: &[u8; 32]) -> Result<([u8; 32], u64), LogError> {
    let mut file = File::open(path)?;
    let mut prev_mac = [0u8; 32];
    let mut entries: u64 = 0;
    loop {
        let mut header = [0u8; ENTRY_FRAME_HEADER];
        let n = file.read(&mut header)?;
        if n == 0 {
            break;
        }
        if n != ENTRY_FRAME_HEADER {
            return Err(LogError::InvalidFrame(format!(
                "partial header at entry {entries}: got {n} bytes"
            )));
        }
        let length = u32::from_le_bytes(header) as usize;
        if length != LOG_ENTRY_PAYLOAD {
            return Err(LogError::InvalidFrame(format!(
                "entry {entries}: expected payload length {LOG_ENTRY_PAYLOAD}, got {length}"
            )));
        }
        let mut payload = [0u8; LOG_ENTRY_PAYLOAD];
        file.read_exact(&mut payload)?;
        let decision_bytes: [u8; DECISION_SIZE] = payload[..DECISION_SIZE]
            .try_into()
            .map_err(|_| LogError::InvalidFrame("decision slice".into()))?;
        let stored_mac: [u8; 32] = payload[DECISION_SIZE..]
            .try_into()
            .map_err(|_| LogError::InvalidFrame("mac slice".into()))?;
        let computed = compute_rolling_mac(mac_key, &prev_mac, &decision_bytes);
        if computed != stored_mac {
            return Err(LogError::MacMismatch(entries));
        }
        prev_mac = stored_mac;
        entries += 1;
    }
    Ok((prev_mac, entries))
}
