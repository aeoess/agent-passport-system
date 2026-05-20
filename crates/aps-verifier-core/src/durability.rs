//! Section 11.3: event durability modes.
//!
//! - Mode A (memory-buffered). R0..R1. Async flush, return immediate.
//! - Mode B1 (blocking commit). R2..R3 conservative. fsync at batch
//!   boundary (default 1ms or 64 events). Chunk 9.
//! - Mode B2 (queued commit). R2..R3 fast. Admit to batch then return;
//!   batch ID carries crash-window reconciliation. Chunk 9.
//! - Mode C (strict). R4. Out of Prototype 1 scope.
//!
//! Chunk 8 provides the shared [`ReceiptSink`] trait, the no-op
//! [`NullSink`], and the [`ModeAReceiptSink`] implementation backed by
//! an in-memory ring buffer and a background flush thread. The durable
//! log format itself lives in [`crate::receipt_log`] and is shared by
//! every mode.

use std::collections::VecDeque;
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use thiserror::Error;

pub use crate::passport::DurabilityMode;

use crate::decision::Decision;
use crate::receipt_log::{LogError, LogWriter};

// -----------------------------------------------------------------------
// Public surface
// -----------------------------------------------------------------------

/// Outcome of a single `emit` call. Mode B2 (chunk 9) populates
/// `batch_id`; Mode A and Mode B1 leave it `None`.
#[derive(Debug, Default, Clone, Copy)]
pub struct EmitOutcome {
    pub batch_id: Option<u64>,
}

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("buffer full")]
    BufferFull,
    #[error("log write failed: {0}")]
    LogWriteFailed(#[from] LogError),
    #[error("shutdown in progress")]
    ShutdownInProgress,
}

/// Sink for decision events emitted by `aps_check`. Each mode chooses
/// when to return (immediately for Mode A; after group fsync for Mode
/// B1) and what `EmitOutcome` to return.
pub trait ReceiptSink: Send + Sync {
    fn emit(&self, decision: &Decision) -> Result<EmitOutcome, ReceiptError>;
}

/// No-op sink. Convenient default for tests that don't care about
/// durability and for unit tests that only inspect the Decision.
pub struct NullSink;

impl ReceiptSink for NullSink {
    fn emit(&self, _decision: &Decision) -> Result<EmitOutcome, ReceiptError> {
        Ok(EmitOutcome::default())
    }
}

// -----------------------------------------------------------------------
// Mode A
// -----------------------------------------------------------------------

struct ModeAState {
    buffer: VecDeque<Decision>,
    writer: LogWriter,
}

/// Memory-buffered sink with a background flush thread. Spec §11.3
/// Mode A.
pub struct ModeAReceiptSink {
    state: Arc<Mutex<ModeAState>>,
    buffer_capacity: usize,
    shutdown: Arc<AtomicBool>,
    flush_handle: Mutex<Option<JoinHandle<()>>>,
}

impl ModeAReceiptSink {
    /// Open or create a durable log at `log_path` and spawn the
    /// background flush thread.
    ///
    /// - `mac_key`: the receipt_stream_key from the passport (§6.1).
    /// - `buffer_capacity`: in-memory ring buffer size in decisions.
    ///   `emit` returns `BufferFull` when this is reached.
    /// - `flush_interval`: maximum wall-clock between background
    ///   drains. Shorter = lower crash-window risk + more I/O; longer
    ///   = larger crash window + smoother batching.
    pub fn new(
        log_path: &Path,
        mac_key: [u8; 32],
        buffer_capacity: usize,
        flush_interval: Duration,
    ) -> Result<Self, ReceiptError> {
        let writer = LogWriter::open(log_path, mac_key)?;
        let state = Arc::new(Mutex::new(ModeAState {
            buffer: VecDeque::with_capacity(buffer_capacity),
            writer,
        }));
        let shutdown = Arc::new(AtomicBool::new(false));
        let flush_handle = {
            let state = Arc::clone(&state);
            let shutdown = Arc::clone(&shutdown);
            thread::spawn(move || flush_loop(state, shutdown, flush_interval))
        };
        Ok(ModeAReceiptSink {
            state,
            buffer_capacity,
            shutdown,
            flush_handle: Mutex::new(Some(flush_handle)),
        })
    }

    /// Drain any buffered events to the durable log and join the
    /// background thread. After this returns, every successfully
    /// `emit`-ed decision is present in the log.
    pub fn shutdown(self) -> Result<(), ReceiptError> {
        self.shutdown.store(true, Ordering::Release);
        if let Some(h) = self.flush_handle.lock().unwrap().take() {
            let _ = h.join();
        }
        let mut state = self.state.lock().unwrap();
        drain_buffer(&mut state)?;
        state.writer.flush()?;
        Ok(())
    }
}

impl ReceiptSink for ModeAReceiptSink {
    fn emit(&self, decision: &Decision) -> Result<EmitOutcome, ReceiptError> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(ReceiptError::ShutdownInProgress);
        }
        let mut state = self
            .state
            .lock()
            .expect("ModeAReceiptSink state mutex poisoned");
        if state.buffer.len() >= self.buffer_capacity {
            return Err(ReceiptError::BufferFull);
        }
        state.buffer.push_back(decision.clone());
        Ok(EmitOutcome::default())
    }
}

fn flush_loop(state: Arc<Mutex<ModeAState>>, shutdown: Arc<AtomicBool>, interval: Duration) {
    // Cap the per-sleep slice so shutdown latency is bounded by the
    // slice regardless of how long `interval` is configured. Without
    // this, a 60-second interval would mean up to 60 seconds of
    // shutdown blocking for the join to land.
    let slice = std::cmp::min(interval, Duration::from_millis(50));
    let mut elapsed = Duration::ZERO;
    while !shutdown.load(Ordering::Acquire) {
        thread::sleep(slice);
        elapsed += slice;
        if elapsed < interval {
            continue;
        }
        elapsed = Duration::ZERO;
        let mut s = match state.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let _ = drain_buffer(&mut s);
    }
}

fn drain_buffer(state: &mut ModeAState) -> Result<(), ReceiptError> {
    let drained: Vec<Decision> = state.buffer.drain(..).collect();
    for d in &drained {
        state.writer.append(d)?;
    }
    state.writer.flush()?;
    Ok(())
}
