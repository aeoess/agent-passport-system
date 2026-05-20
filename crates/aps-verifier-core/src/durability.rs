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

// -----------------------------------------------------------------------
// Mode B1 / B2 shared infrastructure
// -----------------------------------------------------------------------

/// Group-commit configuration shared by Modes B1 and B2. A batch is
/// sealed and fsync'd when either threshold fires first.
#[derive(Debug, Clone, Copy)]
pub struct GroupCommitConfig {
    pub max_batch_size: usize,
    pub max_batch_window: Duration,
}

impl Default for GroupCommitConfig {
    fn default() -> Self {
        // Spec §11.3 defaults.
        GroupCommitConfig {
            max_batch_size: 64,
            max_batch_window: Duration::from_millis(1),
        }
    }
}

struct BatchManagerState {
    current_batch: Vec<Decision>,
    current_batch_id: u64,
    /// Lowest batch_id NOT yet committed. After committing batch N
    /// this advances to N+1. Lives under the state mutex (not as an
    /// atomic) so the producer's update and the waiter's check are
    /// strictly ordered with respect to `commit_cv.wait` — no
    /// lost-wakeup race.
    next_uncommitted_batch_id: u64,
    shutdown: bool,
}

/// Internal helper shared by B1 and B2. Holds the in-memory batch
/// state plus the synchronization primitives used by the commit
/// thread.
struct BatchManager {
    state: std::sync::Mutex<BatchManagerState>,
    full_cv: std::sync::Condvar,
    commit_cv: std::sync::Condvar,
    buffer_capacity: usize,
    config: GroupCommitConfig,
}

impl BatchManager {
    fn new(buffer_capacity: usize, config: GroupCommitConfig) -> Self {
        BatchManager {
            state: std::sync::Mutex::new(BatchManagerState {
                current_batch: Vec::with_capacity(config.max_batch_size),
                current_batch_id: 0,
                next_uncommitted_batch_id: 0,
                shutdown: false,
            }),
            full_cv: std::sync::Condvar::new(),
            commit_cv: std::sync::Condvar::new(),
            buffer_capacity,
            config,
        }
    }

    /// Admit a decision into the currently-open batch. Returns the
    /// batch_id it landed in. Caller decides whether to wait.
    /// Always notifies the commit thread so it wakes from its idle
    /// wait when the batch transitions from empty to non-empty (and so
    /// the wait_timeout in the collect-window phase can exit early on
    /// reaching `max_batch_size`).
    fn admit(&self, decision: Decision) -> Result<u64, ReceiptError> {
        let mut state = self.state.lock().unwrap();
        if state.shutdown {
            return Err(ReceiptError::ShutdownInProgress);
        }
        if state.current_batch.len() >= self.buffer_capacity {
            return Err(ReceiptError::BufferFull);
        }
        let batch_id = state.current_batch_id;
        state.current_batch.push(decision);
        drop(state);
        self.full_cv.notify_one();
        Ok(batch_id)
    }

    /// Block until `batch_id` has been committed to disk.
    fn wait_for_commit(&self, batch_id: u64) {
        let mut state = self.state.lock().unwrap();
        while state.next_uncommitted_batch_id <= batch_id {
            state = self.commit_cv.wait(state).unwrap();
        }
    }

    /// Signal shutdown and wake the commit thread.
    fn signal_shutdown(&self) {
        let mut state = self.state.lock().unwrap();
        state.shutdown = true;
        drop(state);
        self.full_cv.notify_one();
    }
}

fn commit_loop(manager: Arc<BatchManager>, mut writer: LogWriter) {
    use std::time::Instant;

    loop {
        let mut state = manager.state.lock().unwrap();
        // Idle wait: park here until items arrive or shutdown.
        while state.current_batch.is_empty() {
            if state.shutdown {
                return;
            }
            state = manager.full_cv.wait(state).unwrap();
        }
        // Gather phase: hold the batch open until either (a) size
        // threshold hits, (b) window deadline elapses, or (c) shutdown.
        // Each emit's notify wakes the wait_timeout; we re-arm with the
        // remaining time so total gather is bounded by the window.
        let deadline = Instant::now() + manager.config.max_batch_window;
        while !state.shutdown
            && state.current_batch.len() < manager.config.max_batch_size
        {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline - now;
            let (s, result) = manager.full_cv.wait_timeout(state, remaining).unwrap();
            state = s;
            if result.timed_out() {
                break;
            }
        }
        let batch: Vec<Decision> = std::mem::take(&mut state.current_batch);
        let batch_id = state.current_batch_id;
        state.current_batch_id += 1;
        drop(state);

        for d in &batch {
            writer.append(d).expect("LogWriter::append in commit thread");
        }
        writer
            .sync()
            .expect("LogWriter::sync in commit thread");

        // Update under the state lock so the commit visibility and the
        // notify are strictly ordered with respect to any waiter in
        // wait_for_commit.
        let mut state = manager.state.lock().unwrap();
        state.next_uncommitted_batch_id = batch_id + 1;
        drop(state);
        manager.commit_cv.notify_all();
    }
}

// -----------------------------------------------------------------------
// Mode B1: blocking group-commit
// -----------------------------------------------------------------------

/// Mode B1 (spec §11.3): emit blocks until the containing batch has
/// fsync'd. Strongest durability of the three modes.
pub struct ModeB1ReceiptSink {
    manager: Arc<BatchManager>,
    shutdown: Arc<AtomicBool>,
    commit_handle: Mutex<Option<JoinHandle<()>>>,
}

impl ModeB1ReceiptSink {
    pub fn new(
        log_path: &Path,
        mac_key: [u8; 32],
        buffer_capacity: usize,
        commit_config: GroupCommitConfig,
    ) -> Result<Self, ReceiptError> {
        let writer = LogWriter::open(log_path, mac_key)?;
        let manager = Arc::new(BatchManager::new(buffer_capacity, commit_config));
        let shutdown = Arc::new(AtomicBool::new(false));
        let commit_handle = {
            let mgr = Arc::clone(&manager);
            thread::spawn(move || commit_loop(mgr, writer))
        };
        Ok(ModeB1ReceiptSink {
            manager,
            shutdown,
            commit_handle: Mutex::new(Some(commit_handle)),
        })
    }

    pub fn shutdown(self) -> Result<(), ReceiptError> {
        self.shutdown.store(true, Ordering::Release);
        self.manager.signal_shutdown();
        if let Some(h) = self.commit_handle.lock().unwrap().take() {
            let _ = h.join();
        }
        Ok(())
    }
}

impl ReceiptSink for ModeB1ReceiptSink {
    fn emit(&self, decision: &Decision) -> Result<EmitOutcome, ReceiptError> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(ReceiptError::ShutdownInProgress);
        }
        let batch_id = self.manager.admit(decision.clone())?;
        self.manager.wait_for_commit(batch_id);
        // batch_id is a Mode B2 concept per spec §11.3; Mode B1 leaves
        // it None on the outcome.
        Ok(EmitOutcome { batch_id: None })
    }
}

// -----------------------------------------------------------------------
// Mode B2: queued group-commit
// -----------------------------------------------------------------------

/// Mode B2 (spec §11.3): emit admits the decision into the current
/// batch and returns immediately with the batch_id. The background
/// commit thread fsyncs the batch later.
pub struct ModeB2ReceiptSink {
    manager: Arc<BatchManager>,
    shutdown: Arc<AtomicBool>,
    commit_handle: Mutex<Option<JoinHandle<()>>>,
}

impl ModeB2ReceiptSink {
    pub fn new(
        log_path: &Path,
        mac_key: [u8; 32],
        buffer_capacity: usize,
        commit_config: GroupCommitConfig,
    ) -> Result<Self, ReceiptError> {
        let writer = LogWriter::open(log_path, mac_key)?;
        let manager = Arc::new(BatchManager::new(buffer_capacity, commit_config));
        let shutdown = Arc::new(AtomicBool::new(false));
        let commit_handle = {
            let mgr = Arc::clone(&manager);
            thread::spawn(move || commit_loop(mgr, writer))
        };
        Ok(ModeB2ReceiptSink {
            manager,
            shutdown,
            commit_handle: Mutex::new(Some(commit_handle)),
        })
    }

    pub fn shutdown(self) -> Result<(), ReceiptError> {
        self.shutdown.store(true, Ordering::Release);
        self.manager.signal_shutdown();
        if let Some(h) = self.commit_handle.lock().unwrap().take() {
            let _ = h.join();
        }
        Ok(())
    }
}

impl ReceiptSink for ModeB2ReceiptSink {
    fn emit(&self, decision: &Decision) -> Result<EmitOutcome, ReceiptError> {
        if self.shutdown.load(Ordering::Acquire) {
            return Err(ReceiptError::ShutdownInProgress);
        }
        let batch_id = self.manager.admit(decision.clone())?;
        Ok(EmitOutcome {
            batch_id: Some(batch_id),
        })
    }
}
