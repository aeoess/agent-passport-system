//! Chunk-9a Mode B2 (queued group-commit) tests.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use aps_verifier_core::{
    aps_check, CompiledAuthority, Decision, DecisionType, LogWriter, ModeB2ReceiptSink,
    ReasonCode, ReceiptSink, RuntimePassport, ToolEntry, ToolRegistry, VerifierContext,
};

use common::{
    hash_from_hex, test_commit_config, test_receipt_stream_key, ActionBuilder, PassportBuilder,
    TestVerifier,
};

const TOOL_HEX_0: &str = "abcd000000000000000000000000000000000000000000000000000000000000";

fn tmp_log_path() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("receipts.log");
    (dir, path)
}

fn sample_decision() -> Decision {
    Decision {
        decision_type: DecisionType::Allow,
        reason_code: ReasonCode::Ok,
        reserved: [0; 6],
        sequence_id: 42,
        decision_id: [0xAB; 16],
        event_mac: [0xCD; 32],
    }
}

fn happy_setup() -> (CompiledAuthority, ToolRegistry) {
    let mut reg = ToolRegistry::new();
    reg.add(hash_from_hex(TOOL_HEX_0), 0).unwrap();
    let registry_for_compile = ToolRegistry::from_entries(vec![ToolEntry {
        descriptor_hash: hash_from_hex(TOOL_HEX_0),
        local_id: 0,
    }])
    .unwrap();
    let root = reg.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_risk_class("R2")
        .with_tier("T2", "T2")
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(vec!["customer/*"])
        .build_json();
    let passport = RuntimePassport::from_json(&json).unwrap();
    let auth = CompiledAuthority::from_passport(&passport, registry_for_compile).unwrap();
    (auth, reg)
}

#[test]
fn b2_emit_returns_immediately() {
    let (_dir, path) = tmp_log_path();
    let cfg = aps_verifier_core::GroupCommitConfig {
        max_batch_size: 64,
        max_batch_window: Duration::from_millis(100), // long window
    };
    let sink = ModeB2ReceiptSink::new(&path, test_receipt_stream_key(), 256, cfg).unwrap();
    let start = Instant::now();
    sink.emit(&sample_decision()).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_millis(20),
        "B2 emit must NOT wait for window; observed {:?}",
        elapsed
    );
    sink.shutdown().unwrap();
}

#[test]
fn b2_emit_returns_batch_id() {
    let (_dir, path) = tmp_log_path();
    let sink =
        ModeB2ReceiptSink::new(&path, test_receipt_stream_key(), 256, test_commit_config()).unwrap();
    let out = sink.emit(&sample_decision()).unwrap();
    assert!(out.batch_id.is_some(), "Mode B2 must return Some(batch_id)");
    sink.shutdown().unwrap();
}

#[test]
fn b2_emits_within_window_share_batch_id() {
    let (_dir, path) = tmp_log_path();
    // Long window so multiple emits accumulate in the same batch.
    let cfg = aps_verifier_core::GroupCommitConfig {
        max_batch_size: 64,
        max_batch_window: Duration::from_millis(200),
    };
    let sink = ModeB2ReceiptSink::new(&path, test_receipt_stream_key(), 256, cfg).unwrap();
    let ids: Vec<_> = (0..5)
        .map(|_| sink.emit(&sample_decision()).unwrap().batch_id.unwrap())
        .collect();
    let first = ids[0];
    for id in &ids[1..] {
        assert_eq!(*id, first, "all emits inside one window share batch_id");
    }
    sink.shutdown().unwrap();
}

#[test]
fn b2_emits_across_windows_get_different_batch_ids() {
    let (_dir, path) = tmp_log_path();
    let cfg = aps_verifier_core::GroupCommitConfig {
        max_batch_size: 64,
        max_batch_window: Duration::from_millis(20),
    };
    let sink = ModeB2ReceiptSink::new(&path, test_receipt_stream_key(), 256, cfg).unwrap();
    let first = sink.emit(&sample_decision()).unwrap().batch_id.unwrap();
    thread::sleep(Duration::from_millis(80)); // well past 2x window
    let second = sink.emit(&sample_decision()).unwrap().batch_id.unwrap();
    assert!(
        second > first,
        "second batch_id must be > first; got first={} second={}",
        first,
        second
    );
    sink.shutdown().unwrap();
}

#[test]
fn b2_eventually_persists() {
    let (_dir, path) = tmp_log_path();
    let sink =
        ModeB2ReceiptSink::new(&path, test_receipt_stream_key(), 256, test_commit_config()).unwrap();
    sink.emit(&sample_decision()).unwrap();
    // Poll for up to 200ms.
    let deadline = Instant::now() + Duration::from_millis(200);
    loop {
        let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        if len >= aps_verifier_core::LOG_ENTRY_BYTES as u64 {
            break;
        }
        if Instant::now() > deadline {
            panic!("B2 entry did not persist within 200ms");
        }
        thread::sleep(Duration::from_millis(5));
    }
    sink.shutdown().unwrap();
}

#[test]
fn b2_shutdown_persists_pending() {
    let (_dir, path) = tmp_log_path();
    // Long window: nothing background-commits unless shutdown forces it.
    let cfg = aps_verifier_core::GroupCommitConfig {
        max_batch_size: 256,
        max_batch_window: Duration::from_secs(60),
    };
    let sink = ModeB2ReceiptSink::new(&path, test_receipt_stream_key(), 256, cfg).unwrap();
    for _ in 0..10 {
        sink.emit(&sample_decision()).unwrap();
    }
    sink.shutdown().unwrap();
    let w = LogWriter::open(&path, test_receipt_stream_key()).unwrap();
    assert_eq!(w.entries_written(), 10);
}

#[test]
fn b2_concurrent_emits_chain_intact() {
    let (_dir, path) = tmp_log_path();
    let sink =
        Arc::new(ModeB2ReceiptSink::new(&path, test_receipt_stream_key(), 512, test_commit_config()).unwrap());
    let mut handles = Vec::new();
    for _ in 0..50 {
        let s = Arc::clone(&sink);
        handles.push(thread::spawn(move || {
            s.emit(&sample_decision()).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let sink = match Arc::try_unwrap(sink) {
        Ok(s) => s,
        Err(_) => panic!("Arc outstanding"),
    };
    sink.shutdown().unwrap();
    let w = LogWriter::open(&path, test_receipt_stream_key()).expect("chain validates");
    assert_eq!(w.entries_written(), 50);
}

#[test]
fn b2_aps_check_end_to_end() {
    let (auth, _reg) = happy_setup();
    let v = TestVerifier::new();
    let (_dir, path) = tmp_log_path();
    let sink =
        ModeB2ReceiptSink::new(&path, test_receipt_stream_key(), 256, test_commit_config()).unwrap();
    let ctx = VerifierContext::with_sink(
        &v.clock,
        v.instance_id_hash,
        v.attested_tier,
        v.revocation_epoch,
        &sink,
    );
    for i in 0..5u64 {
        let action = ActionBuilder::new()
            .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
            .with_local_tool_id(0)
            .with_resource_path(&["customer", "123"])
            .with_sequence_id(1000 + i)
            .build();
        let d = aps_check(&auth, &action, &ctx);
        assert_eq!(d.decision_type as u8, DecisionType::Allow as u8);
    }
    sink.shutdown().unwrap();
    let w = LogWriter::open(&path, test_receipt_stream_key()).unwrap();
    assert_eq!(w.entries_written(), 5);
}
