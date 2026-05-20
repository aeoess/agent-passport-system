//! Chunk-9a Mode B1 (blocking group-commit) tests.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use aps_verifier_core::{
    aps_check, CompiledAuthority, Decision, DecisionType, LogWriter, ModeB1ReceiptSink,
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
fn b1_emit_blocks_until_fsync() {
    let (_dir, path) = tmp_log_path();
    // 30ms window: single emit must wait the whole window before commit.
    let cfg = aps_verifier_core::GroupCommitConfig {
        max_batch_size: 1024, // far above 1 so size-trigger doesn't fire
        max_batch_window: Duration::from_millis(30),
    };
    let sink = ModeB1ReceiptSink::new(&path, test_receipt_stream_key(), 256, cfg).unwrap();
    let start = Instant::now();
    sink.emit(&sample_decision()).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_millis(20),
        "B1 emit must block for window; observed {:?}",
        elapsed
    );
    sink.shutdown().unwrap();
}

#[test]
fn b1_batch_size_triggers_commit() {
    let (_dir, path) = tmp_log_path();
    // Long window, but batch_size=8 means 8 concurrent emits fire commit.
    let cfg = aps_verifier_core::GroupCommitConfig {
        max_batch_size: 8,
        max_batch_window: Duration::from_secs(60),
    };
    let sink = Arc::new(ModeB1ReceiptSink::new(&path, test_receipt_stream_key(), 256, cfg).unwrap());
    let start = Instant::now();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let s = Arc::clone(&sink);
        handles.push(thread::spawn(move || s.emit(&sample_decision()).unwrap()));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "size-trigger must fire well before 60s window"
    );
    let sink = match Arc::try_unwrap(sink) {
        Ok(s) => s,
        Err(_) => panic!("Arc outstanding"),
    };
    sink.shutdown().unwrap();
}

#[test]
fn b1_emit_all_persisted() {
    let (_dir, path) = tmp_log_path();
    let sink =
        ModeB1ReceiptSink::new(&path, test_receipt_stream_key(), 256, test_commit_config()).unwrap();
    for _ in 0..20 {
        sink.emit(&sample_decision()).unwrap();
    }
    // After the last B1 emit returns, all those decisions are durable.
    let len_before_shutdown = std::fs::metadata(&path).unwrap().len();
    assert!(
        len_before_shutdown >= (20u64 * aps_verifier_core::LOG_ENTRY_BYTES as u64),
        "expected 20 entries durable after B1 emits, got {} bytes",
        len_before_shutdown
    );
    sink.shutdown().unwrap();
}

#[test]
fn b1_shutdown_completes_pending() {
    let (_dir, path) = tmp_log_path();
    let sink =
        ModeB1ReceiptSink::new(&path, test_receipt_stream_key(), 256, test_commit_config()).unwrap();
    sink.emit(&sample_decision()).unwrap();
    sink.shutdown().unwrap();
    let w = LogWriter::open(&path, test_receipt_stream_key()).unwrap();
    assert_eq!(w.entries_written(), 1);
}

#[test]
fn b1_concurrent_emits_chain_intact() {
    let (_dir, path) = tmp_log_path();
    let sink =
        Arc::new(ModeB1ReceiptSink::new(&path, test_receipt_stream_key(), 512, test_commit_config()).unwrap());
    let mut handles = Vec::new();
    for _ in 0..50 {
        let s = Arc::clone(&sink);
        handles.push(thread::spawn(move || s.emit(&sample_decision()).unwrap()));
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
fn b1_aps_check_end_to_end() {
    let (auth, _reg) = happy_setup();
    let v = TestVerifier::new();
    let (_dir, path) = tmp_log_path();
    let sink =
        ModeB1ReceiptSink::new(&path, test_receipt_stream_key(), 256, test_commit_config()).unwrap();
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
