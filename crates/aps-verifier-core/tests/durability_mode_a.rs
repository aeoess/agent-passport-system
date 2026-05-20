//! Chunk-8 tests: Mode A sink + shared log infrastructure +
//! aps_check emit integration.

mod common;

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tempfile::TempDir;

use aps_verifier_core::{
    aps_check, ApprovalAction, CompiledAuthority, Decision, DecisionType, LogWriter,
    ModeAReceiptSink, ReasonCode, ReceiptError, ReceiptSink, RuntimePassport, ToolEntry,
    ToolRegistry, VerifierContext, LOG_ENTRY_BYTES,
};

use common::{
    hash_from_hex, test_receipt_stream_key, ActionBuilder, PassportBuilder, RecordingSink,
    TestVerifier,
};

const TOOL_HEX_0: &str = "abcd000000000000000000000000000000000000000000000000000000000000";

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn tmp_log_path() -> (TempDir, PathBuf) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("receipts.log");
    (dir, path)
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

fn happy_action(sequence_id: u64) -> aps_verifier_core::ActionDescriptor {
    ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "123"])
        .with_sequence_id(sequence_id)
        .build()
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

// -----------------------------------------------------------------------
// LogWriter format tests
// -----------------------------------------------------------------------

#[test]
fn log_entry_round_trip() {
    let (_dir, path) = tmp_log_path();
    let mac_key = [0x77; 32];
    let mut w = LogWriter::open(&path, mac_key).unwrap();
    let d = sample_decision();
    w.append(&d).unwrap();
    w.flush().unwrap();
    drop(w);

    // Reopen scans the chain successfully.
    let w2 = LogWriter::open(&path, mac_key).expect("reopen ok");
    assert_eq!(w2.entries_written(), 1);
    // Raw file should be exactly one framed entry.
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.len(), LOG_ENTRY_BYTES);
}

#[test]
fn log_rolling_mac_chain() {
    let (_dir, path) = tmp_log_path();
    let mac_key = [0x77; 32];
    let mut w = LogWriter::open(&path, mac_key).unwrap();
    for i in 0..10u64 {
        let mut d = sample_decision();
        d.sequence_id = i;
        w.append(&d).unwrap();
    }
    w.flush().unwrap();
    let final_mac = *w.current_mac();
    drop(w);

    // Reopen recomputes the same final mac.
    let w2 = LogWriter::open(&path, mac_key).unwrap();
    assert_eq!(w2.current_mac(), &final_mac);
    assert_eq!(w2.entries_written(), 10);
}

#[test]
fn log_open_resumes_chain() {
    let (_dir, path) = tmp_log_path();
    let mac_key = [0x77; 32];

    let mut w1 = LogWriter::open(&path, mac_key).unwrap();
    for i in 0..5u64 {
        let mut d = sample_decision();
        d.sequence_id = i;
        w1.append(&d).unwrap();
    }
    w1.flush().unwrap();
    let mid_mac = *w1.current_mac();
    drop(w1);

    let mut w2 = LogWriter::open(&path, mac_key).unwrap();
    assert_eq!(w2.current_mac(), &mid_mac);
    for i in 5..10u64 {
        let mut d = sample_decision();
        d.sequence_id = i;
        w2.append(&d).unwrap();
    }
    w2.flush().unwrap();
    assert_eq!(w2.entries_written(), 10);
    drop(w2);

    let w3 = LogWriter::open(&path, mac_key).unwrap();
    assert_eq!(w3.entries_written(), 10);
}

#[test]
fn log_open_detects_corruption() {
    use std::io::{Seek, SeekFrom, Write};
    let (_dir, path) = tmp_log_path();
    let mac_key = [0x77; 32];

    let mut w = LogWriter::open(&path, mac_key).unwrap();
    for _ in 0..3 {
        w.append(&sample_decision()).unwrap();
    }
    w.flush().unwrap();
    drop(w);

    // Flip a byte well inside entry 1's payload.
    let entry_size = LOG_ENTRY_BYTES;
    let target = (entry_size + 50) as u64;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap();
    f.seek(SeekFrom::Start(target)).unwrap();
    f.write_all(&[0xFF]).unwrap();
    drop(f);

    let result = LogWriter::open(&path, mac_key);
    assert!(result.is_err(), "expected open to detect tamper");
}

// -----------------------------------------------------------------------
// Mode A sink behavior
// -----------------------------------------------------------------------

#[test]
fn mode_a_emit_pushes_to_buffer() {
    let (_dir, path) = tmp_log_path();
    let sink = ModeAReceiptSink::new(
        &path,
        test_receipt_stream_key(),
        64,
        Duration::from_secs(60), // long interval so nothing flushes during the test
    )
    .unwrap();
    sink.emit(&sample_decision()).unwrap();
    // Log on disk is still empty (background hasn't fired).
    let bytes_on_disk = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    assert_eq!(bytes_on_disk, 0);
    sink.shutdown().unwrap();
}

#[test]
fn mode_a_background_flush_writes_to_log() {
    let (_dir, path) = tmp_log_path();
    let sink = ModeAReceiptSink::new(
        &path,
        test_receipt_stream_key(),
        64,
        Duration::from_millis(50),
    )
    .unwrap();
    sink.emit(&sample_decision()).unwrap();
    // Wait long enough for at least one background tick.
    thread::sleep(Duration::from_millis(250));
    let len = std::fs::metadata(&path).unwrap().len();
    assert!(
        len >= LOG_ENTRY_BYTES as u64,
        "expected at least one entry on disk, got {len} bytes"
    );
    sink.shutdown().unwrap();
}

#[test]
fn mode_a_shutdown_flushes_pending() {
    let (_dir, path) = tmp_log_path();
    let sink = ModeAReceiptSink::new(
        &path,
        test_receipt_stream_key(),
        64,
        Duration::from_secs(60), // never fires during test
    )
    .unwrap();
    for _ in 0..10 {
        sink.emit(&sample_decision()).unwrap();
    }
    sink.shutdown().unwrap();
    let len = std::fs::metadata(&path).unwrap().len();
    assert_eq!(len, (LOG_ENTRY_BYTES * 10) as u64);

    // Reopen and confirm chain validates.
    let w = LogWriter::open(&path, test_receipt_stream_key()).unwrap();
    assert_eq!(w.entries_written(), 10);
}

#[test]
fn mode_a_buffer_full_returns_err() {
    let (_dir, path) = tmp_log_path();
    let sink = ModeAReceiptSink::new(
        &path,
        test_receipt_stream_key(),
        4,
        Duration::from_secs(60), // never fires; buffer fills
    )
    .unwrap();
    for _ in 0..4 {
        sink.emit(&sample_decision()).unwrap();
    }
    match sink.emit(&sample_decision()) {
        Err(ReceiptError::BufferFull) => {}
        other => panic!("expected BufferFull, got {other:?}"),
    }
    sink.shutdown().unwrap();
}

#[test]
fn mode_a_concurrent_emit() {
    let (_dir, path) = tmp_log_path();
    let sink = Arc::new(
        ModeAReceiptSink::new(
            &path,
            test_receipt_stream_key(),
            256,
            Duration::from_millis(20),
        )
        .unwrap(),
    );
    let mut handles = Vec::new();
    for _ in 0..10 {
        let s = Arc::clone(&sink);
        handles.push(thread::spawn(move || {
            s.emit(&sample_decision()).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    // Take exclusive ownership for shutdown.
    let sink = match Arc::try_unwrap(sink) {
        Ok(s) => s,
        Err(_) => panic!("Arc still has outstanding refs after joining threads"),
    };
    sink.shutdown().unwrap();
    let w = LogWriter::open(&path, test_receipt_stream_key()).unwrap();
    assert_eq!(w.entries_written(), 10);
}

// -----------------------------------------------------------------------
// aps_check integration
// -----------------------------------------------------------------------

#[test]
fn allow_emits_to_sink() {
    let (auth, _reg) = happy_setup();
    let action = happy_action(1000);
    let v = TestVerifier::new();
    let sink = RecordingSink::new();
    let ctx = VerifierContext::with_sink(
        &v.clock,
        v.instance_id_hash,
        v.attested_tier,
        v.revocation_epoch,
        &sink,
    );
    let d = aps_check(&auth, &action, &ctx);
    assert_eq!(d.decision_type as u8, DecisionType::Allow as u8);
    assert_eq!(sink.count(), 1);
    let recorded = sink.recorded();
    assert_eq!(recorded[0].sequence_id, action.sequence_id);
    assert_eq!(recorded[0].event_mac, d.event_mac);
}

#[test]
fn deny_does_not_emit_to_sink() {
    let (auth, _reg) = happy_setup();
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["unrelated"]) // ResourceOutOfScope
        .build();
    let v = TestVerifier::new();
    let sink = RecordingSink::new();
    let ctx = VerifierContext::with_sink(
        &v.clock,
        v.instance_id_hash,
        v.attested_tier,
        v.revocation_epoch,
        &sink,
    );
    let d = aps_check(&auth, &action, &ctx);
    assert_eq!(d.decision_type as u8, DecisionType::Deny as u8);
    assert_eq!(sink.count(), 0, "deny must not emit per spec §9 step 13");
}

#[test]
fn escalate_does_not_emit_to_sink() {
    // Build an authority with an Escalate rule that the happy action
    // matches.
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
        .with_approval_rules(vec![(
            "operation == read AND cost_units > 0".into(),
            ApprovalAction::Escalate,
        )])
        .build_json();
    let passport = RuntimePassport::from_json(&json).unwrap();
    let auth = CompiledAuthority::from_passport(&passport, registry_for_compile).unwrap();

    let action = happy_action(1000);
    let v = TestVerifier::new();
    let sink = RecordingSink::new();
    let ctx = VerifierContext::with_sink(
        &v.clock,
        v.instance_id_hash,
        v.attested_tier,
        v.revocation_epoch,
        &sink,
    );
    let d = aps_check(&auth, &action, &ctx);
    assert_eq!(d.decision_type as u8, DecisionType::Escalate as u8);
    assert_eq!(sink.count(), 0, "escalate must not emit per spec §9");
}

#[test]
fn allow_emit_uses_full_decision() {
    let (auth, _reg) = happy_setup();
    let action = happy_action(1000);
    let v = TestVerifier::new();
    let sink = RecordingSink::new();
    let ctx = VerifierContext::with_sink(
        &v.clock,
        v.instance_id_hash,
        v.attested_tier,
        v.revocation_epoch,
        &sink,
    );
    let d = aps_check(&auth, &action, &ctx);
    let recorded = sink.recorded();
    assert_eq!(recorded.len(), 1);
    let r = &recorded[0];
    assert_ne!(r.event_mac, [0u8; 32]);
    assert_eq!(r.sequence_id, d.sequence_id);
    assert_eq!(r.decision_id, d.decision_id);
}

#[test]
fn mode_a_aps_check_end_to_end() {
    let (auth, _reg) = happy_setup();
    let v = TestVerifier::new();
    let (_dir, path) = tmp_log_path();
    let sink = ModeAReceiptSink::new(
        &path,
        test_receipt_stream_key(),
        64,
        Duration::from_secs(60),
    )
    .unwrap();
    let ctx = VerifierContext::with_sink(
        &v.clock,
        v.instance_id_hash,
        v.attested_tier,
        v.revocation_epoch,
        &sink,
    );
    for i in 0..5u64 {
        let action = happy_action(1000 + i);
        let d = aps_check(&auth, &action, &ctx);
        assert_eq!(d.decision_type as u8, DecisionType::Allow as u8);
    }
    sink.shutdown().unwrap();

    let w = LogWriter::open(&path, test_receipt_stream_key()).unwrap();
    assert_eq!(w.entries_written(), 5);
}
