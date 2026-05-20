//! Chunk-9b tests: crash recovery + SEQUENCE_RECOVERY_INVALID.

mod common;

use std::path::PathBuf;
use std::sync::atomic::Ordering;
use tempfile::TempDir;

use aps_verifier_core::{
    aps_check, recover_log, CompileError, CompiledAuthority, Decision, DecisionType, LogWriter,
    ModeB1ReceiptSink, ReasonCode, RecoveryError, RecoveryStatus, RuntimePassport, ToolEntry,
    ToolRegistry, TruncationReason, VerifierContext, LOG_ENTRY_BYTES,
};

use common::{
    corrupt_log_byte, hash_from_hex, test_commit_config, test_receipt_stream_key, truncate_log,
    write_test_log, ActionBuilder, PassportBuilder, TestVerifier,
};

const TOOL_HEX_0: &str = "abcd000000000000000000000000000000000000000000000000000000000000";

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

fn empty_tmp_log() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("receipts.log");
    (dir, path)
}

fn happy_passport(sequence_start: u64, sequence_end: u64) -> RuntimePassport {
    let registry_for_compile = ToolRegistry::from_entries(vec![ToolEntry {
        descriptor_hash: hash_from_hex(TOOL_HEX_0),
        local_id: 0,
    }])
    .unwrap();
    let root = registry_for_compile.current_root();
    let json = PassportBuilder::new()
        .with_root(root)
        .with_risk_class("R2")
        .with_tier("T2", "T2")
        .with_sequence_window(sequence_start, sequence_end)
        .with_allowed_tools(vec![hash_from_hex(TOOL_HEX_0)])
        .with_allowed_operations(vec!["read"])
        .with_resource_scopes(vec!["customer/*"])
        .build_json();
    RuntimePassport::from_json(&json).unwrap()
}

fn happy_registry() -> ToolRegistry {
    ToolRegistry::from_entries(vec![ToolEntry {
        descriptor_hash: hash_from_hex(TOOL_HEX_0),
        local_id: 0,
    }])
    .unwrap()
}

// -----------------------------------------------------------------------
// Recovery-only paths
// -----------------------------------------------------------------------

#[test]
fn recovery_missing_file_is_fresh_start() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("does-not-exist.log");
    let report = recover_log(&path, test_receipt_stream_key()).unwrap();
    assert_eq!(report.status, RecoveryStatus::FreshStart);
    assert_eq!(report.entries_recovered, 0);
    assert_eq!(report.last_committed_sequence_id, 0);
    assert_eq!(report.last_rolling_mac, [0u8; 32]);
}

#[test]
fn recovery_empty_file_is_fresh_start() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("empty.log");
    std::fs::File::create(&path).unwrap();
    let report = recover_log(&path, test_receipt_stream_key()).unwrap();
    assert_eq!(report.status, RecoveryStatus::FreshStart);
}

#[test]
fn recovery_single_valid_entry_clean() {
    let (_dir, path) = write_test_log(1, 1000, &test_receipt_stream_key());
    let report = recover_log(&path, test_receipt_stream_key()).unwrap();
    assert_eq!(report.status, RecoveryStatus::CleanRecovery);
    assert_eq!(report.entries_recovered, 1);
    assert_eq!(report.last_committed_sequence_id, 1000);
    assert_eq!(report.valid_through_offset, LOG_ENTRY_BYTES as u64);
}

#[test]
fn recovery_ten_valid_entries_clean() {
    let (_dir, path) = write_test_log(10, 1000, &test_receipt_stream_key());
    let report = recover_log(&path, test_receipt_stream_key()).unwrap();
    assert_eq!(report.status, RecoveryStatus::CleanRecovery);
    assert_eq!(report.entries_recovered, 10);
    assert_eq!(report.last_committed_sequence_id, 1009);
}

#[test]
fn recovery_first_entry_mac_mismatch() {
    let (_dir, path) = write_test_log(1, 1000, &test_receipt_stream_key());
    // Corrupt a byte inside entry 0's rolling_mac (bytes 4+64..4+96).
    corrupt_log_byte(&path, 4 + 64 + 5).unwrap();
    match recover_log(&path, test_receipt_stream_key()) {
        Err(RecoveryError::InitialMacFailure) => {}
        other => panic!("expected InitialMacFailure, got {other:?}"),
    }
}

#[test]
fn recovery_first_entry_payload_mismatch() {
    let (_dir, path) = write_test_log(1, 1000, &test_receipt_stream_key());
    // Corrupt a byte inside entry 0's Decision payload (bytes 4..4+64).
    corrupt_log_byte(&path, 4 + 12).unwrap();
    match recover_log(&path, test_receipt_stream_key()) {
        Err(RecoveryError::InitialMacFailure) => {}
        other => panic!("expected InitialMacFailure, got {other:?}"),
    }
}

#[test]
fn recovery_mid_chain_mac_mismatch() {
    let (_dir, path) = write_test_log(10, 1000, &test_receipt_stream_key());
    // Corrupt rolling_mac inside entry 5 (0-indexed): start at offset
    // 5 * LOG_ENTRY_BYTES + 4 + 64.
    let target = 5 * LOG_ENTRY_BYTES as u64 + 4 + 64 + 1;
    corrupt_log_byte(&path, target).unwrap();
    let report = recover_log(&path, test_receipt_stream_key()).unwrap();
    match report.status {
        RecoveryStatus::PartialRecovery {
            reason: TruncationReason::MacMismatch { at_entry: 5 },
            ..
        } => {}
        other => panic!("expected MacMismatch at entry 5, got {other:?}"),
    }
    assert_eq!(report.entries_recovered, 5);
    assert_eq!(report.last_committed_sequence_id, 1004);
}

#[test]
fn recovery_truncated_at_length_prefix() {
    let (_dir, path) = write_test_log(5, 1000, &test_receipt_stream_key());
    // Truncate so the 5th entry's length prefix is incomplete: lop 50
    // bytes off the end (5th entry's full size is 100; cutting 50
    // leaves an incomplete payload but the prefix is still intact).
    // Adjust to truncate inside the prefix itself: chop 99 bytes leaves
    // a 1-byte prefix in entry 5.
    let full_len = 5 * LOG_ENTRY_BYTES as u64;
    truncate_log(&path, full_len - 99).unwrap();
    let report = recover_log(&path, test_receipt_stream_key()).unwrap();
    match report.status {
        RecoveryStatus::PartialRecovery {
            reason: TruncationReason::IncompleteEntry,
            ..
        } => {}
        other => panic!("expected IncompleteEntry, got {other:?}"),
    }
    assert_eq!(report.entries_recovered, 4);
}

#[test]
fn recovery_truncated_at_payload() {
    let (_dir, path) = write_test_log(5, 1000, &test_receipt_stream_key());
    // Truncate so the 5th entry has the full 4-byte length prefix but
    // only part of its 96-byte payload.
    let full_len = 5 * LOG_ENTRY_BYTES as u64;
    truncate_log(&path, full_len - 50).unwrap();
    let report = recover_log(&path, test_receipt_stream_key()).unwrap();
    match report.status {
        RecoveryStatus::PartialRecovery {
            reason: TruncationReason::IncompleteEntry,
            ..
        } => {}
        other => panic!("expected IncompleteEntry, got {other:?}"),
    }
    assert_eq!(report.entries_recovered, 4);
}

#[test]
fn recovery_invalid_length_prefix() {
    let (_dir, path) = write_test_log(1, 1000, &test_receipt_stream_key());
    // Append a 4-byte length prefix valued 999.
    let mut f = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
    use std::io::Write;
    f.write_all(&999u32.to_le_bytes()).unwrap();
    drop(f);
    let report = recover_log(&path, test_receipt_stream_key()).unwrap();
    match report.status {
        RecoveryStatus::PartialRecovery {
            reason: TruncationReason::InvalidLength { length: 999, at_entry: 1 },
            ..
        } => {}
        other => panic!("expected InvalidLength(999) at entry 1, got {other:?}"),
    }
    assert_eq!(report.entries_recovered, 1);
}

#[test]
fn recovery_wrong_mac_key() {
    let (_dir, path) = write_test_log(5, 1000, &[0x77; 32]);
    match recover_log(&path, [0x99; 32]) {
        Err(RecoveryError::InitialMacFailure) => {}
        other => panic!("expected InitialMacFailure on key mismatch, got {other:?}"),
    }
}

#[test]
fn recovery_clean_chain_continuation() {
    let key = test_receipt_stream_key();
    let (_dir, path) = write_test_log(5, 1000, &key);
    // Reopen via LogWriter (which scans + resumes), append 5 more.
    let mut w = LogWriter::open(&path, key).unwrap();
    assert_eq!(w.entries_written(), 5);
    for i in 5..10u64 {
        let d = Decision {
            decision_type: DecisionType::Allow,
            reason_code: ReasonCode::Ok,
            reserved: [0; 6],
            sequence_id: 1000 + i,
            decision_id: [0; 16],
            event_mac: [0; 32],
        };
        w.append(&d).unwrap();
    }
    w.flush().unwrap();
    drop(w);

    let report = recover_log(&path, key).unwrap();
    assert_eq!(report.status, RecoveryStatus::CleanRecovery);
    assert_eq!(report.entries_recovered, 10);
    assert_eq!(report.last_committed_sequence_id, 1009);
}

// -----------------------------------------------------------------------
// CompiledAuthority integration
// -----------------------------------------------------------------------

#[test]
fn authority_with_recovery_fresh_start() {
    let (_dir, path) = empty_tmp_log();
    let passport = happy_passport(1000, 2000);
    let registry = happy_registry();
    let (auth, report) = CompiledAuthority::from_passport_with_recovery(
        &passport,
        &registry,
        &path,
        test_receipt_stream_key(),
    )
    .unwrap();
    assert_eq!(report.status, RecoveryStatus::FreshStart);
    assert_eq!(auth.recovered_floor.load(Ordering::Acquire), 0);
    assert_eq!(auth.sequence_next.load(Ordering::Acquire), 1000);
}

#[test]
fn authority_with_recovery_resumes_correctly() {
    let key = test_receipt_stream_key();
    let (_dir, path) = write_test_log(5, 1000, &key);
    let passport = happy_passport(1000, 2000);
    let registry = happy_registry();
    let (auth, report) =
        CompiledAuthority::from_passport_with_recovery(&passport, &registry, &path, key).unwrap();
    assert_eq!(report.status, RecoveryStatus::CleanRecovery);
    assert_eq!(report.entries_recovered, 5);
    assert_eq!(report.last_committed_sequence_id, 1004);
    assert_eq!(auth.recovered_floor.load(Ordering::Acquire), 1004);
    assert_eq!(auth.sequence_next.load(Ordering::Acquire), 1005);
}

#[test]
fn authority_recovery_log_passport_mismatch_below() {
    let key = test_receipt_stream_key();
    let (_dir, path) = write_test_log(1, 500, &key);
    let passport = happy_passport(1000, 2000);
    let registry = happy_registry();
    match CompiledAuthority::from_passport_with_recovery(&passport, &registry, &path, key) {
        Err(CompileError::LogPassportMismatch {
            recovered_floor: 500,
            sequence_start: 1000,
            ..
        }) => {}
        other => panic!("expected LogPassportMismatch (below), got {other:?}"),
    }
}

#[test]
fn authority_recovery_log_passport_mismatch_above() {
    let key = test_receipt_stream_key();
    // Log floor at 2500; passport window ends at 2000.
    let (_dir, path) = write_test_log(1, 2500, &key);
    let passport = happy_passport(1000, 2000);
    let registry = happy_registry();
    match CompiledAuthority::from_passport_with_recovery(&passport, &registry, &path, key) {
        Err(CompileError::LogPassportMismatch {
            recovered_floor: 2500,
            sequence_end: 2000,
            ..
        }) => {}
        other => panic!("expected LogPassportMismatch (above), got {other:?}"),
    }
}

#[test]
fn authority_recovery_initial_mac_failure() {
    let key = test_receipt_stream_key();
    let (_dir, path) = write_test_log(1, 1000, &key);
    corrupt_log_byte(&path, 4 + 64 + 5).unwrap();
    let passport = happy_passport(1000, 2000);
    let registry = happy_registry();
    match CompiledAuthority::from_passport_with_recovery(&passport, &registry, &path, key) {
        Err(CompileError::RecoveryFailed(RecoveryError::InitialMacFailure)) => {}
        other => panic!("expected RecoveryFailed(InitialMacFailure), got {other:?}"),
    }
}

// -----------------------------------------------------------------------
// aps_check with recovery
// -----------------------------------------------------------------------

fn auth_with_floor(floor: u64, key: [u8; 32]) -> (CompiledAuthority, TempDir, PathBuf) {
    let (dir, path) = write_test_log(floor - 999, 1000, &key);
    let passport = happy_passport(1000, 2000);
    let registry = happy_registry();
    let (auth, _) =
        CompiledAuthority::from_passport_with_recovery(&passport, &registry, &path, key).unwrap();
    assert_eq!(auth.recovered_floor.load(Ordering::Acquire), floor);
    (auth, dir, path)
}

#[test]
fn aps_check_below_floor_returns_recovery_invalid() {
    let key = test_receipt_stream_key();
    let (auth, _dir, _path) = auth_with_floor(1004, key);
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "x"])
        .with_sequence_id(1000)
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::SequenceRecoveryInvalid as u8);
}

#[test]
fn aps_check_at_floor_returns_recovery_invalid() {
    let key = test_receipt_stream_key();
    let (auth, _dir, _path) = auth_with_floor(1004, key);
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "x"])
        .with_sequence_id(1004)
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::SequenceRecoveryInvalid as u8);
}

#[test]
fn aps_check_above_floor_proceeds() {
    let key = test_receipt_stream_key();
    let (auth, _dir, _path) = auth_with_floor(1004, key);
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "x"])
        .with_sequence_id(1005)
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.decision_type as u8, DecisionType::Allow as u8);
}

#[test]
fn aps_check_above_floor_replay_returns_normal_replay() {
    // floor=1004, sequence_next=1005. Action at 1010 is above floor
    // (skips recovery check) but doesn't match sequence_next (returns
    // SequenceReplay, NOT SequenceRecoveryInvalid).
    let key = test_receipt_stream_key();
    let (auth, _dir, _path) = auth_with_floor(1004, key);
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "x"])
        .with_sequence_id(1010)
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::SequenceReplay as u8);
}

#[test]
fn aps_check_fresh_start_no_floor_check() {
    let (_dir, path) = empty_tmp_log();
    let passport = happy_passport(1000, 2000);
    let registry = happy_registry();
    let (auth, _) = CompiledAuthority::from_passport_with_recovery(
        &passport,
        &registry,
        &path,
        test_receipt_stream_key(),
    )
    .unwrap();
    assert_eq!(auth.recovered_floor.load(Ordering::Acquire), 0);
    let action = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "x"])
        .with_sequence_id(1000)
        .build();
    let d = aps_check(&auth, &action, &TestVerifier::new().context());
    assert_eq!(d.decision_type as u8, DecisionType::Allow as u8);
}

// -----------------------------------------------------------------------
// End-to-end crash simulation
// -----------------------------------------------------------------------

#[test]
fn end_to_end_b1_crash_recovery() {
    let key = test_receipt_stream_key();
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("receipts.log");
    let passport = happy_passport(1000, 2000);
    let registry = happy_registry();

    // Phase 1: fresh start, emit 5 Allow decisions through Mode B1.
    {
        let (auth, report) =
            CompiledAuthority::from_passport_with_recovery(&passport, &registry, &path, key)
                .unwrap();
        assert_eq!(report.status, RecoveryStatus::FreshStart);
        let v = TestVerifier::new();
        let sink = ModeB1ReceiptSink::new(&path, key, 256, test_commit_config()).unwrap();
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
                .with_resource_path(&["customer", "x"])
                .with_sequence_id(1000 + i)
                .build();
            let d = aps_check(&auth, &action, &ctx);
            assert_eq!(d.decision_type as u8, DecisionType::Allow as u8, "phase1 step {i}");
        }
        // B1 emits are durable on return; shutdown to release the file
        // handle but the data is already fsync'd.
        sink.shutdown().unwrap();
    }

    // Phase 2: simulated crash recovery. New authority, recovery walks
    // the log and resumes at floor + 1.
    let (auth, report) =
        CompiledAuthority::from_passport_with_recovery(&passport, &registry, &path, key).unwrap();
    assert_eq!(report.status, RecoveryStatus::CleanRecovery);
    assert_eq!(report.last_committed_sequence_id, 1004);
    assert_eq!(auth.recovered_floor.load(Ordering::Acquire), 1004);
    assert_eq!(auth.sequence_next.load(Ordering::Acquire), 1005);

    // Replay attempt: action at 1003 (pre-crash) → SequenceRecoveryInvalid.
    let replay = ActionBuilder::new()
        .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
        .with_local_tool_id(0)
        .with_resource_path(&["customer", "x"])
        .with_sequence_id(1003)
        .build();
    let d = aps_check(&auth, &replay, &TestVerifier::new().context());
    assert_eq!(d.reason_code as u8, ReasonCode::SequenceRecoveryInvalid as u8);

    // Continue forward: 5 more Allow decisions at 1005..=1009.
    let sink = ModeB1ReceiptSink::new(&path, key, 256, test_commit_config()).unwrap();
    let v = TestVerifier::new();
    let ctx = VerifierContext::with_sink(
        &v.clock,
        v.instance_id_hash,
        v.attested_tier,
        v.revocation_epoch,
        &sink,
    );
    for i in 5..10u64 {
        let action = ActionBuilder::new()
            .with_tool_descriptor_hash(hash_from_hex(TOOL_HEX_0))
            .with_local_tool_id(0)
            .with_resource_path(&["customer", "x"])
            .with_sequence_id(1000 + i)
            .build();
        let d = aps_check(&auth, &action, &ctx);
        assert_eq!(d.decision_type as u8, DecisionType::Allow as u8, "phase2 step {i}");
    }
    sink.shutdown().unwrap();

    // Final state: log has 10 entries, chain validates end-to-end.
    let final_report = recover_log(&path, key).unwrap();
    assert_eq!(final_report.status, RecoveryStatus::CleanRecovery);
    assert_eq!(final_report.entries_recovered, 10);
    assert_eq!(final_report.last_committed_sequence_id, 1009);
}

