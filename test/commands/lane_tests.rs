// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Ladder pins (night-improve-3): the window grammar resolution (the
//! port surface's grammar, the 10s default, the clamps), the log
//! lane's actor formatting, the device token decode every build
//! carries (the host half of the cross-encoding proof). The lane
//! walk itself is environment-dependent (journalctl, audit.log, a
//! live probe); its pieces are pinned, its outputs are pinned by the
//! ledger tests. Wired from src/commands/lane.rs.

use super::*;
use crate::commands::touch::{ProcessEvidence, TouchInfo};
use crate::ebpf::ringbuf::exit_names_event;
use std::time::Duration;

#[test]
fn the_default_window_is_ten_seconds() {
    assert_eq!(WINDOW_DEFAULT, Duration::from_secs(10));
}

#[test]
fn resolve_window_maps_the_grammar() {
    let (w, l) = resolve_window(None).unwrap();
    assert_eq!(w, Duration::from_secs(10));
    assert_eq!(l, "10s");

    let (w, l) = resolve_window(Some("60s")).unwrap();
    assert_eq!(w, Duration::from_secs(60));
    assert_eq!(l, "60s");

    let (w, l) = resolve_window(Some("5m")).unwrap();
    assert_eq!(w, Duration::from_secs(300));
    assert_eq!(l, "5m");

    let (w, l) = resolve_window(Some("1h")).unwrap();
    assert_eq!(w, Duration::from_secs(3600));
    assert_eq!(l, "1h");
}

#[test]
fn resolve_window_clamps_the_same_range_as_port() {
    // 0s floors to 1s; 2h ceilings to 1h - one grammar, two surfaces.
    // The absurd ask (u64::MAX/1000 hours, the audit's own token)
    // saturates through the same ceiling: every window surface that
    // resolves through here truncates to the honest 1h maximum.
    let (w, l) = resolve_window(Some("0s")).unwrap();
    assert_eq!(w, Duration::from_secs(1));
    assert_eq!(l, "1s");

    let (w, l) = resolve_window(Some("2h")).unwrap();
    assert_eq!(w, Duration::from_secs(3600));
    assert_eq!(l, "1h");

    let (w, l) = resolve_window(Some("999999h")).unwrap();
    assert_eq!(w, Duration::from_secs(3600));
    assert_eq!(l, "1h");

    let (w, l) = resolve_window(Some("18446744073709551h")).unwrap();
    assert_eq!(w, Duration::from_secs(3600));
    assert_eq!(l, "1h");
}

#[test]
fn resolve_window_refuses_the_non_grammar() {
    for bad in ["7x", "abc", "m", ""] {
        assert!(resolve_window(Some(bad)).is_err(), "{bad} must be refused");
    }
}

#[test]
fn the_stat_device_token_decode_is_the_host_half_of_the_proof() {
    // Mirrors the feature-lane pin: st_dev 0x802 (the sda2 shape)
    // decodes to the kernel form 0x800002 - the integer the BPF
    // side carries. This runs in DEFAULT builds too: the LaneQuery
    // always carries the token.
    assert_eq!(device_token_from_stat(0x802), 0x800002);
    assert_eq!(device_token_from_stat(0), 0);
}

#[test]
fn log_actor_prefers_the_process_and_appends_the_user() {
    let info = |process: Option<ProcessEvidence>, actor: &str| TouchInfo {
        path: "/etc/passwd".into(),
        modified: std::time::UNIX_EPOCH,
        source: crate::commands::touch::EvidenceSource::Journal,
        actor: actor.to_owned(),
        process,
        meta: None,
    };
    let with_pid = info(
        Some(ProcessEvidence {
            name: "cron".to_owned(),
            pid: Some(123),
        }),
        "root",
    );
    assert_eq!(
        log_actor(&with_pid),
        EvidenceActor::process("cron", 123, "root")
    );

    let no_pid = info(
        Some(ProcessEvidence {
            name: "CROND".to_owned(),
            pid: None,
        }),
        "root",
    );
    assert_eq!(log_actor(&no_pid).to_string(), "CROND (root)");

    let no_process = info(None, "root");
    assert_eq!(log_actor(&no_process).to_string(), "root");
}

#[test]
fn the_pin_denial_fallback_names_the_window_in_unaccounted() {
    // night-hunter-5: the degraded step's note rides the standard
    // entry grammar ("1 event window (...)"), names the root
    // boundary, and the mode stays whatever the log lane found - the
    // ledger's shape is untouched by the degradation.
    let dir = std::env::temp_dir().join("zejtron-lane-fallback-pin");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("probe.txt");
    std::fs::write(&path, b"probe").unwrap();
    let users = std::collections::HashMap::new();
    let query = LaneQuery {
        display_path: &path,
        lookup_path: &path,
        users: &users,
        inode: 1,
        device: 1,
    };
    let parts = snapshot_fallback(&query, Duration::from_secs(1));
    let reasons: Vec<&str> = parts
        .unaccounted
        .iter()
        .map(|e| e.reason.as_str())
        .collect();
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("unavailable without root")),
        "the note must name the root boundary: {reasons:?}"
    );
    assert!(
        reasons
            .iter()
            .any(|r| r.contains("falling back to snapshot mode")),
        "the note must name the fallback: {reasons:?}"
    );
    assert!(
        matches!(
            parts.mode,
            crate::evidence::Mode::SnapshotJournal | crate::evidence::Mode::SnapshotNoLane
        ),
        "the degrade stays a snapshot mode: {:?}",
        parts.mode
    );
}

// ── night-improve-61: the post-mortem attribution pins ──────────────

/// One synthetic file event: only the fields the attribution match
/// reads are shaped (timestamp, pid, op); the pads stay zeroed the
/// way the ring contract writes them.
fn file_event_at(timestamp_ns: u64, pid: u32, op: u8) -> crate::ebpf::events::FileEvent {
    crate::ebpf::events::FileEvent {
        timestamp_ns,
        op,
        _pad: [0; 7],
        inode: 598,
        device: 2,
        pid,
        _pad2: 0,
    }
}

/// One synthetic exit record: the comm rides as the kernel's
/// bpf_get_current_comm would have written it, NUL-padded.
fn exit_at(timestamp_ns: u64, pid: u32, comm: &str) -> crate::ebpf::events::ProcExitEvent {
    let mut bytes = [0u8; 16];
    bytes[..comm.len()].copy_from_slice(comm.as_bytes());
    crate::ebpf::events::ProcExitEvent {
        timestamp_ns,
        pid,
        _pad: 0,
        comm: bytes,
    }
}

#[test]
fn an_exit_after_the_write_names_the_writer() {
    // The common server shape: a short-lived writer (a cron one-shot,
    // a shell redirect) writes at t=10 and dies at t=11 - the exit
    // record at or after the event names it.
    let write = file_event_at(10_000_000_000, 4242, crate::ebpf::events::FILE_OP_WRITE);
    let exits = [exit_at(11_000_000_000, 4242, "logrotate")];
    let named = exit_names_event(&exits, write.pid, write.timestamp_ns);
    assert_eq!(named.map(|e| e.pid), Some(4242));
    assert_eq!(
        named.map(|e| crate::commands::doctor::memory::exits::comm_string(&e.comm)),
        Some("logrotate".to_owned())
    );
}

#[test]
fn an_exit_before_the_write_is_a_prior_life_not_the_writer() {
    // A recycled pid: the pid's earlier process died BEFORE this
    // event happened - that record names a different process, and
    // the attribution must refuse it (the writer is still unaccounted).
    let write = file_event_at(10_000_000_000, 4242, crate::ebpf::events::FILE_OP_WRITE);
    let exits = [exit_at(3_000_000_000, 4242, "oldcron")];
    assert!(
        exit_names_event(&exits, write.pid, write.timestamp_ns).is_none(),
        "an exit stamped before the write cannot name the writer"
    );
}

#[test]
fn the_first_at_or_after_exit_wins_over_a_recycled_later_one() {
    // pid 4242 writes at t=10, dies at t=12 ("cron"); the pid is
    // recycled at t=20 and that process dies at t=25 ("bash"). The
    // FIRST at-or-after record is the writer's own death.
    let write = file_event_at(10_000_000_000, 4242, crate::ebpf::events::FILE_OP_WRITE);
    let exits = [
        exit_at(12_000_000_000, 4242, "cron"),
        exit_at(25_000_000_000, 4242, "bash"),
    ];
    let named = exit_names_event(&exits, write.pid, write.timestamp_ns);
    assert_eq!(
        named.map(|e| crate::commands::doctor::memory::exits::comm_string(&e.comm)),
        Some("cron".to_owned()),
        "the first at-or-after exit is the writer, not the recycled later life"
    );
}

#[test]
fn a_foreign_pids_exit_never_names_the_writer() {
    // The ring holds every exit since attach; only the event's own
    // pid's death can attribute it.
    let write = file_event_at(10_000_000_000, 4242, crate::ebpf::events::FILE_OP_WRITE);
    let exits = [
        exit_at(11_000_000_000, 7, "systemd"),
        exit_at(12_000_000_000, 99, "sshd"),
    ];
    assert!(exit_names_event(&exits, write.pid, write.timestamp_ns).is_none());
}
