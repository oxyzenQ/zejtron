// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Ladder pins (night-improve-3): the window grammar resolution (the
//! port surface's grammar, the 10s default, the clamps), the log
//! lane's actor formatting, the device token decode every build
//! carries (the host half of the cross-encoding proof). The lane
//! walk itself is environment-dependent (journalctl, audit.log, a
//! live tap); its pieces are pinned, its outputs are pinned by the
//! ledger tests. Wired from src/commands/lane.rs.

use super::*;
use crate::commands::touch::{ProcessEvidence, TouchInfo};
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
    let (w, l) = resolve_window(Some("0s")).unwrap();
    assert_eq!(w, Duration::from_secs(1));
    assert_eq!(l, "1s");

    let (w, l) = resolve_window(Some("2h")).unwrap();
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
    assert_eq!(log_actor(&with_pid), "cron (pid 123, root)");

    let no_pid = info(
        Some(ProcessEvidence {
            name: "CROND".to_owned(),
            pid: None,
        }),
        "root",
    );
    assert_eq!(log_actor(&no_pid), "CROND (root)");

    let no_process = info(None, "root");
    assert_eq!(log_actor(&no_process), "root");
}
