// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! holds Ledger pins (night-improve-3): the holder rows' grammar
//! (action, actor, provenance), the action phrases single-sourced
//! from the old tree's labels, the verdict composition, the
//! unreadable-stats entries, and a full render of a port-target
//! report (the one target with no environment-dependent lane). The
//! path-target report's live/log legs are exercised by the owner
//! host; their row shapes are pinned here synthetically. Wired from
//! src/commands/holds/ledger.rs.

use super::*;
use crate::commands::holds::{FdMode, MmapPerms};
use crate::evidence::ChangesSection;
use crate::evidence::row::Provenance;
use std::time::Duration;

fn fd_evidence() -> Vec<super::super::Evidence> {
    use super::super::Evidence;
    vec![
        Evidence::Fd(3, FdMode::ReadWrite),
        Evidence::Mmap(MmapPerms {
            read: true,
            write: true,
            execute: false,
            private: true,
        }),
    ]
}

#[test]
fn held_action_prefixes_the_single_sourced_label() {
    use super::super::Evidence;
    let fd = held_action(&Evidence::Fd(3, FdMode::ReadWrite));
    assert_eq!(fd, "held via fd 3 (rw)");
    let mmap = held_action(&Evidence::Mmap(MmapPerms {
        read: true,
        write: true,
        execute: false,
        private: true,
    }));
    assert_eq!(mmap, "held via mmap rw-p");
}

#[test]
fn the_supports_line_carries_the_old_count_line() {
    use super::super::Holder;
    let holders = vec![
        Holder {
            pid: 1,
            name: "bash".to_owned(),
            user: "nightky".to_owned(),
            cwd: None,
            evidence: fd_evidence(),
        },
        Holder {
            pid: 2,
            name: "python3".to_owned(),
            user: "nightky".to_owned(),
            cwd: None,
            evidence: fd_evidence(),
        },
    ];
    let line = supports_line(&holders, &ChangesSection::default(), "10s", false);
    assert_eq!(line, "2 processes hold the path now (bash, python3)");

    // The changes clause rides when the window recorded something.
    let mut changes = ChangesSection::default();
    changes.rows.push(crate::evidence::row::EvidenceRow::new(
        Some(0),
        "opened",
        "cat (pid 9)",
        Provenance::Observed,
    ));
    let line = supports_line(&holders, &changes, "10s", false);
    assert!(line.ends_with("; the window recorded 1 recent change(s) in the last 10s"));

    let empty = supports_line(&[], &ChangesSection::default(), "10s", false);
    assert_eq!(empty, "nothing visibly holds the path now");
}

#[test]
fn the_cannot_line_names_the_lane_gaps() {
    use super::super::ScanStats;
    let quiet = ScanStats::default();
    let unavailable = ChangesSection {
        unavailable: true,
        ..ChangesSection::default()
    };

    // No lane, path target: the spec's named unavailability.
    let line = cannot_line(
        &quiet,
        crate::evidence::Mode::SnapshotNoLane,
        &unavailable,
        false,
    );
    assert!(line.contains("no event lane was available"));

    // Live: the log lane was not consulted.
    let line = cannot_line(
        &quiet,
        crate::evidence::Mode::Live,
        &ChangesSection::default(),
        false,
    );
    assert!(line.contains("the log lane was not consulted in live mode"));

    // Journal fallback: the log's own gaps.
    let line = cannot_line(
        &quiet,
        crate::evidence::Mode::SnapshotJournal,
        &ChangesSection::default(),
        false,
    );
    assert!(line.contains("changes the log does not record"));

    // Unreadable processes ride first.
    let unreadable = ScanStats {
        unreadable_processes: 2,
        ..ScanStats::default()
    };
    let line = cannot_line(
        &unreadable,
        crate::evidence::Mode::SnapshotJournal,
        &ChangesSection::default(),
        false,
    );
    assert!(line.starts_with("some processes were not readable (try sudo)"));
}

#[test]
fn unreadable_stats_become_entries_with_the_old_advice() {
    use super::super::ScanStats;
    let stats = ScanStats {
        unreadable_processes: 2,
        unreadable_fds: 1,
        unreadable_maps: 3,
    };
    let mut entries = Vec::new();
    extend_stats_entries(&mut entries, &stats);
    let rendered: Vec<String> = entries.iter().map(|e| e.render_line()).collect();
    assert_eq!(
        rendered,
        vec![
            "2 processes (unreadable - try sudo for complete holder details)",
            "1 fd tables (unreadable - try sudo for complete holder details)",
            "3 maps (unreadable - try sudo for complete holder details)",
        ]
    );
    let mut none = Vec::new();
    extend_stats_entries(&mut none, &ScanStats::default());
    assert!(none.is_empty(), "a quiet scan adds nothing");
}

#[test]
fn a_port_target_report_renders_the_full_shape() {
    // The port target has no environment-dependent lane, so this is
    // a deterministic integration pin. Whatever holds the port, the
    // header and the mode line hold either way.
    let out = build_port_report(54321, Duration::from_secs(10), "10s".to_owned())
        .expect("the port scan itself cannot fail here");
    assert!(out.starts_with(
        "Evidence report: :54321\nMode: snapshot (window 10s, no event lane available)"
    ));
    assert!(out.contains("Unaccounted:"));
    assert!(out.contains("Verdict:"));
    assert!(out.contains("The evidence supports:"));
    assert!(out.contains("The evidence cannot support:"));
    assert!(out.contains("the file-event lane tracks files; a port target has none"));
}

#[test]
fn the_measured_row_shape_for_a_holder() {
    use super::super::Holder;
    // The actor format: name (pid, user) - the old tree's holder
    // line carried all three facts; the row carries them in one.
    let holder = Holder {
        pid: 1234,
        name: "sshd".to_owned(),
        user: "root".to_owned(),
        cwd: None,
        evidence: fd_evidence(),
    };
    let scan_instant = 1_767_225_600i64;
    let actor = format!("{} (pid {}, {})", holder.name, holder.pid, holder.user);
    let row = crate::evidence::row::EvidenceRow::new(
        Some(scan_instant),
        held_action(&holder.evidence[0]),
        actor,
        Provenance::Measured,
    );
    assert_eq!(
        row.render_line(false),
        "2026-01-01 00:00:00  held via fd 3 (rw)  sshd (pid 1234, root)  [measured]"
    );
}
