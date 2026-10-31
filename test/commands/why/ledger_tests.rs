// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! why Ledger pins (night-improve-3): the dragon's one-liner (the
//! old synthesis logic, now the verdict's supports line) for every
//! input shape, the port synthesis, the --trace explainability
//! ladder, the --raw drill-down's honest absences. Wired from
//! src/commands/why/ledger.rs.

use super::*;
use crate::commands::holds::{Holder, ScanStats};
use crate::commands::touch::{EvidenceSource, ProcessEvidence, TouchInfo};
use crate::evidence::row::{EvidenceActor, EvidenceRow, Provenance};
use crate::evidence::{ChangesSection, EvidenceReport, Mode, Verdict};
use std::time::{Duration, UNIX_EPOCH};

fn holder(pid: u32, name: &str) -> Holder {
    use crate::commands::holds::{Evidence, FdMode};
    Holder {
        pid,
        name: name.to_owned(),
        user: "nightky".to_owned(),
        cwd: None,
        evidence: vec![Evidence::Fd(3, FdMode::ReadWrite)],
    }
}

fn touch_info(actor: &str, source: EvidenceSource) -> TouchInfo {
    TouchInfo {
        path: "/etc/passwd".into(),
        modified: UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        source,
        actor: actor.to_owned(),
        process: Some(ProcessEvidence {
            name: "cron".to_owned(),
            pid: Some(123),
        }),
        meta: None,
    }
}

#[test]
fn the_one_liner_with_holders_and_touch() {
    let holders = vec![holder(1, "bash"), holder(2, "python3")];
    let info = touch_info("root", EvidenceSource::Journal);
    let line = path_supports_line(&holders, Some(&info), &ChangesSection::default(), "10s");
    // Multi-holder: the composed form; single would be "currently
    // held by X (pid=N), ...".
    assert_eq!(
        line,
        "2 processes (bash, python3) hold this path, last modified by root"
    );
}

#[test]
fn the_one_liner_with_a_single_holder_prefers_the_pid_form() {
    let holders = vec![holder(7, "sshd")];
    let info = touch_info("root", EvidenceSource::Journal);
    let line = path_supports_line(&holders, Some(&info), &ChangesSection::default(), "10s");
    assert_eq!(
        line,
        "currently held by sshd (pid=7), last modified by root"
    );
}

#[test]
fn the_one_liner_degrades_when_the_actor_is_unknown() {
    let holders = vec![holder(1, "bash")];
    let info = touch_info("unknown", EvidenceSource::Metadata);
    let line = path_supports_line(&holders, Some(&info), &ChangesSection::default(), "10s");
    assert_eq!(
        line,
        "currently held by bash (pid=1), modification time on record"
    );
}

#[test]
fn the_one_liner_touch_only_and_nothing() {
    let info = touch_info("root", EvidenceSource::Journal);
    let line = path_supports_line(&[], Some(&info), &ChangesSection::default(), "10s");
    assert_eq!(line, "last modified by root (journal evidence)");

    let unknown = touch_info("unknown", EvidenceSource::Metadata);
    let line = path_supports_line(&[], Some(&unknown), &ChangesSection::default(), "10s");
    assert_eq!(line, "path exists with filesystem metadata only");

    let line = path_supports_line(&[], None, &ChangesSection::default(), "10s");
    assert_eq!(line, "no evidence found");
}

#[test]
fn the_changes_clause_rides_the_one_liner() {
    let info = touch_info("root", EvidenceSource::Journal);
    let mut changes = ChangesSection::default();
    changes.rows.push(EvidenceRow::new(
        Some(0),
        EvidenceKind::Opened,
        EvidenceActor::recorded(Some("cat".to_owned()), Some(9), None),
        Provenance::Observed,
    ));
    changes.rows.push(EvidenceRow::new(
        Some(1),
        EvidenceKind::Wrote { via: None },
        EvidenceActor::recorded(Some("tee".to_owned()), Some(5), None),
        Provenance::Observed,
    ));
    let line = path_supports_line(&[], Some(&info), &changes, "10s");
    assert!(line.ends_with("; 2 recent change(s) recorded in the last 10s"));
}

#[test]
fn the_port_synthesis_pins() {
    let empty = port_supports_line(&[]);
    assert_eq!(empty, "no visible holder found");

    let single = port_supports_line(&[holder(7, "sshd")]);
    assert_eq!(single, "sshd (pid=7) owns this socket");

    let multi = port_supports_line(&[holder(7, "sshd"), holder(8, "sshd")]);
    assert_eq!(multi, "2 processes (sshd) share this socket");
}

#[test]
fn the_trace_ladder_names_each_class_present() {
    let report = EvidenceReport {
        subject: "/etc/passwd".to_owned(),
        mode: Mode::Live,
        window_label: "10s".to_owned(),
        measured: vec![
            EvidenceRow::new(
                Some(0),
                EvidenceKind::Held {
                    via: "fd 3 (rw)".to_owned(),
                },
                EvidenceActor::recorded(Some("bash".to_owned()), Some(1), None),
                Provenance::Measured,
            ),
            EvidenceRow::new(
                Some(0),
                EvidenceKind::Runs {
                    cmd: Some("/usr/bin/sshd".to_owned()),
                    unit: Some("sshd".to_owned()),
                },
                EvidenceActor::recorded(Some("sshd".to_owned()), Some(7), None),
                Provenance::Measured,
            ),
            EvidenceRow::new(
                Some(0),
                EvidenceKind::Type {
                    file_type: "file".to_owned(),
                },
                EvidenceActor::none(),
                Provenance::Measured,
            ),
        ],
        changes: ChangesSection {
            rows: vec![
                EvidenceRow::new(
                    Some(1),
                    EvidenceKind::Opened,
                    EvidenceActor::recorded(Some("cat".to_owned()), Some(9), None),
                    Provenance::Observed,
                ),
                EvidenceRow::new(
                    Some(2),
                    EvidenceKind::Wrote { via: None },
                    EvidenceActor::recorded(Some("tee".to_owned()), Some(5), None),
                    Provenance::Observed,
                ),
                EvidenceRow::new(
                    Some(3),
                    EvidenceKind::JournalMention,
                    EvidenceActor::recorded(Some("cron".to_owned()), Some(123), None),
                    Provenance::Inferred,
                ),
            ],
            unavailable: false,
        },
        unaccounted: Vec::new(),
        verdict: Verdict {
            supports: String::new(),
            cannot_support: String::new(),
        },
    };
    let section = trace_section(&report, 1);
    assert!(section.contains("How zejtron knows:"));
    assert!(section.contains("1 [measured] holder row: /proc/<pid>/fd + /proc/<pid>/maps"));
    assert!(section.contains("1 [measured] enrichment row: /proc/<pid>/cgroup"));
    assert!(section.contains("1 [measured] metadata row: stat(2)"));
    assert!(section.contains(
        "2 [observed] event rows: vfs_open kprobe + the write probe (raw_syscalls/sys_enter)"
    ));
    assert!(section.contains("1 [inferred] event row: audit.log SYSCALL+PATH records"));
    assert!(section.contains("Unaccounted and the verdict: composed from the rows above"));
}

#[test]
fn the_trace_ladder_names_the_unavailable_lane() {
    let report = EvidenceReport {
        subject: "/etc/passwd".to_owned(),
        mode: Mode::SnapshotNoLane,
        window_label: "10s".to_owned(),
        measured: Vec::new(),
        changes: ChangesSection {
            rows: Vec::new(),
            unavailable: true,
        },
        unaccounted: Vec::new(),
        verdict: Verdict {
            supports: String::new(),
            cannot_support: String::new(),
        },
    };
    let section = trace_section(&report, 0);
    assert!(section.contains("the doctor's [eBPF] section names the exact reason"));
}

#[test]
fn raw_section_is_honest_about_its_absence() {
    // The none line for an empty capture - the honest shape the
    // renderer owes when the window held nothing.
    let parts = lane::LaneParts {
        mode: Mode::SnapshotNoLane,
        changes: ChangesSection::default(),
        unaccounted: Vec::new(),
        raw: Vec::new(),
    };
    let section = raw_section(&parts);
    assert!(section.starts_with("\nRaw kernel events (file_events ring, as drained):"));
    assert!(section.contains("(none"));
}

#[test]
fn raw_section_renders_the_records_as_drained() {
    use crate::ebpf::events::{FILE_OP_OPEN, FILE_OP_WRITEV, FileEvent};
    let parts = lane::LaneParts {
        mode: Mode::Live,
        changes: ChangesSection::default(),
        unaccounted: Vec::new(),
        raw: vec![
            FileEvent {
                timestamp_ns: 123_456_789_012,
                op: FILE_OP_OPEN,
                _pad: [0; 7],
                inode: 12345,
                device: 0x800002,
                pid: 4321,
                _pad2: 0,
            },
            FileEvent {
                timestamp_ns: 123_456_789_013,
                op: FILE_OP_WRITEV,
                _pad: [0; 7],
                inode: 12345,
                device: 0x800002,
                pid: 4321,
                _pad2: 0,
            },
        ],
    };
    let section = raw_section(&parts);
    assert!(section.contains("123456789012 op=open inode=12345 device=0x800002 pid=4321"));
    // The writev parenthetical (night-improve-42): the raw lane
    // names WHICH write path crossed.
    assert!(
        section.contains("123456789013 op=write (writev) inode=12345 device=0x800002 pid=4321")
    );
}

#[test]
fn the_cannot_line_names_the_live_and_log_gaps() {
    let quiet = ScanStats::default();
    let live = path_cannot_line(&quiet, Mode::Live, 1, 1);
    assert!(live.contains("the log lane was not consulted in live mode"));
    // night-improve-42: writev is no longer the named gap - the
    // probes now cover it; the cannot line names what still crosses
    // neither write probe.
    assert!(live.contains("crossed neither write probe"));
    assert!(live.contains("mmap'd writes"));
    assert!(live.contains("io_uring/AIO"));
    assert!(live.contains("splice-class copies"));

    let nothing = path_cannot_line(&quiet, Mode::SnapshotJournal, 0, 0);
    assert!(nothing.contains("no evidence was collected for this target"));
}

#[test]
fn stamp_of_names_pre_epoch_times_instead_of_unknown() {
    // night-dragon-lts-T1: the why ledger's stamp rode the same
    // lossy Err-arm drop the touch ledger's did - a pre-epoch mtime
    // rendered `unknown` in the evidence rows while the JSON row
    // model (`Option<i64>`) and the clock formatter are both signed.
    // The shared signed conversion keeps the fact.
    let pre_epoch = UNIX_EPOCH - Duration::from_secs(1);
    assert_eq!(stamp_of(pre_epoch), Some(-1));
    assert_eq!(
        crate::info::clock::format_unix_secs(stamp_of(pre_epoch).unwrap()),
        "1969-12-31 23:59:59 (UTC)"
    );
}
