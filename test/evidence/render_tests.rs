// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Renderer pins for the Evidence Ledger (night-improve-3): the
//! locked output shape, all four sections, byte-deterministic, no
//! ANSI escape bytes ever. Wired from src/evidence/render.rs.

use super::super::row::{EvidenceKind, EvidenceRow, Provenance};
use super::super::{ChangesSection, Mode, UnaccountedEntry, Verdict};
use super::*;

const FIXED_SECS: i64 = 1_767_225_600; // 2026-01-01 00:00:00 UTC
const FIXED_LATER: i64 = 1_767_225_607; // +7s

fn sample_report() -> EvidenceReport {
    EvidenceReport {
        subject: "/etc/passwd".to_owned(),
        mode: Mode::Live,
        window_label: "10s".to_owned(),
        measured: vec![
            EvidenceRow::new(
                Some(FIXED_SECS),
                EvidenceKind::Held {
                    via: "fd 3 (rw)".to_owned(),
                },
                "sshd (pid 1234, root)",
                Provenance::Measured,
            ),
            EvidenceRow::new(
                Some(FIXED_SECS),
                EvidenceKind::Held {
                    via: "mmap rw-p".to_owned(),
                },
                "python3 (pid 77, nightky)",
                Provenance::Measured,
            ),
        ],
        changes: ChangesSection {
            rows: vec![
                EvidenceRow::new(
                    Some(FIXED_LATER),
                    EvidenceKind::Opened,
                    "cat (pid 9, root)",
                    Provenance::Observed,
                ),
                EvidenceRow::new(
                    Some(FIXED_LATER),
                    EvidenceKind::Modified {
                        via: Some("audit log"),
                    },
                    "cron (pid 123, root)",
                    Provenance::Inferred,
                ),
            ],
            unavailable: false,
        },
        unaccounted: vec![UnaccountedEntry::new(
            2,
            "writes",
            "no visible PID - namespace boundary or exited before attribution",
        )],
        verdict: Verdict {
            supports: "the supports line".to_owned(),
            cannot_support: "the cannot-support line".to_owned(),
        },
    }
}

#[test]
fn the_locked_shape_renders_verbatim() {
    let out = render_report(&sample_report());
    assert_eq!(
        out,
        "Evidence report: /etc/passwd\n\
         Mode: live (window 10s)\n\
         \n\
         Evidence:\n\
         \x20 2026-01-01 00:00:00 (UTC)  held via fd 3 (rw)  sshd (pid 1234, root)  [measured]\n\
         \x20 2026-01-01 00:00:00  held via mmap rw-p  python3 (pid 77, nightky)  [measured]\n\
         \x20 Changes in the last 10s:\n\
         \x20 2026-01-01 00:00:07  opened  cat (pid 9, root)  [observed]\n\
         \x20 2026-01-01 00:00:07  modified (audit log)  cron (pid 123, root)  [inferred]\n\
         \n\
         Unaccounted:\n\
         \x20 2 writes (no visible PID - namespace boundary or exited before attribution)\n\
         \n\
         Verdict:\n\
         \x20 The evidence supports: the supports line\n\
         \x20 The evidence cannot support: the cannot-support line"
    );
}

#[test]
fn only_the_first_timestamped_row_carries_the_utc_declaration() {
    let out = render_report(&sample_report());
    let lines: Vec<&str> = out.lines().collect();
    // Row 1 keeps the suffix; rows 2-4 are bare.
    assert!(lines[4].contains("(UTC)"));
    assert!(!lines[5].contains("(UTC)"));
    assert!(!lines[7].contains("(UTC)"));
}

#[test]
fn an_empty_window_and_an_absent_lane_are_different_truths() {
    let mut report = sample_report();
    report.mode = Mode::SnapshotNoLane;
    report.changes = ChangesSection {
        rows: Vec::new(),
        unavailable: true,
    };
    let out = render_report(&report);
    assert!(out.contains("  Changes in the last 10s:"));
    assert!(out.contains(
        "Changes in the last 10s: unavailable (this binary/run cannot capture events - \
         see zejtron doctor [eBPF])"
    ));
    // The available-but-empty-window shape (a lane that ran and found
    // nothing) is pinned by its own test; this one stays on the
    // absent-lane truth.
}

#[test]
fn empty_unaccounted_renders_none_observed() {
    let mut report = sample_report();
    report.unaccounted = Vec::new();
    let out = render_report(&report);
    assert!(out.contains("Unaccounted:\n  (none observed)"));
}

#[test]
fn a_lane_that_ran_and_found_nothing_still_prints_the_changes_section() {
    // The mode line promised a fallback; an empty window is a
    // finding, not a missing section - even when the measured rows
    // are empty too (a path no visible process holds).
    let report = EvidenceReport {
        subject: "/etc/passwd".to_owned(),
        mode: Mode::SnapshotJournal,
        window_label: "5s".to_owned(),
        measured: Vec::new(),
        changes: ChangesSection::default(),
        unaccounted: Vec::new(),
        verdict: Verdict {
            supports: String::new(),
            cannot_support: String::new(),
        },
    };
    let out = render_report(&report);
    assert!(out.contains("  Changes in the last 5s:\n  (no events in the window)"));
}

#[test]
fn sparse_evidence_renders_its_verdict_and_empty_sections_still_print() {
    let report = EvidenceReport {
        subject: ":8080".to_owned(),
        mode: Mode::SnapshotNoLane,
        window_label: "10s".to_owned(),
        measured: Vec::new(),
        changes: ChangesSection::default(),
        unaccounted: Vec::new(),
        verdict: Verdict {
            supports: "nothing visibly holds the socket now".to_owned(),
            cannot_support: "any change in the window (no event lane was available)".to_owned(),
        },
    };
    let out = render_report(&report);
    // No Changes subsection rides when there is nothing to name.
    assert!(!out.contains("Changes in the last"));
    assert!(out.contains("Evidence:\n\nUnaccounted:\n  (none observed)"));
}

#[test]
fn rendering_is_deterministic_same_report_same_bytes() {
    assert_eq!(
        render_report(&sample_report()),
        render_report(&sample_report())
    );
}

#[test]
fn no_ansi_escape_bytes_ever() {
    let out = render_report(&sample_report());
    assert!(
        !out.contains('\u{1b}'),
        "the ledger never colors, so NO_COLOR needs no honoring"
    );
}
