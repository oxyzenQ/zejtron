// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! touch Ledger pins (night-improve-3): the metadata rows (the old
//! tree's block, fact for fact, time-bearing facts carrying their
//! own timestamps), the owner resolution through the passwd map, the
//! verdict per lane. The parser itself is untouched and pinned by
//! the existing touch/audit tests. Wired from
//! src/commands/touch/ledger.rs.

use super::*;
use crate::commands::touch::{FileMeta, TouchInfo};
use std::collections::HashMap;
use std::time::{Duration, UNIX_EPOCH};

fn meta_info() -> TouchInfo {
    let meta = FileMeta {
        file_type: "file".to_owned(),
        size: 1234,
        uid: 0,
        gid: 0,
        perms_octal: "0644".to_owned(),
        inode: 12345,
        dev: 2050,
        modified: UNIX_EPOCH + Duration::from_secs(1_767_225_600),
        accessed: UNIX_EPOCH + Duration::from_secs(1_767_225_700),
        changed: UNIX_EPOCH + Duration::from_secs(1_767_225_800),
        is_symlink: false,
        symlink_target: None,
    };
    TouchInfo {
        path: "/etc/passwd".into(),
        modified: meta.modified,
        source: crate::commands::touch::EvidenceSource::Metadata,
        actor: "unknown".to_owned(),
        process: None,
        meta: Some(meta),
    }
}

fn users() -> HashMap<u32, String> {
    let mut users = HashMap::new();
    users.insert(0u32, "root".to_owned());
    users
}

#[test]
fn the_metadata_block_becomes_rows_fact_for_fact() {
    let rows = metadata_rows(&meta_info(), 1_767_230_000, &users());
    let rendered: Vec<String> = rows.iter().map(|r| r.render_line(false)).collect();
    assert_eq!(
        rendered,
        vec![
            "2026-01-01 01:13:20  type file  —  [measured]",
            "2026-01-01 01:13:20  size 1234 bytes  —  [measured]",
            "2026-01-01 01:13:20  owner root:root (uid 0, gid 0)  —  [measured]",
            "2026-01-01 01:13:20  perms 0644  —  [measured]",
            "2026-01-01 01:13:20  inode 12345 (dev 2050)  —  [measured]",
            "2026-01-01 00:00:00  modified  —  [measured]",
            "2026-01-01 00:01:40  accessed  —  [measured]",
            "2026-01-01 00:03:20  changed  —  [measured]",
        ]
    );
}

#[test]
fn time_bearing_facts_carry_their_own_time_not_the_scan_instant() {
    let rows = metadata_rows(&meta_info(), 1_767_230_000, &users());
    // The mtime row is stamped with the mtime; the type row with the
    // scan instant - the honest split, pinned.
    assert_eq!(rows[5].unix_secs, Some(1_767_225_600));
    assert_eq!(rows[0].unix_secs, Some(1_767_230_000));
}

#[test]
fn a_symlink_carries_its_target_row() {
    let mut info = meta_info();
    let Some(meta) = info.meta.as_mut() else {
        unreachable!()
    };
    meta.file_type = "symlink".to_owned();
    meta.is_symlink = true;
    meta.symlink_target = Some("/etc/real-target".to_owned());
    let rows = metadata_rows(&info, 1_767_230_000, &users());
    assert!(rows.iter().any(|r| r.kind
        == crate::evidence::row::EvidenceKind::SymlinkTarget {
            target: "/etc/real-target".to_owned()
        }));
}

#[test]
fn a_missing_meta_block_degrades_to_the_modified_row_only() {
    let mut info = meta_info();
    info.meta = None;
    info.modified = UNIX_EPOCH + Duration::from_secs(1_767_225_600);
    let rows = metadata_rows(&info, 1_767_230_000, &users());
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].kind,
        crate::evidence::row::EvidenceKind::Modified { via: None }
    );
}

#[test]
fn the_supports_line_names_the_facts_and_the_window() {
    let parts_empty = lane_parts_empty();
    let line = supports_line(&parts_empty, "10s");
    assert!(line.starts_with("the filesystem facts for the path are on the record"));
    assert!(!line.contains("recorded in the last"));

    let mut changes = crate::evidence::ChangesSection::default();
    changes.rows.push(crate::evidence::row::EvidenceRow::new(
        Some(0),
        crate::evidence::row::EvidenceKind::Wrote { via: None },
        EvidenceActor::process("tee", 5, "root"),
        crate::evidence::row::Provenance::Observed,
    ));
    let parts_with = lane::LaneParts {
        mode: crate::evidence::Mode::Live,
        changes,
        unaccounted: Vec::new(),
        raw: Vec::new(),
    };
    let line = supports_line(&parts_with, "10s");
    assert!(line.ends_with("; 1 change(s) recorded in the last 10s"));
}

#[test]
fn the_cannot_line_names_the_write_gaps_per_lane() {
    // Live: the vectorized path is covered since night-improve-42;
    // the cannot line names what still crosses neither write probe.
    let parts = lane_parts_empty();
    let live = cannot_line(&{
        let mut p = lane_parts_empty();
        p.mode = crate::evidence::Mode::Live;
        p
    });
    assert!(live.contains("crossed neither write probe"));
    assert!(live.contains("mmap'd writes"));
    assert!(live.contains("io_uring/AIO"));
    assert!(live.contains("splice-class copies"));
    let _ = parts;

    // Journal: the old best-effort note.
    let journal = cannot_line(&{
        let mut p = lane_parts_empty();
        p.mode = crate::evidence::Mode::SnapshotJournal;
        p
    });
    assert!(journal.contains("best-effort and depends on available logs"));

    // No lane: the old metadata note, verbatim class.
    let no_lane = cannot_line(&{
        let mut p = lane_parts_empty();
        p.mode = crate::evidence::Mode::SnapshotNoLane;
        p
    });
    assert!(no_lane.contains("metadata shows when, not who"));
}

fn lane_parts_empty() -> lane::LaneParts {
    lane::LaneParts {
        mode: crate::evidence::Mode::Live,
        changes: crate::evidence::ChangesSection::default(),
        unaccounted: Vec::new(),
        raw: Vec::new(),
    }
}
