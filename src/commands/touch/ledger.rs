// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The touch surface's Evidence Ledger (night-improve-3): the write
//! surface. The snapshot (\[measured] - the stat(2) facts: type, size,
//! owner, perms, inode, the three timestamps) wrapped in the Ledger
//! format, plus the write window (\[observed] writes from the
//! syscall-anchored write probe when the kernel lane is live, \[inferred]
//! from the log lane when it is not, the named unavailability when
//! neither exists).
//!
//! The old tree's metadata block is re-expressed, fact for fact:
//! type, symlink-target, size, owner, perms, inode+dev, modified,
//! accessed, changed - every line a row. Time-bearing facts carry
//! their own time in the row's timestamp column (the mtime row is
//! stamped with the mtime); timeless state carries the scan instant.
//! The parsers are untouched; the format wraps their output.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::evidence::row::{EvidenceKind, EvidenceRow, Provenance};
use crate::evidence::{EvidenceReport, UnaccountedEntry, Verdict};

use super::{TouchError, TouchInfo, inspect_path, parse_passwd};
use crate::commands::lane::{self, LaneQuery, OpFilter, device_token_from_stat};

/// Build the full report for a path. The lane runs first (a live
/// window collects over its duration; the log lane answers
/// instantly), the snapshot follows, the verdict composes both.
pub fn build_report(
    path: &Path,
    window: Duration,
    window_label: String,
    print_json: bool,
) -> Result<String, TouchError> {
    // The lane identity: the file's OWN identity. For a symlink the
    // target's identity is what the kernel sees when the link is
    // opened or written through - fs::metadata follows the link, the
    // same resolution the events will ride.
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            TouchError(format!("path not found: {}", path.display()))
        } else {
            TouchError(format!("{}: {error}", path.display()))
        }
    })?;
    let inode = metadata.ino();
    let device = device_token_from_stat(metadata.dev());

    let users = parse_passwd().unwrap_or_default();
    let lookup = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let query = LaneQuery {
        display_path: path,
        lookup_path: &lookup,
        users: &users,
        inode,
        device,
    };
    let parts = lane::collect(&query, window, OpFilter::Writes).map_err(TouchError)?;

    // The snapshot: touch's own parser, untouched. It carries the
    // audit/journal actor internally too - the lane already queried
    // the same sources, so this call is the metadata half only in
    // practice (inspect_path's log lanes find the same records; the
    // rows and the unaccounted below keep the two halves apart).
    let info = inspect_path(path)?;
    let scan_instant = unix_now();

    let measured = metadata_rows(&info, scan_instant, &users);

    let supports = supports_line(&parts, &window_label);
    let cannot = cannot_line(&parts);
    let mut unaccounted = parts.unaccounted;
    match info.source {
        super::EvidenceSource::Metadata => {}
        super::EvidenceSource::Audit | super::EvidenceSource::Journal => {
            // The old note, verbatim class: the actor inference is
            // only as good as the logs. The in-window record rides
            // the changes rows; this entry names the residual.
            if parts.changes.rows.is_empty() && !parts.changes.unavailable {
                unaccounted.push(UnaccountedEntry::new(
                    1,
                    "actor attribution",
                    "best-effort and depends on available logs",
                ));
            }
        }
    }

    let verdict = Verdict {
        supports,
        cannot_support: cannot,
    };

    let report = EvidenceReport {
        subject: path.display().to_string(),
        mode: parts.mode,
        window_label,
        measured,
        changes: parts.changes,
        unaccounted,
        verdict,
    };
    Ok(if print_json {
        crate::evidence::json::report_json(&report)
    } else {
        crate::evidence::render::render_report(&report)
    })
}

/// The metadata facts as \[measured] rows - the old tree's block,
/// re-expressed line for line. Time-bearing facts (the three
/// timestamps) carry their own time; the rest carry the scan
/// instant.
fn metadata_rows(
    info: &TouchInfo,
    scan_instant: i64,
    users: &std::collections::HashMap<u32, String>,
) -> Vec<EvidenceRow> {
    let mut rows = Vec::new();
    let dash = "—".to_owned();
    if let Some(meta) = &info.meta {
        rows.push(EvidenceRow::new(
            Some(scan_instant),
            EvidenceKind::Type {
                file_type: meta.file_type.clone(),
            },
            dash.clone(),
            Provenance::Measured,
        ));
        if meta.is_symlink
            && let Some(ref target) = meta.symlink_target
        {
            rows.push(EvidenceRow::new(
                Some(scan_instant),
                EvidenceKind::SymlinkTarget {
                    target: target.clone(),
                },
                dash.clone(),
                Provenance::Measured,
            ));
        }
        rows.push(EvidenceRow::new(
            Some(scan_instant),
            EvidenceKind::Size { bytes: meta.size },
            dash.clone(),
            Provenance::Measured,
        ));
        let uname = users
            .get(&meta.uid)
            .cloned()
            .unwrap_or_else(|| meta.uid.to_string());
        let gname = users
            .get(&meta.gid)
            .cloned()
            .unwrap_or_else(|| meta.gid.to_string());
        rows.push(EvidenceRow::new(
            Some(scan_instant),
            EvidenceKind::Owner {
                user: uname,
                group: gname,
                uid: meta.uid,
                gid: meta.gid,
            },
            dash.clone(),
            Provenance::Measured,
        ));
        rows.push(EvidenceRow::new(
            Some(scan_instant),
            EvidenceKind::Permissions {
                octal: meta.perms_octal.clone(),
            },
            dash.clone(),
            Provenance::Measured,
        ));
        rows.push(EvidenceRow::new(
            Some(scan_instant),
            EvidenceKind::Inode {
                id: meta.inode,
                dev: meta.dev,
            },
            dash.clone(),
            Provenance::Measured,
        ));
        let stamp = |t: SystemTime| {
            t.duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .ok()
        };
        rows.push(EvidenceRow::new(
            stamp(meta.modified),
            EvidenceKind::Modified { via: None },
            dash.clone(),
            Provenance::Measured,
        ));
        rows.push(EvidenceRow::new(
            stamp(meta.accessed),
            EvidenceKind::Accessed,
            dash.clone(),
            Provenance::Measured,
        ));
        rows.push(EvidenceRow::new(
            stamp(meta.changed),
            EvidenceKind::Changed,
            dash.clone(),
            Provenance::Measured,
        ));
    } else {
        rows.push(EvidenceRow::new(
            stamp_of(info.modified),
            EvidenceKind::Modified { via: None },
            dash.clone(),
            Provenance::Measured,
        ));
    }
    rows
}

fn stamp_of(t: SystemTime) -> Option<i64> {
    t.duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .ok()
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The verdict's supports line for the write surface.
fn supports_line(parts: &lane::LaneParts, window_label: &str) -> String {
    let mut line = "the filesystem facts for the path are on the record (size, ownership, \
                     perms, timestamps)"
        .to_owned();
    if !parts.changes.rows.is_empty() {
        line.push_str(&format!(
            "; {} change(s) recorded in the last {window_label}",
            parts.changes.rows.len()
        ));
    }
    line
}

/// The verdict's cannot-support line for the write surface - the
/// old notes, named per lane.
fn cannot_line(parts: &lane::LaneParts) -> String {
    let mut segs: Vec<String> = Vec::new();
    match parts.mode {
        crate::evidence::Mode::Live => segs.push(
            "writes that crossed neither write probe - mmap'd writes, async kiocb writes \
             (io_uring/AIO), splice-class copies - and anything older than the window \
             (the log lane was not consulted in live mode)"
                .to_owned(),
        ),
        crate::evidence::Mode::SnapshotJournal => segs.push(
            "who made the change when the log is silent - the log lane is best-effort and \
             depends on available logs; writes it never recorded are not named"
                .to_owned(),
        ),
        crate::evidence::Mode::SnapshotNoLane => segs.push(
            "who made the change (metadata shows when, not who; no event lane was available \
             - see zejtron doctor [eBPF])"
                .to_owned(),
        ),
        crate::evidence::Mode::Mixed => {}
    }
    segs.join("; ")
}

#[cfg(test)]
#[path = "../../../test/commands/touch/ledger_tests.rs"]
mod tests;
