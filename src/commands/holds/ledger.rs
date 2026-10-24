// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The holds surface's Evidence Ledger (night-improve-3): the
//! snapshot's facts (\[measured] - who holds the path NOW, from the
//! same /proc scan phase 2 shipped, parser untouched) wrapped in the
//! Ledger format, plus the event window (\[observed] opens from the
//! kernel lane when it is live, \[inferred] from the log lane when it
//! is not, the named unavailability when neither exists).
//!
//! The old tree output is not deleted, it is re-expressed: every
//! fact the tree carried has a row here - the holder lines became
//! \[measured] rows (one per holder-evidence pair, the actor column
//! carrying name+pid+user), the cwd sub-lines became their own rows,
//! the count line moved into the verdict's supports, the unreadable
//! note became Unaccounted entries carrying the same advice. The
//! parsers themselves are untouched - the format wraps their output,
//! it does not rewrite them.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::evidence::row::{EvidenceActor, EvidenceKind, EvidenceRow, Provenance};
use crate::evidence::{ChangesSection, EvidenceReport, Mode, UnaccountedEntry, Verdict};

use super::{Evidence, Holder, HoldsError, ScanStats, scan_path_holders, scan_port_holders};
use crate::commands::lane::device_token_from_stat;
use crate::commands::lane::{self, LaneQuery, OpFilter};
use crate::commands::touch::parse_passwd;

/// Build the full report for a path target. The lane runs first (a
/// live window collects over its duration), the snapshot scan runs
/// after it (the freshest state, paired with the events that led to
/// it), the verdict composes both.
pub fn build_path_report(
    path: &Path,
    window: Duration,
    window_label: String,
    print_json: bool,
) -> Result<String, HoldsError> {
    // The file identity for the filter key, from the same stat the
    // snapshot side will use (the parsers are untouched; this stat
    // only feeds the lane).
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            HoldsError(format!("{}: no such file or directory", path.display()))
        } else {
            HoldsError(format!("{}: {error}", path.display()))
        }
    })?;
    let inode = metadata.ino();
    let device = device_token_from_stat(metadata.dev());

    let users = parse_passwd().unwrap_or_default();
    let display = path.display().to_string();
    let lookup = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let query = LaneQuery {
        display_path: path,
        lookup_path: &lookup,
        users: &users,
        inode,
        device,
    };
    let parts = lane::collect(&query, window, OpFilter::Opens).map_err(HoldsError)?;

    // The snapshot, taken after the window: the state at the instant
    // the report renders, the same scan phase 2 shipped.
    let (holders, stats) = scan_path_holders(path)?;
    let scan_instant = unix_now();

    let mut measured = Vec::new();
    for holder in &holders {
        let actor = EvidenceActor::process(&holder.name, holder.pid, &holder.user);
        for evidence in &holder.evidence {
            measured.push(EvidenceRow::new(
                Some(scan_instant),
                held_kind(evidence),
                actor.clone(),
                Provenance::Measured,
            ));
        }
    }

    let mut unaccounted = parts.unaccounted;
    extend_stats_entries(&mut unaccounted, &stats);

    let verdict = Verdict {
        supports: supports_line(&holders, &parts.changes, &window_label, false),
        cannot_support: cannot_line(&stats, parts.mode, &parts.changes, false),
    };

    let report = EvidenceReport {
        subject: display,
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

/// Build the report for a port target: the socket holders (\[measured]
/// rows: the fd evidence, the cwd), no event window (the file-event
/// lane tracks files; a port target has no file identity - the
/// unaccounted block names it, and `zejtron port --since` carries
/// the socket window that does apply here).
pub fn build_port_report(
    port: u16,
    _window: Duration,
    window_label: String,
    print_json: bool,
) -> Result<String, HoldsError> {
    let (holders, stats) = scan_port_holders(port)?;
    let scan_instant = unix_now();

    let mut measured = Vec::new();
    for holder in &holders {
        let actor = EvidenceActor::process(&holder.name, holder.pid, &holder.user);
        for evidence in &holder.evidence {
            measured.push(EvidenceRow::new(
                Some(scan_instant),
                held_kind(evidence),
                actor.clone(),
                Provenance::Measured,
            ));
        }
        if let Some(cwd) = &holder.cwd {
            measured.push(EvidenceRow::new(
                Some(scan_instant),
                EvidenceKind::Cwd {
                    path: Some(crate::system::sanitize_display(&cwd.to_string_lossy())),
                },
                actor.clone(),
                Provenance::Measured,
            ));
        } else {
            measured.push(EvidenceRow::new(
                Some(scan_instant),
                EvidenceKind::Cwd { path: None },
                actor.clone(),
                Provenance::Measured,
            ));
        }
    }

    let mut unaccounted = Vec::new();
    extend_stats_entries(&mut unaccounted, &stats);
    unaccounted.push(UnaccountedEntry::new(
        1,
        "event window",
        "not applicable - the file-event lane tracks files; a port target has none \
         (the socket window that applies here is `zejtron port --since`)",
    ));

    let verdict = Verdict {
        supports: supports_line(&holders, &ChangesSection::default(), &window_label, true),
        cannot_support: cannot_line(
            &stats,
            Mode::SnapshotNoLane,
            &ChangesSection::default(),
            true,
        ),
    };

    let report = EvidenceReport {
        subject: format!(":{port}"),
        mode: Mode::SnapshotNoLane,
        window_label,
        measured,
        changes: ChangesSection::default(),
        unaccounted,
        verdict,
    };
    Ok(if print_json {
        crate::evidence::json::report_json(&report)
    } else {
        crate::evidence::render::render_report(&report)
    })
}

/// The typed action for one piece of holder evidence - the same
/// facts the old tree's sub-lines carried, in the row grammar.
fn held_kind(evidence: &Evidence) -> EvidenceKind {
    // The old tree's sub-line, single-sourced: evidence::label() is
    // the one implementation (the phase-2 tree used it verbatim);
    // the typed variant is the only new part.
    EvidenceKind::Held {
        via: evidence.label(),
    }
}

/// The scan instant in unix seconds (the \[measured] rows' timestamp).
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The old unreadable note, one entry per counter, the same advice.
fn extend_stats_entries(unaccounted: &mut Vec<UnaccountedEntry>, stats: &ScanStats) {
    if stats.unreadable_processes > 0 {
        unaccounted.push(UnaccountedEntry::new(
            stats.unreadable_processes,
            "processes",
            "unreadable - try sudo for complete holder details",
        ));
    }
    if stats.unreadable_fds > 0 {
        unaccounted.push(UnaccountedEntry::new(
            stats.unreadable_fds,
            "fd tables",
            "unreadable - try sudo for complete holder details",
        ));
    }
    if stats.unreadable_maps > 0 {
        unaccounted.push(UnaccountedEntry::new(
            stats.unreadable_maps,
            "maps",
            "unreadable - try sudo for complete holder details",
        ));
    }
}

/// The verdict's supports line: the old count line and the old
/// synthesis, composed from what this report actually has.
fn supports_line(
    holders: &[Holder],
    changes: &ChangesSection,
    window_label: &str,
    port_target: bool,
) -> String {
    let target_word = if port_target { "socket" } else { "path" };
    let mut line = if holders.is_empty() {
        format!("nothing visibly holds the {target_word} now")
    } else {
        let names: Vec<&str> = holders.iter().map(|h| h.name.as_str()).collect();
        let unique: Vec<&str> = {
            let mut seen = std::collections::HashSet::new();
            names.iter().copied().filter(|n| seen.insert(*n)).collect()
        };
        format!(
            "{} {} {} the {target_word} now ({})",
            holders.len(),
            if holders.len() == 1 {
                "process"
            } else {
                "processes"
            },
            if holders.len() == 1 { "holds" } else { "hold" },
            unique.join(", ")
        )
    };
    if !changes.rows.is_empty() {
        line.push_str(&format!(
            "; the window recorded {} recent change(s) in the last {window_label}",
            changes.rows.len()
        ));
    }
    line
}

/// The verdict's cannot-support line: the gaps this report actually
/// has, joined; sparse evidence gets a sparse line that names the
/// sparseness.
fn cannot_line(
    stats: &ScanStats,
    mode: Mode,
    changes: &ChangesSection,
    port_target: bool,
) -> String {
    let mut parts: Vec<String> = Vec::new();
    if stats.has_unreadable() {
        parts.push(
            "some processes were not readable (try sudo) - the holder list may be incomplete"
                .to_owned(),
        );
    }
    match mode {
        Mode::Live => parts.push(
            "changes older than the window are not named (the log lane was not consulted \
             in live mode)"
                .to_owned(),
        ),
        Mode::SnapshotJournal => parts.push(
            "changes the log does not record - and opens it never sees - are not named".to_owned(),
        ),
        Mode::SnapshotNoLane => {
            if port_target {
                parts.push(
                    "any file-level change (the file-event lane does not apply to a port \
                     target; `zejtron port --since` carries the socket window)"
                        .to_owned(),
                );
            } else if changes.unavailable {
                parts.push(
                    "any change in the window (no event lane was available - see zejtron \
                     doctor [eBPF])"
                        .to_owned(),
                );
            }
        }
        Mode::Mixed => {}
    }
    if parts.is_empty() {
        return "nothing within this report's sight was left unnamed".to_owned();
    }
    parts.join("; ")
}

#[cfg(test)]
#[path = "../../../test/commands/holds/ledger_tests.rs"]
mod tests;
