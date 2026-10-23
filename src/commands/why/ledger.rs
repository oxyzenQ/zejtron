// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The why surface's Evidence Ledger (night-improve-3): the
//! synthesis surface. It combines holds (the current holders, the
//! recent opens) and touch (the recent writes, the metadata) into
//! one report, adds the systemd unit and cmdline enrichment the old
//! synthesis carried, and answers with one verdict instead of a
//! tree of branches. The dragon's one-liner - the old
//! synthesize_path_explanation - is the verdict's supports line now.
//!
//! `--trace` appends the explainability ladder: how zejtron knows
//! each class of row (which probe, which parser, which fallback) -
//! the postmortem-meeting question, answered in the report itself.
//! `--raw` appends the kernel's own records as drained (every event
//! the ring held for this file, before filtering and attribution) -
//! the drill-down for the analyst who wants the bytes under the
//! rows. Both flags degrade honestly: a run with no live lane
//! prints the named absence, never a fabricated section.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::evidence::row::{EvidenceRow, Provenance};
use crate::evidence::{ChangesSection, EvidenceReport, Mode, UnaccountedEntry, Verdict};

use super::super::holds::{self, Holder, ScanStats};
use super::super::touch::{self, TouchInfo};
use super::raw::raw_section;
use crate::commands::lane::{self, LaneQuery, OpFilter, device_token_from_stat};
use crate::system::{read_cmdline, read_systemd_unit};

/// Build the synthesis report for a path target.
pub fn build_path_report(
    path: &Path,
    window: Duration,
    window_label: String,
    trace: bool,
    raw: bool,
    print_json: bool,
) -> Result<String, super::WhyError> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            super::WhyError(format!("path not found: {}", path.display()))
        } else {
            super::WhyError(format!("{}: {error}", path.display()))
        }
    })?;
    let inode = metadata.ino();
    let device = device_token_from_stat(metadata.dev());

    let users = touch::parse_passwd().unwrap_or_default();
    let lookup = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let query = LaneQuery {
        display_path: path,
        lookup_path: &lookup,
        users: &users,
        inode,
        device,
    };
    let parts = lane::collect(&query, window, OpFilter::Both)
        .map_err(|e| super::WhyError(e.to_string()))?;

    // The snapshot: BOTH halves, as the old why ran them - the
    // holders scan and the touch inspection, parsers untouched.
    let (holders, stats) =
        holds::scan_path_holders(path).map_err(|e| super::WhyError(e.to_string()))?;
    let touch_info = touch::inspect_path(path).ok();
    let scan_instant = unix_now();

    let mut measured = Vec::new();
    for holder in &holders {
        push_holder_rows(&mut measured, holder, scan_instant);
        push_enrichment_rows(&mut measured, holder, scan_instant);
    }
    let mut meta_rows = 0;
    if let Some(info) = &touch_info {
        let before = measured.len();
        push_metadata_rows(&mut measured, info, scan_instant, &users);
        meta_rows = measured.len() - before;
    }

    let supports = path_supports_line(&holders, touch_info.as_ref(), &parts.changes, &window_label);
    let cannot = path_cannot_line(&stats, parts.mode, holders.len(), meta_rows);
    // The raw section is computed before the report consumes parts:
    // it needs the drained records the changes rows were built from.
    let raw_text = if raw {
        raw_section(&parts)
    } else {
        String::new()
    };
    let mut unaccounted = parts.unaccounted;
    if stats.unreadable_processes > 0 {
        unaccounted.push(UnaccountedEntry::new(
            stats.unreadable_processes,
            "processes",
            "unreadable - try sudo for complete explanation",
        ));
    }
    if stats.unreadable_maps > 0 {
        unaccounted.push(UnaccountedEntry::new(
            stats.unreadable_maps,
            "maps",
            "unreadable - try sudo for complete explanation",
        ));
    }
    let report = EvidenceReport {
        subject: path.display().to_string(),
        mode: parts.mode,
        window_label,
        measured,
        changes: parts.changes,
        unaccounted,
        verdict: Verdict {
            supports,
            cannot_support: cannot,
        },
    };
    // The renderer branch: JSON when --print-json (one line, the
    // json lane's contract), the text ledger otherwise. The trace
    // and raw sections are text-mode extras - the CLI conflicts
    // --print-json with them, so the appends below are inert in the
    // JSON branch and the one line stays byte-clean.
    let mut out = if print_json {
        crate::evidence::json::report_json(&report)
    } else {
        crate::evidence::render::render_report(&report)
    };
    if trace {
        out.push_str(&trace_section(&report, meta_rows));
    }
    if raw {
        out.push_str(&raw_text);
    }
    Ok(out)
}

/// Build the synthesis report for a port target: the socket holders
/// and their enrichment, no file window. A port has no file identity
/// (the unaccounted block names it; `zejtron port --since` carries
/// the socket window that applies here).
pub fn build_port_report(
    port: u16,
    _window: Duration,
    window_label: String,
    trace: bool,
    raw: bool,
    print_json: bool,
) -> Result<String, super::WhyError> {
    let (holders, stats) =
        holds::scan_port_holders(port).map_err(|e| super::WhyError(e.to_string()))?;
    let scan_instant = unix_now();

    let mut measured = Vec::new();
    for holder in &holders {
        push_holder_rows(&mut measured, holder, scan_instant);
        if let Some(cwd) = &holder.cwd {
            measured.push(EvidenceRow::new(
                Some(scan_instant),
                format!(
                    "cwd {}",
                    crate::system::sanitize_display(&cwd.to_string_lossy())
                ),
                format!("{} (pid {}, {})", holder.name, holder.pid, holder.user),
                Provenance::Measured,
            ));
        }
        push_enrichment_rows(&mut measured, holder, scan_instant);
    }

    let mut unaccounted = Vec::new();
    if stats.has_unreadable() {
        unaccounted.push(UnaccountedEntry::new(
            1,
            "process reads",
            "some processes were not readable; try sudo for complete explanation",
        ));
    }
    unaccounted.push(UnaccountedEntry::new(
        1,
        "event window",
        "not applicable - the file-event lane tracks files; a port target has none \
         (the socket window that applies here is `zejtron port --since`)",
    ));

    let report = EvidenceReport {
        subject: format!(":{port}"),
        mode: Mode::SnapshotNoLane,
        window_label,
        measured,
        changes: ChangesSection::default(),
        unaccounted,
        verdict: Verdict {
            supports: port_supports_line(&holders),
            cannot_support: port_cannot_line(&stats),
        },
    };
    let mut out = if print_json {
        crate::evidence::json::report_json(&report)
    } else {
        crate::evidence::render::render_report(&report)
    };
    if trace {
        out.push_str(&trace_section(&report, 0));
    }
    if raw {
        out.push_str(&raw_section(&lane::LaneParts {
            mode: Mode::SnapshotNoLane,
            changes: ChangesSection::default(),
            unaccounted: Vec::new(),
            raw: Vec::new(),
        }));
    }
    Ok(out)
}

/// The holder rows (the evidence pairs), shared by both targets.
fn push_holder_rows(rows: &mut Vec<EvidenceRow>, holder: &Holder, scan_instant: i64) {
    let actor = format!("{} (pid {}, {})", holder.name, holder.pid, holder.user);
    for evidence in &holder.evidence {
        rows.push(EvidenceRow::new(
            Some(scan_instant),
            format!("held via {}", evidence.label()),
            actor.clone(),
            Provenance::Measured,
        ));
    }
}

/// The enrichment rows: the systemd unit (from the cgroup) and the
/// cmdline - the old synthesis's cross-reference, as rows. Emitted
/// when either fact is present and new (cmd == name adds nothing).
fn push_enrichment_rows(rows: &mut Vec<EvidenceRow>, holder: &Holder, scan_instant: i64) {
    let unit = read_systemd_unit(Path::new("/proc"), holder.pid);
    let cmdline = read_cmdline(Path::new("/proc"), holder.pid);
    let actor = format!("{} (pid {}, {})", holder.name, holder.pid, holder.user);
    let cmd_fresh = cmdline
        .as_deref()
        .is_some_and(|cmd| !cmd.is_empty() && cmd != holder.name);
    match (&unit, cmd_fresh) {
        (None, false) => {}
        (Some(unit), true) => rows.push(EvidenceRow::new(
            Some(scan_instant),
            format!("runs {} (unit {unit})", cmdline.unwrap_or_default()),
            actor,
            Provenance::Measured,
        )),
        (Some(unit), false) => rows.push(EvidenceRow::new(
            Some(scan_instant),
            format!("runs under unit {unit}"),
            actor,
            Provenance::Measured,
        )),
        (None, true) => rows.push(EvidenceRow::new(
            Some(scan_instant),
            format!("runs {}", cmdline.unwrap_or_default()),
            actor,
            Provenance::Measured,
        )),
    }
}

/// The metadata half (the touch rows), reused for the synthesis.
fn push_metadata_rows(
    rows: &mut Vec<EvidenceRow>,
    info: &TouchInfo,
    scan_instant: i64,
    users: &std::collections::HashMap<u32, String>,
) {
    let dash = "—".to_owned();
    let Some(meta) = &info.meta else {
        rows.push(EvidenceRow::new(
            stamp_of(info.modified),
            "modified".to_owned(),
            dash,
            Provenance::Measured,
        ));
        return;
    };
    let uname = users
        .get(&meta.uid)
        .cloned()
        .unwrap_or_else(|| meta.uid.to_string());
    let gname = users
        .get(&meta.gid)
        .cloned()
        .unwrap_or_else(|| meta.gid.to_string());
    let rows_before = rows.len();
    rows.push(EvidenceRow::new(
        Some(scan_instant),
        format!("type {}", meta.file_type),
        "—".to_owned(),
        Provenance::Measured,
    ));
    if meta.is_symlink
        && let Some(ref target) = meta.symlink_target
    {
        rows.push(EvidenceRow::new(
            Some(scan_instant),
            format!("symlink-target {target}"),
            "—".to_owned(),
            Provenance::Measured,
        ));
    }
    rows.push(EvidenceRow::new(
        Some(scan_instant),
        format!("size {} bytes", meta.size),
        "—".to_owned(),
        Provenance::Measured,
    ));
    rows.push(EvidenceRow::new(
        Some(scan_instant),
        format!("owner {uname}:{gname} (uid {}, gid {})", meta.uid, meta.gid),
        "—".to_owned(),
        Provenance::Measured,
    ));
    rows.push(EvidenceRow::new(
        Some(scan_instant),
        format!("perms {}", meta.perms_octal),
        "—".to_owned(),
        Provenance::Measured,
    ));
    rows.push(EvidenceRow::new(
        Some(scan_instant),
        format!("inode {} (dev {})", meta.inode, meta.dev),
        "—".to_owned(),
        Provenance::Measured,
    ));
    rows.push(EvidenceRow::new(
        stamp_of(meta.modified),
        "modified".to_owned(),
        "—".to_owned(),
        Provenance::Measured,
    ));
    let _ = rows_before;
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

/// The dragon's one-liner, the old synthesis logic carried whole.
fn path_supports_line(
    holders: &[Holder],
    touch_info: Option<&TouchInfo>,
    changes: &ChangesSection,
    window_label: &str,
) -> String {
    let unique_names = |holders: &[Holder]| -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        holders
            .iter()
            .map(|h| h.name.as_str())
            .filter(|n| seen.insert(*n))
            .map(str::to_owned)
            .collect()
    };
    let mut line = match (holders.is_empty(), touch_info) {
        (false, Some(info)) => {
            let names = unique_names(holders);
            let actor = if info.actor != "unknown" {
                format!("last modified by {}", info.actor)
            } else {
                "modification time on record".to_owned()
            };
            if holders.len() == 1 {
                format!(
                    "currently held by {} (pid={}), {actor}",
                    holders[0].name, holders[0].pid
                )
            } else {
                format!(
                    "{} processes ({}) hold this path, {actor}",
                    holders.len(),
                    names.join(", ")
                )
            }
        }
        (false, None) => {
            let names = unique_names(holders);
            if holders.len() == 1 {
                format!(
                    "currently held by {} (pid={})",
                    holders[0].name, holders[0].pid
                )
            } else {
                format!(
                    "{} processes ({}) hold this path",
                    holders.len(),
                    names.join(", ")
                )
            }
        }
        (true, Some(info)) => {
            if info.actor != "unknown" {
                format!("last modified by {} ({})", info.actor, info.source.label())
            } else {
                "path exists with filesystem metadata only".to_owned()
            }
        }
        (true, None) => "no evidence found".to_owned(),
    };
    if !changes.rows.is_empty() {
        line.push_str(&format!(
            "; {} recent change(s) recorded in the last {window_label}",
            changes.rows.len()
        ));
    }
    line
}

fn path_cannot_line(
    stats: &ScanStats,
    mode: Mode,
    holder_count: usize,
    meta_rows: usize,
) -> String {
    let mut segs: Vec<String> = Vec::new();
    if stats.has_unreadable() {
        segs.push(
            "some processes were not readable (try sudo) - the explanation may be incomplete"
                .to_owned(),
        );
    }
    if holder_count == 0 && meta_rows == 0 {
        segs.push("anything - no evidence was collected for this target".to_owned());
    }
    match mode {
        Mode::Live => segs.push(
            "changes older than the window (the log lane was not consulted in live mode); \
             writes that crossed neither write probe - mmap'd writes, async kiocb writes \
             (io_uring/AIO), splice-class copies"
                .to_owned(),
        ),
        Mode::SnapshotJournal => segs.push(
            "changes the log does not record - actor inference is best-effort and depends \
             on available logs"
                .to_owned(),
        ),
        Mode::SnapshotNoLane => segs.push(
            "any change in the window (no event lane was available - see zejtron doctor [eBPF])"
                .to_owned(),
        ),
        Mode::Mixed => {}
    }
    if segs.is_empty() {
        segs.push("nothing within this report's sight was left unnamed".to_owned());
    }
    segs.join("; ")
}

fn port_supports_line(holders: &[Holder]) -> String {
    if holders.is_empty() {
        return "no visible holder found".to_owned();
    }
    let mut seen = std::collections::HashSet::new();
    let names: Vec<String> = holders
        .iter()
        .map(|h| h.name.as_str())
        .filter(|n| seen.insert(*n))
        .map(str::to_owned)
        .collect();
    if holders.len() == 1 {
        format!(
            "{} (pid={}) owns this socket",
            holders[0].name, holders[0].pid
        )
    } else {
        format!(
            "{} processes ({}) share this socket",
            holders.len(),
            names.join(", ")
        )
    }
}

fn port_cannot_line(stats: &ScanStats) -> String {
    let mut segs: Vec<String> = Vec::new();
    if stats.has_unreadable() {
        segs.push("some processes were not readable; try sudo for complete explanation".to_owned());
    }
    segs.push(
        "any file-level change (the file-event lane does not apply to a port target; \
         `zejtron port --since` carries the socket window)"
            .to_owned(),
    );
    segs.join("; ")
}

/// The --trace section: the explainability ladder, one line per
/// class of rows present, each naming its probe, parser, or
/// fallback.
fn trace_section(report: &EvidenceReport, meta_rows: usize) -> String {
    // Roles (night-improve-37): the header rides green (the section
    // header); the rows are the explainability hints and ride grey,
    // with their [measured]/[observed]/[inferred] tags painted by the
    // evidence split (green for the strongest, grey for the weaker).
    let measured_tag = crate::output::ok_out("[measured]");
    let observed_tag = crate::output::ok_out("[observed]");
    let inferred_tag = crate::output::grey_out("[inferred]");
    let mut lines = vec![crate::output::ok_out("How zejtron knows:")];
    let holder_rows = report
        .measured
        .iter()
        .filter(|r| r.action.starts_with("held via"))
        .count();
    if holder_rows > 0 {
        lines.push(format!(
            "  {holder_rows} {} holder rows: /proc/<pid>/fd + /proc/<pid>/maps \
             scan at the instant of this query",
            measured_tag
        ));
    }
    let enrich_rows = report
        .measured
        .iter()
        .filter(|r| r.action.starts_with("runs"))
        .count();
    if enrich_rows > 0 {
        lines.push(format!(
            "  {enrich_rows} {} enrichment rows: /proc/<pid>/cgroup (systemd unit) \
             + /proc/<pid>/cmdline",
            measured_tag
        ));
    }
    if meta_rows > 0 {
        lines.push(format!(
            "  {meta_rows} {} metadata rows: stat(2) on the queried path",
            measured_tag
        ));
    }
    if !report.changes.rows.is_empty() || report.changes.unavailable {
        let observed = report
            .changes
            .rows
            .iter()
            .filter(|r| r.provenance == Provenance::Observed)
            .count();
        let inferred = report.changes.rows.len() - observed;
        if observed > 0 {
            lines.push(format!(
                "  {observed} {} event rows: vfs_open kprobe + the write probe (raw_syscalls/sys_enter) -> \
                 tracked_inodes filter -> file_events ring; CLOCK_MONOTONIC stamps \
                 rendered via /proc/uptime + wall offset",
                observed_tag
            ));
        }
        if inferred > 0 {
            lines.push(format!(
                "  {inferred} {} event rows: audit.log SYSCALL+PATH records (or \
                 journalctl export --grep), replayed - the log's latest record",
                inferred_tag
            ));
        }
        if report.changes.unavailable {
            lines.push(crate::output::grey_out(
                "  the unavailability line: no event lane could serve this run - the \
                 doctor's [eBPF] section names the exact reason",
            ));
        }
    }
    lines.push(crate::output::grey_out(
        "  Unaccounted and the verdict: composed from the rows above - nothing else",
    ));
    format!("\n{}", lines.join("\n"))
}

#[cfg(test)]
#[path = "../../../test/commands/why/ledger_tests.rs"]
mod tests;
