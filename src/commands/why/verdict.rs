// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The why verdict's lines (night-badass-5, a pure move): the
//! dragon's one-liner (the old synthesis logic) for every input
//! shape, the port synthesis, and the cannot-support lines per
//! lane. One builder set, two surfaces - the text ledger seats the
//! lines under its Verdict header, the JSON lane... the why surface
//! carries them in the Evidence Ledger's own verdict object.

use super::super::holds::{Holder, ScanStats};
use super::super::touch::TouchInfo;
use crate::evidence::{ChangesSection, Mode};

/// The dragon's one-liner, the old synthesis logic carried whole.
pub(super) fn path_supports_line(
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

pub(super) fn path_cannot_line(
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

pub(super) fn port_supports_line(holders: &[Holder]) -> String {
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

pub(super) fn port_cannot_line(stats: &ScanStats) -> String {
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
