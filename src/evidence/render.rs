// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The Evidence Ledger renderer (night-improve-3): the locked
//! output shape, rendered byte-deterministically. The shape, once,
//! verbatim:
//!
//! ```text
//! Evidence report: <subject>
//! Mode: <live | snapshot | mixed> (window <N>s)
//!
//! Evidence:
//!   <UTC timestamp>  <action>  <actor>  [<provenance>]
//!   ...
//!   Changes in the last <N>s:
//!   ...
//!
//! Unaccounted:
//!   (none observed)
//!   <N> <category> (<reason>)
//!
//! Verdict:
//!   <one-line summary naming what the evidence supports>
//!   <one-line summary naming what the evidence cannot support>
//! ```
//!
//! Locked rules, all enforced here and pinned by test:
//! - UTC everywhere; the first timestamped row carries the `(UTC)`
//!   suffix that declares the column, every row after it stays bare.
//! - No ANSI escape bytes ever - the format is plain text on every
//!   terminal and every pipe, so `NO_COLOR` needs no honoring (the
//!   ledger never colors in the first place).
//! - Deterministic: the renderer never reorders (the callers sort),
//!   never iterates a hash map, never consults the environment. Same
//!   rows in, same bytes out.
//! - The Changes subsection renders under the state rows: its rows
//!   when there are any, `(no events in the window)` when the window
//!   came back empty, and the named unavailability line (the same
//!   sentence port's window prints - one grammar, two surfaces, the
//!   duplication named) when no event lane could serve at all. An
//!   empty window and an absent lane are different truths.
//! - Unaccounted is always present; empty renders `(none observed)`.
//! - Verdict is always present, exactly two lines.

use super::EvidenceReport;

/// The unavailability line, the port surface's own sentence (the
/// phase-2 grammar): one grammar, two surfaces. Duplicated by hand
/// rather than imported - the evidence module stands alone below the
/// commands, and port's output is locked; the cross-reference is the
/// contract (src/commands/port/window.rs:unavailability_line).
fn unavailability_line(window_label: &str) -> String {
    format!(
        "Changes in the last {window_label}: unavailable (this binary/run cannot capture \
         events - see zejtron doctor [eBPF])"
    )
}

/// Render the full report. Pure function of its input; no
/// environment reads, no clock reads (the rows carry their own
/// times), no allocation beyond the output string.
pub fn render_report(report: &EvidenceReport) -> String {
    let mut lines: Vec<String> = Vec::new();

    // The header: subject, then the mode line with the window (and
    // the lane qualifier inside the same parentheses).
    lines.push(format!("Evidence report: {}", report.subject));
    lines.push(format!(
        "Mode: {} (window {}{})",
        report.mode.base(),
        report.window_label,
        report.mode.lane_qualifier()
    ));
    lines.push(String::new());

    // The Evidence block: the state rows first, then the Changes
    // subsection. The (UTC) suffix marks the first timestamped row
    // of the whole report - one declaration, bare rows after it.
    lines.push("Evidence:".to_owned());
    let mut utc_marked = false;
    for row in &report.measured {
        let line = row.render_line(should_mark_utc(row, &mut utc_marked));
        lines.push(format!("  {line}"));
    }
    // The Changes subsection rides whenever there is any event-lane
    // state to name: rows, the absent-lane unavailability, or a lane
    // that RAN and came back empty (the mode line just promised a
    // fallback; an empty window is a finding, not a missing section).
    // The one silent case is a report with no event-lane state at
    // all - the port targets, whose unaccounted block names the
    // inapplicability instead.
    let lane_ran = !matches!(report.mode, super::Mode::SnapshotNoLane)
        || report.changes.unavailable
        || !report.changes.rows.is_empty();
    if lane_ran {
        lines.push(format!("  Changes in the last {}:", report.window_label));
        if report.changes.unavailable {
            lines.push(format!("  {}", unavailability_line(&report.window_label)));
        } else if report.changes.rows.is_empty() {
            lines.push("  (no events in the window)".to_owned());
        } else {
            for row in &report.changes.rows {
                lines.push(format!(
                    "  {}",
                    row.render_line(should_mark_utc(row, &mut utc_marked))
                ));
            }
        }
    }
    lines.push(String::new());

    // Unaccounted: always present, `(none observed)` when empty.
    lines.push("Unaccounted:".to_owned());
    if report.unaccounted.is_empty() {
        lines.push("  (none observed)".to_owned());
    } else {
        for entry in &report.unaccounted {
            lines.push(format!("  {}", entry.render_line()));
        }
    }
    lines.push(String::new());

    // Verdict: always present, exactly two lines.
    lines.push("Verdict:".to_owned());
    lines.push(format!(
        "  The evidence supports: {}",
        report.verdict.supports
    ));
    lines.push(format!(
        "  The evidence cannot support: {}",
        report.verdict.cannot_support
    ));

    lines.join("\n")
}

/// The (UTC) marking rule: the first row that carries a real
/// timestamp gets the declaration; rows before it (an `unknown` row
/// can precede it) and every row after it stay bare.
fn should_mark_utc(row: &super::row::EvidenceRow, marked: &mut bool) -> bool {
    if *marked {
        return false;
    }
    if row.unix_secs.is_some() {
        *marked = true;
        return true;
    }
    false
}

#[cfg(test)]
#[path = "../../test/evidence/render_tests.rs"]
mod tests;
