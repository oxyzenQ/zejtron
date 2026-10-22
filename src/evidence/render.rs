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
//! - The shape is byte-deterministic per capability rung (night-
//!   improve-37 repainted the surface without changing the shape):
//!   the renderer's only environment read is the stdout capability
//!   probe (cached once per process), and in Mono - every pipe, every
//!   `NO_COLOR` run - the render is the exact plain bytes the shape
//!   shipped with, zero escape bytes. On a terminal the tiers ride
//!   the locked scheme: green section headers and verdict labels,
//!   grey mode lines, timestamps and hints, the provenance tags by
//!   evidence strength, and the values (actions, actors, counts,
//!   subjects) unwrapped - white, the terminal default. `NO_COLOR`
//!   needs no honoring beyond the ladder: the wrappers are the
//!   identity there.
//! - Deterministic ordering: the renderer never reorders (the
//!   callers sort), never iterates a hash map. Same rows in, same
//!   bytes out - per rung.
//! - The Changes subsection renders under the state rows: its rows
//!   when there are any, `(no events in the window)` when the window
//!   came back empty, and the named unavailability line (the same
//!   sentence port's window prints - one grammar, one source, two
//!   surfaces: this module owns the sentence, port speaks it from
//!   here) when no event lane could serve at all. An empty window
//!   and an absent lane are different truths.
//! - Unaccounted is always present; empty renders `(none observed)`.
//! - Verdict is always present, exactly two lines.

use super::EvidenceReport;

/// The unavailability line, the one source of the sentence (the
/// phase-2 grammar): the evidence renderer prints it here, and
/// port's window speaks it from this same function - one grammar,
/// one source, two surfaces. The layering is unchanged: the
/// evidence module still stands alone below the commands (nothing
/// here imports a command); port delegates down, so the sentence
/// can no longer drift between the two surfaces that print it.
pub fn unavailability_line(window_label: &str) -> String {
    format!(
        "Changes in the last {window_label}: unavailable (this binary/run cannot capture \
         events - see zejtron doctor [eBPF])"
    )
}

/// Render the full report. Pure function of its input plus the
/// cached stdout capability (the one environment read); no clock
/// reads (the rows carry their own times). Mono renders the exact
/// plain bytes the shape shipped with.
pub fn render_report(report: &EvidenceReport) -> String {
    let mut lines: Vec<String> = Vec::new();

    // The header: subject, then the mode line with the window (and
    // the lane qualifier inside the same parentheses). Roles: the
    // report label rides green (the section header), the subject is
    // the value and stays unwrapped, the mode line rides grey (the
    // locked scheme's secondary content).
    lines.push(format!(
        "{} {}",
        crate::output::ok_out("Evidence report:"),
        report.subject
    ));
    lines.push(grey_mode_line(report));
    lines.push(String::new());

    // The Evidence block: the state rows first, then the Changes
    // subsection. The (UTC) suffix marks the first timestamped row
    // of the whole report - one declaration, bare rows after it.
    lines.push(crate::output::ok_out("Evidence:"));
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
        lines.push(crate::output::ok_out(&format!(
            "  Changes in the last {}:",
            report.window_label
        )));
        if report.changes.unavailable {
            lines.push(format!(
                "  {}",
                crate::output::grey_out(&unavailability_line(&report.window_label))
            ));
        } else if report.changes.rows.is_empty() {
            lines.push(format!(
                "  {}",
                crate::output::grey_out("(no events in the window)")
            ));
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
    lines.push(crate::output::ok_out("Unaccounted:"));
    if report.unaccounted.is_empty() {
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
    } else {
        for entry in &report.unaccounted {
            lines.push(format!("  {}", entry.render_line()));
        }
    }
    lines.push(String::new());

    // Verdict: always present, exactly two lines. The labels ride
    // green (the verdict is the report's primary content); the
    // verdict texts stay unwrapped - they are composed of the values
    // (names, PIDs, counts) the user came for.
    lines.push(crate::output::ok_out("Verdict:"));
    lines.push(format!(
        "  {} {}",
        crate::output::ok_out("The evidence supports:"),
        report.verdict.supports
    ));
    lines.push(format!(
        "  {} {}",
        crate::output::ok_out("The evidence cannot support:"),
        report.verdict.cannot_support
    ));

    lines.join("\n")
}

/// The mode line: `Mode: <base> (window <label><qualifier>)`. The
/// whole line rides the grey tier - the locked scheme's secondary
/// content (mode lines). In Mono the wrap is the identity.
fn grey_mode_line(report: &EvidenceReport) -> String {
    crate::output::grey_out(&format!(
        "Mode: {} (window {}{})",
        report.mode.base(),
        report.window_label,
        report.mode.lane_qualifier()
    ))
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
