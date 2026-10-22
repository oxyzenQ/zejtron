// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The doctor's symptom lane (night-improve-4, Part B; expanded by
//! night-improve-48): the answer surface. The readiness report
//! tells the operator what zejtron can see; a symptom tells the
//! operator what they came for. One flag on the doctor - no new
//! verb, the surface count stays nine - and five implemented
//! symptoms this version: `ram`, and the four delta/snapshot
//! lanes `cpu`, `disk`, `network`, and `gpu`.
//!
//! The deferral is the honest one, not a stub: `slow` is the one
//! name this version still defers, and it prints its named line and
//! exits 0. No fake data, no hidden feature, no "coming soon"
//! promise - the line names exactly what exists and exactly what
//! does not.
//!
//! Every symptom rides the kernel's own tables (/proc and /sys
//! only, no capabilities beyond the invoking user's own), the
//! delta symptoms sample twice with exactly one 1.0-second sleep
//! between the reads (the wait IS the measurement - never a loop),
//! and when the eBPF tap is attached every symptom may drain the
//! exit ring to name the processes that died inside its window,
//! [observed]. Every consumer the kernel exposes to this
//! invocation is named, and whatever cannot be attributed is named
//! as unaccounted - the Evidence Ledger discipline, applied to
//! each lane.

use super::{cpu, disk, gpu, memory, network};
use std::error::Error;
use std::fmt;

/// The symptoms this version implements - the dispatch arms and
/// the deferral line both carry the list.
pub const IMPLEMENTED: [&str; 5] = ["ram", "cpu", "disk", "network", "gpu"];

/// The one deferral this version still carries: the umbrella
/// symptom that needs the per-lane reports to compose first.
pub const DEFERRED: &str = "slow";

/// The symptom vocabulary this version speaks - the deferral line
/// and the usage error both carry it.
pub const KNOWN: [&str; 6] = ["ram", "cpu", "disk", "network", "gpu", "slow"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymptomError(String);

impl fmt::Display for SymptomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for SymptomError {}

/// The doctor's `--symptom` dispatch. `Ok(())` is a completed report
/// or a completed deferral - both exit 0; an unknown symptom is a
/// usage error (exit 1 through the labeled renderer).
pub fn run(symptom: &str, raw: bool) -> Result<(), SymptomError> {
    if !KNOWN.contains(&symptom) {
        return Err(SymptomError(format!(
            "unknown symptom '{symptom}' - the symptoms this version speaks: {}",
            KNOWN.join(", ")
        )));
    }
    if symptom == DEFERRED {
        // The deferral line rides grey (the locked scheme's secondary
        // content - an honest absence, not a verdict); the symptom
        // names inside it are the values and stay unwrapped, quoted
        // from the one source so the list cannot drift from the
        // dispatch arms.
        let quoted = quoted_list(&IMPLEMENTED);
        println!(
            "{}",
            crate::output::grey_out(&format!(
                "symptom '{DEFERRED}' is not implemented in this version; the implemented \
                 symptoms are {quoted}. '{DEFERRED}' lands in a future release (or a \
                 maintenance update after v80.0.0)."
            ))
        );
        return Ok(());
    }
    // The KNOWN gate above owns the arm set: every name that reaches
    // this match is one of the five implemented lanes.
    let report = match symptom {
        "ram" => memory::report(raw),
        "cpu" => cpu::report(raw),
        "disk" => disk::report(raw),
        "network" => network::report(raw),
        "gpu" => gpu::report(raw),
        _ => unreachable!("the KNOWN gate above owns this arm"),
    };
    println!("{report}");
    Ok(())
}

/// The quoted, comma-and name list the deferral line carries -
/// `'ram', 'cpu', ..., and 'gpu'` - one builder so the prose and
/// the dispatch arms cannot drift apart.
fn quoted_list(names: &[&str]) -> String {
    let quoted: Vec<String> = names.iter().map(|name| format!("'{name}'")).collect();
    match quoted.len() {
        0 => String::new(),
        1 => quoted[0].clone(),
        _ => format!(
            "{}, and {}",
            quoted[..quoted.len() - 1].join(", "),
            quoted[quoted.len() - 1]
        ),
    }
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/symptom_tests.rs"]
mod tests;
