// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The doctor's symptom lane (night-improve-4, Part B): the answer
//! surface. The readiness report tells the operator what zejtron can
//! see; a symptom tells the operator what they came for. One flag on
//! the doctor - no new verb, the surface count stays nine - and one
//! implemented symptom this version: `ram`.
//!
//! The deferral is the honest one, not a stub: a symptom that is not
//! implemented prints its named line and exits 0. No fake data, no
//! hidden feature, no "coming soon" promise - the line names exactly
//! what exists and exactly what does not.
//!
//! The memory symptom rides /proc alone (no eBPF, no capabilities):
//! every consumer the kernel exposes to this invocation is named,
//! and whatever cannot be attributed is named as unaccounted - the
//! Evidence Ledger discipline, applied to RAM.

use super::memory;
use std::error::Error;
use std::fmt;

/// The symptom this version implements. The other three names print
/// the deferral line; anything else is a usage error that names the
/// vocabulary.
pub const IMPLEMENTED: &str = "ram";

/// The symptom vocabulary this version speaks - the deferral line
/// and the usage error both carry it.
pub const KNOWN: [&str; 4] = ["ram", "slow", "disk", "network"];

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
    if symptom != IMPLEMENTED {
        println!(
            "symptom '{symptom}' is not implemented in this version; only '{IMPLEMENTED}' is \
             available. The remaining symptoms land in a future release (or a maintenance \
             update after v80.0.0)."
        );
        return Ok(());
    }
    let report = memory::report(raw);
    println!("{report}");
    Ok(())
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/symptom_tests.rs"]
mod tests;
