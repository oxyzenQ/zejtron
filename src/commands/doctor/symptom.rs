// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The doctor's symptom lane (night-improve-4, Part B; expanded by
//! night-improve-48; the umbrella composed by night-dragon-lts-2):
//! the answer surface. The readiness report tells the operator
//! what zejtron can see; a symptom tells the operator what they
//! came for. One flag on the doctor - no new verb, the surface
//! count stays nine - and six implemented symptoms this version:
//! the four delta/snapshot lanes `cpu`, `disk`, `network`, and
//! `gpu`, the snapshot lane `ram`, and `slow` - the umbrella that
//! composes the cpu, disk, memory, and network lanes over ONE
//! shared 1.0-second window and ranks the cross-lane signatures
//! (see slow.rs) into one severity-ordered answer.
//!
//! Every symptom rides the kernel's own tables (/proc and /sys
//! only, no capabilities beyond the invoking user's own), the
//! delta symptoms sample twice with exactly one 1.0-second sleep
//! between the reads (the wait IS the measurement - never a loop),
//! and when the eBPF probe is attached every symptom may drain the
//! exit ring to name the processes that died inside its window,
//! [observed]. Every consumer the kernel exposes to this
//! invocation is named, and whatever cannot be attributed is named
//! as unaccounted - the Evidence Ledger discipline, applied to
//! each lane.

use super::json;
use super::{cpu, disk, gpu, memory, network, slow};
use std::error::Error;
use std::fmt;

/// The symptom vocabulary this version speaks - the usage error
/// carries it, and since the umbrella landed (night-dragon-lts-2)
/// every spoken name is an implemented lane: the vocabulary IS the
/// dispatch arm set, one list, no drift possible.
pub const KNOWN: [&str; 6] = ["ram", "cpu", "disk", "network", "gpu", "slow"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymptomError(String);

impl fmt::Display for SymptomError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for SymptomError {}

/// The doctor's `--symptom` dispatch. `Ok(())` is a completed
/// report - exit 0; an unknown symptom is a usage error (exit 1
/// through the labeled renderer). The JSON lane (night-badass-5)
/// speaks the same symptom truth as one typed line, and `--raw`
/// stays text-only (the CLI refuses the pair).
pub fn run(symptom: &str, raw: bool, print_json: bool) -> Result<(), SymptomError> {
    if !KNOWN.contains(&symptom) {
        return Err(SymptomError(format!(
            "unknown symptom '{symptom}' - the symptoms this version speaks: {}",
            KNOWN.join(", ")
        )));
    }
    // The KNOWN gate above owns the arm set: every name that reaches
    // this match is one of the six implemented lanes. The JSON lane
    // reuses the sample the text lane renders - one collection, two
    // renderings, the evidence ledger's own law.
    if print_json {
        let line = match symptom {
            "ram" => json::json_ram(&memory::collect()),
            "cpu" => json::json_cpu(&cpu::collect()),
            "disk" => json::json_disk(&disk::collect()),
            "network" => json::json_network(&network::collect()),
            "gpu" => json::json_gpu(&gpu::collect()),
            "slow" => json::json_slow(&slow::collect()),
            _ => unreachable!("the KNOWN gate above owns this arm"),
        };
        println!("{line}");
        return Ok(());
    }
    let report = match symptom {
        "ram" => memory::report(raw),
        "cpu" => cpu::report(raw),
        "disk" => disk::report(raw),
        "network" => network::report(raw),
        "gpu" => gpu::report(raw),
        "slow" => slow::report(raw),
        _ => unreachable!("the KNOWN gate above owns this arm"),
    };
    println!("{report}");
    Ok(())
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/symptom_tests.rs"]
mod tests;
