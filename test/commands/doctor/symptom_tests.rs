// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The symptom dispatch pins (night-improve-4 Part B, expanded by
//! night-improve-48, the umbrella composed by night-dragon-lts-2).
//! The vocabulary is the contract: every spoken name is an
//! implemented lane; unknown symptoms are usage errors that name
//! the vocabulary. The six implemented lanes run against this
//! host's own /proc: the contract here is only that they complete
//! Ok - each report's shape is pinned with synthetic samples in its
//! own test module, and the delta lanes sleep exactly 1.0s while
//! doing it (the runner's parallelism keeps the suite wall time
//! flat; the umbrella pays ONE sleep for all four of its lanes).

use super::*;

#[test]
fn the_vocabulary_is_fully_implemented() {
    // Since the umbrella landed (night-dragon-lts-2) every spoken
    // name is an implemented lane - the one list, pinned.
    assert_eq!(KNOWN, ["ram", "cpu", "disk", "network", "gpu", "slow"]);
}

#[test]
fn the_umbrella_completes_on_the_live_host() {
    // slow rides every lane's reader over ONE shared 1.0s window -
    // the completion contract the other lanes carry, plus the
    // single-sleep shape the funnel promises.
    assert!(run("slow", false, false).is_ok(), "slow must complete Ok");
}

#[test]
fn unknown_symptom_is_a_usage_error_naming_the_vocabulary() {
    let err = run("cpu_ram_disk", false, false).expect_err("unknown symptom must be a usage error");
    assert!(
        err.to_string().contains("unknown symptom 'cpu_ram_disk'"),
        "{err}"
    );
    assert!(
        err.to_string()
            .contains("ram, cpu, disk, network, gpu, slow"),
        "the error names the vocabulary: {err}"
    );
}

#[test]
fn every_spoken_lane_completes_on_the_live_host() {
    // The six lanes run against this host's tables: the contract
    // is completion Ok (the shapes are pinned with synthetic
    // samples in the per-lane modules). The delta lanes
    // sample a real 1.0s window each - the wait IS the measurement.
    for symptom in KNOWN {
        assert!(
            run(symptom, false, false).is_ok(),
            "'{symptom}' must complete Ok on a live host"
        );
    }
}

#[test]
fn the_raw_flag_rides_every_lane() {
    // --raw appends the drill-down on every lane; the flag's
    // contract is the flag's contract everywhere.
    for symptom in KNOWN {
        assert!(
            run(symptom, false, true).is_ok(),
            "'{symptom}' must complete Ok with the drill-down flag"
        );
    }
}
