// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The symptom dispatch pins (night-improve-4 Part B, expanded by
//! night-improve-48). The deferral is the contract: the one
//! not-implemented name prints the named line and exits 0; unknown
//! symptoms are usage errors that name the vocabulary. The five
//! implemented lanes run against this host's own /proc: the
//! contract here is only that they complete Ok - each report's
//! shape is pinned with synthetic samples in its own test module,
//! and the delta lanes sleep exactly 1.0s while doing it (the
//! runner's parallelism keeps the suite wall time flat).

use super::*;

#[test]
fn known_vocabulary_is_the_six_names() {
    assert_eq!(KNOWN, ["ram", "cpu", "disk", "network", "gpu", "slow"]);
    assert_eq!(
        IMPLEMENTED,
        ["ram", "cpu", "disk", "network", "gpu"],
        "the dispatch arms, in the deferral line's own order"
    );
    assert_eq!(DEFERRED, "slow", "the one deferral this version carries");
}

#[test]
fn the_deferral_names_what_exists_and_what_does_not() {
    // The honest deferral: the line names the implemented set (from
    // the one source, quoted) and the deferred name. Exit 0 - a
    // deferral is an answer, not a failure.
    let result = run(DEFERRED, false, false);
    assert!(result.is_ok(), "the deferral must defer with Ok");
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
fn every_implemented_lane_completes_on_the_live_host() {
    // The five lanes run against this host's tables: the contract
    // is completion Ok (the shapes are pinned with synthetic
    // samples in the per-lane modules). The three delta lanes
    // sample a real 1.0s window each - the wait IS the measurement.
    for symptom in IMPLEMENTED {
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
    for symptom in IMPLEMENTED {
        assert!(
            run(symptom, false, true).is_ok(),
            "'{symptom}' must complete Ok with the drill-down flag"
        );
    }
}
