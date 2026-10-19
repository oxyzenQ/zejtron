// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The symptom dispatch pins (night-improve-4, Part B). The
//! deferral is the contract: not-implemented symptoms print the
//! named line and exit 0; unknown symptoms are usage errors that
//! name the vocabulary. The ram report itself is pinned through the
//! memory and ledger test modules with synthetic samples - the
//! dispatch test never depends on the host's own /proc.

use super::*;

#[test]
fn known_vocabulary_is_the_four_names() {
    assert_eq!(KNOWN, ["ram", "slow", "disk", "network"]);
    assert_eq!(IMPLEMENTED, "ram");
}

#[test]
fn unimplemented_symptoms_print_the_deferral_and_exit_zero() {
    // The honest deferral: the line names what exists, what does
    // not, and where the rest lands. Exit 0 - a deferral is an
    // answer, not a failure. (run prints to stdout; the Ok is the
    // contract this test pins.)
    for symptom in ["slow", "disk", "network"] {
        let result = run(symptom, false);
        assert!(result.is_ok(), "'{symptom}' must defer with Ok, not error");
    }
}

#[test]
fn unknown_symptom_is_a_usage_error_naming_the_vocabulary() {
    let err = run("cpu", false).expect_err("unknown symptom must be a usage error");
    assert!(err.to_string().contains("unknown symptom 'cpu'"), "{err}");
    assert!(
        err.to_string().contains("ram, slow, disk, network"),
        "the error names the vocabulary: {err}"
    );
}

#[test]
fn ram_dispatch_completes_on_the_live_host() {
    // The implemented symptom runs against this host's /proc: the
    // contract here is only that it completes Ok (the report's shape
    // is pinned with synthetic samples in the ledger module). On a
    // host without a readable /proc the report degrades honestly -
    // still Ok, still a rendered report.
    assert!(run("ram", false).is_ok());
}
