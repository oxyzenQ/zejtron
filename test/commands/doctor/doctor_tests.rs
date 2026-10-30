// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! doctor unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/doctor/mod.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

fn result(status: CheckStatus, check: &'static str, message: &str) -> CheckResult {
    CheckResult {
        status,
        check,
        message: message.to_owned(),
    }
}

#[test]
fn summary_count_formatting() {
    let checks = [
        result(CheckStatus::Ok, "one", "ok"),
        result(CheckStatus::Warn, "two", "warn"),
        result(CheckStatus::Fail, "three", "fail"),
    ];

    assert_eq!(
        format_summary(summarize(&checks)),
        "  Summary:         ok=1 warn=1 fail=1"
    );
}

#[test]
fn status_row_formatting() {
    assert_eq!(
        format_check_row(&result(CheckStatus::Warn, "journalctl", "missing")),
        "  journalctl:      WARN  missing"
    );
}

#[test]
fn mode_labels_are_stable() {
    // The Mode row is a verdict seat (night-weekly-maintenance-2):
    // in Mono the bold wrappers are the identity, so the row's plain
    // bytes stay exactly the shape this pin has always carried.
    assert_eq!(mode_row(Some(0)), "privileged");
    assert_eq!(
        mode_row(Some(1000)),
        "unprivileged (partial results expected)"
    );
    assert_eq!(mode_row(None), "unprivileged (partial results expected)");
}

#[test]
fn build_metadata_row() {
    let check = check_build_metadata("abcdef123");

    assert_eq!(check.status, CheckStatus::Ok);
    assert_eq!(check.check, "build_meta");
    assert!(check.message.contains("zejtron v"));
    assert!(check.message.contains("(abcdef1)"));
    // night-dragon-maintenance-T1 parity: the doctor's build row
    // carries the SAME canonical variant the -V Build: line does
    // (the documented parity contract on check_build_metadata), so
    // the two surfaces can never drift apart.
    assert!(check.message.contains(&crate::info::build_label()));
}

#[test]
fn stable_output_shape() {
    let checks = [result(CheckStatus::Ok, "os", "linux")];
    let output = format_report(&checks, summarize(&checks));

    assert!(output.starts_with("━━━ zejtron System Doctor ━━━\n\n  Mode: "));
    assert!(output.contains("  os:              OK    linux"));
    // The Summary row closes the report with no blank line above it,
    // and the build fact rides the build_meta row alone - no
    // duplicate Build tail row repeats it (night-improve-42).
    assert!(output.ends_with("  Summary:         ok=1 warn=0 fail=0"));
    assert!(!output.contains("  Build:"));
}
