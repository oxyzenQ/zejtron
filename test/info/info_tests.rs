// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! info unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/info/mod.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

/// The license line exists as ONE contiguous literal
/// (LICENSE_LINE) - the release lane greps exactly those bytes
/// out of `strings` on shipped artifacts. The literal is pinned
/// verbatim here so a drifted line fails in the unit run, not on
/// a release day.
#[test]
fn license_line_is_the_contiguous_bytes_the_release_probe_greps() {
    assert_eq!(LICENSE_LINE, "License: GPL-3.0-only");
}

/// The version report carries the Build-time line between Build
/// and Copyright (sibling parity), and every documented line is
/// present exactly once.
#[test]
fn version_report_carries_build_time_line() {
    let body = version_body();
    for line in [
        "Build-time: ",
        "Copyright: (c) 2026 rezky_nightky (oxyzenQ)",
        "License: GPL-3.0-only",
        "Source: https://github.com/oxyzenQ/zejtron",
    ] {
        let count = body.lines().filter(|l| l.contains(line)).count();
        assert_eq!(count, 1, "line must appear exactly once: {line}");
    }
    // Ordering: Build-time sits directly after the Build line.
    let lines: Vec<&str> = body.lines().collect();
    let build_idx = lines
        .iter()
        .position(|l| l.starts_with("Build: "))
        .expect("Build: line present");
    assert!(
        lines[build_idx + 1].starts_with("Build-time: "),
        "Build-time must follow Build, got: {}",
        lines[build_idx + 1]
    );
}

/// The stamped build time is either the documented degraded
/// "unknown" (host clock unreadable at build time) or matches the
/// Hinnant `M/D/YYYY HH:MM (UTC)` shape with a plausible year. A
/// malformed stamp (e.g. an accidental local-time format with an
/// offset suffix) fails here, not in the wild.
#[test]
fn build_time_stamp_shape_is_m_d_yyyy_hh_mm_utc() {
    let stamp = build_time();
    if stamp == "unknown" {
        return; // degraded path, documented
    }
    assert!(
        stamp.ends_with(" (UTC)"),
        "stamp must carry the (UTC) suffix: {stamp}"
    );
    let core = stamp.strip_suffix(" (UTC)").expect("suffix checked above");
    let (date, time) = core
        .split_once(' ')
        .unwrap_or_else(|| panic!("date and time must be space-separated: {stamp}"));
    let date_parts: Vec<&str> = date.split('/').collect();
    assert_eq!(date_parts.len(), 3, "date must be M/D/YYYY: {stamp}");
    let (month, day, year) = (
        date_parts[0].parse::<u32>().unwrap_or(0),
        date_parts[1].parse::<u32>().unwrap_or(0),
        date_parts[2].parse::<u32>().unwrap_or(0),
    );
    assert!((1..=12).contains(&month), "month out of range: {stamp}");
    assert!((1..=31).contains(&day), "day out of range: {stamp}");
    assert!(year >= 2026, "year implausibly old: {stamp}");
    let time_parts: Vec<&str> = time.split(':').collect();
    assert_eq!(time_parts.len(), 2, "time must be HH:MM: {stamp}");
    assert_eq!(time_parts[0].len(), 2, "hour must be 2 digits: {stamp}");
    assert_eq!(time_parts[1].len(), 2, "minute must be 2 digits: {stamp}");
    let hour = time_parts[0].parse::<u32>().unwrap_or(99);
    let minute = time_parts[1].parse::<u32>().unwrap_or(99);
    assert!(hour <= 23, "hour out of range: {stamp}");
    assert!(minute <= 59, "minute out of range: {stamp}");
}

#[test]
fn build_label_detects_libc_variant() {
    let label = build_label();
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        assert!(
            label.ends_with("-gnu") || label.ends_with("-musl"),
            "build_label must include libc variant (-gnu/-musl), got: {label}"
        );
    }
}

/// night-dragon-maintenance-T1 fallback contract: in a plain
/// `cargo test` build ZEJTRON_BUILD is not forwarded by build.rs, so
/// the canonical label must equal the `local-` prefixed
/// compile-time arch+os+libc detection - every local build names
/// itself with the `local-` marker (the estate-wide label
/// contract). The override path (alias builds reporting
/// `local-pro-native-musl` etc., release builds reporting
/// `pro-linux-amd64-v3-musl`) is verified live by building with the
/// aliases and reading `zejtron -V` - release.yml's Verify step
/// holds the release arm of that loop.
#[test]
fn build_label_falls_back_to_the_local_marker_plus_detected_target() {
    match option_env!("ZEJTRON_BUILD") {
        Some(_) => { /* alias/CI build: override path, verified live */ }
        None => assert_eq!(build_label(), format!("local-{}", detected_build_target())),
    }
}

/// The detected fallback ingredient must stay lowercase and carry
/// the os-arch-libc shape the docs promise (`linux-amd64-gnu`
/// style - the `local-` marker prefixes it in [`build_label`]), so
/// a drift in detected_build_target() cannot silently reshape the
/// Build: line.
#[test]
fn detected_build_target_shape_is_os_arch_libc() {
    let target = detected_build_target();
    assert!(target.contains('-'), "target must be dash-joined: {target}");
    assert!(
        !target.contains(char::is_whitespace),
        "target must be a single token: {target}"
    );
    assert_eq!(target, target.to_lowercase());
}

/// night-dragon-maintenance-T1 contract: the Signature line appears
/// exactly once, directly after Build-time, and is the lane-honest
/// one of the two documented lines - a build whose eBPF lane stamp
/// proves embedded objects (source-built or registry-prebuilt: the
/// objects ride inside the binary either way) carries "Pure eBPF
/// builtin"; a missing stamp carries the honest unstamped line and
/// never the claim it cannot back.
#[test]
fn signature_line_is_pinned_after_build_time_and_lane_honest() {
    let body = version_body();
    let count = body
        .lines()
        .filter(|l| l.starts_with("Signature: "))
        .count();
    assert_eq!(count, 1, "the Signature line must appear exactly once");
    let expected = signature_line();
    assert!(
        [SIGNATURE_LINE, SIGNATURE_UNSTAMPED_LINE].contains(&expected),
        "signature must be one of the documented lines, got: {expected}"
    );
    let lines: Vec<&str> = body.lines().collect();
    let time_idx = lines
        .iter()
        .position(|l| l.starts_with("Build-time: "))
        .expect("Build-time line present");
    assert_eq!(
        lines[time_idx + 1],
        expected,
        "the Signature line must follow Build-time"
    );
    // Lane honesty: only a proven lane stamp earns the full-life
    // claim. Both real lanes embed the object; the unstamped guard
    // arm exists so a broken stamp can never claim purity.
    assert_eq!(
        expected,
        match ebpf_lane() {
            "source-built" | "registry-prebuilt" => SIGNATURE_LINE,
            _ => SIGNATURE_UNSTAMPED_LINE,
        }
    );
}

/// night-dragon-maintenance-T1 contract: the version report's body
/// stays PLAIN (the estate parity law) - no ANSI escape bytes on
/// any capability, and the Signature literal rides the body as ONE
/// contiguous line (the release lane's byte-grep probe greps
/// exactly those bytes, grep -aFq, against v4 artifacts it cannot
/// execute).
#[test]
fn version_report_body_is_plain_and_signature_literal_is_contiguous() {
    let body = version_body();
    assert!(
        !body.contains('\x1b'),
        "the -V body must print plain - no color wrap around the build facts"
    );
    assert_eq!(
        SIGNATURE_LINE,
        "Signature: Pure eBPF builtin \u{2014} Official Build by rezky_nightky (oxyzenQ)"
    );
}
