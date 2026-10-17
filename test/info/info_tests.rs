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
