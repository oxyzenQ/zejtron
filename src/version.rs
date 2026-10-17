// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! zejtron package information constants and the version report
//! (the sibling project's masterclass layout: brand header, then
//! plain build facts a script can grep).

/// The `License:` line as ONE contiguous literal (the sibling's
/// NIGHT-blade-4 discipline). Release lanes verify artifacts WITHOUT
/// executing them by grepping `strings` output, so a line the
/// pipeline greps must never ride a format! inline capture - the
/// template would keep the prefix and the bare id would land
/// elsewhere in rodata. This const IS the whole line, so the bytes
/// stay contiguous by construction.
const LICENSE_LINE: &str = "License: GPL-3.0-only";

pub(crate) const NAME: &str = "zejtron";

/// Dynamic build target label: detects arch + libc env at compile time.
/// Returns e.g. "linux-amd64-gnu" (glibc, dynamic) or "linux-amd64-musl"
/// (static) for x86_64 Linux builds.
fn build_label() -> &'static str {
    if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "musl"
    )) {
        "linux-amd64-musl"
    } else if cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu"
    )) {
        "linux-amd64-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "linux-amd64"
    } else if cfg!(all(
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "musl"
    )) {
        "linux-aarch64-musl"
    } else if cfg!(all(
        target_os = "linux",
        target_arch = "aarch64",
        target_env = "gnu"
    )) {
        "linux-aarch64-gnu"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "linux-aarch64"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "unknown"
    }
}

/// The compile-time build-time stamp (the sibling's NIGHT-hunt-6
/// contract): stamped by build.rs from SystemTime via Howard
/// Hinnant's civil_from_days algorithm - UTC-only, so no timezone
/// database is pulled into the binary and the stamp is identical
/// across build hosts. Shape: `M/D/YYYY HH:MM (UTC)`.
fn build_time() -> &'static str {
    option_env!("ZEJTRON_BUILD_TIME").unwrap_or("unknown")
}

/// The compile-time commit sha, stamped by build.rs's three-step
/// chain (git rev-parse, then GITHUB_SHA, then the registry's
/// .cargo_vcs_info.json) and normalized to one canonical lowercase
/// 7-char shape. The chain's normalizer already rejects unusable
/// answers; the fallback covers a build script that never stamped
/// (degraded but honest).
fn build_hash() -> &'static str {
    option_env!("ZEJTRON_GIT_HASH").unwrap_or("unknown")
}

/// The plain-text body of the version report (everything after the
/// brand header). Separated from [`print_version_report`] so tests
/// can assert the full line set without capturing stdout. Every line
/// stays plain text - grep-clean for scripts (`zejtron -V | grep
/// Build-time`), the header carries the brand color, never the body.
fn version_body() -> String {
    format!(
        "Build: {} ({})\n\
         Build-time: {}\n\
         Copyright: (c) 2026 rezky_nightky (oxyzenQ)\n\
         {LICENSE_LINE}\n\
         Source: https://github.com/oxyzenQ/zejtron",
        build_label(),
        build_hash(),
        build_time(),
    )
}

/// Print the full version report for `-V` / `--version`.
///
/// The sibling's masterclass layout: brand header (name + version,
/// then the one-line description), followed by plain build facts. The
/// header is rendered in brand purple #A855F7 (regular weight, the
/// same RGB the clap lane paints) on a TTY, degrading through the
/// 256-color tier; when piped (non-TTY) everything is plain text so
/// ANSI codes never leak into scripts or log files. The build-facts
/// body is always plain.
///
/// ```text
/// zejtron: v11.0.0
/// Unified Linux introspection toolkit for paths, ports, processes, files, services, and diagnostics. Boring and serious.
/// Build: linux-amd64-gnu (3ae9dda)
/// Build-time: 10/17/2026 09:15 (UTC)
/// Copyright: (c) 2026 rezky_nightky (oxyzenQ)
/// License: GPL-3.0-only
/// Source: https://github.com/oxyzenQ/zejtron
/// ```
pub fn print_version_report() {
    let header = format!(
        "{NAME}: v{}\n{}",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_DESCRIPTION")
    );
    println!("{}", crate::output::brand(&header));
    println!("{}", version_body());
}

#[cfg(test)]
mod tests {
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
}
