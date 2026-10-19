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
/// zejtron: vX.Y.Z
/// Unified Linux introspection toolkit for paths, ports, processes, files, services, and diagnostics. Boring and serious.
/// Build: linux-amd64-gnu (3ae9dda)
/// Build-time: 10/17/2026 09:15 (UTC)
/// Copyright: (c) 2026 rezky_nightky (oxyzenQ)
/// License: GPL-3.0-only
/// Source: `<https://github.com/oxyzenQ/zejtron>`
/// ```
pub mod clock;
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
#[path = "../../test/info/info_tests.rs"]
mod tests;
