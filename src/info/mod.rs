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

/// The body of the version report (everything after the brand
/// header). Separated from [`print_version_report`] so tests can
/// assert the full line set without capturing stdout.
///
/// Roles (night-improve-37): the field labels ride green, the values
/// stay unwrapped (white, the terminal default), and the two
/// metadata tokens ride grey - Build-time is a timestamp, Source is
/// navigational metadata. The License line wraps WHOLE: the literal
/// is one contiguous rodata string the release lanes grep out of
/// `strings` output, so it never splits into label + value (the
/// label's green carries the line; the contiguity contract outranks
/// the label/value split). In Mono every wrap is the identity, so
/// piped output stays byte-identical to the plain shape - grep-clean
/// for scripts (`zejtron -V | grep Build-time`).
fn version_body() -> String {
    [
        format!(
            "{} {} ({})",
            crate::output::ok_out("Build:"),
            build_label(),
            build_hash()
        ),
        format!(
            "{} {}",
            crate::output::ok_out("Build-time:"),
            crate::output::grey_out(build_time())
        ),
        format!(
            "{} {}",
            crate::output::ok_out("Copyright:"),
            "(c) 2026 rezky_nightky (oxyzenQ)"
        ),
        crate::output::ok_out(LICENSE_LINE),
        format!(
            "{} {}",
            crate::output::ok_out("Source:"),
            crate::output::grey_out("https://github.com/oxyzenQ/zejtron")
        ),
    ]
    .join("\n")
}

/// Print the full version report for `-V` / `--version`.
///
/// The sibling's masterclass layout: brand header (the name token,
/// the version value, then the one-line description), followed by the
/// build facts. The name rides brand purple #A855F7 (regular weight,
/// the same RGB the clap lane paints) - the tier's one runtime seat -
/// the version value stays white, and the description line rides
/// grey (metadata, the locked scheme's secondary content). Paint
/// decisions anchor on the STDOUT lane (the surface speaks through
/// stdout), so piped output renders plain bytes and ANSI codes never
/// leak into scripts or log files; `CLICOLOR_FORCE=1` re-arms the
/// lane for captured runs.
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
    println!(
        "{} v{}",
        crate::output::brand_out(&format!("{NAME}:")),
        env!("CARGO_PKG_VERSION")
    );
    println!("{}", crate::output::grey_out(env!("CARGO_PKG_DESCRIPTION")));
    println!("{}", version_body());
}

#[cfg(test)]
#[path = "../../test/info/info_tests.rs"]
mod tests;
