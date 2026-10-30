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

/// The `Signature:` line for the version report as ONE contiguous
/// literal (night-dragon-maintenance-T1, the zelynic NIGHT-dinner-4
/// discipline ported with the estate build-label contract): the
/// claim "Pure eBPF builtin" is true of BOTH zejtron lanes - the
/// objects a git checkout cross-compiles from ebpf/ AND the
/// registry-prebuilt objects staged from ebpf-prebuilt/ - because
/// either way they ride inside the binary (include_bytes!): no
/// toolchain, no clang, no separate object files ever touch the
/// target machine. The eBPF support is UNCONDITIONAL, so every
/// build that compiles is a full-life build and carries this line.
const SIGNATURE_LINE: &str =
    "Signature: Pure eBPF builtin — Official Build by rezky_nightky (oxyzenQ)";

/// The degraded Signature (night-dragon-maintenance-T1): the guard
/// arm of the claims discipline. build/ebpf.rs stamps
/// ZEJTRON_EBPF_LANE unconditionally on both of its lanes
/// (source-built / registry-prebuilt), so a missing stamp means the
/// build script never finished - a build that fails anyway. The
/// guard exists so the version report can never claim embedded
/// objects a stamp never proved: if the impossible happens, the
/// report says the lane is unstamped instead of claiming purity.
const SIGNATURE_UNSTAMPED_LINE: &str =
    "Signature: eBPF lane unstamped — Official Build by rezky_nightky (oxyzenQ)";

/// The eBPF object lane this binary was built through, stamped by
/// build/ebpf.rs as `ZEJTRON_EBPF_LANE`:
///
/// - `source-built` - a git checkout: the object was cross-compiled
///   from the local ebpf/ tree by the nested nightly build.
/// - `registry-prebuilt` - a crates.io source extract: the
///   manifest-verified object from ebpf-prebuilt/ was staged - the
///   same bytes the GitHub Release binaries embed, provenance in
///   ebpf-prebuilt/manifest.toml.
///
/// There is NO dormant lane (night-weekly-maintenance-1 removed the
/// toggle; the support is unconditional), so the None arm is the
/// broken-stamp guard documented on SIGNATURE_UNSTAMPED_LINE.
pub(crate) fn ebpf_lane() -> &'static str {
    option_env!("ZEJTRON_EBPF_LANE").unwrap_or("")
}

/// The Signature line this binary's version report carries
/// (night-dragon-maintenance-T1): the full-life claim when the lane
/// stamp proves embedded objects, the honest unstamped line when it
/// does not. Both real lanes embed the object, so every real build
/// answers SIGNATURE_LINE.
fn signature_line() -> &'static str {
    match ebpf_lane() {
        "source-built" | "registry-prebuilt" => SIGNATURE_LINE,
        _ => SIGNATURE_UNSTAMPED_LINE,
    }
}

pub(crate) const NAME: &str = "zejtron";

/// The compile-time arch+os+libc detection - the fallback
/// ingredient of the canonical label, not the label itself.
/// Returns e.g. "linux-amd64-gnu" (glibc, dynamic) or
/// "linux-amd64-musl" (static) for x86_64 Linux builds.
fn detected_build_target() -> &'static str {
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

/// Canonical build label for the `Build:` line of the version report
/// (night-dragon-maintenance-T1, the estate-wide label contract - the
/// zelynic T1 lineage, cosmostrix `canonical_build_label()` descent).
///
/// Source of truth: the `ZEJTRON_BUILD` env var forwarded at compile
/// time by build.rs - set by the cargo aliases
/// (`local-pro-native-musl`, `local-pro-linux-amd64-v3-musl`,
/// `local-pro-linux-amd64-v4-musl`: the alias name under the
/// `local-` marker, so `-V` names the exact alias that produced the
/// binary) and by the release lane (`pro-` + the platform id, e.g.
/// `pro-linux-amd64-v3-musl` - a downloaded release binary names its
/// shape with the estate `pro-` prefix and never the `local-` one:
/// the download page ships pro- shapes, so -V names the same shape
/// the tarball name encodes, prefix included). When unset (a plain
/// `cargo build`, a crates.io install), it falls back to the
/// `local-` prefixed compile-time arch+libc detection, e.g.
/// `local-linux-amd64-gnu`: the build ran on the machine that runs
/// it, and the label says so. The x86-64 microarch level (v3/v4) is
/// the one dimension the fallback cannot self-detect - exactly why
/// every alias and the release lane stamp the label explicitly.
pub(crate) fn build_label() -> String {
    match option_env!("ZEJTRON_BUILD") {
        Some(label) if !label.is_empty() => label.to_string(),
        _ => format!("local-{}", detected_build_target()),
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
/// The sibling's -V law (night-weekly-maintenance-2, the masterclass
/// color pass): the header carries the purple - the name, the version,
/// and the description ride brand regular #A855F7 in ONE wrap, exactly
/// the sibling's construction - and the body renders PLAIN. The build
/// facts are the data a script greps, and the sibling's version body
/// wraps nothing: no label paint, no value paint, zero escape bytes on
/// a color terminal too. The License line stays ONE contiguous literal
/// (the release lanes' `strings` contract), now rendered unwrapped -
/// the contiguity contract and the plain-body law agree. The Signature
/// line (night-dragon-maintenance-T1) sits on its own line directly
/// after Build-time, easy to grep (`zejtron -V | grep Signature`).
fn version_body() -> String {
    [
        format!("Build: {} ({})", build_label(), build_hash()),
        format!("Build-time: {}", build_time()),
        signature_line().to_owned(),
        "Copyright: (c) 2026 rezky_nightky (oxyzenQ)".to_owned(),
        LICENSE_LINE.to_owned(),
        "Source: https://github.com/oxyzenQ/zejtron".to_owned(),
    ]
    .join("\n")
}

/// Print the full version report for `-V` / `--version`.
///
/// The sibling's masterclass layout (night-weekly-maintenance-2, the
/// color pass): the purple header, then plain build facts. The header
/// is the name, the version, and the one-line description in brand
/// purple #A855F7 (regular weight) wrapped ONCE - the sibling's exact
/// construction - degrading through the ladder's rungs; the body
/// renders plain everywhere, so the facts stay grep-clean for scripts
/// (`zejtron -V | grep Build-time`) on a terminal and in a pipe
/// alike. Paint decisions anchor on the STDOUT lane (the surface
/// speaks through stdout), so piped output renders plain bytes and
/// ANSI codes never leak into scripts or log files;
/// `CLICOLOR_FORCE=1` re-arms the lane for captured runs.
///
/// ```text
/// zejtron: vX.Y.Z
/// Read-only evidence ledger for the Linux host. Native kernel readers, eBPF event windows, zero external wrappers. Boring and serious.
/// Build: local-pro-linux-amd64-v3-musl (3ae9dda)
/// Build-time: 10/17/2026 09:15 (UTC)
/// Signature: Pure eBPF builtin — Official Build by rezky_nightky (oxyzenQ)
/// Copyright: (c) 2026 rezky_nightky (oxyzenQ)
/// License: GPL-3.0-only
/// Source: `<https://github.com/oxyzenQ/zejtron>`
/// ```
///
/// The `Build:` line carries the canonical label from
/// [`build_label`]: `local-pro-<alias>` for local alias builds (the
/// alias name under the `local-` marker), `pro-<platform id>` for
/// release binaries a user downloaded (the estate `pro-` prefix, no
/// `local-`), and `local-` + the detected `linux-<arch>-<libc>`
/// shape for plain local builds (a crates.io install included).
pub mod clock;
pub fn print_version_report() {
    println!(
        "{}",
        crate::output::brand_out(&format!(
            "{NAME}: v{}\n{}",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_DESCRIPTION")
        ))
    );
    println!("{}", version_body());
}

#[cfg(test)]
#[path = "../../test/info/info_tests.rs"]
mod tests;
