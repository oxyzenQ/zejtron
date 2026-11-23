// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! zejtron package information constants and the version report
//! (the sibling project's masterclass layout: brand header, then
//! plain build facts a script can grep).

/// The `License:` line as ONE contiguous literal (the sibling's
/// NIGHT-blade-4 discipline). Release lanes verify artifacts WITHOUT
/// executing them by grepping `strings` output, so a line the
/// pipeline greps must never ride a format! inline capture - the
/// template would keep the prefix and the bare id would land
/// elsewhere in rodata. This const IS the whole line, so the bytes
/// stay contiguous by construction. The dual-license SPDX OR
/// expression (night-ux-orion-2, the masterclass disclosure) names
/// both doors in the same bytes: AGPL-3.0-only, or the Commercial
/// License for closed-source use - the exact string the manifest's
/// license field and every file header carry.
const LICENSE_LINE: &str = "License: AGPL-3.0-only OR Commercial";

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
/// The identity rides the masked provenance layers
/// (night-signature-advanced-1): a plaintext identity here would hand
/// a thief the exact grep target the masked scheme exists to deny, so
/// the const carries the eBPF claim only. The rendered line restores
/// the family clause (night-pro-1, the estate -V law): signature_line
/// appends the manifest materialized from the masked words at render
/// time - the same single unmask pass the Copyright line and the
/// `sig` report already render from - so the three sibling reports
/// and this one carry one "claim, em dash, manifest" shape while the
/// artifact bytes still hold no identity at rest.
const SIGNATURE_LINE: &str = "Signature: Pure eBPF builtin";

/// The degraded Signature (night-dragon-maintenance-T1): the guard
/// arm of the claims discipline. build/ebpf.rs stamps
/// ZEJTRON_EBPF_LANE unconditionally on both of its lanes
/// (source-built / registry-prebuilt), so a missing stamp means the
/// build script never finished - a build that fails anyway. The
/// guard exists so the version report can never claim embedded
/// objects a stamp never proved: if the impossible happens, the
/// report says the lane is unstamped instead of claiming purity.
const SIGNATURE_UNSTAMPED_LINE: &str = "Signature: eBPF lane unstamped";

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
/// (night-dragon-maintenance-T1, the family clause law night-pro-1):
/// the full-life claim followed by the materialized identity manifest
/// when the lane stamp proves embedded objects - the exact shape the
/// sibling reports render - built from the caller's single unmask
/// pass (no second materialization). The honest unstamped line when
/// the stamp does not exist: a broken stamp never quotes a manifest.
fn signature_line(manifest: &str) -> String {
    match ebpf_lane() {
        "source-built" | "registry-prebuilt" => format!("{SIGNATURE_LINE} — {manifest}"),
        _ => SIGNATURE_UNSTAMPED_LINE.to_owned(),
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
/// across build hosts. Shape: `YYYY-MM-DD HH:MMZ` (ISO 8601, UTC;
/// night-pro-1, the estate-wide format).
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

/// The D5 commit-signature stamp (night-netrunner-Z1, the zelynic
/// night-solid-defense-2 lineage): the build-time verdict on "does
/// the commit this binary claims carry a GPG signature by the
/// pinned maintainer key?" - verified by build/gpg.rs against the
/// repo's pinned public key in an isolated keyring, `<state>[:<evidence-hex>]`
/// grammar, consumed by the `sig` matrix's D5 row. "unstamped" is
/// the fail-closed fallback (a build whose script never stamped
/// cannot claim a signature verdict - the runtime row refuses on
/// it, never a silent pass).
pub(crate) fn vcs_commit_sig() -> &'static str {
    option_env!("ZEJTRON_VCS_COMMIT_SIG").unwrap_or("unstamped")
}

/// The body of the version report (everything after the brand
/// header). Separated from [`print_version_report`] so tests can
/// assert the full line set without capturing stdout.
///
/// The sibling's -V law (night-weekly-maintenance-2, the masterclass
/// color pass): the header carries the purple - the name, the version,
/// and the description ride brand regular #A855F7 in ONE wrap, exactly
/// the sibling's construction. The body renders plain, with the one
/// green seat the owner's spec gives the provenance line: the
/// `Depth-matrix:` line is the strongest provenance tag in the report and
/// rides the Ok tier on a terminal (night-signature-advanced-1),
/// plain bytes in a pipe. The License line stays ONE contiguous
/// literal (the release lanes' `strings` contract). The Signature
/// line (night-dragon-maintenance-T1) sits on its own line directly
/// after Build-time, easy to grep (`zejtron -V | grep Signature`);
/// it leads with the eBPF claim and carries the materialized identity
/// manifest after the em dash (night-pro-1, the family -V law) - the
/// identity is still NOT in the artifact as plaintext, it renders
/// from the masked provenance layers (their whole point). The
/// Depth-matrix line rides directly after it:
/// the masked scheme's status line (fingerprint, status, anchor,
/// layers), materialized from one unmask pass per render (the
/// single-pass invariant in [`provenance`]).
fn version_body() -> String {
    let view = provenance::provenance_view();
    // The Copyright line renders the holder from the masked provenance
    // layers at runtime (night-fly-1, the anti-grep contract the
    // release lane's identity probe enforces on BOTH musl legs): the
    // at-rest bytes carry the prefix and the year range only - the
    // holder exists in the artifact as masked words, never contiguous
    // rodata a grep-and-strip rebrand can find. The holder is the D0
    // identity core (the manifest's tail), the masterclass form: no
    // colon after the Copyright word (the Linux kernel and Rust
    // compiler convention - the universal shape every auditor
    // recognizes), no email (the contact rides the sig facts block).
    // The D1 authors layer independently re-encodes the same identity
    // and the binding check refuses a mismatched pair. The trailing
    // year moves when a release lands in a new calendar year
    // (2025-2027 for a 2027 release) and freezes the day the claim
    // changes hands - the range never loses its first year. An empty
    // core (the manifest lost the marker shape - tampering) renders
    // the holder absent: the fact is never guessed.
    let copyright = if view.identity.is_empty() {
        "Copyright (c) 2025-2026".to_owned()
    } else {
        format!("Copyright (c) 2025-2026 {}", view.identity)
    };
    [
        format!("Build: {} ({})", build_label(), build_hash()),
        format!("Build-time: {}", build_time()),
        signature_line(&view.manifest),
        view.depth_line,
        copyright,
        LICENSE_LINE.to_owned(),
        "Source: https://github.com/oxyzenQ/zejtron".to_owned(),
    ]
    .join("\n")
}

/// The full version report as ONE plain string (night-total-hardening-1):
/// the exact bytes [`print_version_report`] writes on a pipe - the
/// capability ladder's plain rung. The verb version lane hands this to
/// clap's version action so a raw DisplayVersion render (any path that
/// bypasses the UX bridge) still prints the complete report, never a
/// bare version number.
pub(crate) fn version_report_text() -> String {
    format!(
        "{NAME}: v{}\n{}\n{}",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_DESCRIPTION"),
        version_body()
    )
}

pub mod clock;
pub(crate) mod commit_sig;
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
/// Build-time: 2026-10-17 09:15Z
/// Signature: Pure eBPF builtin — Official Build by rezky_nightky (oxyzenQ)
/// Depth-matrix: fp=<16 lowercase hex> status=verified anchor=b3:<64 lowercase hex> layers=d0:masked-words,d1:masked-words,d2:dual-fingerprint,d3:blake3-anchor
/// Copyright (c) 2025-2026 rezky_nightky (oxyzenQ)
/// License: AGPL-3.0-only OR Commercial
/// Source: `<https://github.com/oxyzenQ/zejtron>`
/// ```
///
/// The `Depth-matrix:` line rides the status-green tier on a terminal
/// (the owner's spec mark, night-signature-advanced-1) and stays
/// plain bytes in a pipe - the paint decision anchors on the STDOUT
/// lane's capability ladder, the same gate every data surface uses.
///
/// The `Build:` line carries the canonical label from
/// [`build_label`]: `local-pro-<alias>` for local alias builds (the
/// alias name under the `local-` marker), `pro-<platform id>` for
/// release binaries a user downloaded (the estate `pro-` prefix, no
/// `local-`), and `local-` + the detected `linux-<arch>-<libc>`
/// shape for plain local builds (a crates.io install included).
pub(crate) mod provenance;
pub mod signature;
pub fn print_version_report() {
    println!(
        "{}",
        crate::output::brand_out(&format!(
            "{NAME}: v{}\n{}",
            env!("CARGO_PKG_VERSION"),
            env!("CARGO_PKG_DESCRIPTION")
        ))
    );
    for line in version_body().lines() {
        if line.starts_with("Depth-matrix: ") {
            println!("{}", crate::output::ok_out(line));
        } else {
            println!("{line}");
        }
    }
}

#[cfg(test)]
#[path = "../../test/info/info_tests.rs"]
mod tests;
