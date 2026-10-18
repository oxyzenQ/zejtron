// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");

    // Commit-sha resolution chain (the sibling's NIGHT-ask-1
    // cosmostrix lineage), first hit wins:
    //   1. `git rev-parse --short=7 HEAD` - local/git checkouts.
    //   2. `GITHUB_SHA` env - CI environments (full 40-hex sha,
    //      normalized to the same 7-char short shape).
    //   3. `.cargo_vcs_info.json` - registry tarball builds (`cargo
    //      install zejtron`): cargo embeds this file in the published
    //      package with the sha1 of the commit the crate was packaged
    //      from, so builds without a .git directory still recover the
    //      real commit. Watched via rerun-if-changed so a dev checkout
    //      and a registry extract never share one stale verdict.
    // The normalizer rejects anything that is not 7..=40 ASCII hex
    // (a detached submodule can answer the literal `HEAD`), so every
    // source renders one canonical lowercase 7-char shape in `-V`.
    let hash = git_short_sha()
        .or_else(|| env_short_sha("GITHUB_SHA"))
        .or_else(packaged_vcs_sha)
        .unwrap_or_else(|| "unknown".to_owned());

    println!("cargo:rustc-env=ZEJTRON_GIT_HASH={hash}");
    println!("cargo:rerun-if-changed=.cargo_vcs_info.json");

    // Build timestamp (the sibling's NIGHT-hunt-6 lineage): computed
    // from SystemTime via Howard Hinnant's civil_from_days algorithm
    // - std only, no chrono and no [build-dependencies]. UTC-only so
    // no timezone database is pulled into the binary and the stamp is
    // identical across build hosts. Freshness equals the build.rs run
    // time: re-executed whenever git HEAD or source inputs change
    // (cargo's standard build-script caching). Minute precision, the
    // family `M/D/YYYY HH:MM (UTC)` contract the `-V` report carries.
    let build_time = format_build_time_utc();
    println!("cargo:rustc-env=ZEJTRON_BUILD_TIME={build_time}");
}

fn format_build_time_utc() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let Ok(secs) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return "unknown".to_string();
    };
    let total_secs: i64 = i64::try_from(secs.as_secs()).unwrap_or(0);
    format_unix_secs_as_build_time(total_secs)
}

/// Pure formatting function - takes unix-epoch seconds and returns
/// `M/D/YYYY HH:MM (UTC)`. Separated from `format_build_time_utc` so
/// the algorithm is unit-testable without depending on the wall clock.
///
/// Algorithm: split `total_secs` into days + seconds-of-day, then use
/// Howard Hinnant's `civil_from_days` algorithm
/// (`<http://howardhinnant.github.io/date_algorithms.html>`) to convert
/// days-since-epoch to (year, month, day). All arithmetic is on `i64`
/// to avoid unsigned-underflow issues when subtracting the 719468-day
/// shift constant.
fn format_unix_secs_as_build_time(total_secs: i64) -> String {
    let days_since_epoch = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;

    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!("{m}/{d}/{year} {hour:02}:{minute:02} (UTC)")
}

// ── The commit-sha chain (sibling build/vcs.rs lineage) ─────────────

/// First step of the commit-sha chain: `git rev-parse --short=7 HEAD`.
/// Returns `None` when git is absent, fails (no `.git` - a registry
/// extract), or answers something other than usable hex.
fn git_short_sha() -> Option<String> {
    let out = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8(out.stdout).ok()?;
    normalize_short_sha(sha.trim())
}

/// Second step of the commit-sha chain: a full sha from CI env
/// (`GITHUB_SHA`), normalized to the same 7-char short shape.
fn env_short_sha(var: &str) -> Option<String> {
    normalize_short_sha(&std::env::var(var).ok()?)
}

/// Parses the `sha1` field out of a `.cargo_vcs_info.json` document.
/// Pure string extraction - build.rs stays dependency-free (std
/// only), so there is no JSON crate here. The document shape is
/// stable: `{"git":{"sha1":"<40 hex>","dirty":bool},"path_in_vcs":""}`
/// (field order is not guaranteed, so the parse anchors on the
/// `"sha1"` key, not on byte offsets).
fn parse_vcs_sha_json(text: &str) -> Option<String> {
    let key = "\"sha1\"";
    let key_at = text.find(key)?;
    let after_key = &text[key_at + key.len()..];
    let colon_at = after_key.find(':')?;
    let value = after_key[colon_at + 1..].trim_start();
    let value = value.strip_prefix('"')?;
    let end = value.find('"')?;
    normalize_short_sha(&value[..end])
}

/// Third step of the commit-sha chain: read `.cargo_vcs_info.json`
/// from the package root (cargo materializes the file beside the
/// manifest when it packs the crate). Returns `None` when the file is
/// missing (ordinary dev builds - the normal case) or unusable.
fn packaged_vcs_sha() -> Option<String> {
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(manifest_dir.join(".cargo_vcs_info.json")).ok()?;
    parse_vcs_sha_json(&text)
}

/// Shared chain normalizer: a sha is usable when it is 7..=40 ASCII
/// hex characters; the short form is the first 7, lowercased - one
/// canonical shape across all three chain sources. Rejects everything
/// else (`HEAD`, empty, truncated, non-hex noise).
fn normalize_short_sha(s: &str) -> Option<String> {
    let n = s.trim();
    let len = n.len();
    if !(7..=40).contains(&len) || !n.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let short: String = n.chars().take(7).collect();
    Some(short.to_ascii_lowercase())
}

// The tests below never execute under `cargo test` (cargo does not run
// build-script tests) - they run standalone:
//   rustc --edition 2021 --test build.rs -o /tmp/zejtron-build-test && /tmp/zejtron-build-test
// The sibling's rule: the constants here must be real ground truth,
// verified against `date -u -d @<epoch>`, because this suite is the
// only thing that executes them.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_time_format_matches_known_unix_epochs() {
        // UNIX epoch: 1970-01-01 00:00:00 UTC.
        assert_eq!(format_unix_secs_as_build_time(0), "1/1/1970 00:00 (UTC)");

        // 2000-01-01 00:00:00 UTC = 946_684_800 seconds since epoch.
        assert_eq!(
            format_unix_secs_as_build_time(946_684_800),
            "1/1/2000 00:00 (UTC)"
        );

        // 2024-02-29 12:34:00 UTC = 1_709_210_040 seconds since epoch.
        // Leap-day boundary check - Feb 29 must not roll to Mar 1.
        assert_eq!(
            format_unix_secs_as_build_time(1_709_210_040),
            "2/29/2024 12:34 (UTC)"
        );

        // 2026-08-04 15:30:00 UTC = 1_785_857_400 seconds since epoch.
        assert_eq!(
            format_unix_secs_as_build_time(1_785_857_400),
            "8/4/2026 15:30 (UTC)"
        );
    }

    #[test]
    fn build_time_format_truncates_sub_minute_seconds() {
        // 1_709_210_440 = 2024-02-29 12:40:40 UTC: the 40 sub-minute
        // seconds are dropped (minute precision, the family contract),
        // never rounded up.
        assert_eq!(
            format_unix_secs_as_build_time(1_709_210_440),
            "2/29/2024 12:40 (UTC)"
        );
    }

    #[test]
    fn build_time_format_handles_negative_seconds_gracefully() {
        // Pre-epoch timestamps (negative seconds) still produce a
        // valid proleptic Gregorian date via signed arithmetic.
        let result = format_unix_secs_as_build_time(-60);
        assert!(
            result.ends_with("(UTC)"),
            "negative-epoch result should still be (UTC)-suffixed: {result}"
        );
        assert!(
            result.contains("1969"),
            "negative-epoch result should land in 1969: {result}"
        );
    }

    #[test]
    fn vcs_sha_json_parses_the_canonical_document() {
        // Byte-for-byte the shape cargo writes when it packs a crate
        // from a dirty tree (the `dirty` flag rides along).
        let doc = r#"{"git":{"sha1":"a1adb97b91fbb32bd5f22bd85b8dbf2870ea53c1","dirty":true},"path_in_vcs":""}"#;
        assert_eq!(parse_vcs_sha_json(doc).as_deref(), Some("a1adb97"));
    }

    #[test]
    fn vcs_sha_json_tolerates_field_order_and_dirty_absence() {
        // Clean publishes omit `dirty`; key order is not contractual.
        // Uppercase hex exercises the shared lowercasing too.
        let doc = r#"{"path_in_vcs":"","git":{"sha1":"44BE809B91FBB32BD5F22BD85B8DBF2870EA53C1"}"#;
        assert_eq!(parse_vcs_sha_json(doc).as_deref(), Some("44be809"));
    }

    #[test]
    fn vcs_sha_json_rejects_malformed_documents() {
        // No sha1 key at all (the file exists but is not a vcs doc).
        assert_eq!(parse_vcs_sha_json(r#"{"git":{}}"#), None);
        // Value not a quoted string - the anchored parse must not
        // hallucinate a sha out of trailing bytes.
        assert_eq!(parse_vcs_sha_json(r#"{"git":{"sha1":123}}"#), None);
    }

    #[test]
    fn normalize_short_sha_shapes_the_three_chain_sources() {
        // Full 40-hex (GITHUB_SHA / the vcs document) -> first 7,
        // lowercased.
        assert_eq!(
            normalize_short_sha("A1ADB97B91FBB32BD5F22BD85B8DBF2870EA53C1").as_deref(),
            Some("a1adb97")
        );
        // Already-short git output passes through, lowercased.
        assert_eq!(normalize_short_sha("44Be809").as_deref(), Some("44be809"));
        // The submodule `HEAD` answer, too-short, and empty are None.
        assert_eq!(normalize_short_sha("HEAD"), None);
        assert_eq!(normalize_short_sha("abc123"), None);
        assert_eq!(normalize_short_sha(""), None);
    }
}
