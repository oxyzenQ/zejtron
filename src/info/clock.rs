// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The std-only civil clock (the sibling project's Hinnant lineage,
//! NIGHT-hunt-6: chrono dropped from that tree the same way). Every
//! wall-clock surface in zejtron renders through this module: the
//! touch/path evidence timestamps and the build-time stamp in `-V`.
//!
//! Why UTC-only, and why no time crate: the `clock` feature of the
//! dependency this module replaces dragged a timezone database
//! (iana-time-zone) and num-traits into the lockfile for exactly two
//! call sites that formatted timestamps. Local-time rendering needs a
//! tz database; a forensic tool that must render identically on every
//! host (and inside containers with no /etc/localtime at all) is
//! honestly served by UTC with an explicit marker instead of a
//! silently wrong local guess. The family contract agrees: the
//! sibling's `Build-time:` stamp is UTC for the same stated reason.
//! The output shape keeps the tree's long-standing
//! `YYYY-MM-DD HH:MM:SS` core and appends the honest ` (UTC)` suffix.
//!
//! Algorithm: Howard Hinnant's `civil_from_days`
//! (`<http://howardhinnant.github.io/date_algorithms.html>`) converts
//! days-since-1970-01-01 to (year, month, day) in the proleptic
//! Gregorian calendar. All arithmetic is on `i64` so pre-epoch
//! timestamps (negative seconds) ride the same floor-division math
//! without unsigned underflow.

use std::time::{SystemTime, UNIX_EPOCH};

/// Format a wall-clock timestamp as `YYYY-MM-DD HH:MM:SS (UTC)`.
/// Sub-second precision is truncated (never rounded). Pre-epoch
/// timestamps render through the same signed arithmetic.
/// The wall-clock wrapper. Its default-build callers are the
/// feature-gated doctor and the test pins; a default non-test build
/// has none - the nested allow is the honest count of that split.
pub(crate) fn format_system_time(time: SystemTime) -> String {
    let total_secs: i64 = match time.duration_since(UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(error) => {
            let before = error.duration();
            -i64::try_from(before.as_secs()).unwrap_or(i64::MAX)
        }
    };
    format_unix_secs(total_secs)
}

/// Pure formatting core: unix-epoch seconds (signed) to
/// `YYYY-MM-DD HH:MM:SS (UTC)`. Separated from [`format_system_time`]
/// so the algorithm is unit-testable without depending on the wall
/// clock, mirroring the sibling build.rs's split.
pub(crate) fn format_unix_secs(total_secs: i64) -> String {
    let days_since_epoch = total_secs.div_euclid(86_400);
    let secs_of_day = total_secs.rem_euclid(86_400);
    let hour = secs_of_day / 3_600;
    let minute = (secs_of_day % 3_600) / 60;
    let second = secs_of_day % 60;

    // Howard Hinnant's civil_from_days: converts days-since-1970-01-01
    // to (year, month, day) in the proleptic Gregorian calendar.
    // http://howardhinnant.github.io/date_algorithms.html#civil_from_days
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    // Hinnant's full four-term year-of-era:
    // (doe - doe/1460 + doe/36524 - doe/146096) / 365. The final
    // term (night-dragon-lts-1) was missing: doe/146096 is 1 only on
    // day 146096 of an era - Feb 29 of a 400-divisible year (2000,
    // 2400, ...) - and without it that day computed yoe = 400,
    // breaking the [0, 399] invariant and rolling the date forward
    // to Mar 01. Every unix second in [951782400, 951868799] (all
    // of 2000-02-29) rendered one day late; non-400 leap years
    // (2024-02-29, the old test pin) never reach doe = 146096, which
    // is why the suite stayed green.
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02} {hour:02}:{minute:02}:{second:02} (UTC)")
}

// ── The monotonic companions (night-improve-47) ─────────────────────
//
// The eBPF event records carry CLOCK_MONOTONIC stamps
// (bpf_ktime_get_ns), so every surface that renders a kernel
// event row needs the same two companions: the monotonic "now"
// (the window arithmetic's cutoff) and the wall offset that turns
// a monotonic stamp into civil time. They lived as private copies
// in port's window; the post-mortem doctor's exit rows need them
// too, so they moved here - one source, two surfaces (the same
// dedup law the unavailability sentence landed under: the lower
// layer owns the sentence, the surfaces delegate down).

/// The monotonic "now", in nanoseconds, from /proc/uptime (the
/// kernel's own CLOCK_BOOTTIME clock at 10 ms resolution). `None`
/// when the file is unreadable - the honest degradation, never a
/// guess. Boottime-inclusive: on a host that suspended, a cutoff
/// computed from this sits slightly EARLY, so a boundary event
/// survives that strict monotonic would drop - the error direction
/// that over-includes, never under-reports.
pub(crate) fn monotonic_now_ns() -> Option<u64> {
    let uptime = std::fs::read_to_string("/proc/uptime").ok()?;
    let first = uptime.split_whitespace().next()?;
    let seconds: f64 = first.parse().ok()?;
    Some((seconds * 1e9) as u64)
}

/// The wall-clock offset for rendering event timestamps: wall-now
/// minus monotonic-now, both read in the same breath. An event's
/// wall time is its monotonic stamp plus this offset. A pre-epoch
/// wall clock or an unreadable uptime degrades to `None` - the row
/// then renders `unknown UTC` rather than a fabricated time.
pub(crate) fn wall_offset_ns() -> Option<i128> {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_nanos() as i128;
    let mono = monotonic_now_ns()? as i128;
    Some(wall - mono)
}

/// Render a monotonic event stamp as `HH:MM:SS UTC` (the same
/// UTC-only discipline every zejtron surface renders in). The
/// wall offset is read in the caller's breath; an unreadable pair
/// of clocks degrades to `unknown UTC` - an absent fact stays
/// absent, never guessed.
pub(crate) fn time_of_day_from_monotonic_ns(timestamp_ns: u64) -> String {
    match wall_offset_ns() {
        Some(offset) => time_of_day_from_parts(timestamp_ns, offset),
        None => "unknown UTC".to_owned(),
    }
}

/// The pure time-of-day core: a monotonic stamp plus a known wall
/// offset, rendered as `HH:MM:SS UTC`. Separated from
/// [`time_of_day_from_monotonic_ns`] so the arithmetic is
/// unit-testable without depending on the live clocks, mirroring
/// [`format_unix_secs`]'s split.
fn time_of_day_from_parts(timestamp_ns: u64, offset_ns: i128) -> String {
    let secs = ((timestamp_ns as i128 + offset_ns) / 1_000_000_000) as i64;
    let time_of_day = secs.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02} UTC",
        time_of_day / 3_600,
        (time_of_day % 3_600) / 60,
        time_of_day % 60
    )
}

#[cfg(test)]
#[path = "../../test/info/clock_tests.rs"]
mod tests;
