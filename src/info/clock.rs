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

/// The monotonic "now", in nanoseconds, read straight from the
/// kernel's CLOCK_MONOTONIC through the libc pair the crate already
/// carries (night-dragon-lts-1). CLOCK_MONOTONIC is the EXACT clock
/// the eBPF records are stamped with (`bpf_ktime_get_ns`), so the
/// window cutoffs built on this value compare stamps from the same
/// domain - nanosecond resolution, no conversion.
///
/// The pre-fix source was /proc/uptime, which the kernel serves
/// from CLOCK_BOOTTIME: identical to monotonic on a host that never
/// suspended, but BOOTTIME includes suspend time while the eBPF
/// stamps exclude it. On a host with cumulative suspend time S the
/// computed cutoff sat S nanoseconds LATER than the true monotonic
/// cutoff, silently dropping events from the last S nanoseconds of
/// every window - with S >= the window, "Changes in the last 60s"
/// rendered empty for events the camera had just captured. The old
/// doc claimed the error direction over-included; that claim was the
/// exact inversion of the arithmetic. A clock_gettime failure
/// degrades to `None` - the honest absence, never a guess.
pub(crate) fn monotonic_now_ns() -> Option<u64> {
    let mut timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes through a pointer to a timespec
    // this call owns for the whole call; the clock id is a kernel
    // constant. The libc pair is the crate's second raw call (the
    // SIGPIPE reset in main is the first) - the dependency policy's
    // own escape hatch, used because std exposes no CLOCK_MONOTONIC
    // source: std::time::Instant is opaque (no epoch-relative value)
    // and /proc/uptime is boottime, not monotonic.
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timespec) } != 0 {
        return None;
    }
    // CLOCK_MONOTONIC starts at zero at boot and never runs
    // backwards, so both fields are non-negative in practice; the
    // saturating shape only guards the signedness of the raw types.
    let secs = timespec.tv_sec.max(0) as u64;
    let nanos = timespec.tv_nsec.max(0) as u64;
    Some(secs.saturating_mul(1_000_000_000).saturating_add(nanos))
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
