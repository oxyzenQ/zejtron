// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

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

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Format a wall-clock timestamp as `YYYY-MM-DD HH:MM:SS (UTC)`.
/// Sub-second precision is truncated (never rounded). Pre-epoch
/// timestamps render through the same signed arithmetic.
/// The wall-clock wrapper. Its default-build callers are the
/// feature-gated doctor and the test pins; a default non-test build
/// has none - the nested allow is the honest count of that split.
pub(crate) fn format_system_time(time: SystemTime) -> String {
    format_unix_secs(unix_secs(time))
}

/// Signed unix-epoch seconds for any SystemTime, pre-epoch included
/// (night-dragon-lts-T1). The conversion the ledgers' row stamps and
/// the formatter now share: a pre-epoch time returns its negative
/// second count instead of collapsing to `None`/0, because the row
/// model (`Option<i64>`) and `format_unix_secs` are both signed all
/// the way down - the pre-fix plumbing dropped the sign at the last
/// hop and rendered `unknown` for a fact the clock could have named.
/// Saturating at the i64 edges: a SystemTime beyond the seconds a
/// signed count can name clamps instead of wrapping.
pub(crate) fn unix_secs(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(delta) => i64::try_from(delta.as_secs()).unwrap_or(i64::MAX),
        Err(error) => -i64::try_from(error.duration().as_secs()).unwrap_or(i64::MAX),
    }
}

/// The panic-free inverse of [`unix_secs`] (night-dragon-lts-T1):
/// signed unix-epoch seconds back to a SystemTime. Every caller that
/// used to spell `UNIX_EPOCH + Duration::from_secs(x as u64)` on an
/// i64 seconds field (ctime and friends) rode a wrap-then-overflow
/// panic path: a negative second count cast to u64 lands near
/// u64::MAX, and `SystemTime + Duration` panics on overflow in
/// release builds too. The saturating shape can never panic - the
/// input is an i64 by construction, and both arithmetic directions
/// stay inside the platform's i64-backed SystemTime range.
pub(crate) fn system_time_from_unix_secs(secs: i64) -> SystemTime {
    if secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
    }
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
/// degrades to `None` - the honest absence, never a guess. The read
/// itself lives in [`clock_gettime_ns`], shared with the sleep-gap
/// law (night-frontier-Z6, D3).
pub(crate) fn monotonic_now_ns() -> Option<u64> {
    clock_gettime_ns(libc::CLOCK_MONOTONIC)
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

// ── The wall-offset skew law (night-frontier-Z2) ────────────────────
//
// A civil time a report renders is `monotonic stamp + wall offset`,
// and the offset is a MEASUREMENT, not a fact of nature: an NTP step
// (or a manual clock set) between the capture and the render moves
// it under every row already recorded. Two guards make the rendered
// times honest down to the sample they came from:
//
// 1. ONE OFFSET PER RENDER BREATH: a report's rows all render under
//    the offset the renderer sampled once at its start - two rows
//    can never disagree because a step happened between their two
//    reads (the pair law, extended from the range pair to the whole
//    report).
// 2. THE NAMED SKEW: every capturing surface samples the offset
//    again at capture start (the pre sample), and the renderer
//    measures `render offset - pre offset`. Beyond the bound below,
//    the wall clock demonstrably moved under the window, and the
//    report names the skew instead of serving skewed civil times as
//    if they were whole. Inside the bound the difference is the
//    measurement's own noise plus slow slewing - half a rendered
//    second cannot move a rendered second, and naming noise would
//    be the lie of a boundary that fires on healthy hosts.
//
// The bound and the compare are pure, so the law is pinnable
// without two live clock reads.

/// The skew bound, in nanoseconds: half a rendered second. The
/// renderer's whole-second granularity is the truth it serves; a
/// measured offset movement beyond half of that can move a rendered
/// civil second, so it must be named - and nothing below it can.
pub(crate) const SKEW_BOUND_NS: i128 = 500_000_000;

/// The material wall-clock skew of a capture: `post - pre` when the
/// pair is readable and the movement exceeds [`SKEW_BOUND_NS`],
/// `None` otherwise (either clock unreadable, or the movement is
/// inside the bound - the absence stays absent, never a guessed
/// zero). `post` is the offset the renderer actually rendered under;
/// `pre` is the capture-start sample the surface took before the
/// window began.
pub(crate) fn material_skew_ns(pre: Option<i128>, post: Option<i128>) -> Option<i128> {
    let skew = post? - pre?;
    (skew.abs() > SKEW_BOUND_NS).then_some(skew)
}

/// Render a monotonic stamp under an offset the caller sampled ONCE
/// (night-frontier-Z2, the one-offset-per-render-breath law): every
/// row of a report renders under the same measurement, so a wall
/// clock step between two rows' reads can never make the rows
/// disagree. `None` degrades to `unknown UTC` - the same honest
/// absence the per-read forms served.
pub(crate) fn time_of_day_with_offset(timestamp_ns: u64, offset: Option<i128>) -> String {
    match offset {
        Some(offset) => time_of_day_from_parts(timestamp_ns, offset),
        None => "unknown UTC".to_owned(),
    }
}

/// The pure time-of-day core: a monotonic stamp plus a known wall
/// offset, rendered as `HH:MM:SS UTC`. Separated from
/// [`time_of_day_with_offset`] so the arithmetic is
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

// ── The sleep-gap law (night-frontier-Z6, D3: the sleep blackout) ───
//
// The record stamps ride CLOCK_MONOTONIC, and MONOTONIC does not run
// while the host sleeps - suspend, hibernate, a guest kernel's ACPI
// sleep. The kernel serves a THIRD clock that does: CLOCK_BOOTTIME,
// defined as identical to monotonic except that it INCLUDES the time
// spent in suspend (the same source /proc/uptime's first column is
// served from). So the kernel's own definition makes
//
//     gap = BOOTTIME - MONOTONIC == the cumulative suspend time
//           since boot
//
// and the DELTA of two gap samples names exactly the span the host
// slept between them. Three properties make that delta evidence, not
// inference:
//
// - a wall step cannot fake it: the gap is the difference of two
//   kernel clocks in the same breath - NTP moves the wall, never the
//   pair (the Z2 companion: skew names a wall that moved, the sleep
//   gap names a host that slept, and neither can masquerade as the
//   other);
// - an awake host cannot trip it: both clocks run during normal
//   operation, so the gap is as steady as the kernel's timekeeping -
//   the materiality bound below exists so the boundary never fires
//   on clock noise;
// - the delta is proof of ABSENCE: the stamps' clock does not run in
//   the named span, so no event can exist there - the window's
//   Unaccounted block names the blackout instead of leaving an
//   unexplained hole (the anti-forensic shape this closes: suspend
//   the host, manipulate, resume - the gap carries the story).
//
// Honesty bounds, named in the same breath as the claim:
//
// - the reading is two clock_gettime calls microseconds apart, so a
//   single gap sample carries ~microseconds of inter-read skew; the
//   MONOTONIC-first order makes the delta UNDERCOUNT a sleep, never
//   overstate it;
// - a hypervisor-level freeze (a paused VM, a snapshot-and-clone) is
//   a different beast: the guest's clocks jump to the host's on
//   resume, so the pairing may stay whole while the host lost time -
//   that tamper is the wall-skew's and the event-record's story, not
//   the gap's, and the docs say so (D3's domain is the kernel's OWN
//   suspend accounting);
// - a pairing that moves BACKWARDS (a paravirt clock resync) cannot
//   measure a sleep honestly - the delta carries the anomaly arm so
//   the untrustworthiness is named, never silently trusted.
//
// The gap's two sources are cross-pinned live at test time
// (clock_gettime against /proc/uptime, the boottime-domain file the
// monotonic cutoff fix night-dragon-lts-1 documented), so every
// kernel the suite runs on proves the sampling reads true.

/// Read the kernel's third clock pair in one breath: the gap
/// BOOTTIME - MONOTONIC, in nanoseconds. MONOTONIC first, BOOTTIME
/// second: `boot(t2) - mono(t1)` then undercounts the gap by the
/// inter-read span - a blackout report may understate a sleep by
/// microseconds, never overstate it (a count that errs toward
/// absence is the honest direction for a proof-of-absence entry).
/// `None` on a failed read - the honest absence, never a guessed
/// zero.
pub(crate) fn boottime_gap_ns() -> Option<i128> {
    let mono = clock_gettime_ns(libc::CLOCK_MONOTONIC)? as i128;
    let boot = clock_gettime_ns(libc::CLOCK_BOOTTIME)? as i128;
    Some(boot - mono)
}

/// One clock read, in nanoseconds: the shared core of
/// [`monotonic_now_ns`] and [`boottime_gap_ns`]. The libc pair is
/// the crate's second raw call (the same escape hatch the
/// monotonic read documented - std exposes no clock-id source).
fn clock_gettime_ns(clock: libc::clockid_t) -> Option<u64> {
    let mut timespec = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: clock_gettime writes through a pointer to a timespec
    // this call owns for the whole call; the clock id is a kernel
    // constant.
    if unsafe { libc::clock_gettime(clock, &mut timespec) } != 0 {
        return None;
    }
    // Both clocks start at zero at boot and never run backwards, so
    // both fields are non-negative in practice; the saturating shape
    // only guards the signedness of the raw types.
    let secs = timespec.tv_sec.max(0) as u64;
    let nanos = timespec.tv_nsec.max(0) as u64;
    Some(secs.saturating_mul(1_000_000_000).saturating_add(nanos))
}

/// The sleep materiality bound, in nanoseconds: one rendered second.
/// An awake host's gap is as steady as the kernel's timekeeping
/// (microsecond jitter), and a paravirt clock's resync lands inside
/// this bound on the hosts that resync gently - below it the delta
/// is clock noise, and naming noise would be the lie of a boundary
/// that fires on healthy hosts (the SKEW_BOUND reasoning, one
/// granularity up: the spans a blackout names are minutes-and-
/// seconds shaped).
pub(crate) const SLEEP_BOUND_NS: i128 = 1_000_000_000;

/// The material sleep delta of a capture: `post - pre` when the pair
/// is readable and the movement exceeds [`SLEEP_BOUND_NS`] in either
/// direction - `None` otherwise (clocks unreadable, or the host
/// never slept inside the window: the absence stays absent, never a
/// guessed zero). The SIGN is the story: positive is a blackout (the
/// host slept), negative is the paravirt anomaly arm (the pairing
/// itself moved backwards and cannot be trusted to measure). Pure,
/// so the law is pinnable without a live suspend.
pub(crate) fn material_sleep_ns(pre: Option<i128>, post: Option<i128>) -> Option<i128> {
    let delta = post? - pre?;
    (delta.abs() > SLEEP_BOUND_NS).then_some(delta)
}

/// The kernel's active clocksource, read from sysfs
/// (night-frontier-Z10, D7): the regime the stamps' CLOCK_MONOTONIC
/// precision rides ("tsc" vs "hpet"/"acpi_pm"). `None` when the file
/// is absent or unreadable - a kernel without the clocksource
/// interface, the named absence, never a guessed regime name.
pub(crate) fn current_clocksource() -> Option<String> {
    let raw =
        std::fs::read_to_string("/sys/devices/system/clocksource/clocksource0/current_clocksource")
            .ok()?;
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// The watch-truth materiality (night-frontier-Z10, D7): the span of
/// the requested window that began BEFORE the camera existed, in the
/// stamps' own CLOCK_MONOTONIC domain - wall-independent, so an NTP
/// step can never invent a gap and a wall step can never hide one.
/// `pre_monotonic_ns` is the capture's own pre-breath stamp (the
/// window's open instant); the requested span runs
/// `[pre - window, pre]`, so the pre-attach span is
/// `attach - (pre - window)` when positive. `Some(gap)` rides only
/// past the one-second materiality bound (a sub-second edge is the
/// command's own startup cost, noise by the Z2 bound's own order);
/// `None` otherwise - a window fully inside the camera's life adds
/// NOTHING to the render (the negative test pins the byte silence),
/// and a zero/unstamped attach instant (pre-Z10 estate) degrades to
/// `None`, never a guessed gap.
pub(crate) fn material_watch_gap_ns(
    pre_monotonic_ns: Option<u64>,
    attach_monotonic_ns: u64,
    window: std::time::Duration,
) -> Option<i128> {
    let pre = pre_monotonic_ns?;
    if attach_monotonic_ns == 0 {
        return None;
    }
    let window_ns = window.as_nanos() as i128;
    let span_start = pre as i128 - window_ns;
    let gap = attach_monotonic_ns as i128 - span_start;
    if gap > 1_000_000_000 { Some(gap) } else { None }
}

/// Render a sleep span the way the entries speak it: whole seconds
/// and up - `7s`, `14m 12s`, `2h 03m 04s`. Sub-second precision is
/// truncated (never rounded): the rows' whole-second render
/// granularity is the truth the ledgers serve, and a blackout that
/// names milliseconds is noise, not evidence.
pub(crate) fn format_sleep_span(ns: i128) -> String {
    let secs = (ns / 1_000_000_000) as i64;
    let hours = secs / 3_600;
    let minutes = (secs % 3_600) / 60;
    let seconds = secs % 60;
    match (hours, minutes) {
        (0, 0) => format!("{seconds}s"),
        (0, _) => format!("{minutes}m {seconds:02}s"),
        (_, _) => format!("{hours}h {minutes:02}m {seconds:02}s"),
    }
}

#[cfg(test)]
#[path = "../../test/info/clock_tests.rs"]
mod tests;
