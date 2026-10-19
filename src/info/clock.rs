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
    let yoe = (doe - doe / 1_460 + doe / 36_524) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02} {hour:02}:{minute:02}:{second:02} (UTC)")
}

#[cfg(test)]
#[path = "../../test/info/clock_tests.rs"]
mod tests;
