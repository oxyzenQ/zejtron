// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! clock unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/info/clock.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use std::time::Duration;

// Every constant below is verified ground truth via
// `date -u -d @<epoch>` (the sibling's rule: never from memory -
// its own reference carried two wrong constants until this
// discipline caught them).

#[test]
fn known_unix_epochs_render_exactly() {
    // UNIX epoch: 1970-01-01 00:00:00 UTC.
    assert_eq!(format_unix_secs(0), "1970-01-01 00:00:00 (UTC)");

    // 2000-01-01 00:00:00 UTC = 946_684_800 seconds since epoch.
    assert_eq!(format_unix_secs(946_684_800), "2000-01-01 00:00:00 (UTC)");

    // 2024-02-29 12:34:56 UTC = 1_709_210_096 seconds since epoch.
    // Leap-day boundary check: Feb 29 must not roll to Mar 1.
    assert_eq!(format_unix_secs(1_709_210_096), "2024-02-29 12:34:56 (UTC)");

    // 2023-11-14 22:13:20 UTC = 1_700_000_000 seconds since epoch
    // (the long-standing shape-test constant, now pinned to its
    // true civil date).
    assert_eq!(format_unix_secs(1_700_000_000), "2023-11-14 22:13:20 (UTC)");

    // 2026-08-04 15:30:00 UTC = 1_785_857_400 seconds since epoch.
    assert_eq!(format_unix_secs(1_785_857_400), "2026-08-04 15:30:00 (UTC)");
}

#[test]
fn sub_second_precision_is_truncated_not_rounded() {
    // 1_709_210_096.999 = 2024-02-29 12:34:56 UTC: the sub-second
    // remainder is dropped (second precision), never rounded up.
    let time = UNIX_EPOCH + Duration::from_millis(1_709_210_096_999);
    assert_eq!(format_system_time(time), "2024-02-29 12:34:56 (UTC)");
}

#[test]
fn pre_epoch_timestamps_stay_valid_civil_dates() {
    // 1969-12-31 23:59:00 UTC = -60 seconds. The signed arithmetic
    // must produce the correct proleptic Gregorian date, not
    // panic, underflow, or off-by-one into 1970.
    assert_eq!(format_unix_secs(-60), "1969-12-31 23:59:00 (UTC)");

    // One full day before the epoch: 1969-12-31 00:00:00 UTC.
    assert_eq!(format_unix_secs(-86_400), "1969-12-31 00:00:00 (UTC)");

    // Leap year arithmetic crossing the era math backwards:
    // 1968-02-29 12:00:00 UTC = -58_017_600 seconds since epoch
    // (verified via date -u -d @-58017600).
    assert_eq!(format_unix_secs(-58_017_600), "1968-02-29 12:00:00 (UTC)");
}

#[test]
fn system_time_wrapper_matches_the_pure_core() {
    let time = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    assert_eq!(format_system_time(time), format_unix_secs(1_700_000_000));
}

#[test]
fn output_shape_is_zero_padded_core_with_utc_marker() {
    // The tree's long-standing evidence-timestamp shape: a
    // 19-character zero-padded core, plus the explicit UTC marker
    // this module adds. Downstream grep contracts (build.sh's
    // touch lanes) key on the core, the marker is the honesty
    // suffix.
    let formatted = format_unix_secs(1_700_000_000);
    assert_eq!(formatted.len(), 25);
    assert!(formatted.ends_with(" (UTC)"));
    assert_eq!(&formatted[4..5], "-");
    assert_eq!(&formatted[7..8], "-");
    assert_eq!(&formatted[10..11], " ");
    assert_eq!(&formatted[13..14], ":");
    assert_eq!(&formatted[16..17], ":");
}
