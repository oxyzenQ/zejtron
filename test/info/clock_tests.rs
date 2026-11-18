// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

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
fn four_hundred_divisible_leap_days_render_as_feb_29() {
    // night-dragon-lts-1: the year-of-era computation was missing
    // Hinnant's final - doe/146096 term, and Feb 29 of every
    // 400-divisible year (the era's last day, doe = 146096) rolled
    // forward to Mar 01. Verified against `date -u -d @951782400`:
    // Tue Feb 29 00:00:00 UTC 2000. The pins below walk the whole
    // boundary: the day before, both edges of the day itself, and
    // the day after.
    assert_eq!(format_unix_secs(951_782_399), "2000-02-28 23:59:59 (UTC)");
    assert_eq!(format_unix_secs(951_782_400), "2000-02-29 00:00:00 (UTC)");
    assert_eq!(format_unix_secs(951_868_799), "2000-02-29 23:59:59 (UTC)");
    assert_eq!(format_unix_secs(951_868_800), "2000-03-01 00:00:00 (UTC)");

    // The next 400-divisible leap day, one full era (146097 days)
    // later: 2400-02-29 00:00:00 UTC = 13_574_563_200.
    assert_eq!(
        format_unix_secs(13_574_563_200),
        "2400-02-29 00:00:00 (UTC)"
    );
    // And the previous one, pre-epoch: 1600-02-29 12:00:00 UTC =
    // -11_670_955_200 (proleptic Gregorian, the signed lane).
    assert_eq!(
        format_unix_secs(-11_670_955_200),
        "1600-02-29 12:00:00 (UTC)"
    );
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

#[test]
fn time_of_day_core_renders_the_utc_shape() {
    // The monotonic companion's pure core (night-improve-47): a
    // known stamp plus a known offset, rendered as HH:MM:SS UTC -
    // the same zero-padded civil shape, day-less. Offset zero is
    // the boot-time-aligned identity: stamp 0 renders midnight.
    assert_eq!(time_of_day_from_parts(0, 0), "00:00:00 UTC");
    assert_eq!(
        time_of_day_from_parts(((23 * 3600) + (59 * 60) + 59) * 1_000_000_000, 0),
        "23:59:59 UTC"
    );
    assert_eq!(
        time_of_day_from_parts(904 * 1_000_000_000, 0),
        "00:15:04 UTC"
    );
}

#[test]
fn time_of_day_core_wraps_negative_offsets_like_the_epoch_math() {
    // A pre-epoch wall (offset more negative than the stamp) rides
    // the same floor-division shape format_unix_secs pins: rem_euclid
    // keeps every result inside the day, never a negative hour.
    assert_eq!(time_of_day_from_parts(0, -1_000_000_000), "23:59:59 UTC");
    assert_eq!(
        time_of_day_from_parts(3600 * 1_000_000_000, -3660 * 1_000_000_000),
        "23:59:00 UTC"
    );
}

#[test]
fn signed_seconds_round_trip_through_system_time() {
    // night-dragon-lts-T1: the shared signed conversion and its
    // panic-free inverse. Ground truth via `date -u -d @-1`:
    // 1969-12-31 23:59:59 UTC; @-11_670_955_200 is the 1600-02-29
    // noon pin the format tests already carry.
    for secs in [0_i64, 1, 1_785_857_400, -1, -11_670_955_200] {
        let time = system_time_from_unix_secs(secs);
        assert_eq!(unix_secs(time), secs, "round-trip lost {secs}");
    }
}

#[test]
fn pre_epoch_system_times_format_through_the_wall_wrapper() {
    // The integration shape night-dragon-lts-T1 repaired: a
    // pre-epoch SystemTime reaches the formatter with its sign
    // intact. The pre-fix plumbing dropped these to `None`/`unknown`
    // one hop before this function, so its Err arm was dead code.
    let pre_epoch = system_time_from_unix_secs(-1);
    assert_eq!(format_system_time(pre_epoch), "1969-12-31 23:59:59 (UTC)");
    assert_eq!(
        format_system_time(system_time_from_unix_secs(-11_670_955_200)),
        "1600-02-29 12:00:00 (UTC)"
    );
}

#[test]
fn system_time_from_unix_secs_saturates_at_the_i64_edges() {
    // The panic-free law: neither direction may panic (the pre-fix
    // `UNIX_EPOCH + Duration::from_secs(x as u64)` shape panicked on
    // the wrapped negative side), and the i64 edges clamp through
    // the round trip as saturating values.
    let _far_future = system_time_from_unix_secs(i64::MAX);
    let _far_past = system_time_from_unix_secs(i64::MIN);
}

// ── night-frontier-Z2, the wall-offset skew law ─────────────────────

#[test]
fn the_skew_bound_is_half_a_rendered_second() {
    // The bound's own rationale, pinned: half the renderer's
    // whole-second granularity. Beyond it a rendered civil second can
    // move; below it nothing can.
    assert_eq!(SKEW_BOUND_NS, 500_000_000);
}

#[test]
fn material_skew_names_movement_beyond_the_bound() {
    // The signed movement is preserved: a clock stepped FORWARD and
    // one stepped BACKWARD are different stories, and the compare
    // never loses the direction.
    let forward = material_skew_ns(Some(0), Some(SKEW_BOUND_NS + 1));
    assert_eq!(forward, Some(SKEW_BOUND_NS + 1));
    let backward = material_skew_ns(Some(SKEW_BOUND_NS + 1), Some(0));
    assert_eq!(backward, Some(-(SKEW_BOUND_NS + 1)));
    // At exactly the bound: inside (the compare is strictly
    // greater) - the boundary fires only when it is exceeded.
    assert_eq!(material_skew_ns(Some(0), Some(SKEW_BOUND_NS)), None);
}

#[test]
fn material_skew_is_silent_below_the_bound() {
    // Healthy-host noise and slow slewing render as silence: the
    // boundary exists only when it fired, never as a guessed zero.
    assert_eq!(material_skew_ns(Some(0), Some(42)), None);
    assert_eq!(material_skew_ns(Some(0), Some(SKEW_BOUND_NS - 1)), None);
    assert_eq!(material_skew_ns(Some(-9), Some(9)), None);
}

#[test]
fn material_skew_is_absent_when_a_clock_is_unreadable() {
    // Either clock unreadable: the absence stays absent - no guessed
    // zero, no invented movement.
    assert_eq!(material_skew_ns(None, Some(1_000_000_000)), None);
    assert_eq!(material_skew_ns(Some(0), None), None);
    assert_eq!(material_skew_ns(None, None), None);
}

// ── night-frontier-Z6, D3: the sleep-gap law pins ────────────────────

#[test]
fn the_material_sleep_delta_names_only_material_movement() {
    // An awake host: the gap is steady (the kernel runs both clocks
    // together) - below the bound the absence stays absent.
    assert_eq!(
        material_sleep_ns(Some(90_000_000_000), Some(90_000_500_000)),
        None,
        "half a second of gap movement is noise, never a blackout"
    );
    // Exactly at the bound: the boundary fires BEYOND it, the same
    // strictness the skew bound carries.
    assert_eq!(
        material_sleep_ns(Some(0), Some(SLEEP_BOUND_NS)),
        None,
        "at the bound is still the un-named side"
    );
    // The blackout arm: a positive material delta is the span the
    // host spent asleep (the kernel's own definition: BOOTTIME -
    // MONOTONIC == cumulative suspend time, so a growing gap IS the
    // sleep).
    let slept = 14 * 60 + 12; // seconds
    let delta = slept * 1_000_000_000 + 7; // +7 ns of reading jitter
    assert_eq!(
        material_sleep_ns(Some(0), Some(delta)),
        Some(delta),
        "a material positive delta rides whole"
    );
    // The anomaly arm: a backwards pairing cannot measure a sleep
    // honestly - it rides so the untrustworthiness can be named.
    assert_eq!(
        material_sleep_ns(Some(0), Some(-90_000_000_000)),
        Some(-90_000_000_000),
        "a material negative delta is the paravirt anomaly, not a blackout"
    );
    // Unreadable clocks: the honest absence, never a guessed zero.
    assert_eq!(material_sleep_ns(None, Some(0)), None);
    assert_eq!(material_sleep_ns(Some(0), None), None);
}

#[test]
fn sleep_spans_render_whole_seconds_and_up() {
    // Truncation, never rounding: sub-second precision is below the
    // rows' whole-second render granularity.
    assert_eq!(format_sleep_span(7_000_000_000), "7s");
    assert_eq!(format_sleep_span(1_999_999_999), "1s");
    // The minute shape (the proposal's own example): 14m 12s.
    assert_eq!(format_sleep_span(852_000_000_000), "14m 12s");
    // The hour shape: 2h 03m 04s.
    assert_eq!(format_sleep_span(7_384_000_000_000), "2h 03m 04s");
}

#[test]
fn a_wall_step_cannot_read_as_a_sleep_and_vice_versa() {
    // The Z2/D3 companion law: the skew reads the WALL offset pair
    // (wall - monotonic), the sleep gap reads the BOOTTIME -
    // MONOTONIC pair. An NTP step moves the wall offset but not the
    // gap; a suspend moves the gap but not the wall offset. Neither
    // boundary can masquerade as the other.
    let steady = 90_000_000_000i128;
    let steady_gap = Some(steady);
    // A wall step of two seconds: the skew names it...
    let stepped = material_skew_ns(Some(1_000_000_000_000), Some(1_002_000_000_000));
    assert!(stepped.is_some(), "the wall step is named (Z2)");
    // ...while the gap, measured on the same host in the same
    // breath, holds: no blackout.
    assert_eq!(
        material_sleep_ns(steady_gap, Some(90_000_000_001)),
        None,
        "the wall step is not a sleep"
    );
    // And the inverse: a real suspend with a whole wall clock (the
    // kernel steps the civil time from the RTC on resume, inside the
    // 500 ms slew the skew bound forgives) moves the gap and NOT the
    // skew.
    let slept = 900_000_000_000i128;
    assert!(
        material_skew_ns(Some(1_000_000_000_000), Some(1_000_000_000_100)).is_none(),
        "a steady wall is no skew"
    );
    assert!(
        material_sleep_ns(steady_gap, Some(steady + slept)).is_some(),
        "the suspend is a blackout, wall-independent"
    );
}

#[test]
fn the_gap_reads_true_against_the_boottime_domain_file() {
    // The two-source live cross-check: CLOCK_BOOTTIME from
    // clock_gettime and /proc/uptime's first column are the SAME
    // kernel counter (the boottime domain) served through two
    // independent sources - the sampling law is proven, per push, on
    // every kernel the suite runs on, not assumed. The tolerance is
    // the read jitter and the file's own granularity (two reads, a
    // context switch apart).
    let uptime = std::fs::read_to_string("/proc/uptime").expect("/proc/uptime is linux ground");
    let uptime_secs: f64 = uptime
        .split_whitespace()
        .next()
        .expect("uptime's first column")
        .parse()
        .expect("uptime seconds");
    let uptime_ns = (uptime_secs * 1_000_000_000.0) as i128;
    let boot = clock_gettime_ns(libc::CLOCK_BOOTTIME).expect("the third clock reads") as i128;
    let drift = (boot - uptime_ns).abs();
    assert!(
        drift < 2_000_000_000,
        "clock_gettime BOOTTIME and /proc/uptime must agree within 2s: boot {boot} vs uptime {uptime_ns}"
    );
    // And the gap is exactly the kernel's own definition, boot -
    // monotonic, within the two reads' jitter: the suspend span the
    // blackout law measures.
    let mono = clock_gettime_ns(libc::CLOCK_MONOTONIC).expect("the stamps' clock reads") as i128;
    let gap = boottime_gap_ns().expect("the gap reads");
    let derived = (boot - mono - gap).abs();
    assert!(
        derived < 2_000_000_000,
        "the gap must be boot - monotonic within the reads' jitter: gap {gap} vs {}",
        boot - mono
    );
    // A span since boot is never negative by construction.
    assert!(gap >= 0, "the gap is a span since boot, never negative");
}
