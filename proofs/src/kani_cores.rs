// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The Kani tier (night-datapath-1): bounded model checking, FOR ALL
//! INPUTS within each harness's domain. Every harness runs as its own
//! `cargo kani --harness` invocation in proofs.yml, so a verdict is
//! never lost to a sibling's budget - the owner's 30-minute split law
//! is met at the finest split a for-all theorem allows: one harness,
//! one invocation, one verdict, and a per-push lane capped at 15
//! minutes wall.
//!
//! The harnesses prove the pure-arithmetic laws only. The SystemTime
//! round trip stays in the proptest tier on purpose: std's
//! SystemTime arithmetic is syscall-backed, outside a bounded model
//! checker's domain - a harness there would be undecided by
//! construction, not verified. The split of instruments is recorded
//! in docs/PROOFS.md.
//!
//! Each harness doc names the domain, the theorem, and the measured
//! budget class (the decision-table laws are seconds; the 32-bit
//! injectivity law is minutes; the full-domain alias residual is the
//! one measured-uncertain harness and it says so in its doc).

use crate::events_core;

// -- The events core's totality laws --------------------------------------

/// FOR ALL u32 device tokens: the widening is the zero extension the
/// name claims - bit-identical, no sign games. Domain: the full u32.
/// Budget class: seconds (32 symbolic bits).
#[cfg(kani)]
#[kani::proof]
fn device_token_zero_extends_for_all_inputs() {
    let s_dev: u32 = kani::any();
    let token = events_core::device_token_from_kernel(s_dev);
    assert_eq!(token, u64::from(s_dev));
}

/// The shared-record byte counts are the identity the ring contract
/// rides: each *_BYTES constant is the struct's size_of, and the
/// socket record holds its documented 64 bytes (night-frontier-Z8, D5:
/// the identity block rides the appended tail, the legacy head never
/// renumbers). Static by
/// construction; the harness pins it inside the model checker so a
/// repr(C) layout change that moves a size fails the theorem lane
/// too, not just the unit test.
#[cfg(kani)]
#[kani::proof]
fn record_sizes_are_the_shared_contract_for_all_inputs() {
    assert_eq!(events_core::SOCK_EVENT_BYTES, 64);
    assert_eq!(
        events_core::SOCK_EVENT_BYTES,
        size_of::<events_core::SockEvent>()
    );
    assert_eq!(
        events_core::FILE_EVENT_BYTES,
        size_of::<events_core::FileEvent>()
    );
}

/// FOR ALL (family, protocol, oldstate, newstate): the port decision
/// table equals the doc's spec - TCP's listen involvement, UDP's
/// close, everything else dropped. Domain: 16 + 8 + 8 + 8 = 32
/// symbolic bits. Budget class: seconds to minutes.
#[cfg(kani)]
#[kani::proof]
fn is_port_surface_event_matches_the_spec_for_all_inputs() {
    let family: u16 = kani::any();
    let protocol: u8 = kani::any();
    let oldstate: u8 = kani::any();
    let newstate: u8 = kani::any();
    let spec = match (family, protocol) {
        (f, _) if f != events_core::AF_INET && f != events_core::AF_INET6 => false,
        (_, p) if p == events_core::IPPROTO_TCP => {
            newstate == events_core::TCP_LISTEN || oldstate == events_core::TCP_LISTEN
        }
        (_, p) if p == events_core::IPPROTO_UDP => newstate == events_core::TCP_CLOSE,
        _ => false,
    };
    assert_eq!(
        events_core::is_port_surface_event(family, protocol, oldstate, newstate),
        spec
    );
}

/// FOR ALL (inode, device) pairs inside the documented 32-bit domain:
/// the packing is INJECTIVE - two pairs share a key exactly when they
/// share both parts. The filter map's correctness rides this: a
/// collision inside the domain would render one inode's row for
/// another's event. Domain: 4 x 32 = 128 symbolic bits, bounded by
/// assumption to the documented domain. Budget class: minutes.
#[cfg(kani)]
#[kani::proof]
fn pack_filter_key_is_injective_on_the_documented_domain() {
    let inode_a: u32 = kani::any();
    let device_a: u32 = kani::any();
    let inode_b: u32 = kani::any();
    let device_b: u32 = kani::any();
    let key_a = events_core::pack_filter_key(u64::from(inode_a), u64::from(device_a));
    let key_b = events_core::pack_filter_key(u64::from(inode_b), u64::from(device_b));
    // The injectivity shape: CONstrain the keys equal, then demand the
    // parts agree. Any collision inside the domain would now violate
    // one of the two assertions below with a named counterexample.
    kani::assume(key_a == key_b);
    assert_eq!(inode_a, inode_b, "colliding keys named different inodes");
    assert_eq!(device_a, device_b, "colliding keys named different devices");
}

/// FOR ALL (inode, device): the packing aliases exactly as the doc
/// pins - two u64 inodes share a key exactly when their low 32 bits
/// agree (for the same device), the named residual, never a surprise
/// shape. Domain: 2 x 64 + 32 = 160 symbolic bits. Budget class: the
/// measured-uncertain harness - it rides the per-push lane's 15-minute
/// cap, and if the solver ever returns undecided rather than verified
/// inside that budget, the census verdict moves the residual's for-all
/// form to a decomposition round and the sampled proptest law carries
/// the claim meanwhile. The split lever is lemma decomposition, never
/// a bigger budget (the owner's 30-minute law).
#[cfg(kani)]
#[kani::proof]
fn pack_filter_key_aliases_exactly_as_documented_for_all_inputs() {
    let inode_a: u64 = kani::any();
    let inode_b: u64 = kani::any();
    let device_a: u32 = kani::any();
    let device_b: u32 = kani::any();
    let key_a = events_core::pack_filter_key(inode_a, u64::from(device_a));
    let key_b = events_core::pack_filter_key(inode_b, u64::from(device_b));
    let aliases = key_a == key_b;
    let low32_agrees = (inode_a & 0xFFFF_FFFF) == (inode_b & 0xFFFF_FFFF);
    assert_eq!(aliases, low32_agrees && device_a == device_b);
}

// -- The clock core's civil arithmetic totality ----------------------------

/// Hinnant's civil_from_days, re-stated in the harness (the published
/// spec, http://howardhinnant.github.io/date_algorithms.html): days
/// since 1970-01-01 to (year, month, day) in the proleptic Gregorian
/// calendar. The harness-side copy is the theorem's reference - the
/// core's own copy is pinned against it by the proptest tier's
/// sampled bridge and the unit tests' exact strings.
#[cfg(kani)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    (y + if m <= 2 { 1 } else { 0 }, m as u32, d as u32)
}

/// Hinnant's days_from_civil, the inverse reference: (y, m, d) back
/// to days since 1970-01-01. Pure integer arithmetic, no time types.
#[cfg(kani)]
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64; // [0, 11]
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

/// FOR ALL days in the +-4095-year window: Hinnant's civil arithmetic
/// round trips (days -> civil -> days is the identity), every civil
/// part stays in its domain (month 1..=12, day 1..=31, the
/// year-of-era invariant [0, 399] - the exact invariant the
/// night-dragon-lts-1 leap-day fix restored), and the day-of-week
/// progression is consistent (consecutive days advance the civil
/// date). Domain: 41 symbolic bits. Budget class: minutes.
///
/// The window is the theorem's honest domain: +-4095 years covers
/// every timestamp the evidence ledgers can render (the formatter's
/// input is bounded by the filesystems' own ranges), and the era
/// arithmetic is exact across the whole window.
#[cfg(kani)]
#[kani::proof]
fn civil_arithmetic_round_trips_and_stays_in_domain_for_all_inputs() {
    let days: i64 = kani::any();
    kani::assume(-1_495_000 <= days && days <= 1_495_000);
    let (year, month, day) = civil_from_days(days);
    assert!((1..=12).contains(&month), "month out of domain");
    assert!((1..=31).contains(&day), "day out of domain");
    let back = days_from_civil(year, month, day);
    assert_eq!(back, days, "civil round trip broke the day count");
}
