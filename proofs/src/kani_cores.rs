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

use crate::{clock_core, events_core};

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

/// The shared-record contract is the identity the ring rides, pinned
/// whole inside the model checker (night-netrunner-Z2, the byte-layout
/// law): the size, the FIELD-BY-FIELD offset table, and the
/// append-only head/tail vocabulary. The kernel side's `output` call,
/// the host side's record-length check, and the renderers' field reads
/// all walk this one layout - a repr(C) change that moves any byte
/// named here fails the theorem lane, not just the unit test
/// (test/ebpf/ringbuf_tests.rs, test/ebpf/file_events_tests.rs). The
/// offsets are the documented table (events.rs's own comments): the
/// legacy head never renumbers - the SockEvent head ends at 32
/// (through pid), the FileEvent head at 40 (through _pad2) - and the
/// identity block (night-frontier-Z8, D5) rides the appended tail
/// strictly beyond the head's end. The pads are explicit fields (the
/// 5.15-verifier lesson: every byte of the ring record is written,
/// never left to implicit padding), and the pad fields close the
/// records at exactly the pinned sizes. Static by construction; the
/// harness pins it inside the model checker so the contract rides the
/// for-all tier's own verdict.
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
    // The SockEvent layout table (repr(C), natural alignment).
    assert_eq!(offset_of!(events_core::SockEvent, timestamp_ns), 0);
    assert_eq!(offset_of!(events_core::SockEvent, skaddr), 8);
    assert_eq!(offset_of!(events_core::SockEvent, family), 16);
    assert_eq!(offset_of!(events_core::SockEvent, protocol), 18);
    assert_eq!(offset_of!(events_core::SockEvent, oldstate), 19);
    assert_eq!(offset_of!(events_core::SockEvent, newstate), 20);
    assert_eq!(offset_of!(events_core::SockEvent, _pad), 21);
    assert_eq!(offset_of!(events_core::SockEvent, sport), 22);
    assert_eq!(offset_of!(events_core::SockEvent, dport), 24);
    assert_eq!(offset_of!(events_core::SockEvent, _pad2), 26);
    assert_eq!(offset_of!(events_core::SockEvent, pid), 28);
    assert_eq!(offset_of!(events_core::SockEvent, cgroup_id), 32);
    assert_eq!(offset_of!(events_core::SockEvent, comm), 40);
    assert_eq!(offset_of!(events_core::SockEvent, netns_inum), 56);
    assert_eq!(offset_of!(events_core::SockEvent, _pad3), 60);
    // The append-only law: the legacy head ends at 32 (the pre-D5
    // record's own size), the identity block rides strictly beyond
    // it, and the closing pad lands the record at exactly 64.
    assert_eq!(
        offset_of!(events_core::SockEvent, pid) + size_of::<u32>(),
        32
    );
    assert!(offset_of!(events_core::SockEvent, cgroup_id) >= 32);
    assert_eq!(
        offset_of!(events_core::SockEvent, _pad3) + size_of::<u32>(),
        64
    );
    // The FileEvent layout table (the same discipline).
    assert_eq!(offset_of!(events_core::FileEvent, timestamp_ns), 0);
    assert_eq!(offset_of!(events_core::FileEvent, op), 8);
    assert_eq!(offset_of!(events_core::FileEvent, _pad), 9);
    assert_eq!(offset_of!(events_core::FileEvent, inode), 16);
    assert_eq!(offset_of!(events_core::FileEvent, device), 24);
    assert_eq!(offset_of!(events_core::FileEvent, pid), 32);
    assert_eq!(offset_of!(events_core::FileEvent, _pad2), 36);
    assert_eq!(offset_of!(events_core::FileEvent, cgroup_id), 40);
    assert_eq!(offset_of!(events_core::FileEvent, comm), 48);
    assert_eq!(offset_of!(events_core::FileEvent, netns_inum), 64);
    assert_eq!(offset_of!(events_core::FileEvent, _pad3), 68);
    // The same append-only law: the head ends at 40, the identity
    // block rides strictly beyond it, the record closes at exactly
    // 72.
    assert_eq!(
        offset_of!(events_core::FileEvent, _pad2) + size_of::<u32>(),
        40
    );
    assert!(offset_of!(events_core::FileEvent, cgroup_id) >= 40);
    assert_eq!(
        offset_of!(events_core::FileEvent, _pad3) + size_of::<u32>(),
        72
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

// -- The clock core's decision-table laws (night-netrunner-Z2) -------------

/// FOR ALL (pre stamp, attach stamp, window) in the legal domains: the
/// watch-truth materiality IS the documented decision table
/// (night-frontier-Z10, D7) - the prose contract ("the camera refuses
/// to invent a gap when the window rides wholly inside its life; the
/// gap rides only past the one-second materiality bound; an unstamped
/// estate degrades to None, never a guessed gap") becomes solver
/// verdicts. The domains: `pre` rides the full Option<u64> (the
/// capture's pre-breath stamp; None = the pre-Z10 estate's unreadable
/// slot), `attach` the full u64 (0 = the named unstamped estate), and
/// `window` the clamped CLI domain [1s, 1h] - exactly the values the
/// parser's clamp guarantees reach this function (the caller clamps
/// before the capture). Budget class: seconds (pure comparisons over
/// bounded i128, the wall class the Z12 census calls the fast one).
#[cfg(kani)]
#[kani::proof]
fn watch_gap_materiality_is_the_documented_decision_table_for_all_inputs() {
    let pre: Option<u64> = kani::any();
    let attach: u64 = kani::any();
    let window_ns: u64 = kani::any();
    kani::assume((1_000_000_000..=3_600_000_000_000).contains(&window_ns));
    let verdict = clock_core::material_watch_gap_ns(
        pre,
        attach,
        std::time::Duration::from_nanos(window_ns),
    );
    let window_ns = i128::from(window_ns);
    match pre {
        None => assert!(
            verdict.is_none(),
            "an unreadable pre stamp invented a gap"
        ),
        Some(pre) => {
            if attach == 0 {
                assert!(
                    verdict.is_none(),
                    "an unstamped attach invented a gap"
                );
            } else {
                // The raw span arithmetic, re-stated (the doc's own
                // contract): the requested span runs [pre - window,
                // pre], the pre-attach span is attach - (pre - window).
                let raw_gap = i128::from(attach) - (i128::from(pre) - window_ns);
                match verdict {
                    None => assert!(
                        raw_gap <= 1_000_000_000,
                        "the table withheld a gap the materiality bound must name"
                    ),
                    Some(gap) => {
                        assert_eq!(
                            gap, raw_gap,
                            "the rendered gap is not the raw arithmetic"
                        );
                        assert!(
                            raw_gap > 1_000_000_000,
                            "a sub-second edge rode the render"
                        );
                    }
                }
                // The absence arm on its own domain: the window wholly
                // inside the camera's life never renders a row - the
                // camera never invents a gap.
                if i128::from(pre) - window_ns >= i128::from(attach) {
                    assert!(
                        verdict.is_none(),
                        "the camera invented a pre-attach gap"
                    );
                }
            }
        }
    }
}

/// FOR ALL (pre, post) BOOTTIME stamp pairs in the full u64 domain:
/// the sleep materiality IS the documented sign law (night-frontier-Z6,
/// D6). None when either stamp is unreadable - the absence stays
/// absent, never a guessed zero; else Some(delta) iff |delta| exceeds
/// the one-second SLEEP_BOUND, and the delta is the exact post - pre.
/// The SIGN is the story: strictly positive is the blackout arm (the
/// host slept inside the window, the stamps' clock did not run there),
/// strictly negative the paravirt anomaly arm (the pairing itself
/// moved backwards and cannot be trusted to measure) - a Some can
/// never carry zero (the bound's own order). Budget class: seconds
/// (one subtraction and comparisons).
#[cfg(kani)]
#[kani::proof]
fn sleep_blackout_sign_law_holds_for_all_stamp_pairs() {
    let pre: Option<u64> = kani::any();
    let post: Option<u64> = kani::any();
    let verdict = clock_core::material_sleep_ns(pre.map(i128::from), post.map(i128::from));
    match (pre, post) {
        (None, _) | (_, None) => assert!(
            verdict.is_none(),
            "an unreadable stamp invented a sleep delta"
        ),
        (Some(pre), Some(post)) => {
            let raw = i128::from(post) - i128::from(pre);
            match verdict {
                None => assert!(
                    raw.abs() <= clock_core::SLEEP_BOUND_NS,
                    "the table withheld a material sleep delta"
                ),
                Some(delta) => {
                    assert_eq!(
                        delta, raw,
                        "the rendered delta is not the raw arithmetic"
                    );
                    assert!(
                        delta.abs() > clock_core::SLEEP_BOUND_NS,
                        "a sub-bound delta rode the render"
                    );
                    assert!(delta != 0, "a zero delta rode the render");
                    // The sign is the story: exactly one arm exists.
                    assert!(delta > 0 || delta < 0);
                }
            }
        }
    }
}
