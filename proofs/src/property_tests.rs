// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The proptest exhaustion tier (night-datapath-1): sampled,
//! shrinkable cases against the pure cores' laws on stable. Every
//! law here also carries a Kani for-all form or a named census
//! verdict in the kani module - the two instruments divide the work,
//! they do not duplicate it (see docs/PROOFS.md).

use proptest::prelude::*;

use crate::clock_core;
use crate::events_core;

// The exhaustion budget rides each law's proptest! block below: 4096
// shrinkable cases per law per run, the zelynic proofs lane's own
// figure - thousands of sampled cases per law, with shrinking
// witnesses on any failure.

// -- The clock core's laws ------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    // The panic-free inverse pair, across the FULL signed domain the
    // doc claims (night-dragon-lts-T1): every i64 second round trips
    // through SystemTime and back. A failure here is a shrunk
    // counterexample to the "both arithmetic directions stay inside
    // the platform's i64-backed range" claim.
    #[test]
    fn unix_secs_round_trips_through_system_time(secs in any::<i64>()) {
        let time = clock_core::system_time_from_unix_secs(secs);
        prop_assert_eq!(clock_core::unix_secs(time), secs);
    }

    // The fixed-width timestamp is chronologically ordered: two
    // unix second counts inside the sane calendar window render to
    // strings whose lexicographic order equals their chronological
    // order (the ledger's row sorting contract).
    #[test]
    fn format_unix_secs_is_chronologically_ordered(
        a in -4_000_000_000i64..=4_000_000_000i64,
        delta in 0..1_000_000i64,
    ) {
        let b = a.saturating_add(delta).min(4_000_000_000);
        prop_assert!(a <= b);
        let rendered_a = clock_core::format_unix_secs(a);
        let rendered_b = clock_core::format_unix_secs(b);
        prop_assert!(rendered_a.as_bytes() <= rendered_b.as_bytes());
    }

    // The watch-truth decision table, sampled over the full stamp
    // domains and the clamped window range (night-netrunner-Z2; the
    // Kani harness holds the for-all form): the verdict is Some
    // exactly when the raw pre-attach span exceeds the one-second
    // materiality bound, a Some carries the raw arithmetic whole, an
    // unreadable pre stamp and an unstamped attach both degrade to
    // None, and the window wholly inside the camera's life adds
    // nothing - the camera never invents a gap.
    #[test]
    fn watch_gap_matches_the_documented_decision_table(
        pre in any::<Option<u64>>(),
        attach in any::<u64>(),
        window_ns in 1_000_000_000u64..=3_600_000_000_000,
    ) {
        let verdict = clock_core::material_watch_gap_ns(
            pre,
            attach,
            std::time::Duration::from_nanos(window_ns),
        );
        let window_ns = i128::from(window_ns);
        match pre {
            None => prop_assert!(verdict.is_none()),
            Some(pre) => {
                if attach == 0 {
                    prop_assert!(verdict.is_none());
                } else {
                    let raw_gap =
                        i128::from(attach) - (i128::from(pre) - window_ns);
                    match verdict {
                        None => prop_assert!(raw_gap <= 1_000_000_000),
                        Some(gap) => {
                            prop_assert_eq!(gap, raw_gap);
                            prop_assert!(raw_gap > 1_000_000_000);
                        }
                    }
                    if i128::from(pre) - window_ns >= i128::from(attach) {
                        prop_assert!(verdict.is_none());
                    }
                }
            }
        }
    }

    // The sleep materiality sign law, sampled (the Kani harness holds
    // the for-all form): None when either stamp is unreadable, else
    // Some(delta) iff |delta| exceeds the SLEEP_BOUND, the delta is
    // the exact post - pre, and a Some never carries zero - the sign
    // picks exactly one arm (blackout above the bound, paravirt
    // anomaly below zero).
    #[test]
    fn sleep_blackout_matches_the_documented_sign_law(
        pre in any::<Option<u64>>(),
        post in any::<Option<u64>>(),
    ) {
        let verdict = clock_core::material_sleep_ns(pre.map(i128::from), post.map(i128::from));
        match (pre, post) {
            (None, _) | (_, None) => prop_assert!(verdict.is_none()),
            (Some(pre), Some(post)) => {
                let raw = i128::from(post) - i128::from(pre);
                match verdict {
                    None => prop_assert!(raw.abs() <= clock_core::SLEEP_BOUND_NS),
                    Some(delta) => {
                        prop_assert_eq!(delta, raw);
                        prop_assert!(delta.abs() > clock_core::SLEEP_BOUND_NS);
                        prop_assert!(delta != 0);
                    }
                }
            }
        }
    }
}

// -- The events core's laws ----------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    // The filter-key packing residual, sampled over the full domain:
    // two (inode, device) pairs alias into the same key exactly when
    // the low 32 bits of their inodes and their devices agree - the
    // named residual the doc pins, never a surprise shape.
    #[test]
    fn pack_filter_key_aliases_exactly_as_documented(
        inode_a in any::<u64>(),
        inode_b in any::<u64>(),
        device_a in any::<u32>(),
        device_b in any::<u32>(),
    ) {
        let key_a = events_core::pack_filter_key(inode_a, u64::from(device_a));
        let key_b = events_core::pack_filter_key(inode_b, u64::from(device_b));
        let aliases = key_a == key_b;
        let low32_agrees = (inode_a & 0xFFFF_FFFF) == (inode_b & 0xFFFF_FFFF);
        prop_assert_eq!(aliases, low32_agrees && device_a == device_b);
    }

    // The port decision table matches the doc's spec, sampled: the
    // gate is TCP's listen involvement, UDP's close, and nothing
    // else - every family/protocol pair outside INET and the two
    // protocols is dropped.
    #[test]
    fn is_port_surface_event_matches_the_spec(
        family in any::<u16>(),
        protocol in any::<u8>(),
        oldstate in any::<u8>(),
        newstate in any::<u8>(),
    ) {
        let spec = match (family, protocol) {
            (f, _) if f != events_core::AF_INET && f != events_core::AF_INET6 => false,
            (_, p) if p == events_core::IPPROTO_TCP => {
                newstate == events_core::TCP_LISTEN || oldstate == events_core::TCP_LISTEN
            }
            (_, p) if p == events_core::IPPROTO_UDP => {
                newstate == events_core::TCP_CLOSE
            }
            _ => false,
        };
        prop_assert_eq!(
            events_core::is_port_surface_event(family, protocol, oldstate, newstate),
            spec
        );
    }
}

// -- The shared-record contract (static laws, pinned here too) -----------

#[test]
fn record_sizes_are_the_shared_contract() {
    // The kernel side's output call and the host side's record-length
    // check both carry these byte counts; the constants are defined
    // as size_of, so the law is the identity itself. The sock record
    // grew 32 -> 64 with the Z8 identity block (the legacy head never
    // renumbers; the tail rides the appended identity).
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
