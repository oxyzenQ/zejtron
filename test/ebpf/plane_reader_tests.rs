// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The public ID plane reader's unit pins (night-frontier-Z11,
//! phase b, D8). The syscall legs probe a kernel this test tree
//! cannot assume; what IS pinned here is everything pure: the attr
//! union's uapi layout, the pin classification, the reconciliation
//! truth table, and the row wording - the same discipline the
//! file-events contract pins ride (the layout test runs in the gate
//! lanes so a uapi shape change cannot slip through silently).

use super::*;

// ── the attr layout (the uapi contract) ──────────────────────────────

#[test]
fn the_attr_arms_ride_the_uapi_offsets() {
    // The 128-byte union the kernel reads its own prefix from.
    assert_eq!(std::mem::size_of::<BpfAttr>(), 128);
    // GET_NEXT_ID's arm: start_id in, next_id out - shared storage.
    assert_eq!(core::mem::offset_of!(BpfNextId, start_id), 0);
    assert_eq!(core::mem::offset_of!(BpfNextId, next_id), 4);
    // BPF_OBJ_GET's arm: the pathname pointer at offset 0.
    assert_eq!(core::mem::offset_of!(BpfObjGet, pathname), 0);
    assert_eq!(core::mem::offset_of!(BpfObjGet, bpf_fd), 8);
    // BPF_OBJ_GET_INFO_BY_FD's arm: fd, length, pointer.
    assert_eq!(core::mem::offset_of!(BpfInfoByFd, bpf_fd), 0);
    assert_eq!(core::mem::offset_of!(BpfInfoByFd, info_len), 4);
    assert_eq!(core::mem::offset_of!(BpfInfoByFd, info), 8);
}

#[test]
fn the_command_numbers_ride_the_uapi_enum() {
    // The uapi's own enum order (include/uapi/linux/bpf.h), stable
    // since BPF_LINK_GET_NEXT_ID landed in v5.8: MAP_CREATE=0,
    // MAP_LOOKUP_ELEM=1, MAP_UPDATE_ELEM=2, MAP_DELETE_ELEM=3,
    // MAP_GET_NEXT_KEY=4, PROG_LOAD=5, OBJ_PIN=6, OBJ_GET=7,
    // PROG_ATTACH=8, PROG_DETACH=9, PROG_TEST_RUN=10,
    // PROG_GET_NEXT_ID=11, MAP_GET_NEXT_ID=12, PROG_GET_FD_BY_ID=13,
    // MAP_GET_FD_BY_ID=14, OBJ_GET_INFO_BY_FD=15 ... LINK_CREATE=28,
    // LINK_UPDATE=29, LINK_GET_FD_BY_ID=30, LINK_GET_NEXT_ID=31.
    // The wrong-number era read BPF_OBJ_GET as 1 (MAP_LOOKUP_ELEM -
    // every pin resolved as EBADF, pathname bytes read as a map fd)
    // and BPF_LINK_GET_NEXT_ID as 30 (LINK_GET_FD_BY_ID - a command
    // that answers with an fd and never writes next_id, the exact
    // answer-0 spin the walk's echo guard refused to name at
    // start=0); this pin is the contract those defects rode past.
    assert_eq!(BPF_OBJ_GET, 7);
    assert_eq!(BPF_PROG_GET_NEXT_ID, 11);
    assert_eq!(BPF_MAP_GET_NEXT_ID, 12);
    assert_eq!(BPF_OBJ_GET_INFO_BY_FD, 15);
    assert_eq!(BPF_LINK_GET_NEXT_ID, 31);
}

#[test]
fn every_info_shape_this_estate_pins_carries_the_id_at_offset_four() {
    // The read the id rides: prog, map, and link info all open
    // `__u32 type; __u32 id;` - the uapi contract that lets one
    // read serve every class without per-type guessing.
    assert_eq!(core::mem::offset_of!(BpfInfoByFd, info), 8);
    assert_eq!(core::mem::size_of::<BpfInfoByFd>(), 16);
}

// ── the pin classification ───────────────────────────────────────────

#[test]
fn the_estates_own_pins_classify_by_name() {
    // Every pin the loader plants lands in its class by the estate's
    // own naming - the same constants ALL_PINS spells.
    for map in [
        "stats",
        "sock_events",
        "proc_events",
        "tracked_inodes",
        "file_events",
        "offsets",
        "drop_census",
        "generation",
    ] {
        assert_eq!(classify_pin(map), PinClass::Map, "{map} is a map pin");
    }
    for link in ["probe_link", "sock_probe_link", "dirty_probe_link"] {
        assert_eq!(classify_pin(link), PinClass::Link, "{link} is a link pin");
    }
    for prog in [
        "probe",
        "sock_probe",
        "open_probe",
        "unlink_probe",
        "membacked_probe",
    ] {
        assert_eq!(classify_pin(prog), PinClass::Prog, "{prog} is a prog pin");
    }
}

// ── the reconciliation truth table ───────────────────────────────────

fn plane(progs: &[u32], maps: &[u32], links: &[u32]) -> PublicPlane {
    let mut plane = PublicPlane::default();
    if !progs.is_empty() {
        plane.insert(PinClass::Prog, progs.iter().copied().collect());
    }
    if !maps.is_empty() {
        plane.insert(PinClass::Map, maps.iter().copied().collect());
    }
    if !links.is_empty() {
        plane.insert(PinClass::Link, links.iter().copied().collect());
    }
    plane
}

fn resolved(name: &'static str, class: PinClass, id: u32) -> PinObject {
    PinObject {
        name,
        class,
        id: Ok(id),
    }
}

fn unresolved(name: &'static str, class: PinClass, refusal: &str) -> PinObject {
    PinObject {
        name,
        class,
        id: Err(refusal.to_owned()),
    }
}

#[test]
fn every_resolved_pin_id_the_enumeration_names_is_verified() {
    let objects = vec![
        resolved("probe", PinClass::Prog, 7),
        resolved("probe_link", PinClass::Link, 9),
        resolved("stats", PinClass::Map, 12),
    ];
    let verdict = reconcile(&objects, &plane(&[7], &[12], &[9]));
    assert_eq!(verdict, PlaneVerdict::Verified { pins: 3, public: 3 });
}

#[test]
fn a_resolved_pin_id_the_enumeration_omits_is_the_hidden_shape() {
    // The camera's pin resolves (info_by_fd answered), the public
    // enumeration does not name its id - the two kernel views
    // disagree, and the pin name rides beside the verdict.
    let objects = vec![
        resolved("probe", PinClass::Prog, 7),
        resolved("dirty_probe", PinClass::Prog, 88),
        resolved("stats", PinClass::Map, 12),
    ];
    let verdict = reconcile(&objects, &plane(&[7], &[12], &[9]));
    assert_eq!(
        verdict,
        PlaneVerdict::Cloaked {
            pins: 3,
            public: 3,
            cloaked: vec!["dirty_probe"]
        }
    );
}

#[test]
fn the_hidden_names_ride_in_planting_order_with_every_cloak_named() {
    let objects = vec![
        resolved("probe", PinClass::Prog, 7),
        resolved("file_events", PinClass::Map, 40),
        resolved("stats", PinClass::Map, 12),
    ];
    let verdict = reconcile(&objects, &plane(&[7, 999], &[12], &[]));
    assert_eq!(
        verdict,
        PlaneVerdict::Cloaked {
            pins: 3,
            public: 3,
            cloaked: vec!["file_events"]
        }
    );
    // Two cloaks: both named, planting order kept.
    let objects = vec![
        resolved("probe", PinClass::Prog, 7),
        resolved("dirty_probe", PinClass::Prog, 88),
    ];
    let verdict = reconcile(&objects, &plane(&[], &[12], &[]));
    assert_eq!(
        verdict,
        PlaneVerdict::Cloaked {
            pins: 2,
            public: 1,
            cloaked: vec!["probe", "dirty_probe"]
        }
    );
}

#[test]
fn an_unresolved_pin_rides_the_notes_without_flipping_the_verdict() {
    // A pin whose own open refused (the EPERM shape an unprivileged
    // reader hits against a root attach session) is named, never
    // guessed: the verdict stays what the RESOLVED pins proved.
    let objects = vec![
        resolved("probe", PinClass::Prog, 7),
        unresolved("stats", PinClass::Map, "pin access denied (requires root)"),
    ];
    let verdict = reconcile(&objects, &plane(&[7], &[12], &[]));
    assert_eq!(verdict, PlaneVerdict::Verified { pins: 2, public: 2 });
}

// ── the row wording ──────────────────────────────────────────────────

#[test]
fn the_row_wording_pins_the_task_landing_line() {
    let (token, detail) = PlaneVerdict::Verified {
        pins: 10,
        public: 34,
    }
    .label_parts();
    assert_eq!(token, "verified");
    assert_eq!(detail, "(10 pins, 34 public ids)");

    let (token, detail) = PlaneVerdict::Cloaked {
        pins: 10,
        public: 34,
        cloaked: vec!["dirty_probe", "file_events"],
    }
    .label_parts();
    assert_eq!(token, "hidden");
    assert_eq!(
        detail,
        "(2 cloaked: dirty_probe, file_events) - 10 pins, 34 public ids"
    );

    let (token, detail) = PlaneVerdict::Unavailable {
        reason: "requires CAP_SYS_ADMIN (the id enumeration is privileged)".to_owned(),
    }
    .label_parts();
    assert_eq!(token, "unavailable");
    assert_eq!(
        detail,
        "(requires CAP_SYS_ADMIN (the id enumeration is privileged))"
    );

    let (token, detail) = PlaneVerdict::Unavailable {
        reason: "no pin estate (nothing to reconcile)".to_owned(),
    }
    .label_parts();
    assert_eq!(token, "unavailable");
    assert_eq!(detail, "(no pin estate (nothing to reconcile))");
}
