// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The pin estate's identity pins (night-frontier-Z2). The live
//! verify (a real pinned generation map against the real boot id and
//! the real embedded object) belongs to the owner's session and the
//! netrunner legs; what is pinned here is the identity law itself -
//! the FNV digest, the boot-id shaper, the pure verdict, and the
//! slot contract - driven with synthetic stamps. The IO wrappers
//! name their stage (the readback module's error-shape law).

use super::*;

#[test]
fn fnv1a64_is_the_reference_digest() {
    // The reference FNV-1a 64 vectors (the standard's own test
    // strings): an empty input rides the offset basis alone, and the
    // digest is byte-order sensitive.
    assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
    assert_eq!(fnv1a64(b"foobar"), 0x85944171f73967e8);
    // A different byte, a different identity - a digest that
    // collapsed inputs would let a foreign estate pass as ours.
    assert_ne!(fnv1a64(b"foobar"), fnv1a64(b"foobaz"));
}

#[test]
fn the_boot_id_shaper_hashes_the_trimmed_uuid() {
    // The UUID's bytes are the identity; trailing whitespace is not.
    // The same UUID under different trailing newlines rides the same
    // stamp (the file's own trailing newline varies by reader).
    let uuid = "2c98e50d-5f3d-4da6-b27e-d498927786ce";
    assert_eq!(
        boot_id_fnv_from(uuid),
        boot_id_fnv_from(&format!("{uuid}\n"))
    );
    // A different boot is a different identity - the fact the whole
    // check rests on.
    assert_ne!(
        boot_id_fnv_from(uuid),
        boot_id_fnv_from("3c98e50d-5f3d-4da6-b27e-d498927786ce")
    );
}

#[test]
fn the_verdict_accepts_same_boot_and_same_object() {
    let boot = 0x1234_5678_9abc_def0;
    let object = 0x0fed_cba9_8765_4321;
    assert!(identity_verdict(boot, object, 1_700_000_000, boot, object).is_ok());
}

#[test]
fn the_verdict_refuses_a_foreign_boot_by_name() {
    let verdict = identity_verdict(0x1234, 0x5678, 1_700_000_000, 0x9abc, 0x5678);
    let error = verdict.unwrap_err();
    // The repo-owned sentinel carries the class (the
    // PIN_ACCESS_DENIED precedent: classifiers match the constant,
    // never the prose).
    assert!(error.starts_with(GENERATION_IDENTITY), "{error}");
    // The planted stamp beside the current one, both named.
    assert!(error.contains("another boot"), "{error}");
    assert!(error.contains("planted stamp 0x1234"), "{error}");
    assert!(error.contains("this boot 0x9abc"), "{error}");
    // The recovery path is named: re-attach, not a guess.
    assert!(error.contains("doctor --detach"), "{error}");
}

#[test]
fn the_verdict_refuses_a_foreign_build_by_name() {
    let verdict = identity_verdict(0x1234, 0x5678, 1_700_000_000, 0x1234, 0x9abc);
    let error = verdict.unwrap_err();
    assert!(error.starts_with(GENERATION_IDENTITY), "{error}");
    // The upgrade story: another build between attach and now, its
    // attach instant named, the record-contract consequence said.
    assert!(error.contains("another zejtron build"), "{error}");
    assert!(error.contains("attached at unix 1700000000"), "{error}");
    assert!(error.contains("record contract"), "{error}");
    assert!(error.contains("doctor --detach"), "{error}");
}

#[test]
fn the_boot_slot_is_checked_before_the_object_slot() {
    // A stamp that disagrees on BOTH slots names the boot drift: the
    // kexec/reboot story is the deeper fact (the object stamps are
    // meaningless across boots).
    let verdict = identity_verdict(0x1234, 0x5678, 0, 0x9abc, 0x9abc);
    let error = verdict.unwrap_err();
    assert!(error.contains("another boot"), "{error}");
    assert!(!error.contains("another zejtron build"), "{error}");
}

#[test]
fn the_slot_contract_is_the_map_layout() {
    // Both sides keep the slots in lockstep (the stats lockstep
    // law's shape): the writer plants boot, object, attached, in
    // that order; the reader reads them by constant.
    assert_eq!(GEN_SLOT_BOOT, 0);
    assert_eq!(GEN_SLOT_OBJECT, 1);
    assert_eq!(GEN_SLOT_ATTACHED, 2);
    assert_eq!(GENERATION_SLOTS, 3);
}

#[test]
fn the_object_identity_is_the_embedded_object_itself() {
    // The object fnv rides the embedded ELF - the record contract.
    // The digest is stable within this binary and differs from any
    // other input; the STABILITY (same bytes, same digest) is the
    // property the idempotence verdict rests on.
    let first = object_fnv();
    let second = object_fnv();
    assert_eq!(first, second);
    assert_ne!(first, fnv1a64(b"not the object"));
}

#[test]
fn the_missing_stamp_reads_as_a_named_refusal() {
    // Host-tolerant (the missing-pin error shape law): a host with a
    // live stamped estate has a readable stamp; the error-path pin
    // only applies when the pin is genuinely absent (a pre-Z2
    // estate, a partial sweep).
    if crate::ebpf::all_pins_present() {
        return;
    }
    if crate::ebpf::any_pin_present() {
        return;
    }
    let error = verify_at_drain().unwrap_err();
    assert!(error.starts_with(GENERATION_IDENTITY), "{error}");
    assert!(error.contains("generation stamp"), "{error}");
}
