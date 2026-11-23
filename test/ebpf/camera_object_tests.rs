// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! Camera-object unit pins (night-netrunner-Z1, the pure move out of
//! loader_tests.rs at the 600-LOC cap). Lives under the single test/
//! tree and is #[path]-wired from src/ebpf/camera_object.rs. The
//! privileged plant itself (attach on a live host) is exercised by
//! CI's root lanes and the owner's live sessions; what IS pinned
//! here is the embedded object's structural truth and the anchor
//! gate's every verdict class through its pure seam.

use super::*;
use crate::ebpf::embedded;

#[test]
fn probe_elf_is_an_aligned_bpf_object() {
    // The real embedded object, as it ships inside the binary: ELF
    // magic, and 8-byte aligned (the AlignedElf contract - aya's
    // parser reads ELF64 structures straight out of the buffer).
    assert!(PROBE_ELF.starts_with(&[0x7f, b'E', b'L', b'F']));
    assert_eq!(
        embedded::alignment_violation(PROBE_ELF, "zejtron-ebpf"),
        None,
        "the embedded probe must sit 8-byte aligned by construction"
    );
}

/// The alignment preflight's own seam: the pristine object passes,
/// and the pure detector behind it still answers misalignment.
#[test]
fn camera_preflight_passes_on_the_pristine_object() {
    camera_preflight().expect("the pristine camera passes its preflight");
}

/// The pristine build's real plant-path self-check: the gate hands
/// back the verified anchor line over the very PROBE_ELF bytes this
/// binary embeds, against the stamp its own build.rs produced. A
/// build whose object was patched after staging fails HERE, before
/// any privilege is spent - the loader that rejects an object
/// without a valid anchor.
#[test]
fn camera_anchor_gate_passes_on_the_pristine_object() {
    let anchor = camera_anchor_gate().expect("the pristine camera must verify");
    assert!(
        anchor.starts_with("b3:"),
        "the verified anchor line names its digest: {anchor}"
    );
    assert!(
        anchor.contains("recomputes from the embedded probe object"),
        "{anchor}"
    );
}

/// The tamper arm, through the real gate seam: one flipped byte in
/// the embedded object must refuse, naming BOTH digests - the
/// recomputed one and the stamped one. Pure over (stamp, bytes), so
/// the flip is pinned in memory without patching a real artifact.
#[test]
fn a_patched_camera_refuses_the_plant() {
    use crate::info::signature::{DepthStatus, camera_object_row};
    let stamped = "e642ace8b8e9a3f549434d21c45413688fc6e3ec3afb7292f078cd0850f996ec";
    let mut patched = PROBE_ELF.to_vec();
    let middle = patched.len() / 2;
    patched[middle] ^= 0x01;
    let (status, detail) = camera_object_row(Some(stamped), &patched);
    assert_eq!(status, DepthStatus::Refused, "{detail}");
    assert!(
        detail.contains("hashes to b3:") && detail.contains(stamped),
        "names both digests: {detail}"
    );
    assert!(
        detail.contains("patched after the build"),
        "names the tamper shape: {detail}"
    );
}

/// The missing-stamp arm is the plant path's fail-closed law: where
/// the sig matrix's D4 row names the unavailability honestly for an
/// OLD build, the loader REFUSES - an object the plant path cannot
/// vouch for must not plant, so the Unavailable row maps to a gate
/// refusal carrying the same named detail.
#[test]
fn a_build_without_the_stamp_refuses_the_plant_fail_closed() {
    use crate::info::signature::{DepthStatus, camera_object_row};
    let (status, detail) = camera_object_row(None, PROBE_ELF);
    assert_eq!(status, DepthStatus::Unavailable, "{detail}");
    // The gate maps this exact arm to Err: prove the mapping law
    // with the gate's own pure seam, synthetic on both inputs.
    let gate_verdict = camera_object_row(None, b"synthetic");
    assert_eq!(gate_verdict.0, DepthStatus::Unavailable);
    assert!(
        gate_verdict
            .1
            .contains("did not stamp the camera object digest"),
        "the named detail rides the gate refusal: {}",
        gate_verdict.1
    );
}
