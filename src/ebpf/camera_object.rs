// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The camera object's own module (night-netrunner-Z1, split out of
//! loader.rs per the 600-LOC no-mercy cap - the btf_decode.rs
//! precedent: the concern gets its own module, a pure move, gates
//! green in between). The embedded eBPF probe object and the anchor
//! gate that vouches for it at plant time live here: the object is
//! the one artifact that executes at ring 0, so its bytes carry
//! their own supply-chain seat - the loader refuses to plant an
//! object that does not answer its build-stamped BLAKE3 digest.
//!
//! The gate's verdict is the sig matrix's D4 row single-sourced
//! through [`crate::info::signature::camera_object_row`]: one
//! implementation behind both the report (the `sig` surface's
//! camera-object row) and the plant path (attach's step 0), no drift
//! between saying and doing. Fail-closed at the plant where D4 is
//! honest-unavailable: a build without the stamp refuses the PLANT
//! (an object the loader cannot vouch for must not plant), while the
//! sig row names the same state `unavailable` for an old build's age
//! signal.

use super::embedded;

/// The embedded pure-Rust probe object (night-improve-1): the aya-ebpf
/// ELF staged into OUT_DIR by build.rs. It rides inside the
/// AlignedElf wrapper (the NIGHT-hunt-30 lesson - see embedded.rs)
/// so aya's ELF parser reads 8-aligned bytes whatever the linker
/// decided.
pub(crate) static PROBE_ELF: &[u8] =
    &embedded::AlignedElf::new(*include_bytes!(concat!(env!("OUT_DIR"), "/zejtron-ebpf.o"))).bytes;

/// The camera anchor gate (night-netrunner-Z1, the loader half of
/// the eBPF supply-chain attestation): the plant path's own answer
/// to "does this object answer its build-stamped digest?" - the
/// sig matrix's D4 row (single-sourced through
/// [`crate::info::signature::camera_object_row`]) rendered as a
/// gate verdict instead of a report row. Pass hands back the
/// verified anchor line for the transparency trace; every other
/// state refuses - the loader that rejects an object without a
/// valid anchor is the whole point of this seam. Pure over the
/// stamp and the embedded bytes, so all three arms are pinnable
/// without patching a real artifact.
pub(crate) fn camera_anchor_gate() -> Result<String, String> {
    use crate::info::signature::DepthStatus;
    let stamped = option_env!("ZEJTRON_CAMERA_OBJECT_B3");
    match crate::info::signature::camera_object_row(stamped, PROBE_ELF) {
        (DepthStatus::Pass, detail) => Ok(detail),
        (DepthStatus::Refused, detail) => Err(detail),
        (DepthStatus::Unavailable, detail) => Err(format!(
            "{detail} - the plant path fails closed where the sig row \
             names the same unavailability: an object the loader cannot \
             vouch for must not plant"
        )),
    }
}

/// The alignment preflight (the AlignedElf contract): structurally
/// impossible while the object rides inside [`embedded::AlignedElf`],
/// kept so a regression diagnoses in one line.
pub(crate) fn camera_preflight() -> Result<(), String> {
    match embedded::alignment_violation(PROBE_ELF, "zejtron-ebpf") {
        Some(violation) => Err(violation),
        None => Ok(()),
    }
}

/// The gate refusal's attach-shaped wrap: the named verdict plus the
/// plant-path law, the message attach returns when the gate refuses.
pub(crate) fn attach_refusal(reason: String) -> String {
    format!(
        "attach refused: {reason}. The embedded camera object must recompute \
         the digest the build stamped over the staged bytes before anything \
         is planted"
    )
}

#[cfg(test)]
#[path = "../../test/ebpf/camera_object_tests.rs"]
mod tests;
