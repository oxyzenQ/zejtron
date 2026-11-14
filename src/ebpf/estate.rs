// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The pin estate's identity (night-frontier-Z2, the generation
//! stamp): the camera proves that the camera found is THIS boot's
//! own camera, planted by THIS build. Until now `all_pins_present`
//! answered the question structurally - the pins exist, so they are
//! ours - and the answer carried an assumption: a complete pin set
//! under the one directory COULD have been planted by a different
//! zejtron build (an upgrade between attach and drain serves a new
//! binary the old object's record contract), or by anything that
//! left a foreign estate under the pin path. The generation map
//! turns the assumption into a check: at attach the loader stamps
//! three slots into a pinned `generation` map - the boot's identity
//! (fnv1a64 over /proc/sys/kernel/random/boot_id, the fact that
//! changes at every reboot and every kexec), the probe object's
//! identity (fnv1a64 over the embedded ELF - the record contract
//! itself), and the attach instant (unix seconds, so a foreign
//! estate can say WHEN it was planted) - and every drain re-derives
//! the two live facts and compares. A mismatch refuses by name, the
//! planted word beside the current one, with the remedy named.
//!
//! WHY FNV-1a AND NOT BLAKE3: the digest here is an IDENTITY, not a
//! security boundary - it must be (a) deterministic across runs and
//! compilers (std's DefaultHasher is seed-stable only within one
//! binary), (b) different for different objects, (c) dependency-free.
//! FNV-1a 64 is all three, and the manifest's blake3 pins already
//! guard the object's integrity elsewhere; nothing here defends
//! against a crafted collision, because nothing here gates an
//! attacker - it gates a stale camera against its own operator.
//!
//! THE IDENTITY LAW'S BOUNDARY, NAMED: the stamp proves same-boot,
//! same-object - it cannot prove the stamps were not forged by
//! something writing the pinned map directly (the root that could
//! plant pins could forge a stamp; the check defends against
//! staleness and mistake, not malice-with-root). And a pre-Z2 estate
//! carries no generation pin at all: all_pins_present reads it as a
//! partial set (NotAttached, the doctor names it), and one
//! `doctor --attach` replants it stamped - the upgrade path's whole
//! cost.

use std::time::{SystemTime, UNIX_EPOCH};

use aya::maps::{Array, Map, MapData};

use super::{PIN_MAP_GENERATION, loader};

/// The refusal marker (the repo-owned sentinel): every identity
/// refusal starts with this exact string, so a classifier or a test
/// matches the class, never the prose (the PIN_ACCESS_DENIED and
/// OFFSETS_DRIFT precedents).
pub const GENERATION_IDENTITY: &str = "pin estate identity";

/// The generation map's slot contract (the map the BPF side never
/// reads - a passive identity record the loader owns whole).
/// `generation[0]`: the boot identity.
pub const GEN_SLOT_BOOT: u32 = 0;
/// `generation[1]`: the probe object identity.
pub const GEN_SLOT_OBJECT: u32 = 1;
/// `generation[2]`: the attach instant, unix seconds.
pub const GEN_SLOT_ATTACHED: u32 = 2;
/// The map's slot count (the BPF side's max_entries, hardcoded
/// beside the map). Userspace-only by design - the readers name the
/// slots by constant and never need the count; the scoped allow is
/// the honest count of that split.
#[allow(dead_code)]
pub const GENERATION_SLOTS: u32 = 3;

/// FNV-1a 64-bit: the pure identity digest (see the module doc for
/// why FNV and not blake3 here). Offset basis 0xcbf29ce484222325,
/// prime 0x100000001b3 - the reference parameters, one byte at a
/// time, no unsafe, no deps.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The boot identity from a boot_id file's CONTENT (pure seam): the
/// trimmed text hashed whole - the UUID's bytes are the identity,
/// whitespace is not.
fn boot_id_fnv_from(text: &str) -> u64 {
    fnv1a64(text.trim().as_bytes())
}

/// The boot identity, as this boot carries it right now:
/// /proc/sys/kernel/random/boot_id - a UUID the kernel generates at
/// boot and keeps until the next one. An unreadable boot_id is the
/// named unavailability (the stamp cannot be derived; the law is
/// verify-or-refuse).
fn boot_id_fnv() -> Result<u64, String> {
    let text = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|e| format!("{GENERATION_IDENTITY}: cannot read the boot id: {e}"))?;
    Ok(boot_id_fnv_from(&text))
}

/// The probe object's identity: fnv1a64 over the embedded ELF bytes
/// - the record contract itself. The same object always hashes the
/// same; a different build (a changed probe, a changed record) rides
/// a different identity.
fn object_fnv() -> u64 {
    fnv1a64(loader::PROBE_ELF)
}

/// The attach instant, unix seconds - the stamp's informational slot
/// (a foreign estate can say WHEN it was planted; the refusal names
/// it).
fn attach_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Stamp the freshly pinned generation map: boot identity, object
/// identity, attach instant - the three slots the drains read back.
/// Written through the pin (the tracked_inodes writer's own lane:
/// from_pin, typed view, the named error shape). Called by the
/// plant chain the moment the map is pinned, before any program
/// attaches - the self-verification's drain (verify_write, which
/// opens a ring and rides the identity gate) must find the estate
/// already stamped.
pub fn write_generation_stamp() -> Result<(), String> {
    let map_data = MapData::from_pin(PIN_MAP_GENERATION).map_err(|e| {
        format!("{GENERATION_IDENTITY}: pinned generation map {PIN_MAP_GENERATION}: {e}")
    })?;
    let mut map = Map::Array(map_data);
    let mut generation: Array<_, u64> = Array::try_from(&mut map).map_err(|e| {
        format!("{GENERATION_IDENTITY}: the pinned generation map is not an array: {e}")
    })?;
    let boot = boot_id_fnv()?;
    let object = object_fnv();
    let attached = attach_unix_secs();
    generation.set(GEN_SLOT_BOOT, &boot, 0).map_err(|e| {
        format!("{GENERATION_IDENTITY}: generation[{GEN_SLOT_BOOT}] write failed: {e}")
    })?;
    generation.set(GEN_SLOT_OBJECT, &object, 0).map_err(|e| {
        format!("{GENERATION_IDENTITY}: generation[{GEN_SLOT_OBJECT}] write failed: {e}")
    })?;
    generation
        .set(GEN_SLOT_ATTACHED, &attached, 0)
        .map_err(|e| {
            format!("{GENERATION_IDENTITY}: generation[{GEN_SLOT_ATTACHED}] write failed: {e}")
        })?;
    Ok(())
}

/// The pure identity compare: the planted stamp against the current
/// facts. `Ok(())` is the same-boot, same-object verdict; `Err`
/// names which slot disagrees, the planted word beside the current
/// one, and the remedy. Separated from the IO so the law is pinnable
/// with synthetic stamps (the read side's furthest_stage precedent).
fn identity_verdict(
    planted_boot: u64,
    planted_object: u64,
    planted_attached: u64,
    current_boot: u64,
    current_object: u64,
) -> Result<(), String> {
    if planted_boot != current_boot {
        return Err(format!(
            "{GENERATION_IDENTITY}: the pin estate was planted under another boot \
             (planted stamp {planted_boot:#x}, this boot {current_boot:#x}) - the \
             camera found is not this boot's camera; re-attach (doctor --detach, \
             then doctor --attach)"
        ));
    }
    if planted_object != current_object {
        return Err(format!(
            "{GENERATION_IDENTITY}: the pin estate was planted by another zejtron build \
             (planted stamp {planted_object:#x}, attached at unix {planted_attached}; \
             this build {current_object:#x}) - the records it holds ride the other \
             build's record contract; re-attach (doctor --detach, then doctor --attach)"
        ));
    }
    Ok(())
}

/// Verify the pin estate's identity at a recording boundary: read
/// the planted stamp, re-derive the current boot and object facts,
/// compare. `Ok(())` is the same-boot, same-object verdict; `Err` is
/// the named refusal (a missing generation pin among them - an
/// estate planted by a pre-Z2 binary that somehow rides a complete
/// structural check, which is exactly the shape the stamp exists to
/// refuse).
pub fn verify_at_drain() -> Result<(), String> {
    let map_data = MapData::from_pin(PIN_MAP_GENERATION).map_err(|e| {
        format!(
            "{GENERATION_IDENTITY}: pinned generation map {PIN_MAP_GENERATION}: {e} \
             (an estate planted before the generation stamp carries no identity \
             at all - re-attach to plant a stamped one)"
        )
    })?;
    let map = Map::Array(map_data);
    let generation: Array<_, u64> = Array::try_from(&map).map_err(|e| {
        format!("{GENERATION_IDENTITY}: the pinned generation map is not an array: {e}")
    })?;
    let slot = |index: u32| -> Result<u64, String> {
        generation
            .get(&index, 0)
            .map_err(|e| format!("{GENERATION_IDENTITY}: generation[{index}] read failed: {e}"))
    };
    let planted_boot = slot(GEN_SLOT_BOOT)?;
    let planted_object = slot(GEN_SLOT_OBJECT)?;
    let planted_attached = slot(GEN_SLOT_ATTACHED)?;
    identity_verdict(
        planted_boot,
        planted_object,
        planted_attached,
        boot_id_fnv()?,
        object_fnv(),
    )
}

#[cfg(test)]
#[path = "../../test/ebpf/estate_tests.rs"]
mod tests;
