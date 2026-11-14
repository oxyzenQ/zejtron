// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The drain-boundary offsets re-verification (night-frontier-Z1):
//! the second half of the offsets law. Attach verifies the parse
//! BEFORE anything is planted (src/ebpf/btf.rs, called from the
//! loader's preflight); this module re-derives the planted walk
//! table from the host's CURRENT BTF before a drain trusts the
//! records the table produced. The two halves together close the
//! verification loop around every recording boundary: the camera's
//! offsets are per-host data at attach, and they stay per-host data
//! at drain.
//!
//! WHAT THIS GATES, AND WHY ONLY THE FILE RING: the offsets map
//! serves the file probes - open, write, writev, unlink, rename all
//! walk kernel structs at its offsets, and a walk table that no
//! longer matches the kernel reads garbage SILENTLY (the exact
//! failure class the offsets law exists to prevent, one window
//! later). The sock probe's records ride verified tracepoint-context
//! constants (ebpf/src/main.rs's ctx_offsets, a fixed prefix stable
//! since the tracepoint landed), and the exit probe's records ride
//! helpers alone (pid/comm/ktime) - neither reads the offsets map,
//! so neither carries offsets trust, and neither is gated here: a
//! drift refusal on a ring whose records cannot be corrupted would
//! be a refusal that lies. The file ring's drain is the one boundary
//! where offsets trust is load-bearing, so it is the one boundary
//! this module sits behind (src/ebpf/ringbuf.rs drain_file_events).
//!
//! WHAT DRIFT MEANS HERE: the planted offsets map is re-derived from
//! the host's /sys/kernel/btf/vmlinux AS IT EXISTS NOW - all fifteen
//! slots, the thirteen struct offsets plus the two BTF-derived
//! anchors (the vfs_unlink dentry argument position and the
//! renamedata old_dentry member offset, resolved by
//! src/ebpf/btf_unlink.rs). A mismatch is the named refusal, by
//! slot, planted value beside the host's current word: the camera's
//! walk table no longer matches the kernel it is planted on, and
//! records written with the old table cannot be trusted. The one
//! BTF blob read serves both parses (the struct walk and the symbol
//! walk are two parses of one file, the attach boundary's own
//! shape). What a kexec-style kernel swap means for the estate
//! outside this window - the pins vanish with the boot, and a
//! partial pin set reads as not-attached (the doctor names it,
//! `doctor --attach` heals it) - is the neighboring law, not this
//! one; this module catches the drift that can hide INSIDE a live
//! pin estate.
//!
//! The refusals are repo-owned sentinels, never OS prose: the
//! OFFSETS_DRIFT prefix is the marker tests and classifiers match
//! on (the PIN_ACCESS_DENIED precedent in src/ebpf/mod.rs - matching
//! a repo-owned constant cannot drift with a dependency bump).

use aya::maps::{Array, Map, MapData};

use super::events::{OFF_SLOT_RENAMEDATA_OLD_DENTRY, OFF_SLOT_UNLINK_DENTRY_ARG, OFF_SLOTS};
use super::{PIN_MAP_OFFSETS, btf, btf_unlink};

/// The refusal marker (the repo-owned sentinel): every drift refusal
/// starts with this exact string, so a classifier or a test matches
/// the class, never the prose.
pub const OFFSETS_DRIFT: &str = "offsets drift at the drain boundary";

/// The fifteen slots the re-derivation covers, in events.rs
/// OFF_SLOT_* order: the thirteen struct offsets the attach trace
/// (src/ebpf/loader.rs's OFF_TRACE) names, plus the two anchor slots
/// the symbol walk resolves. A slot's name is the refusal's own
/// word for the slot - `struct member` for the byte offsets, the
/// position/offset phrasing for the two anchors.
const SLOT_NAMES: [&str; OFF_SLOTS as usize] = [
    "dentry.d_inode",
    "inode.i_ino",
    "file.f_path",
    "file.f_inode",
    "vfsmount.mnt_sb",
    "super_block.s_dev",
    "path.mnt",
    "path.dentry",
    "task_struct.files",
    "files_struct.fdt",
    "fdtable.max_fds",
    "fdtable.fd",
    "inode.i_sb",
    "vfs_unlink dentry argument position",
    "renamedata.old_dentry offset",
];

/// The planted walk table, exactly as the pinned offsets map holds
/// it right now: all fifteen slots, read through the pin (the same
/// `MapData::from_pin` lane as every readback - no capability
/// needed). Slot = index, the night-hunter-3 lesson's own contract
/// (the writer rides the parsed array whole, so the map's order IS
/// the OFF_SLOT_* order).
fn planted_offsets() -> Result<[u64; OFF_SLOTS as usize], String> {
    let map_data = MapData::from_pin(PIN_MAP_OFFSETS)
        .map_err(|e| format!("drain-boundary verify: pinned offsets map {PIN_MAP_OFFSETS}: {e}"))?;
    let map = Map::Array(map_data);
    let offsets: Array<_, u64> = Array::try_from(&map).map_err(|e| {
        format!("drain-boundary verify: the pinned offsets map is not an array: {e}")
    })?;
    let mut planted = [0u64; OFF_SLOTS as usize];
    for slot in 0..OFF_SLOTS {
        planted[slot as usize] = offsets
            .get(&slot, 0)
            .map_err(|e| format!("drain-boundary verify: offsets[{slot}] read failed: {e}"))?;
    }
    Ok(planted)
}

/// The host's current walk table, re-derived from one read of the
/// host's own BTF: the thirteen struct offsets (btf.rs's parse) plus
/// the two anchor slots (btf_unlink.rs's symbol walk) - the attach
/// boundary's own two parses of one blob, re-run. Every parse
/// failure is the named refusal too: a host whose BTF went
/// unreadable since attach cannot be verified against, and the law
/// is verify-or-refuse, never trust-or-hope.
fn derived_offsets() -> Result<[u64; OFF_SLOTS as usize], String> {
    let data = std::fs::read("/sys/kernel/btf/vmlinux")
        .map_err(|e| format!("drain-boundary verify: cannot read /sys/kernel/btf/vmlinux: {e}"))?;
    let struct_walk =
        btf::parse_btf_offsets(&data).map_err(|e| format!("drain-boundary verify: {e}"))?;
    let lane = btf_unlink::verify_unlink_lane_in(&data)
        .map_err(|e| format!("drain-boundary verify: {e}"))?;
    let mut derived = [0u64; OFF_SLOTS as usize];
    derived[..struct_walk.len()].copy_from_slice(&struct_walk);
    derived[OFF_SLOT_UNLINK_DENTRY_ARG as usize] = u64::from(lane.dentry_arg);
    derived[OFF_SLOT_RENAMEDATA_OLD_DENTRY as usize] = lane.old_dentry_offset;
    Ok(derived)
}

/// The pure compare: the first slot where the planted table and the
/// re-derived table disagree, `None` when they agree on all fifteen.
/// Separated from the IO so the drift law is pinnable with synthetic
/// tables, no host and no pins (the read side's furthest_stage
/// precedent).
fn drift_slot(
    planted: &[u64; OFF_SLOTS as usize],
    derived: &[u64; OFF_SLOTS as usize],
) -> Option<usize> {
    (0..OFF_SLOTS as usize).find(|&slot| planted[slot] != derived[slot])
}

/// The refusal message: by slot, the planted value beside the
/// host's current word, the marker carrying the class. The planted
/// value renders first - the camera's own word is what the records
/// were written with; the derived value is what THIS kernel says
/// now.
fn drift_message(slot: usize, planted: u64, derived: u64) -> String {
    format!(
        "{OFFSETS_DRIFT}: offsets[{slot}] ({}) planted {planted}, \
         the current kernel's BTF derives {derived} - the camera's \
         walk table no longer matches this kernel, and the records it \
         wrote cannot be trusted; re-attach (doctor --detach, then \
         doctor --attach)",
        SLOT_NAMES[slot]
    )
}

/// Verify the planted walk table against the host's CURRENT BTF: the
/// drain-boundary half of the offsets law. `Ok(())` is the all-
/// fifteen-agree verdict; `Err` names the first drifting slot (or
/// the unreadable BTF / map, each its own named refusal). The check
/// is read-only end to end - two file reads (the offsets map's pin,
/// the BTF blob) and one compare; the window it protects pays
/// milliseconds to keep its rows worth trusting.
pub fn verify_offsets_at_drain() -> Result<(), String> {
    let planted = planted_offsets()?;
    let derived = derived_offsets()?;
    match drift_slot(&planted, &derived) {
        None => Ok(()),
        Some(slot) => Err(drift_message(slot, planted[slot], derived[slot])),
    }
}

#[cfg(test)]
#[path = "../../test/ebpf/reverify_tests.rs"]
mod tests;
