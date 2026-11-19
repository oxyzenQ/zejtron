// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The planting half of the loader (split from loader.rs at the 600
//! LOC no-mercy cap, night-hunter-4 - a pure move, gates green in
//! between): the probe-object knowledge and the per-program plant
//! chain. The orchestration half stays in [`super::loader`]: the
//! gate verdict, the BTF verification, the pin-dir lifecycle, and
//! the fail protocol that cleans every pin on any failure.
//!
//! The names in this module are the probe object's OWN vocabulary -
//! the ELF symbols (the fn names in ebpf/src/) and the map names
//! (the #[map] names) - while the attach points they are planted at
//! ride the pin constants in [`super`] (the one directory contract).

use aya::Ebpf;
use aya::maps::Array;
use aya::maps::Map;
use aya::maps::MapData;
use aya::programs::KProbe;
use aya::programs::TracePoint;
use aya::programs::links::FdLink;

use super::btf;
use super::btf_unlink::UnlinkLane;
use super::events::{
    OFF_SLOT_ADDR_SPACE_HOST, OFF_SLOT_IO_KIOCB_FILE, OFF_SLOT_PAGE_MAPPING,
    OFF_SLOT_RENAMEDATA_OLD_DENTRY, OFF_SLOT_UNLINK_DENTRY_ARG,
};
use super::{
    PIN_LINK, PIN_LINK_DIRTY, PIN_LINK_EXIT, PIN_LINK_IOURING, PIN_LINK_MEMBACKED, PIN_LINK_OPEN,
    PIN_LINK_RENAME, PIN_LINK_SOCK, PIN_LINK_SPLICE, PIN_LINK_UNLINK, PIN_LINK_WRITE,
    PIN_LINK_WRITEV, PIN_MAP_DROP_CENSUS, PIN_MAP_FILE_EVENTS, PIN_MAP_GENERATION, PIN_MAP_OFFSETS,
    PIN_MAP_PROC_EVENTS, PIN_MAP_SOCK_EVENTS, PIN_MAP_STATS, PIN_MAP_TRACKED_INODES, PIN_PROG,
    PIN_PROG_DIRTY, PIN_PROG_EXIT, PIN_PROG_IOURING, PIN_PROG_MEMBACKED, PIN_PROG_OPEN,
    PIN_PROG_RENAME, PIN_PROG_SOCK, PIN_PROG_SPLICE, PIN_PROG_UNLINK, PIN_PROG_WRITE,
    PIN_PROG_WRITEV,
};
use crate::output::verbose::vlog;

/// The program name in the probe object (the ELF symbol - the fn name
/// in ebpf/src/main.rs) - phase 1's exec counter.
pub(super) const PROGRAM: &str = "sched_process_exec";

/// The tracepoint category (the attach-time half of the attach point;
/// the section name in the object carries the event half).
pub(super) const TRACEPOINT_CATEGORY: &str = "sched";

/// The tracepoint event name.
pub(super) const TRACEPOINT_EVENT: &str = "sched_process_exec";

/// The stats map name in the probe object (the \#\[map\] name in
/// ebpf/src/main.rs - the userspace mirror of the same contract).
pub(super) const MAP_STATS: &str = "stats";

/// The socket-state program's name (night-improve-2) - phase 2's
/// inet_sock_set_state probe.
pub(super) const SOCK_PROGRAM: &str = "inet_sock_set_state";

/// The socket-state tracepoint's category and event.
pub(super) const SOCK_TRACEPOINT_CATEGORY: &str = "sock";
pub(super) const SOCK_TRACEPOINT_EVENT: &str = "inet_sock_set_state";

/// The sock_events ring map name in the probe object.
pub(super) const MAP_SOCK_EVENTS: &str = "sock_events";

/// The file-open program's name (the ELF symbol - the fn name in
/// ebpf/src/main.rs). The ATTACH symbol is a separate constant -
/// the program is role-named, the symbol is kernel-named, and the
/// two meet only here (night-improve-3).
pub(super) const OPEN_PROGRAM: &str = "open_probe";

/// The kernel symbol the open probe attaches to (entry probe, offset
/// 0).
pub(super) const OPEN_SYMBOL: &str = "vfs_open";

/// The file-write program's name.
pub(super) const WRITE_PROGRAM: &str = "write_probe";

/// The write probe's tracepoint category (night-improve-59, the
/// third generation): raw_syscalls - the syscall tracepoint, the
/// one mechanism with zero observed failures across the whole
/// estate (the sock, exec, and exit probes already ride it from the
/// 5.15 floor through the 7.2 line). The first generation anchored
/// at the vfs_write kprobe (dead on the -O3 distro builds that
/// inline it into the syscall stub); the second at the stub kprobe
/// itself (attachable, pinned, absolutely silent - the drop census
/// proved the program never ran while ftrace fired at the same
/// name and the same raw kallsyms address). The third generation
/// filters the sys_enter record to write(2) by the syscall id and
/// walks the fd from the record's args[0] through the BTF-verified
/// fd-table hops - and the attach verifies its own recorded write
/// before declaring success (verify_write), so the silent-anchor
/// class cannot survive attach.
pub(super) const WRITE_TRACEPOINT_CATEGORY: &str = "raw_syscalls";
pub(super) const WRITE_TRACEPOINT_EVENT: &str = "sys_enter";

/// The vectorized-write program's name (night-improve-42) - the ELF
/// symbol in ebpf/src/main.rs. The ATTACH symbol is not a constant:
/// it is verified from the host's own BTF at attach time
/// (vfs_writev preferred, do_iter_write the verified fallback), the
/// argument-position sibling of the offsets law - a symbol whose
/// first argument the host cannot vouch for is a guess, and a
/// guessed argument position reads garbage silently.
pub(super) const WRITEV_PROGRAM: &str = "writev_probe";

/// The unlink program's name (night-frontier-2) - the ELF symbol in
/// ebpf/src/unlink.rs, the forensic closer: the probe that answers
/// WHO DELETED THIS FILE. The attach symbol is verified before
/// anything is planted (the dentry argument position is derived
/// from the host's own BTF by btf_unlink.rs and rides the offsets
/// map), the argument-position sibling of the writev law.
pub(super) const UNLINK_PROGRAM: &str = "unlink_probe";

/// The kernel symbol the unlink probe attaches to (entry probe,
/// offset 0) - the symbol the BTF scan's FUNC record lookup
/// vouches for.
pub(super) const UNLINK_SYMBOL: &str = "vfs_unlink";

/// The rename program's name (night-frontier-2) - the ELF symbol in
/// ebpf/src/unlink.rs, the movement half of the forensic pair.
pub(super) const RENAME_PROGRAM: &str = "rename_probe";

/// The kernel symbol the rename probe attaches to (entry probe,
/// offset 0): vfs_rename, the funnel every rename(2) flavor passes
/// through, its renamedata argument shape verified at attach.
pub(super) const RENAME_SYMBOL: &str = "vfs_rename";

/// The post-mortem exit program's name (night-improve-47) - the ELF
/// symbol in ebpf/src/exits.rs, the program whose records name the
/// processes that exited while nobody was asking.
pub(super) const EXIT_PROGRAM: &str = "sched_process_exit";

/// The post-mortem exit tracepoint's category and event.
pub(super) const EXIT_TRACEPOINT_CATEGORY: &str = "sched";
pub(super) const EXIT_TRACEPOINT_EVENT: &str = "sched_process_exit";

/// The mmap-dirty program names (night-frontier-Z7, D4) - the ELF
/// symbols in ebpf/src/offpath.rs. Which ONE plants is the dirty
/// ladder's verdict (btf_offpath.rs): the folio shape on folio
/// kernels, the page shape on the folio-less line; the other program
/// stays unloaded.
pub(super) const DIRTY_FOLIO_PROGRAM: &str = "dirty_folio_probe";
pub(super) const DIRTY_PAGE_PROGRAM: &str = "dirty_page_probe";

/// The splice probe's program name - the write probe's own
/// tracepoint, filtered to __NR_splice.
pub(super) const SPLICE_PROGRAM: &str = "splice_probe";
pub(super) const SPLICE_TRACEPOINT_CATEGORY: &str = "raw_syscalls";
pub(super) const SPLICE_TRACEPOINT_EVENT: &str = "sys_enter";

/// The io_uring probe's program name and tracepoint pair -
/// availability-scanned at the attach boundary (tracefs), shape-
/// verified from BTF; a host without either names the capability
/// down.
pub(super) const IOURING_PROGRAM: &str = "iouring_probe";
pub(super) const IOURING_TRACEPOINT_CATEGORY: &str = "io_uring";
pub(super) const IOURING_TRACEPOINT_EVENT: &str = "io_uring_submit_sqe";

/// The memory-backed probe's program name (night-frontier-Z9, D6) -
/// the ELF symbol in ebpf/src/offpath.rs. The ATTACH symbol is not a
/// constant: it is the memory-backed ladder's verdict
/// (btf_offpath.rs: fault_dirty_shared_page preferred, the surviving
/// wp_page_shared arm the verified fallback), the attach-symbol
/// sibling of the writev law.
pub(super) const MEMBACKED_PROGRAM: &str = "membacked_fault_probe";

/// The tracked_inodes filter map name in the probe object.
pub(super) const MAP_TRACKED_INODES: &str = "tracked_inodes";

/// The file_events ring map name in the probe object.
pub(super) const MAP_FILE_EVENTS: &str = "file_events";

/// The proc_events ring map name in the probe object (night-improve-47
/// - the post-mortem exit stream).
pub(super) const MAP_PROC_EVENTS: &str = "proc_events";

/// The offsets config map name in the probe object.
pub(super) const MAP_OFFSETS: &str = "offsets";

/// The drop census map name in the probe object (night-frontier-Z1 -
/// the ring reserve-failure counters).
pub(super) const MAP_DROP_CENSUS: &str = "drop_census";

/// The generation stamp map name in the probe object
/// (night-frontier-Z2 - the pin estate's identity record).
pub(super) const MAP_GENERATION: &str = "generation";

/// The plant step: load all eight programs, attach each to its
/// point, pin programs + links + maps. Any error names itself; the
/// caller's fail() protocol cleans up everything the attempt
/// planted - never a half-attached probe.
pub(super) fn plant(
    bpf: &mut Ebpf,
    writev_symbol: &str,
    dirty: Option<&super::btf_offpath::DirtyAnchor>,
    iouring: Option<&super::btf_offpath::IouringLane>,
    membacked: Option<&super::btf_offpath::MemBackedLane>,
) -> Result<(), String> {
    plant_tracepoint(
        bpf,
        PROGRAM,
        TRACEPOINT_CATEGORY,
        TRACEPOINT_EVENT,
        PIN_PROG,
        PIN_LINK,
    )?;
    plant_tracepoint(
        bpf,
        SOCK_PROGRAM,
        SOCK_TRACEPOINT_CATEGORY,
        SOCK_TRACEPOINT_EVENT,
        PIN_PROG_SOCK,
        PIN_LINK_SOCK,
    )?;
    plant_kprobe(bpf, OPEN_PROGRAM, OPEN_SYMBOL, PIN_PROG_OPEN, PIN_LINK_OPEN)?;
    plant_tracepoint(
        bpf,
        WRITE_PROGRAM,
        WRITE_TRACEPOINT_CATEGORY,
        WRITE_TRACEPOINT_EVENT,
        PIN_PROG_WRITE,
        PIN_LINK_WRITE,
    )?;
    plant_kprobe(
        bpf,
        WRITEV_PROGRAM,
        writev_symbol,
        PIN_PROG_WRITEV,
        PIN_LINK_WRITEV,
    )?;
    plant_kprobe(
        bpf,
        UNLINK_PROGRAM,
        UNLINK_SYMBOL,
        PIN_PROG_UNLINK,
        PIN_LINK_UNLINK,
    )?;
    plant_kprobe(
        bpf,
        RENAME_PROGRAM,
        RENAME_SYMBOL,
        PIN_PROG_RENAME,
        PIN_LINK_RENAME,
    )?;
    plant_tracepoint(
        bpf,
        EXIT_PROGRAM,
        EXIT_TRACEPOINT_CATEGORY,
        EXIT_TRACEPOINT_EVENT,
        PIN_PROG_EXIT,
        PIN_LINK_EXIT,
    )?;
    // The off-path trio (night-frontier-Z7, D4): the dirty anchor's
    // verified shape plants exactly one program; the splice probe
    // rides the write probe's own tracepoint; the io_uring probe
    // plants only when the availability scan passed. Each is the
    // plant_kprobe/plant_tracepoint chain the core programs use -
    // same pins, same fail protocol, no new machinery.
    if let Some(anchor) = dirty {
        let dirty_program = match anchor.shape {
            super::btf_offpath::DirtyShape::Folio => DIRTY_FOLIO_PROGRAM,
            super::btf_offpath::DirtyShape::Page => DIRTY_PAGE_PROGRAM,
        };
        plant_kprobe(
            bpf,
            dirty_program,
            anchor.symbol,
            PIN_PROG_DIRTY,
            PIN_LINK_DIRTY,
        )?;
    } else {
        vlog!(
            "engine",
            "mmap-dirty capability named down (no vouchable dirty anchor in this kernel's BTF)"
        );
    }
    plant_tracepoint(
        bpf,
        SPLICE_PROGRAM,
        SPLICE_TRACEPOINT_CATEGORY,
        SPLICE_TRACEPOINT_EVENT,
        PIN_PROG_SPLICE,
        PIN_LINK_SPLICE,
    )?;
    if iouring.is_some() {
        plant_tracepoint(
            bpf,
            IOURING_PROGRAM,
            IOURING_TRACEPOINT_CATEGORY,
            IOURING_TRACEPOINT_EVENT,
            PIN_PROG_IOURING,
            PIN_LINK_IOURING,
        )?;
    } else {
        vlog!(
            "engine",
            "io_uring capability named down (no vouchable io_kiocb.file in this kernel's BTF or no tracepoint seat)"
        );
    }
    // The memory-backed rung (night-frontier-Z9, D6): the ladder's
    // verified anchor plants the one fault-funnel program; a host
    // whose BTF carries no vouchable arm names the capability down -
    // the additive lanes' own law, the camera stands.
    if let Some(lane) = membacked {
        plant_kprobe(
            bpf,
            MEMBACKED_PROGRAM,
            lane.anchor,
            PIN_PROG_MEMBACKED,
            PIN_LINK_MEMBACKED,
        )?;
    } else {
        vlog!(
            "engine",
            "memory-backed capability named down (no vouchable shared-write-fault arm in this kernel's BTF)"
        );
    }
    bpf.take_map(MAP_STATS)
        .ok_or_else(|| format!("the probe object carries no '{MAP_STATS}' map"))?
        .pin(PIN_MAP_STATS)
        .map_err(|e| format!("the map pin {PIN_MAP_STATS} failed: {e}"))?;
    vlog!("engine", "map pinned: {PIN_MAP_STATS}");
    bpf.take_map(MAP_SOCK_EVENTS)
        .ok_or_else(|| format!("the probe object carries no '{MAP_SOCK_EVENTS}' map"))?
        .pin(PIN_MAP_SOCK_EVENTS)
        .map_err(|e| format!("the map pin {PIN_MAP_SOCK_EVENTS} failed: {e}"))?;
    vlog!("engine", "map pinned: {PIN_MAP_SOCK_EVENTS}");
    bpf.take_map(MAP_PROC_EVENTS)
        .ok_or_else(|| format!("the probe object carries no '{MAP_PROC_EVENTS}' map"))?
        .pin(PIN_MAP_PROC_EVENTS)
        .map_err(|e| format!("the map pin {PIN_MAP_PROC_EVENTS} failed: {e}"))?;
    vlog!("engine", "map pinned: {PIN_MAP_PROC_EVENTS}");
    bpf.take_map(MAP_TRACKED_INODES)
        .ok_or_else(|| format!("the probe object carries no '{MAP_TRACKED_INODES}' map"))?
        .pin(PIN_MAP_TRACKED_INODES)
        .map_err(|e| format!("the map pin {PIN_MAP_TRACKED_INODES} failed: {e}"))?;
    vlog!("engine", "map pinned: {PIN_MAP_TRACKED_INODES}");
    bpf.take_map(MAP_FILE_EVENTS)
        .ok_or_else(|| format!("the probe object carries no '{MAP_FILE_EVENTS}' map"))?
        .pin(PIN_MAP_FILE_EVENTS)
        .map_err(|e| format!("the map pin {PIN_MAP_FILE_EVENTS} failed: {e}"))?;
    vlog!("engine", "map pinned: {PIN_MAP_FILE_EVENTS}");
    bpf.take_map(MAP_OFFSETS)
        .ok_or_else(|| format!("the probe object carries no '{MAP_OFFSETS}' map"))?
        .pin(PIN_MAP_OFFSETS)
        .map_err(|e| format!("the map pin {PIN_MAP_OFFSETS} failed: {e}"))?;
    vlog!("engine", "map pinned: {PIN_MAP_OFFSETS}");
    bpf.take_map(MAP_DROP_CENSUS)
        .ok_or_else(|| format!("the probe object carries no '{MAP_DROP_CENSUS}' map"))?
        .pin(PIN_MAP_DROP_CENSUS)
        .map_err(|e| format!("the map pin {PIN_MAP_DROP_CENSUS} failed: {e}"))?;
    vlog!("engine", "map pinned: {PIN_MAP_DROP_CENSUS}");
    bpf.take_map(MAP_GENERATION)
        .ok_or_else(|| format!("the probe object carries no '{MAP_GENERATION}' map"))?
        .pin(PIN_MAP_GENERATION)
        .map_err(|e| format!("the map pin {PIN_MAP_GENERATION} failed: {e}"))?;
    vlog!("engine", "map pinned: {PIN_MAP_GENERATION}");
    // The stamp, the moment the map exists (night-frontier-Z2): boot
    // identity, object identity, attach instant - before any program
    // attaches, because the attach's own self-verification drain
    // rides the identity gate.
    super::estate::write_generation_stamp()?;
    vlog!("engine", "generation stamp written: this boot, this build");
    Ok(())
}

/// Write the BTF-parsed offsets through the pin, slot by slot in the
/// events.rs order. Thirteen slots from the struct walk - the walks
/// the four kprobes read, parsed from the host's own BTF - plus the
/// two anchor slots the unlink/rename lane's symbol walk resolved
/// (the vfs_unlink dentry argument index and the renamedata
/// old_dentry member offset), written through the OFF_SLOT_*
/// constants so a contract drift names its slot. Every write error
/// names the slot.
pub(super) fn write_offsets(
    offsets: &btf::ProbeOffsets,
    lane: &UnlinkLane,
    offpath: Option<&super::btf_offpath::OffPathOffsets>,
    iouring: Option<&super::btf_offpath::IouringLane>,
    identity: &btf::IdentityOffsets,
    membacked: Option<&super::btf_offpath::MemBackedLane>,
) -> Result<(), String> {
    vlog!(
        "engine",
        "writing the BTF-parsed offsets into the pinned map"
    );
    let map_data = MapData::from_pin(PIN_MAP_OFFSETS)
        .map_err(|e| format!("pinned offsets map {PIN_MAP_OFFSETS}: {e}"))?;
    let mut owned = Map::Array(map_data);
    let mut map: Array<_, u64> = Array::try_from(&mut owned)
        .map_err(|e| format!("the pinned offsets map is not an array: {e}"))?;
    // The write list IS the parsed array, slot = index: the contract
    // between btf.rs (the values, built in slot order) and events.rs
    // (the OFF_SLOT_* indices) is slot-alignment itself, so this loop
    // structurally cannot lag it. The night-hunter-3 lesson lives
    // here: night-improve-57 grew the contract by the four fd-walk
    // slots (8..11) but this writer kept an explicit eight-pair
    // table - the map stayed zero on the fd-walk slots, the probe
    // read task_struct+0 as its "files" pointer, and the census
    // blamed stage 4 on any host the probe was planted on, whatever
    // its kernel. A value the map cannot hold fails right here, by
    // slot, never silently.
    for (slot, value) in offsets.iter().enumerate() {
        map.set(slot as u32, value, 0)
            .map_err(|e| format!("offsets[{slot}] write failed: {e}"))?;
    }
    // The two anchor slots, by their own constants: the night-hunter-3
    // lesson names the failure class a lagging writer breeds, so the
    // non-contiguous tail is written by the same OFF_SLOT_* contract
    // the BPF readers use - a renumber names itself here.
    map.set(OFF_SLOT_UNLINK_DENTRY_ARG, &u64::from(lane.dentry_arg), 0)
        .map_err(|e| format!("offsets[{OFF_SLOT_UNLINK_DENTRY_ARG}] write failed: {e}"))?;
    map.set(OFF_SLOT_RENAMEDATA_OLD_DENTRY, &lane.old_dentry_offset, 0)
        .map_err(|e| format!("offsets[{OFF_SLOT_RENAMEDATA_OLD_DENTRY}] write failed: {e}"))?;
    // The off-path slots (night-frontier-Z7, D4), by their own
    // constants: the dirty-descent pair (15, 16) rides whenever the
    // parse vouched for it - the probe plants only when the anchor
    // ladder verified, and a zero slot the probe never reads is the
    // honest shape. The io_kiocb hop (17) rides only when the
    // io_uring lane verified; a named-down capability leaves the
    // slot zero, and its program is never attached.
    if let Some(offpath) = offpath {
        let dirty_pair = [
            (OFF_SLOT_PAGE_MAPPING, offpath.page_mapping),
            (OFF_SLOT_ADDR_SPACE_HOST, offpath.address_space_host),
        ];
        for (slot, value) in dirty_pair {
            let Some(value) = value else {
                return Err(format!(
                    "the off-path offsets parse lost the slot {slot} the anchor verified - refusing"
                ));
            };
            map.set(slot, &value, 0)
                .map_err(|e| format!("offsets[{slot}] write failed: {e}"))?;
        }
    }
    if let Some(lane) = iouring {
        map.set(OFF_SLOT_IO_KIOCB_FILE, &lane.io_kiocb_file_offset, 0)
            .map_err(|e| format!("offsets[{OFF_SLOT_IO_KIOCB_FILE}] write failed: {e}"))?;
    }
    // The identity-walk slots (night-frontier-Z8, D5), by their own
    // constants: the netns chain every record rides - written
    // EXPLICITLY, never by array position (the same law the anchors
    // and the off-path hops ride; the core array ride above covers
    // slots 0..12 and must never grow into this tail). Identity is
    // CORE: the parse already refused by name at the attach boundary,
    // so these slots always carry verified values when the estate
    // plants.
    for (slot, value) in [
        (
            super::events::OFF_SLOT_TASK_NSPROXY,
            identity[btf::IDENT_SLOT_TASK_NSPROXY],
        ),
        (
            super::events::OFF_SLOT_NSPROXY_NET,
            identity[btf::IDENT_SLOT_NSPROXY_NET],
        ),
        (
            super::events::OFF_SLOT_NET_NS,
            identity[btf::IDENT_SLOT_NET_NS],
        ),
        (
            super::events::OFF_SLOT_NS_COMMON_INUM,
            identity[btf::IDENT_SLOT_NS_COMMON_INUM],
        ),
    ] {
        map.set(slot, &value, 0)
            .map_err(|e| format!("offsets[{slot}] write failed: {e}"))?;
    }
    // The memory-backed walk slots (night-frontier-Z9, D6), by their
    // own constants: the vm_fault.page hop, the superblock's s_type
    // hop, and the filesystem-type name pointer the class gate reads
    // through. They ride only when the ladder verified; a named-down
    // capability leaves the slots zero, and its program is never
    // attached (the io_uring lane's own shape).
    if let Some(lane) = membacked {
        for (slot, value) in [
            (
                super::events::OFF_SLOT_VM_FAULT_PAGE,
                lane.vm_fault_page_offset,
            ),
            (
                super::events::OFF_SLOT_SUPER_BLOCK_S_TYPE,
                lane.sb_type_offset,
            ),
            (super::events::OFF_SLOT_FS_TYPE_NAME, lane.fst_name_offset),
        ] {
            map.set(slot, &value, 0)
                .map_err(|e| format!("offsets[{slot}] write failed: {e}"))?;
        }
    }
    Ok(())
}

/// Unplant ONE off-path capability (night-frontier-Z7, D4): the
/// record verification failed for it, so its pins come down - the
/// pinned links first (the detach law: an interrupted cleanup leaves
/// a DETACHED probe), then the program pins. The mask rewrite is the
/// caller's (it knows the final verdict set). Returns the number of
/// pins actually removed.
pub(super) fn unplant_offpath_capability(bit: u64) -> Result<usize, String> {
    let pins: &[&str] = match bit {
        super::estate::OFFPATH_BIT_DIRTY => &[PIN_PROG_DIRTY, PIN_LINK_DIRTY],
        super::estate::OFFPATH_BIT_SPLICE => &[PIN_PROG_SPLICE, PIN_LINK_SPLICE],
        super::estate::OFFPATH_BIT_IOURING => &[PIN_PROG_IOURING, PIN_LINK_IOURING],
        super::estate::OFFPATH_BIT_MEMBACKED => &[PIN_PROG_MEMBACKED, PIN_LINK_MEMBACKED],
        _ => return Err(format!("unknown off-path capability bit {bit}")),
    };
    let mut removed = 0usize;
    // Link first, then program - the detach law's own order.
    for pin in [pins[1], pins[0]] {
        if std::fs::remove_file(pin).is_ok() {
            removed += 1;
            vlog!("engine", "off-path capability unplanted: {pin}");
        }
    }
    if removed < 2 {
        return Err(format!(
            "the named-down unplant removed only {removed} of 2 pins - a \
             half-removed capability is the half state the estate refuses; \
             the attach cannot proceed (the fail protocol cleans everything)"
        ));
    }
    Ok(removed)
}

/// Plant ONE kprobe program (night-improve-3): load, attach at the
/// symbol's entry (offset 0), pin the link first, then the program.
/// The aya 0.16 chain is the tracepoint's: take_link, `TryInto<FdLink>`
/// (a kprobe attach is fd-backed), FdLink::pin - a PinnedLink with
/// no detach-on-drop. An unknown symbol fails HERE, loudly, by name:
/// that is the attach-time honesty a kprobe buys over a hardcoded
/// offset (a wrong offset reads garbage silently; a missing symbol
/// refuses the attach).
fn plant_kprobe(
    bpf: &mut Ebpf,
    program_name: &str,
    symbol: &str,
    prog_pin: &str,
    link_pin: &str,
) -> Result<(), String> {
    vlog!("engine", "attaching kprobe {symbol}");
    let program: &mut KProbe = bpf
        .program_mut(program_name)
        .ok_or_else(|| format!("the probe object carries no '{program_name}' program"))?
        .try_into()
        .map_err(|e| format!("'{program_name}' is not a kprobe program: {e}"))?;
    program
        .load()
        .map_err(|e| format!("the verifier refused the '{program_name}' program: {e}"))?;
    let link_id = program.attach(symbol, 0).map_err(|e| {
        format!("the {symbol} kprobe attach failed (is the symbol exported in this kernel?): {e}")
    })?;
    let link = program
        .take_link(link_id)
        .map_err(|e| format!("the attached link could not be taken: {e}"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(|e| format!("the {symbol} link is not fd-backed (cannot pin): {e}"))?;
    fd_link
        .pin(link_pin)
        .map_err(|e| format!("the link pin {link_pin} failed: {e}"))?;
    program
        .pin(prog_pin)
        .map_err(|e| format!("the program pin {prog_pin} failed: {e}"))?;
    Ok(())
}

/// Plant ONE tracepoint program: load, attach, pin the link first
/// (the pin is what keeps the probe alive after this process exits),
/// then the program. aya 0.16's chain: take_link hands the link over
/// from the program's registry (dropping the wrapper would detach
/// it), the TracePointLink converts into its FdLink backing (a
/// tracepoint attach is fd-backed), and FdLink::pin consumes the fd
/// link into a PinnedLink - which, unlike the wrapper, has NO
/// detach-on-drop: once pinned, the link stays attached for exactly
/// as long as the pin file exists. Unlinking the pin (detach's
/// clear_pins) is what detaches the probe.
fn plant_tracepoint(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    event: &str,
    prog_pin: &str,
    link_pin: &str,
) -> Result<(), String> {
    vlog!("engine", "attaching tracepoint {category}/{event}");
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| format!("the probe object carries no '{program_name}' program"))?
        .try_into()
        .map_err(|e| format!("'{program_name}' is not a tracepoint program: {e}"))?;
    program
        .load()
        .map_err(|e| format!("the verifier refused the '{program_name}' program: {e}"))?;
    let link_id = program
        .attach(category, event)
        .map_err(|e| format!("the {category}/{event} attach failed: {e}"))?;
    let link = program
        .take_link(link_id)
        .map_err(|e| format!("the attached link could not be taken: {e}"))?;
    let fd_link: FdLink = link
        .try_into()
        .map_err(|e| format!("the {category}/{event} link is not fd-backed (cannot pin): {e}"))?;
    fd_link
        .pin(link_pin)
        .map_err(|e| format!("the link pin {link_pin} failed: {e}"))?;
    program
        .pin(prog_pin)
        .map_err(|e| format!("the program pin {prog_pin} failed: {e}"))?;
    Ok(())
}
