// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
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
use super::{
    PIN_LINK, PIN_LINK_EXIT, PIN_LINK_OPEN, PIN_LINK_SOCK, PIN_LINK_WRITE, PIN_LINK_WRITEV,
    PIN_MAP_FILE_EVENTS, PIN_MAP_OFFSETS, PIN_MAP_PROC_EVENTS, PIN_MAP_SOCK_EVENTS, PIN_MAP_STATS,
    PIN_MAP_TRACKED_INODES, PIN_PROG, PIN_PROG_EXIT, PIN_PROG_OPEN, PIN_PROG_SOCK, PIN_PROG_WRITE,
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

/// The post-mortem exit program's name (night-improve-47) - the ELF
/// symbol in ebpf/src/exits.rs, the program whose records name the
/// processes that exited while nobody was asking.
pub(super) const EXIT_PROGRAM: &str = "sched_process_exit";

/// The post-mortem exit tracepoint's category and event.
pub(super) const EXIT_TRACEPOINT_CATEGORY: &str = "sched";
pub(super) const EXIT_TRACEPOINT_EVENT: &str = "sched_process_exit";

/// The tracked_inodes filter map name in the probe object.
pub(super) const MAP_TRACKED_INODES: &str = "tracked_inodes";

/// The file_events ring map name in the probe object.
pub(super) const MAP_FILE_EVENTS: &str = "file_events";

/// The proc_events ring map name in the probe object (night-improve-47
/// - the post-mortem exit stream).
pub(super) const MAP_PROC_EVENTS: &str = "proc_events";

/// The offsets config map name in the probe object.
pub(super) const MAP_OFFSETS: &str = "offsets";

/// The plant step: load all six programs, attach each to its
/// point, pin programs + links + maps. Any error names itself; the
/// caller's fail() protocol cleans up everything the attempt
/// planted - never a half-attached probe.
pub(super) fn plant(bpf: &mut Ebpf, writev_symbol: &str) -> Result<(), String> {
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
    plant_tracepoint(
        bpf,
        EXIT_PROGRAM,
        EXIT_TRACEPOINT_CATEGORY,
        EXIT_TRACEPOINT_EVENT,
        PIN_PROG_EXIT,
        PIN_LINK_EXIT,
    )?;
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
    Ok(())
}

/// Write the BTF-parsed offsets through the pin, slot by slot in the
/// events.rs order. Eight slots - the file walks the two kprobes
/// read, parsed from the host's own BTF. Every write error names
/// the slot.
pub(super) fn write_offsets(offsets: &btf::ProbeOffsets) -> Result<(), String> {
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
        map.set(slot as u32, *value, 0)
            .map_err(|e| format!("offsets[{slot}] write failed: {e}"))?;
    }
    Ok(())
}

/// Plant ONE kprobe program (night-improve-3): load, attach at the
/// symbol's entry (offset 0), pin the link first, then the program.
/// The aya 0.14 chain is the tracepoint's: take_link, `TryInto<FdLink>`
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
/// then the program. aya 0.14's chain: take_link hands the link over
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
