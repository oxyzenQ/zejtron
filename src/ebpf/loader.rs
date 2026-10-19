// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The tap loader - attach and detach (night-improve-1, the
//! zylaxion orchestration lineage; night-improve-2 grows the chain
//! to two tracepoints and a ring buffer; night-improve-3 grows it
//! to four programs and five maps, and teaches attach to verify the
//! struct offsets against the host's own BTF before planting;
//! night-improve-4 grows it to six programs and six maps - the two
//! sched_process lifecycle tracepoints and the proc_events ring -
//! and widens the BTF-verified offset set to the tracepoint
//! contexts and the task_struct pair).
//!
//! This is the privileged one-shot. `doctor --attach` loads the
//! embedded tap object, loads ALL SIX programs (phase 1's
//! sched/sched_process_exec counter + exec event, phase 2's
//! sock/inet_sock_set_state socket-event tap, phase 3's
//! vfs_open/vfs_write file taps, night-improve-4's
//! sched/sched_process_fork and sched/sched_process_exit lifecycle
//! taps), attaches each, and pins
//! EVERYTHING to bpffs - programs, links, maps - then writes the
//! BTF-parsed struct offsets into the `offsets` map, and the
//! process may exit, because the pinned links keep the taps alive
//! and the pinned maps keep the counters, the rings, the filter
//! map, and the offsets alive. After `attach` returns, nothing of
//! zejtron is resident in userspace. `doctor --detach` unpins
//! everything; the link pins go first so an interrupted cleanup
//! leaves a DETACHED tap, never a half-attached one.
//!
//! Idempotence and self-heal (the zylaxion contract): a complete pin
//! set is already-attached (a success shape - running attach twice is
//! fine); a partial pin set (a crashed attach, a manual rm) is
//! cleaned and replanted. A failed attach cleans every pin it planted
//! - no half state, ever.
//!
//! Every refusal names its reason: the kernel floor, the lockdown
//! mode, the missing capabilities, the unverifiable offsets. No
//! silent fallback.

use aya::Ebpf;
use aya::maps::Array;
use aya::maps::Map;
use aya::maps::MapData;
use aya::programs::KProbe;
use aya::programs::TracePoint;
use aya::programs::links::FdLink;

use super::btf;
use super::embedded;
use super::{
    LaneVerdict, PIN_DIR, PIN_LINK, PIN_LINK_EXIT, PIN_LINK_FORK, PIN_LINK_OPEN, PIN_LINK_SOCK,
    PIN_LINK_WRITE, PIN_MAP_FILE_EVENTS, PIN_MAP_OFFSETS, PIN_MAP_PROC_EVENTS, PIN_MAP_SOCK_EVENTS,
    PIN_MAP_STATS, PIN_MAP_TRACKED_INODES, PIN_PROG, PIN_PROG_EXIT, PIN_PROG_FORK, PIN_PROG_OPEN,
    PIN_PROG_SOCK, PIN_PROG_WRITE, any_pin_present, lane_verdict, probe_kernel,
};

use super::events::{
    OFF_SLOT_DENTRY_D_INODE, OFF_SLOT_FILE_F_INODE, OFF_SLOT_FILE_F_PATH, OFF_SLOT_INODE_I_INO,
    OFF_SLOT_PATH_DENTRY, OFF_SLOT_PATH_MNT, OFF_SLOT_SUPER_BLOCK_S_DEV, OFF_SLOT_TASK_REAL_PARENT,
    OFF_SLOT_TASK_TGID, OFF_SLOT_TP_EXIT_PID, OFF_SLOT_TP_FORK_CHILD_PID,
    OFF_SLOT_TP_FORK_PARENT_PID, OFF_SLOT_VFSMOUNT_MNT_SB,
};

/// The embedded pure-Rust tap object (night-improve-1): the aya-ebpf
/// ELF staged into OUT_DIR by build.rs. It rides inside the
/// AlignedElf wrapper (the NIGHT-hunt-30 lesson - see embedded.rs)
/// so aya's ELF parser reads 8-aligned bytes whatever the linker
/// decided.
static TAP_ELF: &[u8] =
    &embedded::AlignedElf::new(*include_bytes!(concat!(env!("OUT_DIR"), "/zejtron-ebpf.o"))).bytes;

/// The program name in the tap object (the ELF symbol - the fn name
/// in ebpf/src/main.rs) - phase 1's exec counter.
const PROGRAM: &str = "sched_process_exec";

/// The tracepoint category (the attach-time half of the attach point;
/// the section name in the object carries the event half).
const TRACEPOINT_CATEGORY: &str = "sched";

/// The tracepoint event name.
const TRACEPOINT_EVENT: &str = "sched_process_exec";

/// The stats map name in the tap object (the \#\[map\] name in
/// ebpf/src/main.rs - the userspace mirror of the same contract).
const MAP_STATS: &str = "stats";

/// The socket-state program's name (night-improve-2) - phase 2's
/// inet_sock_set_state tap.
const SOCK_PROGRAM: &str = "inet_sock_set_state";

/// The socket-state tracepoint's category and event.
const SOCK_TRACEPOINT_CATEGORY: &str = "sock";
const SOCK_TRACEPOINT_EVENT: &str = "inet_sock_set_state";

/// The sock_events ring map name in the tap object.
const MAP_SOCK_EVENTS: &str = "sock_events";

/// The file-open program's name (the ELF symbol - the fn name in
/// ebpf/src/main.rs). The ATTACH symbol is a separate constant -
/// the program is role-named, the symbol is kernel-named, and the
/// two meet only here (night-improve-3).
const OPEN_PROGRAM: &str = "open_tap";

/// The kernel symbol the open tap attaches to (entry probe, offset
/// 0).
const OPEN_SYMBOL: &str = "vfs_open";

/// The file-write program's name.
const WRITE_PROGRAM: &str = "write_tap";

/// The kernel symbol the write tap attaches to.
const WRITE_SYMBOL: &str = "vfs_write";

/// The fork lifecycle program's name (night-improve-4, proctap.rs).
const FORK_PROGRAM: &str = "sched_process_fork";

/// The fork tracepoint's category and event.
const FORK_TRACEPOINT_CATEGORY: &str = "sched";
const FORK_TRACEPOINT_EVENT: &str = "sched_process_fork";

/// The exit lifecycle program's name.
const EXIT_PROGRAM: &str = "sched_process_exit";

/// The exit tracepoint's category and event.
const EXIT_TRACEPOINT_CATEGORY: &str = "sched";
const EXIT_TRACEPOINT_EVENT: &str = "sched_process_exit";

/// The tracked_inodes filter map name in the tap object.
const MAP_TRACKED_INODES: &str = "tracked_inodes";

/// The file_events ring map name in the tap object.
const MAP_FILE_EVENTS: &str = "file_events";

/// The proc_events ring map name in the tap object (night-improve-4).
const MAP_PROC_EVENTS: &str = "proc_events";

/// The offsets config map name in the tap object.
const MAP_OFFSETS: &str = "offsets";

/// Attach the tap: the privileged one-shot.
///
/// Returns a human-readable summary the doctor prints verbatim; every
/// failure is an error string that names its reason, and no failure
/// leaves a partial pin set.
pub fn attach() -> Result<String, String> {
    // 1. The gate: the same probe and the same verdict the doctor's
    //    [eBPF] section reads - one truth, no drift between surfaces.
    //    The LiveAttached shape is the idempotence case handled below.
    let facts = probe_kernel();
    match lane_verdict(&facts) {
        LaneVerdict::Dormant => {
            return Err(
                "this binary was built without the ebpf feature - rebuild with \
                 --features ebpf to attach the tap"
                    .to_owned(),
            );
        }
        LaneVerdict::Snapshot(reason) => {
            return Err(format!(
                "attach refused: {reason}. The eBPF lane needs kernel >= {} (probed: {}), \
                 lockdown inactive, and CAP_BPF + CAP_PERFMON in the effective set \
                 ({}); re-run under sudo on a capable host",
                super::floor_label(),
                facts.release_label(),
                facts.caps_label()
            ));
        }
        LaneVerdict::LiveAttached => {
            // Idempotence: a complete pin set IS attached. Read the
            // live counter for the honest report.
            let count = super::readback::read_events_counter()
                .map(|n| format!("N={n}"))
                .unwrap_or_else(|e| format!("counter unreadable ({e})"));
            return Ok(format!(
                "tap is already attached - nothing to do (all pins present; \
                 doctor --detach removes it); events since attach: {count}"
            ));
        }
        LaneVerdict::Live => {
            // A partial pin set rides the same path: the pre-clean
            // below heals it.
        }
    }

    // 1.5. The offsets verification (night-improve-3): parse the
    //      struct offsets from the host's own BTF BEFORE anything is
    //      planted. A wrong hardcoded offset would read garbage
    //      silently - the loudest possible refusal is the only
    //      honest alternative, and it happens here, with zero pins
    //      touched.
    let offsets = btf::parse_probe_offsets().map_err(|e| {
        format!(
            "attach refused: cannot verify the struct offsets from BTF \
             ({e}). The file taps read kernel structs at offsets taken \
             from /sys/kernel/btf/vmlinux - a build without BTF cannot \
             verify them, and a guessed offset goes blind silently. \
             No tap is planted"
        )
    })?;

    // 2. Self-heal: a partial pin set (a crashed attach, a manual rm)
    //    is cleaned before replanting; a stale pin directory (a prior
    //    mkdir that failed before planting) is removed the same way.
    //    Foreign entries are NOT ours to remove - the honest refusal.
    if any_pin_present() {
        clear_pins();
    }
    match std::fs::remove_dir(PIN_DIR) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
            return Err(format!(
                "{PIN_DIR} holds entries zejtron did not create - remove them by \
                 hand and re-run doctor --attach"
            ));
        }
        Err(e) => {
            return Err(format!(
                "{PIN_DIR} could not be removed (is bpffs mounted?): {e}"
            ));
        }
    }

    // 3. The pin directory must exist before anything pins into it.
    if let Err(e) = std::fs::create_dir(PIN_DIR) {
        return Err(format!("{PIN_DIR} (is bpffs mounted?): {e}"));
    }

    // 4. The alignment preflight (the AlignedElf contract):
    //    structurally impossible now, kept so a regression diagnoses
    //    in one line.
    if let Some(violation) = embedded::alignment_violation(TAP_ELF, "zejtron-ebpf") {
        return Err(violation);
    }

    // 6. Load the tracepoint programs and the kprobes, attach each
    //    to its point, pin everything. Any failure past this point
    //    must clean the pins it planted - the fail() protocol.
    let mut bpf =
        Ebpf::load(TAP_ELF).map_err(|e| fail(format!("the tap object failed to load: {e}")))?;

    let attach_result = plant(&mut bpf);
    match attach_result {
        Ok(()) => {
            // 6.5. Write the BTF-parsed offsets through the pin - the
            //     last planted piece, and the one the whole file lane
            //     rides on. A failure here cleans everything (the
            //     fail protocol); a tap whose offsets cannot be
            //     written is a tap that must not stay planted.
            if let Err(e) = write_offsets(&offsets) {
                return Err(fail(e));
            }
            // 7. The fresh counter read: the verification battery's
            //    N=0 shape. A freshly attached counter reads zero
            //    (the kernel zeroes new maps); the readback proves
            //    the whole chain - the loader CAN read what the
            //    kernel holds.
            let count = super::readback::read_events_counter()
                .map(|n| format!("N={n}"))
                .unwrap_or_else(|e| format!("counter unreadable ({e})"));
            Ok(format!(
                "tap attached: tracepoints sched/sched_process_exec + \
                 sock/inet_sock_set_state + sched/sched_process_fork + \
                 sched/sched_process_exit, kprobes vfs_open + vfs_write, \
                 offsets verified from this host's BTF, counter live; events \
                 since attach: {count}\npins: {PIN_DIR} (tap, tap_link, stats, \
                 sock_tap, sock_tap_link, sock_events, open_tap, open_tap_link, \
                 write_tap, write_tap_link, tracked_inodes, file_events, offsets, \
                 fork_tap, fork_tap_link, exit_tap, exit_tap_link, proc_events)"
            ))
        }
        Err(e) => Err(fail(e)),
    }
}

/// The plant step: load all six programs, attach each to its
/// point, pin programs + links + maps. Any error names itself; the
/// caller's fail() protocol cleans up everything the attempt
/// planted - never a half-attached tap.
fn plant(bpf: &mut Ebpf) -> Result<(), String> {
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
    plant_kprobe(
        bpf,
        WRITE_PROGRAM,
        WRITE_SYMBOL,
        PIN_PROG_WRITE,
        PIN_LINK_WRITE,
    )?;
    plant_tracepoint(
        bpf,
        FORK_PROGRAM,
        FORK_TRACEPOINT_CATEGORY,
        FORK_TRACEPOINT_EVENT,
        PIN_PROG_FORK,
        PIN_LINK_FORK,
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
        .ok_or_else(|| format!("the tap object carries no '{MAP_STATS}' map"))?
        .pin(PIN_MAP_STATS)
        .map_err(|e| format!("the map pin {PIN_MAP_STATS} failed: {e}"))?;
    bpf.take_map(MAP_SOCK_EVENTS)
        .ok_or_else(|| format!("the tap object carries no '{MAP_SOCK_EVENTS}' map"))?
        .pin(PIN_MAP_SOCK_EVENTS)
        .map_err(|e| format!("the map pin {PIN_MAP_SOCK_EVENTS} failed: {e}"))?;
    bpf.take_map(MAP_TRACKED_INODES)
        .ok_or_else(|| format!("the tap object carries no '{MAP_TRACKED_INODES}' map"))?
        .pin(PIN_MAP_TRACKED_INODES)
        .map_err(|e| format!("the map pin {PIN_MAP_TRACKED_INODES} failed: {e}"))?;
    bpf.take_map(MAP_FILE_EVENTS)
        .ok_or_else(|| format!("the tap object carries no '{MAP_FILE_EVENTS}' map"))?
        .pin(PIN_MAP_FILE_EVENTS)
        .map_err(|e| format!("the map pin {PIN_MAP_FILE_EVENTS} failed: {e}"))?;
    bpf.take_map(MAP_OFFSETS)
        .ok_or_else(|| format!("the tap object carries no '{MAP_OFFSETS}' map"))?
        .pin(PIN_MAP_OFFSETS)
        .map_err(|e| format!("the map pin {PIN_MAP_OFFSETS} failed: {e}"))?;
    bpf.take_map(MAP_PROC_EVENTS)
        .ok_or_else(|| format!("the tap object carries no '{MAP_PROC_EVENTS}' map"))?
        .pin(PIN_MAP_PROC_EVENTS)
        .map_err(|e| format!("the map pin {PIN_MAP_PROC_EVENTS} failed: {e}"))?;
    Ok(())
}

/// Write the BTF-parsed offsets through the pin, slot by slot in the
/// events.rs order. Thirteen slots since night-improve-4: the eight
/// file-walk slots, then the fork/exit tracepoint context offsets
/// and the task_struct pair the exec/exit ppid walk dereferences.
/// Every write error names the slot.
fn write_offsets(offsets: &btf::ProbeOffsets) -> Result<(), String> {
    let map_data = MapData::from_pin(PIN_MAP_OFFSETS)
        .map_err(|e| format!("pinned offsets map {PIN_MAP_OFFSETS}: {e}"))?;
    let mut owned = Map::Array(map_data);
    let mut map: Array<_, u64> = Array::try_from(&mut owned)
        .map_err(|e| format!("the pinned offsets map is not an array: {e}"))?;
    let writes: [(u32, u64); 13] = [
        (OFF_SLOT_DENTRY_D_INODE, offsets[0]),
        (OFF_SLOT_INODE_I_INO, offsets[1]),
        (OFF_SLOT_FILE_F_PATH, offsets[2]),
        (OFF_SLOT_FILE_F_INODE, offsets[3]),
        (OFF_SLOT_VFSMOUNT_MNT_SB, offsets[4]),
        (OFF_SLOT_SUPER_BLOCK_S_DEV, offsets[5]),
        (OFF_SLOT_PATH_MNT, offsets[6]),
        (OFF_SLOT_PATH_DENTRY, offsets[7]),
        (OFF_SLOT_TP_FORK_PARENT_PID, offsets[8]),
        (OFF_SLOT_TP_FORK_CHILD_PID, offsets[9]),
        (OFF_SLOT_TP_EXIT_PID, offsets[10]),
        (OFF_SLOT_TASK_REAL_PARENT, offsets[11]),
        (OFF_SLOT_TASK_TGID, offsets[12]),
    ];
    for (slot, value) in writes {
        map.set(slot, value, 0)
            .map_err(|e| format!("offsets[{slot}] write failed: {e}"))?;
    }
    Ok(())
}

/// Plant ONE kprobe program (night-improve-3): load, attach at the
/// symbol's entry (offset 0), pin the link first, then the program.
/// The aya 0.14 chain is the tracepoint's: take_link, TryInto<FdLink>
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
    let program: &mut KProbe = bpf
        .program_mut(program_name)
        .ok_or_else(|| format!("the tap object carries no '{program_name}' program"))?
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
/// (the pin is what keeps the tap alive after this process exits),
/// then the program. aya 0.14's chain: take_link hands the link over
/// from the program's registry (dropping the wrapper would detach
/// it), the TracePointLink converts into its FdLink backing (a
/// tracepoint attach is fd-backed), and FdLink::pin consumes the fd
/// link into a PinnedLink - which, unlike the wrapper, has NO
/// detach-on-drop: once pinned, the link stays attached for exactly
/// as long as the pin file exists. Unlinking the pin (detach's
/// clear_pins) is what detaches the tap.
fn plant_tracepoint(
    bpf: &mut Ebpf,
    program_name: &str,
    category: &str,
    event: &str,
    prog_pin: &str,
    link_pin: &str,
) -> Result<(), String> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .ok_or_else(|| format!("the tap object carries no '{program_name}' program"))?
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

/// The failure protocol: clean every pin this attempt planted (never
/// half-attached), then hand the original error back. Returns the
/// error text unchanged so the caller wraps it with the cleanup
/// report.
fn fail(error: String) -> String {
    let removed = clear_pins();
    let _ = std::fs::remove_dir(PIN_DIR);
    format!(
        "{error} (cleaned {} pin(s) - nothing of zejtron remains half-attached)",
        removed
    )
}

/// Unpin everything (best-effort, idempotent). Link first - an
/// interrupted cleanup leaves a DETACHED tap. Returns the number of
/// pins actually removed.
fn clear_pins() -> usize {
    super::ALL_PINS
        .iter()
        .filter(|p| std::fs::remove_file(p).is_ok())
        .count()
}

/// Detach the tap: unpin everything, idempotent. If no pins exist,
/// the honest "nothing to detach" (exit 0 through the doctor's Ok).
pub fn detach() -> Result<String, String> {
    if !any_pin_present() && !Path::new(PIN_DIR).exists() {
        return Ok("nothing to detach - no pins present".to_owned());
    }
    let removed = clear_pins();
    match std::fs::remove_dir(PIN_DIR) {
        // The directory is gone (or never was): the clean end state,
        // whichever way it was reached.
        Ok(()) => {}
        // A failed remove that left nothing behind is still clean: the
        // guard is the state, not the call.
        Err(_) if !Path::new(PIN_DIR).exists() => {}
        Err(e) => {
            return Err(format!(
                "{PIN_DIR} could not be removed (foreign entries? {e}) - remove \
                 them by hand"
            ));
        }
    }
    Ok(format!(
        "tap detached: unpinned {removed} pin(s); {PIN_DIR} is gone"
    ))
}

use std::path::Path;

#[cfg(test)]
#[path = "../../test/ebpf/loader_tests.rs"]
mod tests;
