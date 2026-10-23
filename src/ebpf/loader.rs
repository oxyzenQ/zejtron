// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The probe loader - attach and detach (night-improve-1, the
//! zylaxion orchestration lineage; night-improve-2 grows the chain
//! to two tracepoints and a ring buffer; night-improve-3 grows it
//! to four programs and five maps, and teaches attach to verify the
//! struct offsets against the host's own BTF before planting;
//! night-improve-34 shrinks it back to four programs and five maps -
//! the two sched_process lifecycle tracepoints and their ring went
//! with the lifecycle stream surface's removal, and the offsets
//! contract shrinks to the eight file-walk slots; night-improve-42
//! grows it to five programs and the same five maps - the writev
//! probe, whose attach symbol is verified from the host's own BTF
//! before anything is planted, the argument-position sibling of
//! the offsets law; night-improve-47 grows it to six programs and
//! six maps - the post-mortem exit probe (ebpf/src/exits.rs) and its
//! proc_events ring, the drain the doctor's ram symptom reads).
//!
//! This is the privileged one-shot. `doctor --attach` loads the
//! embedded probe object, loads ALL SIX programs (phase 1's
//! sched/sched_process_exec counter, phase 2's
//! sock/inet_sock_set_state socket-event probe, phase 3's
//! vfs_open/vfs_write file probes, night-improve-42's vfs_writev
//! vectorized-write probe, night-improve-47's
//! sched/sched_process_exit post-mortem exit probe), attaches each,
//! and pins
//! EVERYTHING to bpffs - programs, links, maps - then writes the
//! BTF-parsed struct offsets into the `offsets` map, and the
//! process may exit, because the pinned links keep the probes alive
//! and the pinned maps keep the counters, the rings, the filter
//! map, and the offsets alive. After `attach` returns, nothing of
//! zejtron is resident in userspace. `doctor --detach` unpins
//! everything; the link pins go first so an interrupted cleanup
//! leaves a DETACHED probe, never a half-attached one.
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
    LaneVerdict, PIN_DIR, PIN_LINK, PIN_LINK_EXIT, PIN_LINK_OPEN, PIN_LINK_SOCK, PIN_LINK_WRITE,
    PIN_LINK_WRITEV, PIN_MAP_FILE_EVENTS, PIN_MAP_OFFSETS, PIN_MAP_PROC_EVENTS,
    PIN_MAP_SOCK_EVENTS, PIN_MAP_STATS, PIN_MAP_TRACKED_INODES, PIN_PROG, PIN_PROG_EXIT,
    PIN_PROG_OPEN, PIN_PROG_SOCK, PIN_PROG_WRITE, PIN_PROG_WRITEV, any_pin_present, lane_verdict,
    probe_kernel,
};

use super::events::{
    OFF_SLOT_DENTRY_D_INODE, OFF_SLOT_FILE_F_INODE, OFF_SLOT_FILE_F_PATH, OFF_SLOT_INODE_I_INO,
    OFF_SLOT_PATH_DENTRY, OFF_SLOT_PATH_MNT, OFF_SLOT_SUPER_BLOCK_S_DEV, OFF_SLOT_VFSMOUNT_MNT_SB,
};

/// The embedded pure-Rust probe object (night-improve-1): the aya-ebpf
/// ELF staged into OUT_DIR by build.rs. It rides inside the
/// AlignedElf wrapper (the NIGHT-hunt-30 lesson - see embedded.rs)
/// so aya's ELF parser reads 8-aligned bytes whatever the linker
/// decided.
static PROBE_ELF: &[u8] =
    &embedded::AlignedElf::new(*include_bytes!(concat!(env!("OUT_DIR"), "/zejtron-ebpf.o"))).bytes;

/// The program name in the probe object (the ELF symbol - the fn name
/// in ebpf/src/main.rs) - phase 1's exec counter.
const PROGRAM: &str = "sched_process_exec";

/// The tracepoint category (the attach-time half of the attach point;
/// the section name in the object carries the event half).
const TRACEPOINT_CATEGORY: &str = "sched";

/// The tracepoint event name.
const TRACEPOINT_EVENT: &str = "sched_process_exec";

/// The stats map name in the probe object (the \#\[map\] name in
/// ebpf/src/main.rs - the userspace mirror of the same contract).
const MAP_STATS: &str = "stats";

/// The socket-state program's name (night-improve-2) - phase 2's
/// inet_sock_set_state probe.
const SOCK_PROGRAM: &str = "inet_sock_set_state";

/// The socket-state tracepoint's category and event.
const SOCK_TRACEPOINT_CATEGORY: &str = "sock";
const SOCK_TRACEPOINT_EVENT: &str = "inet_sock_set_state";

/// The sock_events ring map name in the probe object.
const MAP_SOCK_EVENTS: &str = "sock_events";

/// The file-open program's name (the ELF symbol - the fn name in
/// ebpf/src/main.rs). The ATTACH symbol is a separate constant -
/// the program is role-named, the symbol is kernel-named, and the
/// two meet only here (night-improve-3).
const OPEN_PROGRAM: &str = "open_probe";

/// The kernel symbol the open probe attaches to (entry probe, offset
/// 0).
const OPEN_SYMBOL: &str = "vfs_open";

/// The file-write program's name.
const WRITE_PROGRAM: &str = "write_probe";

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
const WRITE_TRACEPOINT_CATEGORY: &str = "raw_syscalls";
const WRITE_TRACEPOINT_EVENT: &str = "sys_enter";

/// The vectorized-write program's name (night-improve-42) - the ELF
/// symbol in ebpf/src/main.rs. The ATTACH symbol is not a constant:
/// it is verified from the host's own BTF at attach time
/// (vfs_writev preferred, do_iter_write the verified fallback), the
/// argument-position sibling of the offsets law - a symbol whose
/// first argument the host cannot vouch for is a guess, and a
/// guessed argument position reads garbage silently.
const WRITEV_PROGRAM: &str = "writev_probe";

/// The post-mortem exit program's name (night-improve-47) - the ELF
/// symbol in ebpf/src/exits.rs, the program whose records name the
/// processes that exited while nobody was asking.
const EXIT_PROGRAM: &str = "sched_process_exit";

/// The post-mortem exit tracepoint's category and event.
const EXIT_TRACEPOINT_CATEGORY: &str = "sched";
const EXIT_TRACEPOINT_EVENT: &str = "sched_process_exit";

/// The tracked_inodes filter map name in the probe object.
const MAP_TRACKED_INODES: &str = "tracked_inodes";

/// The file_events ring map name in the probe object.
const MAP_FILE_EVENTS: &str = "file_events";

/// The proc_events ring map name in the probe object (night-improve-47
/// - the post-mortem exit stream).
const MAP_PROC_EVENTS: &str = "proc_events";

/// The offsets config map name in the probe object.
const MAP_OFFSETS: &str = "offsets";

/// Attach the probe: the privileged one-shot.
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
                "probe is already attached - nothing to do (all pins present; \
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
             ({e}). The file probes read kernel structs at offsets taken \
             from /sys/kernel/btf/vmlinux - a build without BTF cannot \
             verify them, and a guessed offset goes blind silently. \
             No probe is planted"
        )
    })?;

    // 1.6. The writev symbol verification (night-improve-42): the
    //      vectorized-write probe probes a symbol whose first argument
    //      must be a pointer to struct file. The symbol and its
    //      argument shape are read from the same host BTF, before
    //      anything is planted - the argument-position sibling of
    //      the offsets law above. A kernel that carries neither
    //      vfs_writev nor do_iter_write under a verifiable shape
    //      refuses here, by name, with zero pins touched.
    let writev_symbol = btf::verify_writev_symbol().map_err(|e| {
        format!(
            "attach refused: cannot verify the vectorized-write probe's attach \
             point from BTF ({e}). The writev probe probes vfs_writev (fallback \
             do_iter_write) at its first argument, and the host's BTF must \
             vouch for that argument being a pointer to struct file - a \
             guessed argument position reads garbage silently. No probe is \
             planted"
        )
    })?;

    // 2. Self-heal: a partial pin set (a crashed attach, a manual rm)
    //    is cleaned before replanting; a stale pin directory (a prior
    //    mkdir that failed before planting) is removed the same way.
    //    Foreign entries refuse the attach - the sweep belongs to
    //    --detach (the sledgehammer); attach never deletes what it
    //    did not create.
    if any_pin_present() {
        clear_pins();
    }
    match std::fs::remove_dir(PIN_DIR) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) if e.kind() == std::io::ErrorKind::DirectoryNotEmpty => {
            return Err(format!(
                "{PIN_DIR} holds entries zejtron did not create - run \
                 doctor --detach (the sledgehammer: it sweeps the whole \
                 pin estate) and re-run doctor --attach"
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
    if let Some(violation) = embedded::alignment_violation(PROBE_ELF, "zejtron-ebpf") {
        return Err(violation);
    }

    // 6. Load the tracepoint programs and the kprobes, attach each
    //    to its point, pin everything. Any failure past this point
    //    must clean the pins it planted - the fail() protocol.
    let mut bpf =
        Ebpf::load(PROBE_ELF).map_err(|e| fail(format!("the probe object failed to load: {e}")))?;

    let attach_result = plant(&mut bpf, writev_symbol);
    match attach_result {
        Ok(()) => {
            // 6.5. Write the BTF-parsed offsets through the pin - the
            //     last planted piece, and the one the whole file lane
            //     rides on. A failure here cleans everything (the
            //     fail protocol); a probe whose offsets cannot be
            //     written is a probe that must not stay planted.
            if let Err(e) = write_offsets(&offsets) {
                return Err(fail(e));
            }
            // 6.6. The write probe's own verification (night-improve-59):
            //     record-verify or refuse. The offsets law and the
            //     writev symbol law verify the PARSE; this verifies
            //     the RECORD - a scratch file is tracked, one write
            //     is pushed through the probe, and the drained ring
            //     must carry the scratch's own (inode, device, op).
            //     A silent anchor - the failure class that took the
            //     vfs_write kprobe on the -O3 distro builds and the
            //     stub kprobe everywhere - cannot survive this
            //     door: the attach refuses and the fail protocol
            //     takes the pins down.
            if let Err(e) = super::verify_write::verify_write_probe() {
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
                "probes attached: tracepoints sched/sched_process_exec + \
                 sock/inet_sock_set_state + sched/sched_process_exit (the post-mortem \
                 exit probe) + raw_syscalls/sys_enter (the write probe, verified by its \
                 own recorded write), kprobes vfs_open + {writev_symbol} \
                 (the vectorized-write probe, verified from this host's BTF), offsets \
                 verified from this host's BTF, counter live; \
                 events since attach: {count}\npins: {PIN_DIR} (probe, probe_link, stats, \
                 sock_probe, sock_probe_link, sock_events, exit_probe, exit_probe_link, \
                 proc_events, open_probe, open_probe_link, \
                 write_probe, write_probe_link, writev_probe, writev_probe_link, \
                 tracked_inodes, file_events, offsets)"
            ))
        }
        Err(e) => Err(fail(e)),
    }
}

/// The plant step: load all six programs, attach each to its
/// point, pin programs + links + maps. Any error names itself; the
/// caller's fail() protocol cleans up everything the attempt
/// planted - never a half-attached probe.
fn plant(bpf: &mut Ebpf, writev_symbol: &str) -> Result<(), String> {
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
    bpf.take_map(MAP_SOCK_EVENTS)
        .ok_or_else(|| format!("the probe object carries no '{MAP_SOCK_EVENTS}' map"))?
        .pin(PIN_MAP_SOCK_EVENTS)
        .map_err(|e| format!("the map pin {PIN_MAP_SOCK_EVENTS} failed: {e}"))?;
    bpf.take_map(MAP_PROC_EVENTS)
        .ok_or_else(|| format!("the probe object carries no '{MAP_PROC_EVENTS}' map"))?
        .pin(PIN_MAP_PROC_EVENTS)
        .map_err(|e| format!("the map pin {PIN_MAP_PROC_EVENTS} failed: {e}"))?;
    bpf.take_map(MAP_TRACKED_INODES)
        .ok_or_else(|| format!("the probe object carries no '{MAP_TRACKED_INODES}' map"))?
        .pin(PIN_MAP_TRACKED_INODES)
        .map_err(|e| format!("the map pin {PIN_MAP_TRACKED_INODES} failed: {e}"))?;
    bpf.take_map(MAP_FILE_EVENTS)
        .ok_or_else(|| format!("the probe object carries no '{MAP_FILE_EVENTS}' map"))?
        .pin(PIN_MAP_FILE_EVENTS)
        .map_err(|e| format!("the map pin {PIN_MAP_FILE_EVENTS} failed: {e}"))?;
    bpf.take_map(MAP_OFFSETS)
        .ok_or_else(|| format!("the probe object carries no '{MAP_OFFSETS}' map"))?
        .pin(PIN_MAP_OFFSETS)
        .map_err(|e| format!("the map pin {PIN_MAP_OFFSETS} failed: {e}"))?;
    Ok(())
}

/// Write the BTF-parsed offsets through the pin, slot by slot in the
/// events.rs order. Eight slots - the file walks the two kprobes
/// read, parsed from the host's own BTF. Every write error names
/// the slot.
fn write_offsets(offsets: &btf::ProbeOffsets) -> Result<(), String> {
    let map_data = MapData::from_pin(PIN_MAP_OFFSETS)
        .map_err(|e| format!("pinned offsets map {PIN_MAP_OFFSETS}: {e}"))?;
    let mut owned = Map::Array(map_data);
    let mut map: Array<_, u64> = Array::try_from(&mut owned)
        .map_err(|e| format!("the pinned offsets map is not an array: {e}"))?;
    let writes: [(u32, u64); 8] = [
        (OFF_SLOT_DENTRY_D_INODE, offsets[0]),
        (OFF_SLOT_INODE_I_INO, offsets[1]),
        (OFF_SLOT_FILE_F_PATH, offsets[2]),
        (OFF_SLOT_FILE_F_INODE, offsets[3]),
        (OFF_SLOT_VFSMOUNT_MNT_SB, offsets[4]),
        (OFF_SLOT_SUPER_BLOCK_S_DEV, offsets[5]),
        (OFF_SLOT_PATH_MNT, offsets[6]),
        (OFF_SLOT_PATH_DENTRY, offsets[7]),
    ];
    for (slot, value) in writes {
        map.set(slot, value, 0)
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
/// interrupted cleanup leaves a DETACHED probe. Returns the number of
/// pins actually removed.
fn clear_pins() -> usize {
    super::ALL_PINS
        .iter()
        .filter(|p| std::fs::remove_file(p).is_ok())
        .count()
}

/// Detach the probe: unpin everything, then the sledgehammer - sweep
/// whatever else the pin directory holds (legacy pins from earlier
/// versions, foreign leftovers, partial states) and remove the
/// directory itself, so the next attach always starts fresh. The one
/// button that returns the estate to bare bpffs; no other tool or
/// manual rm is ever needed. Idempotent: if no pins exist and the
/// directory is gone, the honest "nothing to detach" (exit 0 through
/// the doctor's Ok).
pub fn detach() -> Result<String, String> {
    if !any_pin_present() && !Path::new(PIN_DIR).exists() {
        return Ok("nothing to detach - no pins present".to_owned());
    }
    let removed = clear_pins();
    // The sledgehammer step: our own pins are gone; count whatever is
    // left (legacy pin names from earlier versions, foreign files),
    // then remove the directory whole. PIN_DIR is zejtron's own
    // constant path - the one directory this tool owns - so nothing
    // outside zejtron's estate can be swept by it.
    let swept = std::fs::read_dir(PIN_DIR)
        .map(|entries| entries.filter_map(|entry| entry.ok()).count())
        .unwrap_or(0);
    match std::fs::remove_dir_all(PIN_DIR) {
        // The directory is gone (or never was): the clean end state,
        // whichever way it was reached.
        Ok(()) => {}
        // A failed remove that left nothing behind is still clean: the
        // guard is the state, not the call.
        Err(_) if !Path::new(PIN_DIR).exists() => {}
        Err(e) => {
            return Err(format!(
                "{PIN_DIR} could not be swept (is bpffs mounted?): {e}"
            ));
        }
    }
    if swept > 0 {
        return Ok(format!(
            "probes detached: unpinned {removed} pin(s), swept {swept} foreign \
             entr{}; {PIN_DIR} is gone",
            if swept == 1 { "y" } else { "ies" }
        ));
    }
    Ok(format!(
        "probes detached: unpinned {removed} pin(s); {PIN_DIR} is gone"
    ))
}

use std::path::Path;

#[cfg(test)]
#[path = "../../test/ebpf/loader_tests.rs"]
mod tests;
