// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The tap loader - attach and detach (night-improve-1, the
//! zylaxion orchestration lineage; night-improve-2 grows the chain
//! to two tracepoints and a ring buffer).
//!
//! This is the privileged one-shot. `doctor --attach` loads the
//! embedded tap object, loads BOTH tracepoint programs (phase 1's
//! sched/sched_process_exec counter and phase 2's
//! sock/inet_sock_set_state socket-event tap), attaches each, and
//! pins EVERYTHING to bpffs - programs, links, maps - then the
//! process may exit, because the pinned links keep the taps alive
//! and the pinned maps keep the counter and the event ring alive.
//! After `attach` returns, nothing of zejtron is resident in
//! userspace. `doctor --detach` unpins everything; the link pins go
//! first so an interrupted cleanup leaves a DETACHED tap, never a
//! half-attached one.
//!
//! Idempotence and self-heal (the zylaxion contract): a complete pin
//! set is already-attached (a success shape - running attach twice is
//! fine); a partial pin set (a crashed attach, a manual rm) is
//! cleaned and replanted. A failed attach cleans every pin it planted
//! - no half state, ever.
//!
//! Every refusal names its reason: the kernel floor, the lockdown
//! mode, the missing capabilities. No silent fallback.

use aya::Ebpf;
use aya::programs::TracePoint;
use aya::programs::links::FdLink;

use super::embedded;
use super::{
    LaneVerdict, PIN_DIR, PIN_LINK, PIN_LINK_SOCK, PIN_MAP_SOCK_EVENTS, PIN_MAP_STATS, PIN_PROG,
    PIN_PROG_SOCK, any_pin_present, lane_verdict, probe_kernel,
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

    // 5. Load the object (map relocations happen here; the program
    //    loads below). Any failure past this point must clean the
    //    pins it planted - the fail() protocol.
    let mut bpf =
        Ebpf::load(TAP_ELF).map_err(|e| fail(format!("the tap object failed to load: {e}")))?;

    // 6. Load the tracepoint program and attach it to the
    //    sched_process_exec tracepoint. The attach returns a link id;
    //    taking the link out of the object and pinning it is what
    //    keeps the tap alive after this process exits.
    let attach_result = plant(&mut bpf);
    match attach_result {
        Ok(()) => {
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
                 sock/inet_sock_set_state, counter live; events since attach: \
                 {count}\npins: {PIN_DIR} (tap, tap_link, stats, sock_tap, \
                 sock_tap_link, sock_events)"
            ))
        }
        Err(e) => Err(fail(e)),
    }
}

/// The plant step: load both programs, attach each to its
/// tracepoint, pin both programs + links + maps. Any error names
/// itself; the caller's fail() protocol cleans up everything the
/// attempt planted - never a half-attached tap.
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
    bpf.take_map(MAP_STATS)
        .ok_or_else(|| format!("the tap object carries no '{MAP_STATS}' map"))?
        .pin(PIN_MAP_STATS)
        .map_err(|e| format!("the map pin {PIN_MAP_STATS} failed: {e}"))?;
    bpf.take_map(MAP_SOCK_EVENTS)
        .ok_or_else(|| format!("the tap object carries no '{MAP_SOCK_EVENTS}' map"))?
        .pin(PIN_MAP_SOCK_EVENTS)
        .map_err(|e| format!("the map pin {PIN_MAP_SOCK_EVENTS} failed: {e}"))?;
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
