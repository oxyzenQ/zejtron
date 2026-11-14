// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The ring readers (night-improve-2 opens the first, night-improve-3
//! the second, night-improve-47 the third; feature builds only): the
//! event-window pumps. std +
//! aya, nothing else — no thread, no poll loop, no daemon. The pump
//! runs for exactly one command: open the pinned ring, read the
//! records the kernel holds, hand back a bounded Vec (or feed one
//! across a whole wait, slice by slice). The kernel-side filters
//! already bound what crosses each ring (the port-surface transitions
//! in sock_events; the tracked inodes in file_events; the leader
//! check in proc_events); the rolling
//! cap here bounds the Vec even if a ring holds more history than
//! the window wants. (night-improve-34 removed the old lifecycle
//! pump with the lifecycle stream surface; night-improve-47 opens
//! the third reader as the post-mortem exit pump - a different
//! shape: the doctor drains once, filters to its window, prints,
//! and exits.)
//!
//! One semantic the caller must know (and the CHANGELOG names): a
//! ring buffer read CONSUMES. Advancing the reader advances the
//! consumer position the kernel keeps in the map itself, so each
//! drain sees the events accumulated since the previous drain (or
//! since attach, for the first). No daemon means no persistent
//! reader — that is the honest shape of a command-lifetime pump, and
//! each ring's own 256 KiB bounds what can accumulate between drains.
//!
//! The record length is checked before every parse (a short record
//! is skipped, never failed — the zylaxion bridge discipline), and
//! the parse itself is the one unavoidable pod-cast: the bytes in
//! each ring are a repr(C) record by contract (src/ebpf/events.rs,
//! pinned by test), written by the kernel side's `output` call.

use aya::maps::{Map, MapData, RingBuf};

use super::PIN_MAP_FILE_EVENTS;
use super::PIN_MAP_PROC_EVENTS;
use super::PIN_MAP_SOCK_EVENTS;
use super::events::{
    FILE_EVENT_BYTES, FileEvent, PROCEXIT_EVENT_BYTES, ProcExitEvent, SOCK_EVENT_BYTES, SockEvent,
};

/// The rolling cap: the pump never hands back more than this many
/// events, newest kept, oldest dropped. 4096 records is half the
/// sock ring's 8192-record capacity — a window-shaped bound, not a
/// log-shaped one. The file ring holds 6553 40-byte records at the
/// same 256 KiB; the same cap bounds both.
pub const ROLLING_CAP: usize = 4096;

/// Open one pinned ring buffer by its pin path. The shared half of
/// every drain: the map is opened through its pin (a missing pin is
/// a diagnosis, never a generic failure) and converted to a live
/// consumer. Reopening is safe across runs - the consumer position
/// lives in the kernel map itself, so each drain continues where the
/// previous one stopped (that is why a run shows the events since
/// the previous drain, or since attach for the first).
pub fn open_ring(pin: &str, label: &str) -> Result<RingBuf<MapData>, String> {
    let map_data = MapData::from_pin(pin).map_err(|e| {
        let base = format!("pinned {label} map {pin}: {e}");
        if super::pin_access_denied(&e) {
            // The ladder's degrade marker (night-hunter-5): the same
            // classification the tracked_inodes writer carries - a
            // permission refusal at the open is an unavailability,
            // not a command death.
            format!("{}: {base}", super::PIN_ACCESS_DENIED)
        } else {
            base
        }
    })?;
    // The identity gate (night-frontier-Z2, the generation stamp):
    // every recording boundary first proves the estate it found is
    // THIS boot's own camera, planted by THIS build - the stamp was
    // written at attach, the live facts are re-derived here, and a
    // mismatch refuses by name before one record is trusted. The
    // file ring's drain adds the offsets re-verification on top
    // (night-frontier-Z1): WHOSE camera is the estate-wide law, WHICH
    // walk table is the file-lane's own.
    super::estate::verify_at_drain()?;
    RingBuf::try_from(Map::RingBuf(map_data))
        .map_err(|e| format!("the pinned {label} map is not a ring buffer: {e}"))
}

/// The sock_events ring, opened: the port surface's window-shaped
/// capture (night-improve-4) holds one ring for the whole wait and
/// drains it slice by slice.
pub fn open_sock_ring() -> Result<RingBuf<MapData>, String> {
    open_ring(PIN_MAP_SOCK_EVENTS, "sock_events")
}

/// Push one event into the rolling window: newest kept, oldest
/// dropped when the cap is full. Generic over the record type so
/// both rings share the one rolling discipline; separated from the
/// drains so the rolling behavior is pinnable with a synthetic Vec,
/// no ring required. This is the per-event form of the discipline,
/// pinned by the test suite's intermediate-state assertions; the
/// drains themselves use [`extend_rolling`], which pays one front
/// trim per drain instead of one shift per record (night-dragon-1),
/// so the per-event path has no production caller left.
#[cfg_attr(not(test), allow(dead_code))]
pub fn push_rolling<T>(window: &mut Vec<T>, event: T, cap: usize) {
    if window.len() == cap {
        window.remove(0);
    }
    window.push(event);
}

/// Append a whole drain to the rolling window in one step: the
/// window keeps the last `cap` records of (window ++ batch), newest
/// last, exactly the state per-record [`push_rolling`] calls would
/// have produced, with at most two memmoves per drain instead of
/// one front shift per record (night-dragon-1: a full 8192-record
/// sock-ring drain used to memmove ~half a gigabyte through
/// `Vec::remove(0)`, and the port window's slice pump paid it again
/// on every poll slice). The batch itself is bounded by the ring's
/// own 256 KiB capacity - no reader-side drain cap is needed, and
/// none is added: the reader consumes what the kernel holds, and a
/// cap that stopped reading would silently drop events on the
/// one-shot drains.
pub fn extend_rolling<T>(window: &mut Vec<T>, batch: Vec<T>, cap: usize) {
    let overflow = window.len().saturating_add(batch.len()).saturating_sub(cap);
    if overflow >= window.len() {
        // Every surviving record comes from the batch.
        let keep_from = batch.len().saturating_sub(cap);
        window.clear();
        window.extend(batch.into_iter().skip(keep_from));
    } else {
        window.drain(..overflow);
        window.extend(batch);
    }
}

/// Drain the records currently available on an OPEN sock_events ring
/// into a rolling Vec, without reopening the map. The window-shaped
/// half (night-improve-4): a caller that collects over a duration
/// keeps one ring open and drains it slice by slice — the consumer
/// position advances with every call, so the Vec accumulates exactly
/// what crossed while the caller waited, and the rolling cap bounds
/// the Vec no matter how long the wait. The one-shot shape this
/// function replaced (open, drain once, drop) died with Fix 2: the
/// port window now collects over its duration, so every caller keeps
/// the ring for the whole wait.
pub fn drain_sock_events_from(ring: &mut RingBuf<MapData>, out: &mut Vec<SockEvent>) {
    // night-dragon-1: the records collect into a batch first -
    // bounded by the ring's own 256 KiB capacity - and the rolling
    // cap is applied once in extend_rolling. The window's final
    // content is the last-cap-of-the-stream the per-record form
    // produced, without the per-record front shift.
    let mut batch: Vec<SockEvent> = Vec::new();
    while let Some(record) = ring.next() {
        if record.len() != SOCK_EVENT_BYTES {
            continue;
        }
        // The pod-cast: the bytes are a repr(C) SockEvent by the
        // contract both sides compile from one file, and the length
        // check above is the bounds proof. Reading a u64-aligned
        // struct from a byte slice the kernel wrote is the one
        // unsafe step aya's API leaves to the caller.
        let event = unsafe { core::ptr::read_unaligned(record.as_ptr() as *const SockEvent) };
        batch.push(event);
    }
    extend_rolling(out, batch, ROLLING_CAP);
}

/// Drain every record the pinned file_events ring holds (the
/// Evidence Ledger's window) into a bounded, rolling Vec. The same
/// contract as [`drain_sock_events_from`], record for record.
///
/// The drain-boundary offsets re-verification (night-frontier-Z1)
/// rides here and only here: the file probes' records were written
/// by walks reading the offsets map, so a walk table that no longer
/// matches the host's BTF would make every record in this drain a
/// silent lie - the re-derivation (src/ebpf/reverify.rs) re-runs the
/// attach boundary's own two parses against the host's current BTF
/// and refuses by slot, planted value beside the current word,
/// before one record is trusted. The sock and exit drains carry no
/// offsets trust (their probes read verified context constants and
/// helpers, never the offsets map), so gating them would be a
/// refusal that lies.
pub fn drain_file_events() -> Result<Vec<FileEvent>, String> {
    let mut ring = open_ring(PIN_MAP_FILE_EVENTS, "file_events")?;
    super::reverify::verify_offsets_at_drain()?;
    let mut batch: Vec<FileEvent> = Vec::new();
    while let Some(record) = ring.next() {
        if record.len() != FILE_EVENT_BYTES {
            continue;
        }
        // The pod-cast, the file record's turn: the same
        // contract-and-bounds proof as the sock reader's.
        let event = unsafe { core::ptr::read_unaligned(record.as_ptr() as *const FileEvent) };
        batch.push(event);
    }
    let mut window: Vec<FileEvent> = Vec::new();
    extend_rolling(&mut window, batch, ROLLING_CAP);
    Ok(window)
}

/// Drain every record the pinned proc_events ring holds (the
/// post-mortem exit stream, night-improve-47) into a bounded,
/// rolling Vec. The same contract as [`drain_file_events`], record
/// for record; the caller owns the window cutoff - the doctor keeps
/// the last five seconds and the read consumes, the Lazy Camera
/// contract unchanged (docs/EBPF_LIFECYCLE.md).
pub fn drain_proc_exits() -> Result<Vec<ProcExitEvent>, String> {
    let mut ring = open_ring(PIN_MAP_PROC_EVENTS, "proc_events")?;
    let mut batch: Vec<ProcExitEvent> = Vec::new();
    while let Some(record) = ring.next() {
        if record.len() != PROCEXIT_EVENT_BYTES {
            continue;
        }
        // The pod-cast, the exit record's turn: the same
        // contract-and-bounds proof as the file reader's.
        let event = unsafe { core::ptr::read_unaligned(record.as_ptr() as *const ProcExitEvent) };
        batch.push(event);
    }
    let mut window: Vec<ProcExitEvent> = Vec::new();
    extend_rolling(&mut window, batch, ROLLING_CAP);
    Ok(window)
}

/// The post-mortem attribution rule (night-improve-61), the one
/// matcher every live lane shares - the file lanes (holds/touch/
/// why) and the port window alike: the exit record that names an
/// event's actor is the FIRST exit carrying the same pid stamped
/// at or after the event's own timestamp - the actor did the work,
/// then died. A record carrying the same pid but stamped BEFORE
/// the event is a prior life of a recycled pid naming a different
/// process; the first at-or-after record is this actor's own death.
pub fn exit_names_event(
    exits: &[ProcExitEvent],
    pid: u32,
    event_timestamp_ns: u64,
) -> Option<&ProcExitEvent> {
    exits
        .iter()
        .find(|exit| exit.pid == pid && exit.timestamp_ns >= event_timestamp_ns)
}

/// The teardown-lag envelope for LEFT LISTEN attribution (the
/// night-dragon-lts-T1 residual): a socket's teardown can trail the
/// process's own death - the close is deferred through the exit
/// path's cleanup ordering and the RCU grace period the sock
/// probe's records ride - so the exit record that names a LEFT
/// LISTEN event may land a beat BEFORE the event's own stamp.
/// 250ms is the bounded guard: near enough that a recycled pid's
/// prior life cannot reach it (a prior life is a DIFFERENT process,
/// dead long before), far enough for the teardown ordering.
pub const TEARDOWN_LAG_NANOS: u64 = 250_000_000;

/// The LEFT LISTEN-only post-mortem fallback: the exit record with
/// the same pid stamped strictly BEFORE the event but within the
/// teardown-lag envelope, returned with the measured lag in
/// nanoseconds (the number the row's note renders). An exit at or
/// after the event is refused here - that case belongs to the
/// strict rule above, and a lag of zero would make the note a lie.
/// Only the port surface's LEFT LISTEN branch consults this rule;
/// every other surface (and the file lanes) keep the strict
/// at-or-after answer as their first and only match.
pub fn exit_names_event_after_teardown(
    exits: &[ProcExitEvent],
    pid: u32,
    event_timestamp_ns: u64,
) -> Option<(&ProcExitEvent, u64)> {
    exits.iter().find_map(|exit| {
        if exit.pid != pid || exit.timestamp_ns >= event_timestamp_ns {
            return None;
        }
        let lag_ns = event_timestamp_ns - exit.timestamp_ns;
        (lag_ns <= TEARDOWN_LAG_NANOS).then_some((exit, lag_ns))
    })
}

#[cfg(test)]
#[path = "../../test/ebpf/ringbuf_tests.rs"]
mod tests;
