// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The fallback-lane collector (night-improve-3): the one place the
//! ladder lives, shared by holds, touch, and why. The ladder is
//! exclusive and every step is honest about its source:
//!
//! 1. eBPF attached (root, BTF, kernel 5.15+, feature enabled, probe
//!    live) - \[observed] rows from the kernel's own records;
//! 2. eBPF unavailable but the log lane present (audit.log or
//!    journalctl) - \[inferred] rows from the log, replayed;
//! 3. neither - no event rows, the named unavailability line, and
//!    the Unaccounted block names the missing window.
//!
//! The log lane's row actions are source-true whatever the surface:
//! an audit record is `modified (audit log)` (the parser only
//! matches modification syscalls), a journal grep hit is a
//! `journal mention` (the journal mentioned the path - it proves
//! neither an open nor a write). The log lane cannot distinguish
//! opens from writes; the actions say so. The kernel lane can, and
//! the per-surface OpFilter picks which class of event this surface
//! cares about (holds: opens; touch: writes; why: both).
//!
//! In the live lane the log is not consulted at all - the ladder is
//! exclusive, and the verdict (not a row) names that nothing older
//! than the window was looked for.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use crate::evidence::row::{EvidenceActor, EvidenceKind, EvidenceRow, Provenance};
use crate::evidence::{ChangesSection, Mode, UnaccountedEntry};

/// The default window for holds/touch/why (the spec's lock): short
/// enough that the live lane's collection-over-duration stays quick,
/// long enough to catch the common "who just touched this".
pub const WINDOW_DEFAULT: Duration = Duration::from_secs(10);

/// Resolve a `--since` argument into the window and its label: the
/// port surface's own grammar (`s`/`m`/`h`, clamped [1s, 1h] - one
/// grammar, two surfaces, imported rather than duplicated), with
/// the 10s default when the flag is absent. Every surface resolves
/// through here so the default can never drift between them. An
/// out-of-bounds ask - above the ceiling or below the floor - rides
/// one stderr warning (the clamp note, night-dragon-lts-T1
/// residual, both directions since night-total-hardening-1) and
/// never touches stdout.
pub fn resolve_window(since: Option<&str>) -> Result<(Duration, String), String> {
    use crate::commands::port::window::{
        clamp_window, parse_window, truncation_note, window_label,
    };
    let window = match since {
        Some(raw) => {
            let parsed = parse_window(raw).map_err(|e| format!("{e}"))?;
            if let Some(note) = truncation_note(raw, parsed) {
                eprintln!("{note}");
            }
            clamp_window(parsed)
        }
        None => WINDOW_DEFAULT,
    };
    let label = window_label(window);
    Ok((window, label))
}

/// The canonical device token from a stat(2) st_dev value (the
/// userspace encoding glibc reports - the 12-bit-major packing, the
/// same split holds' dev_major_minor applies). st_dev and the kernel
/// s_dev are two encodings of one (major, minor) pair; this brings
/// both sides to the same canonical integer - the form the BPF side
/// carries in its records and its filter keys. Lives here (not in
/// the feature-gated events module) because the LaneQuery needs it
/// in every build; the six-line decode is duplicated from
/// holds/procfs.rs by hand (that parser is a locked snapshot
/// surface), and mirrored on the BPF side by
/// events::device_token_from_kernel.
pub fn device_token_from_stat(st_dev: u64) -> u64 {
    let major = ((st_dev & 0x0000_0000_000f_ff00) >> 8) | ((st_dev & 0xffff_f000_0000_0000) >> 32);
    let minor = (st_dev & 0x0000_0000_0000_00ff) | ((st_dev & 0x0000_0000_fff0_0000) >> 12);
    (major << 20) | minor
}

/// Which class of live events this surface reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpFilter {
    /// Open events only (holds).
    Opens,
    /// Write events only (touch).
    Writes,
    /// Both (why).
    Both,
}

/// What the ladder produced for one window.
#[derive(Debug)]
pub struct LaneParts {
    /// The mode line's verdict.
    pub mode: Mode,
    /// The Changes subsection (rows + the unavailable bit).
    pub changes: ChangesSection,
    /// The entries the lane itself owes the Unaccounted block (the
    /// out-of-window log record, the unavailable window, the live
    /// events whose pid is no longer visible).
    pub unaccounted: Vec<UnaccountedEntry>,
    /// The raw kernel records of the live capture, as drained -
    /// every event the ring held for this file, before the surface
    /// filter and before attribution. Carried for `why --raw`; absent
    /// in default builds (no live lane exists to produce any).
    pub raw: Vec<crate::ebpf::events::FileEvent>,
}

/// The per-run context the log half needs; the live half needs only
/// the identity. One struct keeps the signature from growing flags.
pub struct LaneQuery<'a> {
    /// The path as the user wrote it (the log grep key).
    pub display_path: &'a Path,
    /// The path as the log grep should read it (absolute).
    pub lookup_path: &'a Path,
    /// The uid-to-name map (shared with the log parsers).
    pub users: &'a HashMap<u32, String>,
    /// The queried file's inode (full 64 bits). Read only by the live
    /// half; the default build writes it and never reads it (the
    /// allow is the honest count of that split).
    pub inode: u64,
    /// The queried file's canonical device token. Same split as
    /// `inode`.
    pub device: u64,
}

/// Walk the ladder for one window. `Err` only from the live half
/// when the chain died mid-command (a chain that failed under the
/// command is worth an error, never a silent lane switch); the log
/// half degrades honestly instead of failing. The one pre-flight
/// exception (night-hunter-5): the pins exist but this caller may
/// not open them (EPERM/EACCES at BPF_OBJ_GET - a non-root run
/// against a root attach session). That is an unavailability, not a
/// death: the ladder steps down to the snapshot lane, and the
/// Unaccounted block names the event window this caller could not
/// have.
pub fn collect(
    query: &LaneQuery<'_>,
    window: Duration,
    filter: OpFilter,
) -> Result<LaneParts, String> {
    {
        if crate::ebpf::all_pins_present() {
            // The diagnostic trace (night-hunter-4): which lane the
            // ledger rode, on stderr only.
            crate::output::verbose::vlog!("lane", "live eBPF window selected (attached)");
            return match collect_live(query, window, filter) {
                Ok(parts) => Ok(parts),
                Err(err) if err.starts_with(crate::ebpf::PIN_ACCESS_DENIED) => {
                    crate::output::verbose::vlog!(
                        "lane",
                        "pin access denied (requires root) - snapshot fallback"
                    );
                    Ok(snapshot_fallback(query, window))
                }
                Err(err) => Err(err),
            };
        }
    }
    crate::output::verbose::vlog!("lane", "snapshot only (eBPF not attached)");
    Ok(crate::commands::lane_log::collect_log(query, window))
}

/// The degraded step (night-hunter-5): the snapshot/log lane's parts
/// with the Unaccounted block naming the event window the caller
/// could not have. The ledger's grammar is untouched - the note
/// rides the standard entry shape ("1 event window (...)"), the mode
/// stays whatever the log lane found.
fn snapshot_fallback(query: &LaneQuery<'_>, window: Duration) -> LaneParts {
    let mut parts = crate::commands::lane_log::collect_log(query, window);
    parts.unaccounted.push(UnaccountedEntry::new(
        1,
        "event window",
        "unavailable without root - falling back to snapshot mode",
    ));
    parts
}

// ── The live half (feature builds only) ─────────────────────────────

fn collect_live(
    query: &LaneQuery<'_>,
    window: Duration,
    filter: OpFilter,
) -> Result<LaneParts, String> {
    let capture = crate::ebpf::fileprobe::capture_file_window(query.inode, query.device, window)?;
    let events = capture.events;
    let pre_offset = capture.pre.offset;
    let pre_gap = capture.pre.gap;

    // ONE render breath (night-frontier-Z2, the wall-offset skew
    // law): every row of this ledger renders under the ONE offset
    // sampled here, and the capture's PRE offset measures the wall
    // clock's movement across the window - beyond the half-second
    // bound the movement is named in the Unaccounted block instead
    // of riding the civil times silently. The sleep gap rides the
    // same breath (night-frontier-Z6, D3): the PRE gap against this
    // render-time gap is the kernel's own suspend accounting across
    // the capture - wall-independent, so an NTP step can never read
    // as a sleep and a sleep can never hide as a wall step.
    let render_offset = crate::info::clock::wall_offset_ns();
    let skew = crate::info::clock::material_skew_ns(pre_offset, render_offset);
    let sleep =
        crate::info::clock::material_sleep_ns(pre_gap, crate::info::clock::boottime_gap_ns());
    crate::output::verbose::vlog!(
        "lane",
        "render offset sampled once; pre-render skew measured: {skew:?}; \
         sleep delta measured: {sleep:?}"
    );

    // The rows keep the capture's ascending order (the renderer
    // never reorders), so each attributed event lands in a SLOT and
    // an event whose actor is not resolvable yet parks its slot as
    // None - the post-mortem pass below fills the gaps IN PLACE, so
    // a row attributed from the exit ring can never jump ahead of a
    // live-attributed row that happened later.
    let mut slots: Vec<Option<EvidenceRow>> = Vec::new();
    let mut post_mortem: Vec<(usize, &crate::ebpf::events::FileEvent)> = Vec::new();
    let mut gone_opens: usize = 0;
    let mut gone_writes: usize = 0;
    let mut gone_changes: usize = 0;
    for event in &events {
        let is_open = event.op == crate::ebpf::events::FILE_OP_OPEN;
        // Both write paths are writes: the plain write probe (op=2) and
        // the vectorized writev probe (op=4, night-improve-42). The
        // filter must never re-open the gap the second probe closed -
        // a Writes-only window that dropped writev rows would be the
        // false negative reborn one layer up.
        let is_write = event.op == crate::ebpf::events::FILE_OP_WRITE
            || event.op == crate::ebpf::events::FILE_OP_WRITEV
            // The off-path write truths ride the Writes filter too
            // (night-frontier-Z7, D4): a Writes-only window that
            // dropped the mmap/io_uring/splice-into rows would be
            // the false-negative reborn one layer up - the exact
            // gap these ops exist to close.
            || event.op == crate::ebpf::events::FILE_OP_MMAP_DIRTY
            || event.op == crate::ebpf::events::FILE_OP_MMAP_MEMBACKED
            || event.op == crate::ebpf::events::FILE_OP_SPLICE_IN
            || event.op == crate::ebpf::events::FILE_OP_IO_URING_WRITE;
        // And the forensic pair (op=3 / op=5, night-frontier-2): the
        // unlink and rename probes closed the ledger's oldest hole -
        // the death and movement of the watched file. Both-filter
        // runs (the why surface) see them as the changes they are;
        // the Opens and Writes filters keep their exact meanings.
        let is_change = is_write
            || event.op == crate::ebpf::events::FILE_OP_UNLINK
            || event.op == crate::ebpf::events::FILE_OP_RENAME;
        let wanted = match filter {
            OpFilter::Opens => is_open,
            OpFilter::Writes => is_write,
            OpFilter::Both => is_open || is_change,
        };
        if !wanted {
            continue;
        }
        // The row's actor: the /proc facts for the recorded pid,
        // resolved at render time - the same fields the snapshot's
        // holder rows carry. A pid with no visible /proc entry at
        // render time is a post-mortem candidate (the passes below):
        // the common server shape is a short-lived writer -
        // a cron one-shot, a logrotate run, a shell redirect - that
        // finished its write and died inside the window.
        let Some((name, user)) = pid_context(event.pid, query.users) else {
            // The record's own comm (night-frontier-Z8, D5) names the
            // actor first: the acting task's own name, read by the
            // same probe in the same breath as the event - zero
            // pid-reuse risk, no /proc round-trip to outlive the
            // actor. The name may be the acting THREAD's (a worker
            // pool's "wr-3"), not the leader's - the honest thread-
            // level truth, rendered in the recorded-actor shape.
            if let Some(comm) = record_actor_name(event) {
                slots.push(Some(EvidenceRow::new(
                    crate::ebpf::fileprobe::event_unix_secs_with(event, render_offset),
                    event_kind(event.op),
                    EvidenceActor::recorded(Some(comm), Some(event.pid), None),
                    Provenance::Observed,
                )));
            } else {
                post_mortem.push((slots.len(), event));
                slots.push(None);
            }
            continue;
        };
        slots.push(Some(EvidenceRow::new(
            crate::ebpf::fileprobe::event_unix_secs_with(event, render_offset),
            event_kind(event.op),
            EvidenceActor::process(name, event.pid, user),
            Provenance::Observed,
        )));
    }

    // The exit-ring pass (night-improve-61): the post-mortem
    // attribution for the events whose record comm is absent (a
    // failed helper read leaves the field zeroed - the D5 ladder's
    // honest hole). The sched/sched_process_exit probe (the
    // night-improve-47 estate) records every process exit - pid and
    // comm, the same pair a /proc read would have named - into the
    // proc_events ring, and this is the consumer that answers the
    // question the unaccounted block used to shrug at: WHICH
    // short-lived process wrote the file. The exit record carries
    // no uid, so the row's user stays an honest absence (the
    // recorded-actor shape, "name (pid N)"); the event itself stays
    // [observed] - the kernel saw the write. The ring is drained
    // ONLY when some parked event needs it: a fully-live window
    // never consumes the doctor's exit stream.
    if !post_mortem.is_empty() {
        let exits = match crate::ebpf::ringbuf::drain_proc_exits() {
            Ok(exits) => exits,
            Err(error) => {
                crate::output::verbose::vlog!(
                    "lane",
                    "exit ring unavailable for post-mortem attribution: {error}"
                );
                Vec::new()
            }
        };
        if !exits.is_empty() {
            crate::output::verbose::vlog!(
                "lane",
                "post-mortem attribution: {} exit record(s) in the ring",
                exits.len()
            );
        }
        for (slot, event) in post_mortem {
            match crate::ebpf::ringbuf::exit_names_event(&exits, event.pid, event.timestamp_ns) {
                Some(exit) => {
                    let comm = crate::commands::doctor::memory::exits::comm_string(&exit.comm);
                    slots[slot] = Some(EvidenceRow::new(
                        crate::ebpf::fileprobe::event_unix_secs_with(event, render_offset),
                        event_kind(event.op),
                        EvidenceActor::recorded(Some(comm), Some(event.pid), None),
                        Provenance::Observed,
                    ));
                }
                None => {
                    if event.op == crate::ebpf::events::FILE_OP_OPEN {
                        gone_opens += 1;
                    } else if event.op == crate::ebpf::events::FILE_OP_UNLINK
                        || event.op == crate::ebpf::events::FILE_OP_RENAME
                    {
                        gone_changes += 1;
                    } else {
                        gone_writes += 1;
                    }
                }
            }
        }
    }

    let rows: Vec<EvidenceRow> = slots.into_iter().flatten().collect();

    let mut unaccounted = Vec::new();
    if gone_opens > 0 {
        unaccounted.push(UnaccountedEntry::new(
            gone_opens,
            "opens",
            "no visible PID - namespace boundary or exited before attribution",
        ));
    }
    if gone_writes > 0 {
        unaccounted.push(UnaccountedEntry::new(
            gone_writes,
            "writes",
            "no visible PID - namespace boundary or exited before attribution",
        ));
    }
    if gone_changes > 0 {
        unaccounted.push(UnaccountedEntry::new(
            gone_changes,
            "changes",
            "no visible PID - namespace boundary or exited before attribution",
        ));
    }
    // night-frontier-Z1, the drop-truth: the camera's own failures,
    // named where the boundaries are named. The census is cumulative
    // since attach - the only form a cross-run reader can compare
    // without a reset write (a fresh process inherits no previous
    // count) - so the entry says what the number IS, and the window
    // above may be missing records the same way. A count-backed
    // boundary (the extend_stats_entries pattern): it rides only
    // when nonzero, and an unreadable census degrades to the verbose
    // trace, never to a guessed zero.
    match crate::ebpf::readback::read_drop_census() {
        Ok(census) => {
            if let Some(entry) =
                crate::commands::lane_unaccounted::file_ring_drop_entry(census.file)
            {
                unaccounted.push(entry);
            }
        }
        Err(error) => {
            crate::output::verbose::vlog!("lane", "drop census unreadable: {error}");
        }
    }
    // The wall-clock skew boundary (night-frontier-Z2): named when
    // the wall clock demonstrably moved across the capture (beyond
    // the half-second bound) - the rows above render under the
    // post-capture offset, and this entry says how far that offset
    // can sit from the times the events actually happened at. A
    // state boundary (the movement happened): it rides whenever the
    // measurement answers, the "1 event window (...)" class.
    if let Some(skew) = skew {
        unaccounted.push(crate::commands::lane_unaccounted::wall_skew_entry(skew));
    }
    // The sleep blackout boundary (night-frontier-Z6, D3): named when
    // the BOOTTIME-MONOTONIC gap moved materially across the capture.
    // A positive delta is the blackout arm - the span the host spent
    // asleep inside this window, where no event can exist (the
    // stamps' clock does not run there): proof of absence, the hole
    // carried as evidence. A negative delta is the paravirt anomaly
    // arm - the pairing moved backwards, and the withheld measurement
    // is named instead of trusted.
    if let Some(sleep) = sleep {
        unaccounted.push(crate::commands::lane_unaccounted::sleep_blackout_entry(
            sleep,
        ));
    }
    // The watch-truth boundary (night-frontier-Z10, D7): the third
    // absence - the watcher's own. The drop census names the
    // kernel's failures and the sleep blackout names the host's;
    // neither can name the span the requested window covers BEFORE
    // the camera existed, because only the attach instant can. The
    // compare rides the stamps' own CLOCK_MONOTONIC domain (the
    // generation map's Z10 slot) - wall-independent, so an NTP step
    // can never invent a gap - and the entry rides only past the
    // one-second materiality bound: a window fully inside the
    // camera's life adds NOTHING (the negative test pins the byte
    // silence). A pre-Z10 estate (no monotonic slot) degrades to a
    // verbose trace, never a guessed gap.
    match crate::ebpf::estate::attach_facts() {
        Ok((attach_unix, attach_mono)) => {
            if let Some(gap_ns) = crate::info::clock::material_watch_gap_ns(
                capture.pre.monotonic_ns,
                attach_mono,
                window,
            ) {
                let attach_wall = crate::info::clock::format_unix_secs(attach_unix as i64);
                unaccounted.push(crate::commands::lane_unaccounted::watch_gap_entry(
                    gap_ns,
                    Some(attach_wall),
                ));
            }
        }
        Err(error) => {
            crate::output::verbose::vlog!("lane", "attach facts unreadable: {error}");
        }
    }
    // The clocksource regime boundary (night-frontier-Z10, D7): the
    // stamps stay one CLOCK_MONOTONIC domain, but the precision
    // REGIME the durations ride can move under the window (the
    // watchdog's tsc-unstable fallback). Named only when the regime
    // demonstrably moved across the capture - both ends readable and
    // different - the state-backed materiality bound; a steady
    // regime adds NOTHING.
    if let Some(post_source) = crate::info::clock::current_clocksource()
        && let Some(pre_source) = &capture.pre.clocksource
        && pre_source != &post_source
    {
        unaccounted.push(crate::commands::lane_unaccounted::clocksource_switch_entry(
            pre_source,
            &post_source,
        ));
    }
    // The silent-deletion reconciliation (night-frontier-Z11): the
    // two lanes' deletion truth compared. The rows stay single-lane
    // (the ladder's exclusivity) - the comparison is a boundary, not
    // a row. The ring IS the camera's record: when it holds an unlink
    // or a rename for this window the lanes agree and the probe pays
    // nothing; when it does not, the audit log is asked the same
    // question the snapshot lane would answer - did a successful
    // deletion syscall name this path (and this inode) inside the
    // window? A yes is the disagreement the Unaccounted block names.
    let ring_saw_deletion = events.iter().any(|event| {
        event.op == crate::ebpf::events::FILE_OP_UNLINK
            || event.op == crate::ebpf::events::FILE_OP_RENAME
    });
    if !ring_saw_deletion {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let cutoff_secs = now_secs.saturating_sub(window.as_secs() as i64);
        if let Some(record_secs) = crate::commands::touch::audit::try_audit_deletion(
            query.lookup_path,
            query.inode,
            cutoff_secs,
        ) {
            let record_wall = crate::info::clock::format_unix_secs(record_secs as i64);
            unaccounted.push(crate::commands::lane_unaccounted::silent_deletion_entry(
                &record_wall,
            ));
        }
    }
    // events arrive ascending from the capture; the filter keeps the
    // order. No re-sorting here - the renderer never reorders.
    Ok(LaneParts {
        mode: Mode::Live,
        changes: ChangesSection {
            rows,
            unavailable: false,
        },
        unaccounted,
        raw: events,
    })
}

/// The event's action, typed from its op: the writev parenthetical
/// is the whole point of op=4 - the operator learns WHICH syscall
/// family the writer used. One mapping for both the live pass and
/// the post-mortem pass, so a row attributed from the exit ring
/// renders the same phrase a live-attributed row would.
fn event_kind(op: u8) -> EvidenceKind {
    match op {
        crate::ebpf::events::FILE_OP_OPEN => EvidenceKind::Opened,
        crate::ebpf::events::FILE_OP_WRITEV => EvidenceKind::Wrote {
            via: Some("writev"),
        },
        crate::ebpf::events::FILE_OP_UNLINK => EvidenceKind::Unlinked,
        crate::ebpf::events::FILE_OP_RENAME => EvidenceKind::Renamed,
        // The off-path write truths (night-frontier-Z7, D4): the via
        // qualifier names the path no write(2) crossed - the whole
        // point of the new vocabulary, the row tells the operator
        // WHICH silent path carried the bytes.
        crate::ebpf::events::FILE_OP_MMAP_DIRTY => EvidenceKind::Wrote {
            via: Some("mmap (dirty page)"),
        },
        crate::ebpf::events::FILE_OP_MMAP_MEMBACKED => EvidenceKind::Wrote {
            via: Some("mmap (memory-backed page)"),
        },
        crate::ebpf::events::FILE_OP_SPLICE_IN => EvidenceKind::Wrote {
            via: Some("splice (into)"),
        },
        crate::ebpf::events::FILE_OP_SPLICE_OUT => EvidenceKind::SplicedOut,
        crate::ebpf::events::FILE_OP_IO_URING_WRITE => EvidenceKind::Wrote {
            via: Some("io_uring (async)"),
        },
        _ => EvidenceKind::Wrote { via: None },
    }
}

/// The record's own actor name (night-frontier-Z8, D5): the comm the
/// acting task carried at event time, when the field is populated -
/// the ladder's second arm, tighter than the exit ring (the same
/// probe read it in the same breath as the event, so no pid-reuse
/// rule is needed) and the answer that survives a /proc read the
/// actor already outlived. `None` when the field is zeroed - a
/// failed helper read - the honest hole the exit-ring pass still
/// serves.
fn record_actor_name(event: &crate::ebpf::events::FileEvent) -> Option<String> {
    // A real comm always starts with a name byte: the helper
    // NUL-terminates and zero-fills past the end, so a first byte of
    // zero means either the field was never written (the failed
    // helper read) or the bytes are malformed garbage - both are the
    // honest absence, never a guessed "unknown".
    (event.comm[0] != 0).then(|| crate::commands::doctor::memory::exits::comm_string(&event.comm))
}

/// The pid's Name and Uid (real) from /proc, resolved to a username.
/// `None` when the process is gone or hidden - the honest absence.
fn pid_context(pid: u32, users: &HashMap<u32, String>) -> Option<(String, String)> {
    use crate::commands::touch::uid_to_user;
    use crate::system::read_status_value;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let name = crate::system::read_status_name(&status)?;
    let uid = read_status_value(&status, "Uid").and_then(|value| {
        value
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<u32>().ok())
    });
    let user = match uid {
        Some(uid) => uid_to_user(uid, users),
        None => "unknown".to_owned(),
    };
    Some((name, user))
}

#[cfg(test)]
#[path = "../../test/commands/lane_tests.rs"]
mod tests;
