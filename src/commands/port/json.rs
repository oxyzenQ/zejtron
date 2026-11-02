// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The port surface's JSON lane (night-badass-9, the universal JSON
//! law): the report the text tree renders, as one typed line. The
//! schema mirrors the surface's own two truths - the snapshot's
//! socket table (`ports`) and the event window's transitions
//! (`changes`), with the same lane honesty the text lane renders:
//! a window the chain cannot serve is `changes.available: false`
//! with the reason named, never a fabricated empty event list that
//! pretends the kernel spoke.
//!
//! The snapshot rows carry every owner a socket has (the owner map is
//! inode-keyed and one socket can be held by several processes - the
//! text's `PID a, b (name, name)` row shape, typed). The event rows
//! carry the same transition vocabulary the text renders, as
//! jq-friendly kind tokens: `listened`, `left-listen`, `closed`.

use std::fmt::Write as _;

use super::events::{PostMortemVerdict, protocol_family_label, transition_label};
use super::lane_state::{LaneUnavailable, lane_reason};
use super::model::{OwnerMap, PortOptions, ScanStats, SocketEntry};
use super::window::window_label;
use crate::ebpf::events::{ProcExitEvent, SockEvent};
use crate::evidence::json::{write_array, write_opt_string, write_string};

/// The port report as one JSON line. `events` is `Some` only when the
/// event window actually ran (the lane captured); `None` is every
/// snapshot-only shape, and the `changes` block carries the named
/// reason instead of invented rows.
///
/// The exit ring is drained ONLY when some event needs it (the text
/// section's own rule, the parity law's consumption half): a fully
/// live window never consumes the exit stream. The seam form below
/// carries the drained records so the tests can pin the text/JSON
/// parity hermetically.
pub(super) fn port_report_json(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
    events: Option<&[SockEvent]>,
    bounds: Option<(u64, u64)>,
    lane_down: Option<LaneUnavailable>,
) -> String {
    let needs_exit_ring = events.is_some_and(|events| {
        events
            .iter()
            .any(|event| event_pid_name(event.pid).is_none())
    });
    let exits = if needs_exit_ring {
        match crate::ebpf::ringbuf::drain_proc_exits() {
            Ok(exits) => Some(exits),
            Err(error) => {
                crate::output::verbose::vlog!(
                    "port",
                    "exit ring unavailable for post-mortem attribution: {error}"
                );
                Some(Vec::new())
            }
        }
    } else {
        None
    };
    port_report_json_with_exits(
        sockets,
        owners,
        stats,
        options,
        events,
        exits.as_deref(),
        bounds,
        lane_down,
    )
}

/// The seam form: the same JSON line with the drained exit records
/// injected - the text lane's format_event_section_with_exits
/// pattern, so the parity tests can feed BOTH lanes the same fixture
/// (same events, same exits) and pin the verdicts equal. `None`
/// means the caller never needed the ring; an empty slice means the
/// ring was drained and held nothing - the two are the same
/// attribution outcome but different consumption contracts.
/// `bounds` rides the observed window the capture bracketed: the
/// changes block names both instants (`window_start_utc` /
/// `window_end_utc`, `HH:MM:SS UTC` each) when the window ran and
/// the clock could be read, and carries both as `null` when it did
/// not or could not - never omitted, never invented. `lane_down`
/// rides the capture's actual verdict: the reason token AND its
/// human next action (`hint`) name the real cause - a lane this
/// euid cannot read is not a lane that is not attached, and the
/// two need different next actions.
// The seam's shape IS the parity contract: each parameter is one
// fixture axis the tests pin independently (events, exits, bounds,
// the lane verdict), the same shape the doctor's exit-row renderer
// allows.
#[allow(clippy::too_many_arguments)]
pub(super) fn port_report_json_with_exits(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
    events: Option<&[SockEvent]>,
    exits: Option<&[ProcExitEvent]>,
    bounds: Option<(u64, u64)>,
    lane_down: Option<LaneUnavailable>,
) -> String {
    let mut out = String::with_capacity(512);
    out.push_str("{\"subject\":");
    match options.port {
        Some(port) => {
            let _ = write!(out, "\":{port}\"");
        }
        None => out.push_str("null"),
    }
    out.push_str(",\"mode\":");
    // The lane verdict: `live` only when the event window ran; the
    // snapshot shapes (phase-1 tree, --snapshot-only, the refusal)
    // are all honest snapshots.
    out.push_str(if events.is_some() {
        "\"live\""
    } else {
        "\"snapshot\""
    });
    out.push_str(",\"window\":");
    write_string(&mut out, &window_label(options.window));
    out.push_str(",\"ports\":");
    write_array(&mut out, sockets.len(), |out, index| {
        socket_json(out, &sockets[index], owners);
    });
    out.push_str(",\"changes\":{\"available\":");
    out.push_str(if events.is_some() { "true" } else { "false" });
    // The reason and its next action (the misleading-reason
    // residual): a lane this euid cannot read is "lane-unreadable"
    // with the sudo hint, NOT "lane-not-attached" with an attach
    // instruction that never heals it. The hint is null when the
    // reason is null (the lane worked) and null on snapshot-only
    // (the operator's own request is a named shape, not a failure
    // with a next action).
    let (reason, hint) = if events.is_some() {
        (None, None)
    } else {
        let (reason, hint) = unavailability_parts(options, lane_down);
        (Some(reason), hint)
    };
    out.push_str(",\"reason\":");
    match reason {
        Some(reason) => write_string(&mut out, reason),
        None => out.push_str("null"),
    }
    out.push_str(",\"hint\":");
    match hint {
        Some(hint) => write_string(&mut out, hint),
        None => out.push_str("null"),
    }
    // The observed window's boundaries (the one-shot window
    // semantics residual): two sequential runs watch two different
    // windows, and the automated consumer needs to see WHICH window
    // a changes block describes. Present whenever the window ran;
    // null when it did not (every unavailable shape) or when the
    // clock's own read failed (the honest absence, never a guessed
    // boundary). The pair renders under one wall offset - the
    // span between the two strings is the stamps' span.
    let window_range = bounds.and_then(|(start, end)| {
        crate::info::clock::time_of_day_pair_from_monotonic_ns(start, end)
    });
    out.push_str(",\"window_start_utc\":");
    match &window_range {
        Some((start, _)) => write_string(&mut out, start),
        None => out.push_str("null"),
    }
    out.push_str(",\"window_end_utc\":");
    match &window_range {
        Some((_, end)) => write_string(&mut out, end),
        None => out.push_str("null"),
    }
    out.push_str(",\"events\":");
    let mut unaccounted = 0usize;
    match events {
        Some(events) => {
            let exits: &[ProcExitEvent] = exits.unwrap_or(&[]);
            let mut rows: Vec<String> = Vec::new();
            for event in events {
                // The same row contract the text section renders: a
                // non-transition or an unreadable protocol never
                // becomes a row; a pid the kernel no longer shows is
                // the post-mortem candidate the exit ring may still
                // name - the same shared verdict the text renders
                // (the parity law: same evidence, same verdict,
                // whatever the output format).
                let Some(kind) = event_kind(event.protocol, event.oldstate, event.newstate) else {
                    continue;
                };
                let Some(proto) = protocol_family_label(event.protocol, event.family) else {
                    continue;
                };
                let Some(name) = event_pid_name(event.pid) else {
                    match super::events::post_mortem_verdict(exits, event) {
                        PostMortemVerdict::AtOrAfter(exit) => {
                            let comm =
                                crate::commands::doctor::memory::exits::comm_string(&exit.comm);
                            rows.push(event_row_json(
                                event,
                                kind,
                                proto,
                                Some(&comm),
                                Some("post-mortem"),
                                None,
                                None,
                            ));
                        }
                        PostMortemVerdict::TeardownLag(exit, lag_ns) => {
                            let comm =
                                crate::commands::doctor::memory::exits::comm_string(&exit.comm);
                            rows.push(event_row_json(
                                event,
                                kind,
                                proto,
                                Some(&comm),
                                Some("post-mortem"),
                                Some(super::events::lag_whole_ms(lag_ns)),
                                None,
                            ));
                        }
                        PostMortemVerdict::Miss { left_listen } => {
                            unaccounted += 1;
                            rows.push(event_row_json(
                                event,
                                kind,
                                proto,
                                None,
                                Some("unaccounted"),
                                None,
                                left_listen.then_some(super::events::LEFT_LISTEN_RACE_NOTE),
                            ));
                        }
                    }
                    continue;
                };
                rows.push(event_row_json(
                    event,
                    kind,
                    proto,
                    Some(&name),
                    None,
                    None,
                    None,
                ));
            }
            write_array(&mut out, rows.len(), |out, index| {
                out.push_str(&rows[index]);
            });
        }
        None => out.push_str("[]"),
    }
    out.push_str(",\"unaccounted\":");
    let _ = write!(out, "{unaccounted}");
    out.push_str("},\"scan\":{\"unreadable_processes\":");
    let _ = write!(out, "{}", stats.unreadable_processes);
    out.push_str(",\"unreadable_fds\":");
    let _ = write!(out, "{}", stats.unreadable_fds);
    out.push_str("}}");
    out
}

fn socket_json(out: &mut String, socket: &SocketEntry, owners: &OwnerMap) {
    out.push_str("{\"protocol\":");
    write_string(out, socket.protocol.label());
    out.push_str(",\"local_addr\":");
    write_string(out, &format_endpoint(socket));
    out.push_str(",\"state\":");
    write_opt_string(out, socket.state.as_deref());
    out.push_str(",\"owners\":");
    match owners.get(&socket.inode) {
        Some(holders) if !holders.is_empty() => {
            write_array(out, holders.len(), |out, index| {
                let holder = &holders[index];
                out.push_str("{\"pid\":");
                let _ = write!(out, "{}", holder.pid);
                out.push_str(",\"process\":");
                write_string(out, &holder.name);
                out.push_str(",\"user\":");
                write_string(out, &holder.user);
                out.push('}');
            });
        }
        _ => out.push_str("[]"),
    }
    out.push('}');
}

/// The endpoint token the text lane's snapshot rows render: IPv6
/// bracketed, IPv4 bare. (The text lane carries the same shape inline
/// in its snapshot_row; the JSON lane keeps the contract here so the
/// two read alike.)
fn format_endpoint(socket: &SocketEntry) -> String {
    if socket.address.contains(':') {
        format!("[{}]:{}", socket.address, socket.port)
    } else {
        format!("{}:{}", socket.address, socket.port)
    }
}

/// The JSON kind token for a transition - the text lane's transition
/// labels, as one jq-friendly word each.
fn event_kind(protocol: u8, oldstate: u8, newstate: u8) -> Option<&'static str> {
    match transition_label(protocol, oldstate, newstate) {
        Some("ENTERED LISTEN") => Some("listened"),
        Some("LEFT LISTEN") => Some("left-listen"),
        Some("CLOSED") => Some("closed"),
        _ => None,
    }
}

/// One typed event row, shared by every branch: the live shape
/// (kind, protocol, port, pid, process, time) with the post-mortem
/// fields appended only when a post-mortem case produced the row.
/// The field laws: `attribution` rides only rows the exit-ring
/// verdict produced ("post-mortem" | "unaccounted" - its absence on
/// a live row IS the contract: not a post-mortem case, nothing to
/// say); `lag_ms` rides only the teardown-lag branch, always an
/// integer, never null (absent means the branch did not fire);
/// `race_note` rides only the unaccounted LEFT LISTEN branch, the
/// text note's own words; `process` is null when no source can name
/// the actor (the lane's absence law - nulls, not empty strings).
pub(super) fn event_row_json(
    event: &SockEvent,
    kind: &str,
    proto: &str,
    process: Option<&str>,
    attribution: Option<&str>,
    lag_ms: Option<u64>,
    race_note: Option<&str>,
) -> String {
    let mut row = String::new();
    row.push_str("{\"kind\":");
    write_string(&mut row, kind);
    row.push_str(",\"protocol\":");
    let lowered = proto.to_ascii_lowercase();
    write_string(&mut row, &lowered);
    row.push_str(",\"port\":");
    let _ = write!(row, "{}", event.sport);
    row.push_str(",\"pid\":");
    let _ = write!(row, "{}", event.pid);
    row.push_str(",\"process\":");
    match process {
        Some(name) => write_string(&mut row, name),
        None => row.push_str("null"),
    }
    row.push_str(",\"time_utc\":");
    write_string(
        &mut row,
        &crate::info::clock::time_of_day_from_monotonic_ns(event.timestamp_ns),
    );
    if let Some(attribution) = attribution {
        row.push_str(",\"attribution\":");
        write_string(&mut row, attribution);
    }
    if let Some(ms) = lag_ms {
        row.push_str(",\"lag_ms\":");
        let _ = write!(row, "{ms}");
    }
    if let Some(note) = race_note {
        row.push_str(",\"race_note\":");
        write_string(&mut row, note);
    }
    row.push('}');
    row
}

/// Why the event window did not run, with the human next action:
/// the stable reason token the automation lane gates on plus the
/// hint the changes block renders alongside it. `snapshot-only` is
/// the operator's own explicit request - a named shape, not a
/// failure, so no hint rides it. Anything else is the lane's honest
/// absence: the capture's actual verdict when it says one, the
/// historical blanket ("lane-not-attached") when a caller hands
/// down a missing window without a verdict (the test seam's shape).
fn unavailability_parts(
    options: &PortOptions,
    lane_down: Option<LaneUnavailable>,
) -> (&'static str, Option<&'static str>) {
    if options.snapshot_only {
        return ("snapshot-only", None);
    }
    let (reason, hint) = lane_reason(lane_down.unwrap_or(LaneUnavailable::NotAttached));
    (reason, Some(hint))
}

/// The process name for an event's pid at render time - the same
/// /proc/<pid>/status Name read the text section's attribution uses.
/// `None` counts toward the unaccounted block.
fn event_pid_name(pid: u32) -> Option<String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("Name:"))?;
    line.split_whitespace().nth(1).map(ToOwned::to_owned)
}

#[cfg(test)]
#[path = "../../../test/commands/port/json_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "../../../test/commands/port/json_window_tests.rs"]
mod window_tests;
