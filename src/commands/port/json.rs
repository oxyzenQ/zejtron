// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

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

use super::model::{OwnerMap, PortOptions, ScanStats, SocketEntry};
use super::window::{protocol_family_label, transition_label, window_label};
use crate::ebpf::events::SockEvent;
use crate::evidence::json::{write_array, write_opt_string, write_string};

/// The port report as one JSON line. `events` is `Some` only when the
/// event window actually ran (the lane captured); `None` is every
/// snapshot-only shape, and the `changes` block carries the named
/// reason instead of invented rows.
pub(super) fn port_report_json(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
    events: Option<&[SockEvent]>,
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
    out.push_str(",\"reason\":");
    match events {
        Some(_) => out.push_str("null"),
        None => write_string(&mut out, unavailability_reason(options)),
    }
    out.push_str(",\"events\":");
    let mut unaccounted = 0usize;
    match events {
        Some(events) => {
            let mut rows: Vec<String> = Vec::new();
            for event in events {
                // The same row contract the text section renders: a
                // non-transition or an unreadable protocol never
                // becomes a row; a pid the kernel no longer shows is
                // the honest unaccounted gap.
                let Some(kind) = event_kind(event.protocol, event.oldstate, event.newstate) else {
                    continue;
                };
                let Some(proto) = protocol_family_label(event.protocol, event.family) else {
                    continue;
                };
                let Some(name) = event_pid_name(event.pid) else {
                    unaccounted += 1;
                    continue;
                };
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
                write_string(&mut row, &name);
                row.push_str(",\"time_utc\":");
                write_string(
                    &mut row,
                    &crate::info::clock::time_of_day_from_monotonic_ns(event.timestamp_ns),
                );
                row.push('}');
                rows.push(row);
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

/// Why the event window did not run - the stable reason token the
/// automation lane gates on. `snapshot-only` is the operator's own
/// explicit request; anything else is the lane's honest absence.
fn unavailability_reason(options: &PortOptions) -> &'static str {
    if options.snapshot_only {
        "snapshot-only"
    } else {
        "lane-not-attached"
    }
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
