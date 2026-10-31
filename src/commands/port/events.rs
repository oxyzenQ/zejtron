// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The event-row rendering half of the port window (split from
//! window.rs at the 600-LOC cap, the night-hunter-4 precedent): the
//! per-event renderer, the transition and protocol labels, the
//! post-mortem attribution pass, the UDP-only kernel-truth note, and
//! the --events-only output shape. The grammar (parse/clamp/label),
//! the capture pump, and the report assembly stay in window.rs -
//! this module renders what that module collects.

use std::time::Duration;

use super::model::PortOptions;
use super::window::{capture_window, unavailability_line, window_label};
use crate::ebpf::events::SockEvent;

/// The `--events-only` shape: the live event section, or the refusal.
pub(super) fn events_only_output(options: &PortOptions) -> String {
    match capture_window(options) {
        Some(events) => {
            let mut section = format_event_section(&events, options.window, options.no_pid);
            if udp_events_only(options) {
                section.push('\n');
                section.push_str(&udp_event_lane_note());
            }
            section
        }
        None => unavailability_line(options.window),
    }
}

/// Render an event's wall-clock time of day as `HH:MM:SS UTC` -
/// the civil clock module's monotonic companion owns the
/// arithmetic and the UTC-only law (night-improve-47 moved the
/// helper trio to one source; this is port's thin facade over it,
/// so the port window and the doctor's exit rows cannot drift).
fn event_time_of_day(event: &SockEvent) -> String {
    crate::info::clock::time_of_day_from_monotonic_ns(event.timestamp_ns)
}

/// The process name for a pid at render time, from the same
/// `/proc/<pid>/status` Name: field the snapshot's owner lines read -
/// one name source, two surfaces. `None` when the process is gone or
/// hidden: that event counts toward the unaccounted block.
fn event_pid_name(pid: u32) -> Option<String> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    let line = status.lines().find(|l| l.starts_with("Name:"))?;
    line.split_whitespace().nth(1).map(ToOwned::to_owned)
}

/// One event row: the [event] tag, the wall-clock time, the
/// protocol token, the wildcard address with the source port, the
/// transition label, the pid token, and the actor's name - one
/// renderer for the live-attributed and the post-mortem-attributed
/// rows alike, so a row named from the exit ring renders the same
/// shape a live-attributed row does.
fn event_row(event: &SockEvent, label: &str, proto: &str, name: String, no_pid: bool) -> String {
    let pid_part = if no_pid {
        String::new()
    } else {
        format!("  {} {}", crate::output::grey_out("PID"), event.pid)
    };
    // Roles: the [event] tag rides green (the kernel-recorded
    // transition, the strongest evidence this surface carries),
    // the event time rides grey (a timestamp), the protocol,
    // port, transition label, pid, and name stay unwrapped (the
    // values).
    format!(
        "{}  {}  {}  {}:{}  {}{}  ({})",
        crate::output::ok_out("[event]"),
        crate::output::grey_out(&event_time_of_day(event)),
        proto,
        "*",
        event.sport,
        label,
        pid_part,
        name
    )
}

/// True when the event window is filtered to UDP alone (--udp
/// without --tcp): the shape whose emptiness is a kernel fact, not
/// an observation.
pub(super) fn udp_events_only(options: &PortOptions) -> bool {
    options.udp && !options.tcp
}

/// The UDP-only event window's kernel truth (night-improve-61, the
/// micro-VM census): the sock probe rides the
/// sock/inet_sock_set_state tracepoint, and the kernel's UDP path
/// never routes through it - a UDP socket's state changes bypass
/// inet_sk_state_store, so a UDP lifecycle (open, send, close)
/// leaves no record on this lane (verified empirically on the
/// Alpine 6.12 floor kernel: zero tracepoint records for a full
/// UDP lifecycle with the event enabled). A UDP-only event window
/// is therefore empty by construction, and the honest shape says
/// so instead of rendering "(no events in the window)" as if the
/// window had listened and heard nothing. The snapshot lane still
/// carries UDP sockets (the /proc/net/udp parse) - the event lane
/// is the half the kernel does not offer.
pub(super) fn udp_event_lane_note() -> String {
    format!(
        "{} the kernel fires no lifecycle events for UDP sockets - this event lane is TCP-only; UDP sockets ride the snapshot",
        crate::output::grey_out("note:")
    )
}

/// The transition label for an event row: what the row says
/// happened. `None` when the record is not a port-surface
/// transition (the kernel-side filter is the same predicate - the
/// ring should never carry one - but the renderer refuses to invent
/// a label).
pub fn transition_label(protocol: u8, oldstate: u8, newstate: u8) -> Option<&'static str> {
    use crate::ebpf::events::{IPPROTO_TCP, IPPROTO_UDP, TCP_CLOSE, TCP_LISTEN};
    match protocol {
        IPPROTO_TCP if newstate == TCP_LISTEN => Some("ENTERED LISTEN"),
        IPPROTO_TCP if oldstate == TCP_LISTEN => Some("LEFT LISTEN"),
        IPPROTO_UDP if newstate == TCP_CLOSE => Some("CLOSED"),
        _ => None,
    }
}

/// The protocol+family token for an event row: `TCP4`/`TCP6`/`UDP4`/
/// `UDP6`. The event record carries no address - the bind address is
/// the snapshot's truth; the record carries the port and who changed
/// it - so the family rides the protocol token instead of hiding
/// (two events on the same port, one v4 and one v6, stay
/// distinguishable). `None` for anything the filter would have
/// dropped.
pub fn protocol_family_label(protocol: u8, family: u16) -> Option<&'static str> {
    use crate::ebpf::events::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP};
    match (protocol, family) {
        (IPPROTO_TCP, AF_INET) => Some("TCP4"),
        (IPPROTO_TCP, AF_INET6) => Some("TCP6"),
        (IPPROTO_UDP, AF_INET) => Some("UDP4"),
        (IPPROTO_UDP, AF_INET6) => Some("UDP6"),
        _ => None,
    }
}

/// The full event-window section: the Changes header, one row per
/// attributed event (ascending), and the unaccounted block that
/// names what neither source can see. Every event whose pid has no
/// visible /proc entry at render time is a post-mortem candidate
/// (night-improve-61): the exit ring may still name it - a
/// short-lived listener (an nc one-shot, a health-check bind, a
/// cron-opened socket) is gone from /proc before the query renders,
/// and the exit record that names it is the only survivor. Only an
/// event the exit ring cannot name either counts toward the
/// unaccounted block.
pub fn format_event_section(events: &[SockEvent], window: Duration, no_pid: bool) -> String {
    let mut lines = Vec::new();
    // The Changes header rides green (the section header).
    lines.push(crate::output::ok_out(&format!(
        "Changes in the last {}:",
        window_label(window)
    )));

    let mut unaccounted: usize = 0;
    // The rows keep the capture's ascending order (the renderer
    // never reorders), so each attributed event lands in a SLOT and
    // a post-mortem candidate parks its slot as None - the exit-ring
    // pass below fills the gaps IN PLACE.
    let mut slots: Vec<Option<String>> = Vec::new();
    let mut post_mortem: Vec<(usize, &SockEvent)> = Vec::new();
    for event in events {
        let Some(label) = transition_label(event.protocol, event.oldstate, event.newstate) else {
            // Not a port-surface transition (the ring contract says
            // this cannot happen; the renderer still refuses to
            // invent a row for it).
            continue;
        };
        let Some(proto) = protocol_family_label(event.protocol, event.family) else {
            continue;
        };
        let Some(name) = event_pid_name(event.pid) else {
            post_mortem.push((slots.len(), event));
            slots.push(None);
            continue;
        };
        slots.push(Some(event_row(event, label, proto, name, no_pid)));
    }

    // The exit-ring pass (night-improve-61): the same post-mortem
    // attribution the file lanes carry, the same shared match rule
    // (ebpf::ringbuf::exit_names_event) and the same comm shaper.
    // Drained ONLY when some event needs it: a fully-live window
    // never consumes the exit stream.
    if !post_mortem.is_empty() {
        let exits = match crate::ebpf::ringbuf::drain_proc_exits() {
            Ok(exits) => exits,
            Err(error) => {
                crate::output::verbose::vlog!(
                    "port",
                    "exit ring unavailable for post-mortem attribution: {error}"
                );
                Vec::new()
            }
        };
        for (slot, event) in post_mortem {
            match crate::ebpf::ringbuf::exit_names_event(&exits, event.pid, event.timestamp_ns) {
                Some(exit) => {
                    let name = crate::commands::doctor::memory::exits::comm_string(&exit.comm);
                    let label = transition_label(event.protocol, event.oldstate, event.newstate);
                    let proto = protocol_family_label(event.protocol, event.family);
                    if let (Some(label), Some(proto)) = (label, proto) {
                        slots[slot] = Some(event_row(event, label, proto, name, no_pid));
                    } else {
                        unaccounted += 1;
                    }
                }
                None => unaccounted += 1,
            }
        }
    }
    let rows: Vec<String> = slots.into_iter().flatten().collect();

    if rows.is_empty() {
        // The empty-window line rides grey (the locked scheme names
        // it explicitly).
        lines.push(crate::output::grey_out("  (no events in the window)"));
    } else {
        lines.extend(rows);
    }

    lines.push(String::new());
    lines.push(crate::output::ok_out("Unaccounted:"));
    // The boundary notes ride grey (hints, the locked scheme's
    // secondary content); the count is the value and stays unwrapped
    // - the same count-white/reason-grey split the ledger's
    // UnaccountedEntry rows apply.
    lines.push(format!(
        "{}{unaccounted}{}",
        crate::output::grey_out("  "),
        crate::output::grey_out(
            " events in the window with no visible PID (namespace boundary or\n  exited before attribution)"
        )
    ));
    lines.push(crate::output::grey_out(
        "  Snapshot and event window can disagree - that is the point; the\n  snapshot is the state at this instant, the window is what changed.",
    ));
    lines.join("\n")
}

#[cfg(test)]
#[path = "../../../test/commands/port/events_tests.rs"]
mod tests;
