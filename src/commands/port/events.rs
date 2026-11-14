// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
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
use crate::ebpf::events::{ProcExitEvent, SockEvent};

/// The `--events-only` shape: the live event section, or the refusal.
pub(super) fn events_only_output(options: &PortOptions) -> String {
    match capture_window(options) {
        Ok(capture) => {
            let mut section = format_event_section(
                &capture.events,
                options.window,
                options.no_pid,
                capture.bounds,
                capture.pre_offset,
            );
            if udp_events_only(options) {
                section.push('\n');
                section.push_str(&udp_event_lane_note());
            }
            section
        }
        // Every not-live shape renders the same refusal sentence it
        // always has (the text lane's behavior is unchanged; the
        // JSON lane is where the actual cause is named).
        Err(_) => unavailability_line(options.window),
    }
}

/// Render an event's wall-clock time of day as `HH:MM:SS UTC` -
/// the civil clock module's monotonic companion owns the
/// arithmetic and the UTC-only law (night-improve-47 moved the
/// helper trio to one source; this is port's thin facade over it,
/// so the port window and the doctor's exit rows cannot drift).
fn event_time_of_day(event: &SockEvent, offset: Option<i128>) -> String {
    crate::info::clock::time_of_day_with_offset(event.timestamp_ns, offset)
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
fn event_row(
    event: &SockEvent,
    label: &str,
    proto: &str,
    name: String,
    no_pid: bool,
    offset: Option<i128>,
) -> String {
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
        crate::output::grey_out(&event_time_of_day(event, offset)),
        proto,
        "*",
        event.sport,
        label,
        pid_part,
        name
    )
}

/// The protocol+family token for the teardown branch's rows: the
/// same token the event rows render, recomputed for a parked
/// post-mortem event (the first pass already proved it readable).
fn proto_family_of(event: &SockEvent) -> Option<&'static str> {
    protocol_family_label(event.protocol, event.family)
}

/// The teardown-lag row (the night-dragon-lts-T1 residual): the
/// event_row shape riding [observed] - grey, the exit ring's record
/// is the evidence, not the kernel's live /proc answer - with the
/// measured lag named in grey after the actor. The lag is the
/// truth this row exists to carry: the exit fired first, the
/// socket's teardown trailed it, and the number says by how much.
fn teardown_lag_row(
    event: &SockEvent,
    proto: &str,
    name: &str,
    no_pid: bool,
    lag_ns: u64,
    offset: Option<i128>,
) -> String {
    let pid_part = if no_pid {
        String::new()
    } else {
        format!("  {} {}", crate::output::grey_out("PID"), event.pid)
    };
    format!(
        "{}  {}  {}  {}:{}  {}{}  ({})  {}",
        crate::output::grey_out("[observed]"),
        crate::output::grey_out(&event_time_of_day(event, offset)),
        proto,
        "*",
        event.sport,
        "LEFT LISTEN",
        pid_part,
        name,
        crate::output::grey_out(&format!(
            "attribution from post-mortem exit ring (socket teardown lag: \
             exit fired {} before LEFT LISTEN)",
            format_lag(lag_ns)
        ))
    )
}

/// The lag in whole milliseconds - the one number both lanes render:
/// this file's "Xms"/"under 1ms" note and the JSON row's typed
/// `lag_ms` integer. One arithmetic, two renderings, no drift
/// between the formats.
pub(super) fn lag_whole_ms(lag_ns: u64) -> u64 {
    lag_ns / 1_000_000
}

/// The lag as the note reads it: whole milliseconds from 1 up,
/// "under 1ms" below that - the truth without false-precision
/// decimals.
fn format_lag(lag_ns: u64) -> String {
    match lag_whole_ms(lag_ns) {
        0 => "under 1ms".to_owned(),
        ms => format!("{ms}ms"),
    }
}

/// The post-mortem verdict for one parked event, decided ONCE for
/// both renderers (the night-dragon-lts-T1 residual, now shared):
/// the text section and the JSON lane consume the same decision, so
/// the two outputs cannot tell different stories about the same
/// evidence. The matchers themselves stay in ebpf::ringbuf,
/// untouched - this is the order they are consulted in and the
/// envelope they are consulted under, in one place.
pub(super) enum PostMortemVerdict<'a> {
    /// The strict at-or-after rule names the actor (the
    /// night-improve-61 rule every live lane keeps).
    AtOrAfter(&'a ProcExitEvent),
    /// The LEFT LISTEN-only teardown-lag envelope names the actor,
    /// with the measured lag in nanoseconds - the number both lanes
    /// render ([observed] in text, `lag_ms` in JSON).
    TeardownLag(&'a ProcExitEvent, u64),
    /// No exit record names the event under either rule. The flag
    /// carries whether the prose note applies - the teardown race
    /// story is LEFT LISTEN's alone; every other transition is a
    /// bare count.
    Miss { left_listen: bool },
}

/// The verdict for one post-mortem candidate: the strict rule
/// first, the LEFT LISTEN-only teardown-lag fallback second, the
/// honest miss otherwise. The single source of truth behind the
/// parity law - same events, same exits, same verdict in text and
/// JSON. The exit-ring slice comes in pre-drained (the callers'
/// seam forms carry it) so the decision itself never touches I/O.
pub(super) fn post_mortem_verdict<'a>(
    exits: &'a [ProcExitEvent],
    event: &SockEvent,
) -> PostMortemVerdict<'a> {
    if let Some(exit) = crate::ebpf::ringbuf::exit_names_event(exits, event.pid, event.timestamp_ns)
    {
        return PostMortemVerdict::AtOrAfter(exit);
    }
    let is_left_listen =
        transition_label(event.protocol, event.oldstate, event.newstate) == Some("LEFT LISTEN");
    if is_left_listen
        && let Some((exit, lag_ns)) = crate::ebpf::ringbuf::exit_names_event_after_teardown(
            exits,
            event.pid,
            event.timestamp_ns,
        )
    {
        return PostMortemVerdict::TeardownLag(exit, lag_ns);
    }
    PostMortemVerdict::Miss {
        left_listen: is_left_listen,
    }
}

/// The honest miss's prose - the one sentence both lanes speak: the
/// text note appends it after "LEFT LISTEN — ", the JSON row carries
/// it typed as `race_note`. One constant, byte-identical in both
/// outputs (the parity law: same evidence, same words, whatever the
/// output format).
pub(super) const LEFT_LISTEN_RACE_NOTE: &str = "no matching exit event \
(process exited before teardown; race window by kernel ordering)";

/// The honest LEFT LISTEN miss (the residual's second branch): the
/// exit ring holds no record that names the event even within the
/// teardown envelope - the process exited before the teardown could
/// be recorded against it, and inventing an actor would be a lie.
/// One grey row per miss, under the count.
fn left_listen_miss_note(event: &SockEvent, proto: &str, offset: Option<i128>) -> String {
    format!(
        "  {}  {}  {}  {}:{}  LEFT LISTEN — {LEFT_LISTEN_RACE_NOTE}",
        crate::output::grey_out("[unaccounted]"),
        crate::output::grey_out(&event_time_of_day(event, offset)),
        proto,
        "*",
        event.sport,
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

/// The wall-clock skew line (night-frontier-Z2): one grey row for a
/// wall clock that demonstrably moved across the capture, the signed
/// movement named and the rows' exposure said. The count-backed zero
/// class does not apply: the movement HAPPENED (the compare already
/// gated it at the half-second bound), so the line always renders.
/// Pure, pinnable without two live clock reads.
fn wall_skew_line(skew_ns: i128) -> String {
    format!(
        "{}{skew_ns:+}{}",
        crate::output::grey_out("  "),
        crate::output::grey_out(
            " ns of wall-clock skew measured across this capture (beyond the\n  500 ms bound) - the times above render under the post-capture offset and\n  can sit that far from the times the events happened at"
        )
    )
}

/// The sock ring's drop-truth line (night-frontier-Z1): one grey
/// row for the reserve failures, `None` when the count is zero (the
/// count-backed boundary class - the boundary exists only when it
/// fired). Pure, so the wording and the threshold are pinnable
/// without a pinned map (the lane.rs file_ring_drop_entry
/// precedent).
fn ring_drop_line(drops: u64) -> Option<String> {
    (drops > 0).then(|| {
        format!(
            "{}{drops}{}",
            crate::output::grey_out("  "),
            crate::output::grey_out(
                " sock_events ring drops since attach (the camera saw\n  transitions the ring could not hold; the window above may be missing events the same way)"
            )
        )
    })
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
pub fn format_event_section(
    events: &[SockEvent],
    window: Duration,
    no_pid: bool,
    bounds: Option<(u64, u64)>,
    pre_offset: Option<i128>,
) -> String {
    // The ring is drained ONLY when some event needs it: a fully
    // live window never consumes the exit stream. The seam form
    // below carries the drained records so the tests can pin the
    // attribution paths hermetically.
    let needs_exit_ring = events
        .iter()
        .any(|event| event_pid_name(event.pid).is_none());
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
    // The drop census (night-frontier-Z1): the sock ring's own
    // reserve failures, read beside the exit ring so the section's
    // Unaccounted block names what the camera saw but could not
    // hold. An unreadable census is the verbose trace, never a
    // guessed zero.
    let ring_drops = match crate::ebpf::readback::read_drop_census() {
        Ok(census) => Some(census.sock),
        Err(error) => {
            crate::output::verbose::vlog!("port", "drop census unreadable: {error}");
            None
        }
    };
    format_event_section_with_exits(
        events,
        window,
        no_pid,
        bounds,
        exits.as_deref(),
        ring_drops,
        pre_offset,
    )
}

/// The seam form: the same section with the drained exit records
/// injected (the test seam, the format_path_report_with pattern).
/// `None` means the caller never needed the ring; an empty slice
/// means the ring was drained and held nothing - the two are the
/// same attribution outcome (nothing to name) but different
/// consumption contracts. `bounds` rides the observed window the
/// capture bracketed (see [`window_range`]): `Some` puts the range
/// in the header and the empty line, `None` keeps the locked
/// range-less shapes. `ring_drops` is the seam's drop-truth axis
/// (night-frontier-Z1): `None` when the census did not answer, the
/// sock ring's cumulative reserve-failure count when it did - the
/// line renders only when the count is nonzero.
pub fn format_event_section_with_exits(
    events: &[SockEvent],
    window: Duration,
    no_pid: bool,
    bounds: Option<(u64, u64)>,
    exits: Option<&[ProcExitEvent]>,
    ring_drops: Option<u64>,
    pre_offset: Option<i128>,
) -> String {
    // ONE render breath (night-frontier-Z2, the wall-offset skew
    // law): the offset every row and the header range render under,
    // sampled once - and the skew it measures against the capture's
    // PRE sample, named in the Unaccounted block when it moves
    // beyond the half-second bound. Two rows can never disagree
    // because a wall clock step fell between their reads.
    let render_offset = crate::info::clock::wall_offset_ns();
    let skew = crate::info::clock::material_skew_ns(pre_offset, render_offset);
    let range = match (bounds, render_offset) {
        (Some((start, end)), Some(offset)) => Some((
            crate::info::clock::time_of_day_with_offset(start, Some(offset)),
            crate::info::clock::time_of_day_with_offset(end, Some(offset)),
        )),
        _ => None,
    };
    let mut lines = Vec::new();
    // The Changes header rides green (the section header). With the
    // observed bounds the header names WHICH window: two sequential
    // runs watch two different windows, and the boundaries say so.
    lines.push(crate::output::ok_out(&match &range {
        Some((start, end)) => {
            format!(
                "Changes in the last {} ({start} → {end}):",
                window_label(window)
            )
        }
        None => format!("Changes in the last {}:", window_label(window)),
    }));

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
        slots.push(Some(event_row(
            event,
            label,
            proto,
            name,
            no_pid,
            render_offset,
        )));
    }

    // The exit-ring pass (night-improve-61): the same post-mortem
    // attribution the file lanes carry, the same shared match rule
    // (ebpf::ringbuf::exit_names_event) and the same comm shaper.
    // The LEFT LISTEN branch adds the teardown-lag fallback (the
    // night-dragon-lts-T1 residual): socket teardown can trail the
    // process's own death, so an exit stamped a beat BEFORE the
    // event - within the bounded 250ms envelope - still names the
    // row, as [observed] with the measured lag; a LEFT LISTEN the
    // ring cannot name at all renders the race note instead of a
    // bare count. Every other transition keeps the strict rule: no
    // exit at or after the event, no attribution.
    let exits: &[ProcExitEvent] = exits.unwrap_or(&[]);
    let mut left_listen_misses: Vec<String> = Vec::new();
    for (slot, event) in post_mortem {
        // The shared verdict (the parity law): the same decision the
        // JSON lane renders, in one place - this pass only shapes the
        // row the verdict names.
        match post_mortem_verdict(exits, event) {
            PostMortemVerdict::AtOrAfter(exit) => {
                let name = crate::commands::doctor::memory::exits::comm_string(&exit.comm);
                let label = transition_label(event.protocol, event.oldstate, event.newstate);
                let proto = protocol_family_label(event.protocol, event.family);
                if let (Some(label), Some(proto)) = (label, proto) {
                    slots[slot] = Some(event_row(event, label, proto, name, no_pid, render_offset));
                } else {
                    unaccounted += 1;
                }
            }
            PostMortemVerdict::TeardownLag(exit, lag_ns) => {
                let name = crate::commands::doctor::memory::exits::comm_string(&exit.comm);
                match proto_family_of(event) {
                    Some(proto) => {
                        slots[slot] = Some(teardown_lag_row(
                            event,
                            proto,
                            &name,
                            no_pid,
                            lag_ns,
                            render_offset,
                        ));
                    }
                    None => unaccounted += 1,
                }
            }
            PostMortemVerdict::Miss { left_listen } => {
                unaccounted += 1;
                if left_listen && let Some(proto) = proto_family_of(event) {
                    left_listen_misses.push(left_listen_miss_note(event, proto, render_offset));
                }
            }
        }
    }
    let rows: Vec<String> = slots.into_iter().flatten().collect();

    if rows.is_empty() {
        // The empty-window line rides grey (the locked scheme names
        // it explicitly) - and with the observed bounds it names
        // WHICH window came up empty, so an empty window still
        // tells itself apart from the next run's empty window.
        lines.push(crate::output::grey_out(&match &range {
            Some((start, end)) => format!("  (no events in the window: {start} → {end})"),
            None => "  (no events in the window)".to_owned(),
        }));
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
    // The drop truth (night-frontier-Z1): the sock ring's own
    // reserve failures, named when the census answered and the count
    // is nonzero - the count-backed boundary class, one grey row
    // beside the attribution boundary above. Cumulative since
    // attach: the camera's lifetime total, not this window's share
    // (a fresh process inherits no previous count), so the line
    // says what the number IS.
    if let Some(line) = ring_drops.and_then(ring_drop_line) {
        lines.push(line);
    }
    // The wall-clock skew boundary (night-frontier-Z2): a state
    // boundary - it rides whenever the measurement answered, the
    // "1 event window (...)" class, the signed movement named and
    // the rows' exposure said plainly.
    if let Some(skew) = skew {
        lines.push(wall_skew_line(skew));
    }
    // The LEFT LISTEN race notes (the night-dragon-lts-T1 residual):
    // each miss names itself instead of hiding in the count - the
    // kernel's teardown ordering, said plainly, one grey row per
    // event the ring could not reach.
    for note in &left_listen_misses {
        lines.push(note.clone());
    }
    lines.push(crate::output::grey_out(
        "  Snapshot and event window can disagree - that is the point; the\n  snapshot is the state at this instant, the window is what changed.",
    ));
    lines.join("\n")
}

#[cfg(test)]
#[path = "../../../test/commands/port/events_tests.rs"]
mod tests;
