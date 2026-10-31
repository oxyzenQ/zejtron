// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The port surface's event window (night-improve-2): the second
//! truth. The snapshot (the /proc parse, unchanged) says what IS;
//! the event window says what CHANGED - which sockets entered or
//! left LISTEN (TCP) or were closed (UDP) in the last N seconds,
//! with the pid of the process that made the change, recorded
//! in-kernel at the moment it happened. The race condition that
//! haunted /proc parsing stops mattering: the window already
//! recorded who made the change, at the moment it happened.
//!
//! The provenance ledger is minimal by design (phase 3 formalizes
//! the full Evidence Ledger): every row carries exactly one prefix -
//! `[snapshot]` for the state at the instant of the query, `[event]`
//! for a recorded transition - and the unaccounted block names what
//! neither source can see.
//!
//! The fallback contract (the one the battery pins byte-for-byte):
//! without the ebpf feature, or without a live chain (no root, not
//! attached), `port` is the snapshot-only tool phase 1 shipped - the
//! same tree output, the same flags, nothing degraded and nothing
//! upgraded. The event window appears only when the chain can
//! actually capture events, and the explicit request a run cannot
//! serve (`--events-only` without a live chain) gets the named
//! refusal line, never a silent empty section.
//!
//! The lane-independent half (the grammar, the clamp, the refusal)
//! compiles in every build; the capture and the live rendering
//! compile only under the ebpf feature. The two halves meet in
//! [`format_port_output`], whose signature is lane-independent so
//! the run() dispatch cannot tell the builds apart.

use std::time::Duration;

use super::model::{OwnerMap, PortError, PortOptions, ScanStats, SocketEntry};
use super::render::format_report;

// The live-rendering half's imports - compiled only when the reader
// and the renderer exist.
use super::model::{ProcessInfo, Protocol};
use super::render::append_note;
use crate::output::spinner::Countdown;
use std::time::Instant;

/// The window floor: a zero or sub-second window is not a window.
pub const WINDOW_FLOOR: Duration = Duration::from_secs(1);

/// The window ceiling: an hour. A longer window than that is a
/// log-shaped problem, not an evidence-shaped one.
pub const WINDOW_CEILING: Duration = Duration::from_secs(3600);

/// The default window when `--since` is absent: one minute.
pub const WINDOW_DEFAULT: Duration = Duration::from_secs(60);

// ── The window grammar (lane-independent) ──────────────────────────

/// Parse a `--since` duration: an integer plus one unit from
/// `s`/`m`/`h` (`60s`, `5m`, `1h`). Deliberately NOT recent's
/// parser: that one speaks the file-age grammar (`m`/`h`/`d` - days
/// are meaningless inside a one-hour window, seconds are meaningless
/// for file ages); this one speaks the window grammar, and the two
/// surfaces keep their own grammars rather than sharing a
/// lowest-common denominator that serves neither.
pub fn parse_window(input: &str) -> Result<Duration, PortError> {
    let invalid = || PortError(format!("invalid duration: {input}"));
    // The unit is the final CHARACTER, never the final byte
    // (night-dragon-lts-1): str::split_at panics when its index
    // lands inside a multibyte character, so a `--since 5分` or a
    // bare `é` - any input whose last byte is not a char boundary -
    // crashed the CLI instead of being rejected. Peeling the last
    // char off through chars() keeps every multibyte unit a clean
    // parse error: the amount slice ends on a char boundary by
    // construction, and the unit arm comparison moves from &str to
    // char. The two-char minimum the old len() check enforced
    // survives structurally: an empty input has no last char, and a
    // bare unit leaves an empty amount that parse() refuses.
    let Some(unit) = input.chars().next_back() else {
        return Err(invalid());
    };
    let amount = &input[..input.len() - unit.len_utf8()];
    let amount: u64 = amount.parse().map_err(|_| invalid())?;
    // Saturating on purpose (night-total-lts-1): a parsed u64 times
    // the unit multiplier can overflow (an absurd "18446744073709551h"
    // asks for more seconds than a u64 holds), and the wrapping
    // product was not the clamp's contract - a wrapped value can
    // land anywhere, including inside the window floor. Saturating
    // sends every absurd ask to the ceiling, which clamp_window
    // then shapes into the honest 1h maximum; debug builds (the
    // test lane) panicked on the same input before the fix.
    match unit {
        's' => Ok(Duration::from_secs(amount)),
        'm' => Ok(Duration::from_secs(amount.saturating_mul(60))),
        'h' => Ok(Duration::from_secs(amount.saturating_mul(3600))),
        _ => Err(invalid()),
    }
}

/// Clamp the window into [1s, 3600s]: `0s` becomes `1s`, `2h`
/// becomes `1h`. The clamp is the contract, so every lane agrees on
/// what a window means no matter what was asked.
pub fn clamp_window(window: Duration) -> Duration {
    window.clamp(WINDOW_FLOOR, WINDOW_CEILING)
}

/// The window as a compact label: whole hours as `1h`, whole
/// minutes above a minute as `5m`, everything else in seconds -
/// and the 60s default stays `60s` (the shape the spec's locked
/// format prints). One shape, both headers, no drift.
pub fn window_label(window: Duration) -> String {
    let secs = window.as_secs();
    if secs != 0 && secs.is_multiple_of(3600) {
        format!("{}h", secs / 3600)
    } else if secs > 60 && secs.is_multiple_of(60) {
        format!("{}m", secs / 60)
    } else {
        format!("{secs}s")
    }
}

/// The refusal line: the explicit event request this run cannot
/// serve. One shape for every reason (featureless binary, no root,
/// chain not attached) - the sentence names them all, and the
/// doctor's \[eBPF\] section names the exact one. The sentence's
/// single source lives in the evidence renderer
/// (crate::evidence::render::unavailability_line); this is the
/// Duration-taking facade port's callers speak, so the two
/// surfaces cannot drift apart again.
pub fn unavailability_line(window: Duration) -> String {
    crate::evidence::render::unavailability_line(&window_label(window))
}

// ── The output assembly (lane-independent signature) ───────────────

/// The full port output for this run.
///
/// - `--snapshot-only`: the phase-1 tree, byte-identical, in every
///   lane - the escape hatch that never changes.
/// - `--events-only`: the event section when the chain is live, the
///   named refusal when it is not.
/// - default: the window report (snapshot rows + event section +
///   unaccounted) when the chain is live; the phase-1 tree otherwise.
pub fn format_port_output(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
) -> String {
    if options.snapshot_only {
        return format_report(sockets, owners, stats, options);
    }
    if options.events_only {
        return events_only_output(options);
    }
    default_output(sockets, owners, stats, options)
}

/// The `--events-only` shape: the live event section, or the refusal.
fn events_only_output(options: &PortOptions) -> String {
    match capture_window(options) {
        Some(events) => format_event_section(&events, options.window, options.no_pid),
        None => unavailability_line(options.window),
    }
}

/// The default shape: both truths when the chain is live, the
/// phase-1 snapshot tree when it is not.
fn default_output(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
) -> String {
    match capture_window(options) {
        Some(events) => format_window_report(sockets, owners, stats, options, &events),
        None => format_report(sockets, owners, stats, options),
    }
}

// ── The capture and the live rendering (feature builds only) ───────

use crate::ebpf::events::SockEvent;

/// Capture the window: the pin state first (a partial chain is not a
/// live chain - `doctor --attach` heals it), then the collection, then
/// the window/protocol/port filters. `None` is every not-live shape;
/// the caller renders the fallback, and the refusal line (when the
/// user asked explicitly) names the doctor as the place the exact
/// reason lives.
pub fn capture_window(options: &PortOptions) -> Option<Vec<SockEvent>> {
    if !crate::ebpf::all_pins_present() {
        // The diagnostic trace (night-hunter-4): stderr only - the
        // port report's stdout stays pipe-clean.
        crate::output::verbose::vlog!("lane", "snapshot only (eBPF not attached)");
        return None;
    }
    crate::output::verbose::vlog!("lane", "live eBPF window selected (attached)");
    let mut ring = crate::ebpf::ringbuf::open_sock_ring().ok()?;
    let mut collected: Vec<SockEvent> = Vec::new();
    collect_over_window(&mut ring, &mut collected, options.window);
    Some(window_events(&collected, options))
}

/// The drain slice: how often the collection wakes to empty the ring
/// while it waits. Short enough that a busy host cannot overflow the
/// ring's 8192 records between two drains, long enough that the
/// wakeup cost is noise next to the wait itself.
const POLL_SLICE: Duration = Duration::from_millis(100);

/// Collect over the window's duration - the wait IS the collection
/// (night-improve-4, Fix 2: the same grammar holds/touch/why already
/// speak; their live lane sleeps the window because the filter map
/// only lets events cross while the key is planted, and the port
/// surface now waits for the same reason the label is only honest
/// after the wait: "Changes in the last Ns" is a claim, and the
/// claim is only true when the last Ns were actually watched).
///
/// The ring is kept OPEN for the whole wait and drained slice by
/// slice: the first drain takes whatever history the ring held (the
/// events since the previous drain, or since attach), every later
/// drain takes what crossed while we slept, and the cutoff filter in
/// [`window_events`] cuts the union to the requested window. The
/// rolling cap bounds the Vec no matter how busy the host was. No
/// daemon, no reader beyond the command's own lifetime - the pump
/// exists for exactly this wait and dies with it.
fn collect_over_window(
    ring: &mut aya::maps::RingBuf<aya::maps::MapData>,
    out: &mut Vec<SockEvent>,
    window: Duration,
) {
    // The narration (night-hunter-6): the loop already wakes every
    // slice to drain the ring; the countdown rides the same clock
    // and never touches the report's stdout.
    let mut countdown = Countdown::start("watching for socket events");
    let deadline = Instant::now() + window;
    loop {
        crate::ebpf::ringbuf::drain_sock_events_from(ring, out);
        let now = Instant::now();
        if now >= deadline {
            break;
        }
        countdown.update(deadline - now);
        std::thread::sleep(POLL_SLICE.min(deadline - now));
    }
    countdown.finish();
}

/// Filter the collected events to the requested window and selection,
/// ascending by timestamp. The clock arithmetic is CLOCK_MONOTONIC
/// end to end: the records are `bpf_ktime_get_ns` stamps, and "now"
/// comes from /proc/uptime - the std-only monotonic source (10 ms
/// resolution, and boottime-inclusive: on a host that suspended, the
/// computed cutoff sits slightly EARLY, so a boundary event survives
/// that strict monotonic would drop - the error direction that
/// over-includes, never under-reports).
///
/// One semantic rides on the collection itself: a ring buffer read
/// CONSUMES (the consumer position lives in the kernel map), so the
/// collected set is the ring's history (since the previous drain or
/// attach) plus everything that crossed during the wait - and the
/// cutoff narrows that union to the requested window. Since the wait
/// itself covers the full window, the label below is backed by real
/// observation, end to end. No daemon, no persistent reader - the
/// honest shape of a command-lifetime pump.
fn window_events(events: &[SockEvent], options: &PortOptions) -> Vec<SockEvent> {
    use crate::ebpf::events::{IPPROTO_TCP, IPPROTO_UDP};
    let now_ns = crate::info::clock::monotonic_now_ns();
    let cutoff_ns = now_ns.map(|now| now.saturating_sub(options.window.as_nanos() as u64));

    let mut selected: Vec<_> = events
        .iter()
        // Defense in depth: the kernel-side filter is this same
        // predicate (one file, both sides), but the host refuses to
        // render what a ring should never have carried - a record
        // that is not a port-surface transition dies here too.
        .filter(|event| {
            crate::ebpf::events::is_port_surface_event(
                event.family,
                event.protocol,
                event.oldstate,
                event.newstate,
            )
        })
        .filter(|event| match cutoff_ns {
            Some(cutoff) => event.timestamp_ns >= cutoff,
            // No readable clock: keep the drained events rather than
            // guessing a cutoff - the ring is bounded, and the label
            // still names the requested window.
            None => true,
        })
        .filter(|event| {
            let include_tcp = options.tcp || !options.udp;
            let include_udp = options.udp || !options.tcp;
            match event.protocol {
                IPPROTO_TCP => include_tcp,
                IPPROTO_UDP => include_udp,
                _ => false,
            }
        })
        .filter(|event| options.port.is_none_or(|port| event.sport == port))
        .copied()
        .collect();
    selected.sort_by_key(|event| event.timestamp_ns);
    selected
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

/// The window report: the snapshot rows (the same filtered sockets
/// phase 1 renders, flat, `[snapshot]`-prefixed, TCP block first),
/// the event section, and the unreadable note when the scan hit
/// walls - the note is snapshot honesty, and it survives the format
/// change.
fn format_window_report(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
    events: &[SockEvent],
) -> String {
    let mut lines = Vec::new();
    // The window header rides green (the section header).
    lines.push(crate::output::ok_out(&format!(
        "Ports (window {}):",
        window_label(options.window)
    )));
    lines.push(String::new());
    lines.extend(snapshot_rows(sockets, owners, options));
    lines.push(String::new());
    lines.push(format_event_section(events, options.window, options.no_pid));
    append_note(&mut lines, stats);
    lines.join("\n")
}

/// The `[snapshot]` rows: the phase-1 socket selection (the same
/// filters, the same sort), flat rows instead of the tree, TCP
/// first then UDP (the spec's grouping). `--group` collapses
/// repeated rows with the same ×N suffix the tree uses; `--no-pid`
/// drops the PID token; an ownerless row names `owner unknown`
/// exactly as the tree's owner lines do.
fn snapshot_rows(sockets: &[SocketEntry], owners: &OwnerMap, options: &PortOptions) -> Vec<String> {
    let by_phase_sort = |left: &SocketEntry, right: &SocketEntry| {
        left.port
            .cmp(&right.port)
            .then(left.address.cmp(&right.address))
    };

    let mut rows: Vec<String> = Vec::new();
    if options.group {
        let groups = super::render::group_sockets(sockets, owners);
        for protocol in [Protocol::Tcp, Protocol::Udp] {
            let mut block: Vec<_> = groups
                .iter()
                .filter(|group| group.socket.protocol == protocol)
                .collect();
            block.sort_by(|left, right| by_phase_sort(&left.socket, &right.socket));
            for group in block {
                rows.push(snapshot_row(
                    protocol,
                    &group.socket,
                    &group.owners,
                    options,
                    Some(group.count),
                ));
            }
        }
        return rows;
    }

    for protocol in [Protocol::Tcp, Protocol::Udp] {
        let mut block: Vec<_> = sockets
            .iter()
            .filter(|socket| socket.protocol == protocol)
            .collect();
        block.sort_by(|left, right| by_phase_sort(left, right));
        for socket in block {
            let socket_owners = owners.get(&socket.inode).cloned().unwrap_or_default();
            rows.push(snapshot_row(
                protocol,
                socket,
                &socket_owners,
                options,
                None,
            ));
        }
    }
    rows
}

/// One `[snapshot]` row. The endpoint formatting matches the tree's
/// `format_socket` (IPv6 addresses bracketed), the state token rides
/// when /proc carried one, and the owner tail is `PID a, b  (name,
/// name)` - or `owner unknown`, the tree's own honesty.
fn snapshot_row(
    protocol: Protocol,
    socket: &SocketEntry,
    owners: &[ProcessInfo],
    options: &PortOptions,
    group_count: Option<usize>,
) -> String {
    let endpoint = if socket.address.contains(':') {
        format!("[{}]:{}", socket.address, socket.port)
    } else {
        format!("{}:{}", socket.address, socket.port)
    };
    // Roles (night-improve-37): the [snapshot] tag rides grey - the
    // manual check pins it there, and it is the weaker evidence (a
    // /proc parse at this instant); the protocol, endpoint, state,
    // and owner tokens are the values and stay unwrapped; the group
    // count rides grey (an annotation); the owner-absence token rides
    // grey (the "no events" class). In Mono every wrap is the
    // identity, byte-identical to the pinned shape.
    let mut row = format!(
        "{}  {}  {}",
        crate::output::grey_out("[snapshot]"),
        match protocol {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
        },
        endpoint
    );
    if let Some(state) = &socket.state {
        row.push_str("  ");
        row.push_str(state);
    }
    if let Some(count) = group_count.filter(|count| *count > 1) {
        row.push_str(&format!(
            " {}",
            crate::output::grey_out(&format!("×{count}"))
        ));
    }
    if owners.is_empty() {
        row.push_str(&format!("  {}", crate::output::grey_out("owner unknown")));
    } else {
        let names: Vec<&str> = owners.iter().map(|o| o.name.as_str()).collect();
        if options.no_pid {
            row.push_str(&format!("  ({})", names.join(", ")));
        } else {
            let pids: Vec<String> = owners.iter().map(|o| o.pid.to_string()).collect();
            row.push_str(&format!(
                "  {} {}  ({})",
                crate::output::grey_out("PID"),
                pids.join(", "),
                names.join(", ")
            ));
        }
    }
    row
}

/// The full event-window section: the Changes header, one row per
/// attributed event (ascending), and the unaccounted block that
/// names what neither source can see. Every event whose pid has no
/// visible /proc entry at render time counts toward the unaccounted
/// block - a namespace boundary or an exit between the change and
/// the query.
pub fn format_event_section(events: &[SockEvent], window: Duration, no_pid: bool) -> String {
    let mut lines = Vec::new();
    // The Changes header rides green (the section header).
    lines.push(crate::output::ok_out(&format!(
        "Changes in the last {}:",
        window_label(window)
    )));

    let mut unaccounted: usize = 0;
    let mut rows: Vec<String> = Vec::new();
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
            unaccounted += 1;
            continue;
        };
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
        rows.push(format!(
            "{}  {}  {}  {}:{}  {}{}  ({})",
            crate::output::ok_out("[event]"),
            crate::output::grey_out(&event_time_of_day(event)),
            proto,
            "*",
            event.sport,
            label,
            pid_part,
            name
        ));
    }

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
#[path = "../../../test/commands/port/window_tests.rs"]
mod tests;
