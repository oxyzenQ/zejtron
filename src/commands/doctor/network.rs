// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The network symptom (night-improve-48): "who is eating my
//! bandwidth, why are my ports stalling?" answered by a
//! 1.0-second delta sample of the kernel's own network tables. Two
//! /proc/net/dev reads (per-interface byte/packet deltas), one
//! /proc/net/tcp + tcp6 walk (the socket-state census - TIME_WAIT
//! and CLOSE_WAIT are the two stall signatures), one /proc/<pid>/fd
//! walk (which process holds how many sockets), one sleep, one
//! Evidence Ledger, exit.
//!
//! Every count is permission-honest: another user's fd table is
//! unreadable and counted into the Unaccounted block, never
//! silently dropped.

use super::delta::{self, SAMPLE_WINDOW_DESC};
use super::memory::exits::ExitLane;
use super::memory::pid_dirs;
use crate::output::noun_for;
use std::collections::BTreeMap;
use std::time::SystemTime;

/// The row cap for the per-surface tables - the ledger's own TOP_N.
const TOP_N: usize = 10;

/// The port-exhaustion boundary: TIME_WAIT sockets above this count
/// are the named risk (a named boundary, not a mood - the ephemeral
/// port range is c. 28 thousand wide, and a thousand-plus sockets
/// parked in TIME_WAIT is the shape of a churning connector).
/// pub(crate) since night-dragon-lts-2: the umbrella symptom's
/// socket-churn finding rides the same named boundary, one number,
/// no drift.
pub(crate) const PORT_EXHAUSTION_RISK: usize = 1024;

/// The CLOSE_WAIT pile boundary the umbrella symptom rides: sockets
/// parked in CLOSE_WAIT are ones the remote end closed and a local
/// process never did - a handful is a race, a pile is an app not
/// closing its sockets. 32 is the named boundary (a power of two
/// far above the close() racing floor, far below the fd table's
/// usual 1024 ceiling).
pub(crate) const CLOSE_WAIT_PILE: usize = 32;

/// One interface's window delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IfRow {
    pub name: String,
    pub rx_bytes: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub tx_packets: u64,
}

impl IfRow {
    fn total(&self) -> u64 {
        self.rx_bytes
            .saturating_add(self.tx_bytes)
            .saturating_add(self.rx_packets)
            .saturating_add(self.tx_packets)
    }
}

/// One socket holder: the pid and the count of its socket fds at
/// the census instant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HolderRow {
    pub pid: u32,
    pub comm: String,
    pub sockets: usize,
}

/// The socket-state census across /proc/net/tcp and tcp6.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct SocketStates {
    pub total: usize,
    pub established: usize,
    pub time_wait: usize,
    pub close_wait: usize,
}

/// The whole network sample: everything the report rode on.
#[derive(Debug, Clone, Default)]
pub(crate) struct NetworkSample {
    pub sampled_at: String,
    /// Interfaces with a nonzero window delta, descending by total,
    /// then by name (deterministic).
    pub interfaces: Vec<IfRow>,
    pub sockets: SocketStates,
    /// Top socket holders, descending by count then pid, capped.
    pub holders: Vec<HolderRow>,
    /// Other users' fd tables this invocation may not read.
    pub fd_permission_refused: usize,
    pub exit_lane: ExitLane,
}

/// Parse one /proc/net/dev data line ("iface: rx tx ...") - 16
/// numeric fields after the colon. None for headers and malformed
/// lines (the caller skips, never guesses).
pub(crate) fn parse_net_dev_line(line: &str) -> Option<(String, IfRow)> {
    let (name, rest) = line.split_once(':')?;
    let name = name.trim().to_owned();
    if name.is_empty() {
        return None;
    }
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() < 12 {
        return None;
    }
    let num = |i: usize| fields[i].parse().ok();
    Some((
        name.clone(),
        IfRow {
            name,
            rx_bytes: num(0)?,
            rx_packets: num(1)?,
            tx_bytes: num(8)?,
            tx_packets: num(9)?,
        },
    ))
}

/// The TCP state numbers from include/net/tcp_states.h, as /proc
/// renders them (hex, no 0x prefix): the two stall signatures and
/// the healthy baseline.
const ST_ESTABLISHED: &str = "01";
const ST_TIME_WAIT: &str = "06";
const ST_CLOSE_WAIT: &str = "08";

/// Census one /proc/net/tcp{,6} table: every line's state field
/// (the 4th whitespace column), counted into the named states and
/// the total. The header line has no state column and is skipped
/// by the parse itself.
pub(crate) fn census_sockets(contents: &str, states: &mut SocketStates) {
    for line in contents.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(state) = fields.get(3) else { continue };
        states.total += 1;
        match *state {
            ST_ESTABLISHED => states.established += 1,
            ST_TIME_WAIT => states.time_wait += 1,
            ST_CLOSE_WAIT => states.close_wait += 1,
            _ => {}
        }
    }
}

/// Count one pid's open sockets by walking its fd table's link
/// targets ("socket:[...]"). Returns (sockets, refused) - a
/// permission refusal is a named absence, not a zero.
fn count_sockets(pid: u32) -> (usize, bool) {
    let entries = match std::fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => entries,
        Err(e) => return (0, e.kind() == std::io::ErrorKind::PermissionDenied),
    };
    let mut sockets = 0usize;
    for entry in entries.flatten() {
        if let Ok(target) = std::fs::read_link(entry.path())
            && target.to_string_lossy().starts_with("socket:[")
        {
            sockets += 1;
        }
    }
    (sockets, false)
}

/// The interface deltas: every interface present in both reads with
/// a nonzero combined delta, descending by total then by name - the
/// deterministic sort law. Separated from [`collect`] so the
/// arithmetic is unit-pinnable with synthetic maps.
pub(crate) fn interface_deltas(
    a: &BTreeMap<String, IfRow>,
    b: &BTreeMap<String, IfRow>,
) -> Vec<IfRow> {
    let mut rows: Vec<IfRow> = b
        .iter()
        .filter_map(|(name, row_b)| {
            let row_a = a.get(name)?;
            let row = IfRow {
                name: name.clone(),
                rx_bytes: row_b.rx_bytes.saturating_sub(row_a.rx_bytes),
                rx_packets: row_b.rx_packets.saturating_sub(row_a.rx_packets),
                tx_bytes: row_b.tx_bytes.saturating_sub(row_a.tx_bytes),
                tx_packets: row_b.tx_packets.saturating_sub(row_a.tx_packets),
            };
            (row.total() > 0).then_some(row)
        })
        .collect();
    rows.sort_by(|left, right| {
        right
            .total()
            .cmp(&left.total())
            .then(left.name.cmp(&right.name))
    });
    rows
}

/// Collect the network sample: two /proc/net/dev reads, one socket
/// census, one fd walk, one sleep - the wait IS the measurement.
pub(crate) fn collect() -> NetworkSample {
    let dev_a = read_net_dev();
    delta::sample_gap();
    let dev_b = read_net_dev();
    let (sockets, holders, refused) = collect_now_facts();
    from_pair(
        &dev_a,
        &dev_b,
        sockets,
        holders,
        refused,
        delta::collect_exits_overlay(),
    )
}

/// The post-window "now" facts (night-dragon-lts-2): the socket
/// census across /proc/net/tcp{,6} and the fd-table holders walk,
/// lifted verbatim out of [`collect`] - the instants-after-the-window
/// reads the umbrella symptom (`slow`) shares so one window feeds
/// every lane. Nothing here sleeps; the walk is the cost.
pub(crate) fn collect_now_facts() -> (SocketStates, Vec<HolderRow>, usize) {
    let mut sockets = SocketStates::default();
    for table in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(contents) = std::fs::read_to_string(table) {
            census_sockets(&contents, &mut sockets);
        }
    }
    let mut holders: Vec<HolderRow> = Vec::new();
    let mut refused = 0usize;
    for pid in pid_dirs(std::path::Path::new("/proc")) {
        let (count, was_refused) = count_sockets(pid);
        if was_refused {
            refused += 1;
            continue;
        }
        if count == 0 {
            continue;
        }
        let comm = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|contents| delta::parse_pid_stat(&contents).map(|s| s.comm))
            .unwrap_or_else(|| "unknown".to_owned());
        holders.push(HolderRow {
            pid,
            comm,
            sockets: count,
        });
    }
    holders.sort_by(|left, right| {
        right
            .sockets
            .cmp(&left.sockets)
            .then(left.pid.cmp(&right.pid))
    });
    holders.truncate(TOP_N);
    (sockets, holders, refused)
}

/// The network sample from a shared pair of instants
/// (night-dragon-lts-2): the interface deltas and the now-facts
/// assembled, verbatim, out of [`collect`] so the umbrella symptom
/// (`slow`) can compute this lane from the SAME t0/t1 pair its cpu
/// and disk numbers ride on - one window, simultaneous evidence,
/// one sleep for the whole report family. Nothing here reads the
/// host; a synthetic pair pins every number the render carries.
pub(crate) fn from_pair(
    dev_a: &BTreeMap<String, IfRow>,
    dev_b: &BTreeMap<String, IfRow>,
    sockets: SocketStates,
    holders: Vec<HolderRow>,
    fd_permission_refused: usize,
    exit_lane: ExitLane,
) -> NetworkSample {
    let interfaces = interface_deltas(dev_a, dev_b);
    NetworkSample {
        sampled_at: crate::info::clock::format_system_time(SystemTime::now()),
        interfaces,
        sockets,
        holders,
        fd_permission_refused,
        exit_lane,
    }
}

/// Read /proc/net/dev into the interface map. pub(crate) since
/// night-dragon-lts-2: the umbrella symptom reads the same pair
/// this lane rides on, one source of parse truth.
pub(crate) fn read_net_dev() -> BTreeMap<String, IfRow> {
    let contents = std::fs::read_to_string("/proc/net/dev").unwrap_or_default();
    let mut map = BTreeMap::new();
    for line in contents.lines().skip(2) {
        if let Some((name, row)) = parse_net_dev_line(line) {
            map.insert(name, row);
        }
    }
    map
}

/// The report: collect, render, one String, exit.
pub(crate) fn report(raw: bool) -> String {
    render(&collect(), raw)
}

/// The pure render - separated from [`collect`] so the shape is
/// unit-pinnable with synthetic samples, the memory ledger's own
/// discipline: the report is the contract, not the host.
pub(crate) fn render(sample: &NetworkSample, raw: bool) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "{} symptom - network",
        crate::output::ok_out("Evidence report:")
    ));
    lines.push(crate::output::grey_out(delta::mode_line(
        &sample.exit_lane,
        true,
    )));
    lines.push(crate::output::grey_out(&format!(
        "Sampled: {} (window 1.0s)",
        sample.sampled_at
    )));
    lines.push(String::new());
    render_interfaces(sample, &mut lines);
    render_socket_states(sample, &mut lines);
    render_holders(sample, &mut lines);
    delta::render_exits_overlay(&sample.exit_lane, &mut lines);
    render_unaccounted(sample, &mut lines);
    render_verdict(sample, &mut lines);
    if raw {
        render_raw(&mut lines);
    }
    lines.join("\n")
}

fn render_interfaces(sample: &NetworkSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Interfaces (window 1.0s):"));
    if sample.interfaces.is_empty() {
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
        lines.push(String::new());
        return;
    }
    for row in &sample.interfaces {
        lines.push(format!(
            "  {}  RX {} ({} packets)  TX {} ({} packets)  {}",
            row.name,
            crate::output::grey_out(&fmt_bytes(row.rx_bytes)),
            row.rx_packets,
            crate::output::grey_out(&fmt_bytes(row.tx_bytes)),
            row.tx_packets,
            crate::output::ok_out("[measured]")
        ));
    }
    lines.push(String::new());
}

fn render_socket_states(sample: &NetworkSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Socket states:"));
    lines.push(format!(
        "  ESTABLISHED {}  TIME_WAIT {}  CLOSE_WAIT {}  (of {} {})  {}",
        sample.sockets.established,
        sample.sockets.time_wait,
        sample.sockets.close_wait,
        sample.sockets.total,
        noun_for(sample.sockets.total, "socket", "sockets"),
        crate::output::ok_out("[measured]")
    ));
    lines.push(String::new());
}

fn render_holders(sample: &NetworkSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Top socket holders:"));
    if sample.holders.is_empty() {
        lines.push(format!("  {}", crate::output::grey_out("(none observed)")));
        lines.push(String::new());
        return;
    }
    for row in &sample.holders {
        lines.push(format!(
            "  PID {} ({})  {} {} open  {}",
            row.pid,
            row.comm,
            row.sockets,
            noun_for(row.sockets, "socket", "sockets"),
            crate::output::ok_out("[measured]")
        ));
    }
    lines.push(String::new());
}

fn render_unaccounted(sample: &NetworkSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Unaccounted:"));
    lines.push(delta::sampling_unaccounted(
        &sample.exit_lane,
        SAMPLE_WINDOW_DESC,
    ));
    if sample.fd_permission_refused > 0 {
        lines.push(format!(
            "  {} {}  {}",
            sample.fd_permission_refused,
            crate::output::grey_out(
                "processes' fd tables unreadable (permission) - the holder list names \
                 only the holders visible to this user"
            ),
            crate::output::grey_out("[unaccounted]")
        ));
    }
    lines.push(String::new());
}

fn render_verdict(sample: &NetworkSample, lines: &mut Vec<String>) {
    lines.push(crate::output::ok_out("Verdict:"));
    for line in verdict_lines(sample) {
        lines.push(format!("  {line}"));
    }
}

/// The verdict's lines, without the two-space indent and the
/// header - one source for the text renderer and the JSON lane
/// (night-badass-5).
pub(crate) fn verdict_lines(sample: &NetworkSample) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    match sample.interfaces.first() {
        Some(top) => lines.push(format!(
            "The busiest interface is {} (RX {}, TX {} in the window).",
            top.name,
            fmt_bytes(top.rx_bytes),
            fmt_bytes(top.tx_bytes)
        )),
        None => lines.push("No interface moved a byte or a packet in the window.".to_owned()),
    }
    // The port-exhaustion boundary: a named number, a named risk -
    // the fact the user verifies, never an instruction.
    if sample.sockets.time_wait > PORT_EXHAUSTION_RISK {
        lines.push(format!(
            "The TIME_WAIT count ({}) is above {PORT_EXHAUSTION_RISK} - local port \
             exhaustion pressure is the named risk (many short-lived connections are \
             churning; the top holder above is the busiest socket owner).",
            sample.sockets.time_wait
        ));
    }
    lines
}

/// The drill-down: the interface table verbatim at render time (the
/// ram report's own re-read pattern).
fn render_raw(lines: &mut Vec<String>) {
    lines.push(String::new());
    lines.push(crate::output::ok_out("Raw /proc reads (drill-down):"));
    match std::fs::read_to_string("/proc/net/dev") {
        Ok(contents) => {
            lines.push(crate::output::grey_out("  /proc/net/dev:"));
            for line in contents.lines() {
                lines.push(format!("    {line}"));
            }
        }
        Err(e) => lines.push(crate::output::grey_out(&format!(
            "  /proc/net/dev unreadable ({e})"
        ))),
    }
}

/// The adaptive size label - the memory ledger's own, one source
/// for the whole symptom family.
fn fmt_bytes(bytes: u64) -> String {
    super::memory::ledger::fmt_bytes(bytes)
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/network_tests.rs"]
mod tests;
