// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeSet;

use super::model::{
    GroupKey, OwnerIdentity, OwnerMap, PortOptions, ProcessInfo, ScanStats, SocketEntry,
    SocketGroup,
};

pub fn format_report(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
) -> String {
    if options.group {
        return format_grouped_report(sockets, owners, stats, options);
    }

    let mut lines = Vec::new();

    if let Some(port) = options.port {
        if sockets.is_empty() {
            // The empty-result line rides grey; the port is the value.
            lines.push(format!(
                "{} {port}.",
                crate::output::grey_out("No sockets found for port")
            ));
            return lines.join("\n");
        }
        // The subject header rides green.
        lines.push(crate::output::ok_out(&format!(":{port}")));
        append_socket_lines(&mut lines, sockets, owners, options, "");
    } else {
        lines.push(crate::output::ok_out("ports"));
        if sockets.is_empty() {
            lines.push(crate::output::grey_out("No sockets found."));
            return lines.join("\n");
        }
        append_socket_lines(&mut lines, sockets, owners, options, "");
        let owner_count = unique_owner_count(sockets, owners);
        lines.push(String::new());
        // The footer line: counts are the values (unwrapped), the
        // unit words ride grey (footer text).
        lines.push(format!(
            "{} {} · {} {}",
            sockets.len(),
            crate::output::grey_out(plural(sockets.len(), "port", "ports")),
            owner_count,
            crate::output::grey_out(plural(owner_count, "owner", "owners"))
        ));
        // State breakdown for TCP sockets — investigators want to see at a
        // glance "5 LISTEN · 12 ESTABLISHED · 3 TIME_WAIT". The key rides
        // grey; the breakdown is the value and stays unwrapped.
        let state_breakdown = state_breakdown(sockets);
        if !state_breakdown.is_empty() {
            lines.push(format!(
                "{} {state_breakdown}",
                crate::output::grey_out("states:")
            ));
        }
    }

    append_note(&mut lines, stats);
    lines.join("\n")
}

fn format_grouped_report(
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    stats: &ScanStats,
    options: &PortOptions,
) -> String {
    let mut lines = Vec::new();

    if let Some(port) = options.port {
        if sockets.is_empty() {
            // The empty-result line rides grey; the port is the value.
            lines.push(format!(
                "{} {port}.",
                crate::output::grey_out("No sockets found for port")
            ));
            return lines.join("\n");
        }
        lines.push(crate::output::ok_out(&format!(":{port}")));
    } else {
        lines.push(crate::output::ok_out("ports"));
        if sockets.is_empty() {
            lines.push(crate::output::grey_out("No sockets found."));
            return lines.join("\n");
        }
    }

    let groups = group_sockets(sockets, owners);
    append_group_lines(&mut lines, &groups, options, "");

    let socket_count: usize = groups.iter().map(|group| group.count).sum();
    let owner_count = unique_group_owner_count(&groups);
    lines.push(String::new());
    // The footer line: counts are the values (unwrapped), the unit
    // words ride grey (footer text).
    lines.push(format!(
        "{} {} · {} {} · {} {}",
        groups.len(),
        crate::output::grey_out(plural(groups.len(), "group", "groups")),
        socket_count,
        crate::output::grey_out(plural(socket_count, "socket", "sockets")),
        owner_count,
        crate::output::grey_out(plural(owner_count, "owner", "owners"))
    ));

    append_note(&mut lines, stats);
    lines.join("\n")
}

pub(crate) fn group_sockets(sockets: &[SocketEntry], owners: &OwnerMap) -> Vec<SocketGroup> {
    let mut groups: Vec<(GroupKey, SocketGroup)> = Vec::new();

    for socket in sockets {
        let group_owners = owners.get(&socket.inode).cloned().unwrap_or_default();
        let key = GroupKey {
            protocol: socket.protocol,
            address: socket.address.clone(),
            port: socket.port,
            state: socket.state.clone(),
            owners: group_owners.iter().map(OwnerIdentity::from).collect(),
        };

        if let Some((_, group)) = groups.iter_mut().find(|(existing, _)| existing == &key) {
            group.count += 1;
        } else {
            groups.push((
                key,
                SocketGroup {
                    socket: socket.clone(),
                    owners: group_owners,
                    count: 1,
                },
            ));
        }
    }

    groups.into_iter().map(|(_, group)| group).collect()
}

fn unique_owner_count(sockets: &[SocketEntry], owners: &OwnerMap) -> usize {
    let mut unique = BTreeSet::new();
    for process in sockets
        .iter()
        .filter_map(|socket| owners.get(&socket.inode))
        .flatten()
    {
        unique.insert(process.pid);
    }
    unique.len()
}

fn unique_group_owner_count(groups: &[SocketGroup]) -> usize {
    let mut unique = BTreeSet::new();
    for process in groups.iter().flat_map(|group| &group.owners) {
        unique.insert(process.pid);
    }
    unique.len()
}

fn append_socket_lines(
    lines: &mut Vec<String>,
    sockets: &[SocketEntry],
    owners: &OwnerMap,
    options: &PortOptions,
    indent: &str,
) {
    for (index, socket) in sockets.iter().enumerate() {
        let last_socket = index + 1 == sockets.len();
        let branch = if last_socket {
            "└──"
        } else {
            "├──"
        };
        let child_indent = if last_socket { "    " } else { "│   " };
        // The tree glyph rides grey (grammar); the socket row is the
        // value and stays unwrapped.
        lines.push(format!(
            "{indent}{} {}",
            crate::output::grey_out(branch),
            format_socket(socket)
        ));
        append_owner_lines(
            lines,
            owners.get(&socket.inode),
            options,
            &format!("{indent}{child_indent}"),
        );
    }
}

fn append_group_lines(
    lines: &mut Vec<String>,
    groups: &[SocketGroup],
    options: &PortOptions,
    indent: &str,
) {
    for (index, group) in groups.iter().enumerate() {
        let last_group = index + 1 == groups.len();
        let branch = if last_group { "└──" } else { "├──" };
        let child_indent = if last_group { "    " } else { "│   " };
        lines.push(format!(
            "{indent}{} {}",
            crate::output::grey_out(branch),
            format_group(group)
        ));
        append_owner_lines(
            lines,
            Some(&group.owners),
            options,
            &format!("{indent}{child_indent}"),
        );
    }
}

fn format_group(group: &SocketGroup) -> String {
    let mut value = format_socket(&group.socket);
    if group.count > 1 {
        value.push_str(&format!(" ×{}", group.count));
    }
    value
}

fn append_owner_lines(
    lines: &mut Vec<String>,
    processes: Option<&Vec<ProcessInfo>>,
    options: &PortOptions,
    indent: &str,
) {
    let Some(processes) = processes.filter(|processes| !processes.is_empty()) else {
        // The absence token rides grey (the "no events" class).
        lines.push(format!(
            "{indent}{} {}",
            crate::output::grey_out("└──"),
            crate::output::grey_out(format_unknown_owner())
        ));
        return;
    };

    for (index, process) in processes.iter().enumerate() {
        let last = index + 1 == processes.len();
        let branch = if last { "└──" } else { "├──" };
        lines.push(format!(
            "{indent}{} {}",
            crate::output::grey_out(branch),
            format_owner(process, options.no_pid)
        ));
        if options.port.is_some()
            && let Some(cwd) = &process.cwd
        {
            let cwd_indent = if last { "    " } else { "│   " };
            // The cwd key rides grey (an inline annotation); the path
            // is the value and stays unwrapped.
            lines.push(format!(
                "{indent}{}{} {}",
                crate::output::grey_out(cwd_indent),
                crate::output::grey_out("└── cwd"),
                cwd.display()
            ));
        }
    }
}

fn format_socket(socket: &SocketEntry) -> String {
    let endpoint = if socket.address.contains(':') {
        format!("[{}]:{}", socket.address, socket.port)
    } else {
        format!("{}:{}", socket.address, socket.port)
    };
    let mut value = format!("{} {}", socket.protocol.label(), endpoint);
    if let Some(state) = &socket.state {
        value.push(' ');
        value.push_str(state);
    }
    // Show remote endpoint when non-zero (i.e., connection is established or
    // has a peer — LISTEN sockets have 0.0.0.0:0).
    if socket.remote_port != 0 {
        let remote = if socket.remote_address.contains(':') {
            format!("[{}]:{}", socket.remote_address, socket.remote_port)
        } else {
            format!("{}:{}", socket.remote_address, socket.remote_port)
        };
        value.push_str(&format!(" <- {remote}"));
    }
    value
}

pub fn format_owner(process: &ProcessInfo, no_pid: bool) -> String {
    // Roles (night-improve-37): the comm name is the value (white,
    // unwrapped); the pid=, user=, fd= keys ride grey (inline
    // annotations) with their values unwrapped. In Mono every wrap is
    // the identity, byte-identical to the pinned shape.
    let mut parts = Vec::new();
    parts.push(process.name.clone());
    if !no_pid {
        parts.push(format!(
            "{}{}",
            crate::output::grey_out("pid="),
            process.pid
        ));
    }
    parts.push(format!(
        "{}{}",
        crate::output::grey_out("user="),
        process.user
    ));
    if let Some(fd) = process.fd {
        parts.push(format!("{}{fd}", crate::output::grey_out("fd=")));
    }
    parts.join(" ")
}

pub fn format_unknown_owner() -> &'static str {
    "unknown"
}

/// Build a "5 LISTEN · 12 ESTABLISHED · 3 TIME_WAIT" style summary of TCP
/// socket states. Returns empty string when no TCP sockets have a state.
fn state_breakdown(sockets: &[SocketEntry]) -> String {
    use std::collections::BTreeMap;
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for socket in sockets {
        if let Some(state) = socket.state.as_deref() {
            *counts.entry(state).or_default() += 1;
        }
    }
    // Sort by count descending for the most useful states first
    let mut entries: Vec<(&&str, &usize)> = counts.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    entries
        .iter()
        .map(|(state, count)| format!("{count} {state}"))
        .collect::<Vec<_>>()
        .join(" · ")
}

pub fn should_show_unreadable_note(stats: &ScanStats) -> bool {
    stats.unreadable_processes > 0 || stats.unreadable_fds > 0
}

pub(crate) fn append_note(lines: &mut Vec<String>, stats: &ScanStats) {
    if should_show_unreadable_note(stats) {
        lines.push(String::new());
        // The advice line rides grey (a hint, the locked scheme's
        // secondary content).
        lines.push(crate::output::grey_out(
            "note: some processes were not readable; try sudo for complete owner details",
        ));
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

#[cfg(test)]
#[path = "../../../test/commands/port/render_tests.rs"]
mod tests;
