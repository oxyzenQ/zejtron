// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The net surface's render half (the tree renderer: one section per
//! report block, the roles of night-improve-37, the values unwrapped).
//! Moved verbatim from the net module (night-improve-37's tree
//! discipline: the 600-line cap means SPLIT, a pure move, gates green
//! in between) - no logic changed, the render byte-identical in Mono
//! and tiered on the stdout lane exactly as before.

use super::{InterfaceEntry, NetReport};

/// One "key value" paint: the key token rides grey (an inline
/// annotation, the locked scheme's secondary content), the value
/// stays unwrapped (white, the terminal default). The one helper the
/// net surface's annotation rows ride, so the roles stay uniform
/// across the four sections (night-improve-37).
fn kv(key: &str, value: &str) -> String {
    format!("{}{value}", crate::output::grey_out(key))
}

pub fn render_report(report: &NetReport) -> String {
    // Roles (night-improve-37): the root and the section labels ride
    // green (the section headers), the tree glyphs ride grey
    // (grammar), the values (names, addresses, MACs, counts) stay
    // unwrapped. In Mono every wrap is the identity.
    let mut lines = vec![crate::output::ok_out("net")];

    let has_arp = !report.arp_neighbors.is_empty();
    let has_routes = !report.routes.is_empty();
    let has_resolver = report.resolver.is_some();
    let has_more = has_arp || has_routes || has_resolver;

    render_interfaces_section(&mut lines, report, has_more);
    render_arp_section(&mut lines, report, has_routes || has_resolver);
    render_routes_section(&mut lines, report, has_resolver);
    render_resolver_section(&mut lines, report);

    lines.join("\n")
}

fn render_interfaces_section(lines: &mut Vec<String>, report: &NetReport, has_more: bool) {
    let branch = if has_more { "├" } else { "└" };
    lines.push(format!(
        "{branch}── {}",
        crate::output::ok_out("interfaces")
    ));
    let indent = if has_more { "│" } else { " " };

    if report.interfaces.is_empty() {
        // The absence line rides grey (the "no events" class).
        lines.push(format!(
            "{indent}   └── {}",
            crate::output::grey_out("none visible")
        ));
        return;
    }

    for (i, iface) in report.interfaces.iter().enumerate() {
        let is_last = i + 1 == report.interfaces.len();
        let leaf = if is_last { "└" } else { "├" };
        let leaf_indent = if is_last { " " } else { "│" };
        lines.push(format!(
            "{indent}   {leaf}── {}",
            format_iface_summary(iface)
        ));
        // Render address + stats sub-rows
        render_iface_details(lines, iface, &format!("{indent}   {leaf_indent}   "));
    }
}

fn render_iface_details(lines: &mut Vec<String>, iface: &InterfaceEntry, prefix: &str) {
    let mut sub: Vec<String> = Vec::new();
    for ip in &iface.ipv4 {
        sub.push(kv("ipv4 ", ip));
    }
    for ip in &iface.ipv6 {
        sub.push(kv("ipv6 ", ip));
    }
    if let Some(flags) = iface.flags {
        let flag_str = decode_flags(flags);
        if !flag_str.is_empty() {
            sub.push(kv("flags ", &flag_str));
        }
        if flags & 0x100 != 0 {
            // The warning token rides yellow (the warnings tier).
            sub.push(crate::output::warn_out("warn: promiscuous-mode"));
        }
    }
    if let (Some(rx), Some(tx)) = (iface.rx_bytes, iface.tx_bytes) {
        sub.push(format!(
            "{}{} {}{}",
            crate::output::grey_out("rx "),
            human_bytes(rx),
            crate::output::grey_out("tx "),
            human_bytes(tx)
        ));
    }
    if let (Some(rxp), Some(txp)) = (iface.rx_packets, iface.tx_packets) {
        sub.push(format!(
            "{} rx={rxp} tx={txp}",
            crate::output::grey_out("pkts")
        ));
    }
    let total_errors = iface.rx_errors.unwrap_or(0) + iface.tx_errors.unwrap_or(0);
    let total_drops = iface.rx_dropped.unwrap_or(0) + iface.tx_dropped.unwrap_or(0);
    if total_errors > 0 || total_drops > 0 {
        sub.push(format!(
            "{}{total_errors} {}{total_drops}",
            crate::output::grey_out("errors="),
            crate::output::grey_out(" drops=")
        ));
    }

    for (i, line) in sub.iter().enumerate() {
        let is_last = i + 1 == sub.len();
        let leaf = if is_last { "└" } else { "├" };
        lines.push(format!("{prefix}{leaf}── {line}"));
    }
}

pub(crate) fn decode_flags(flags: u32) -> String {
    let mut parts = Vec::new();
    if flags & 0x1 != 0 {
        parts.push("UP");
    }
    if flags & 0x2 != 0 {
        parts.push("BROADCAST");
    }
    if flags & 0x8 != 0 {
        parts.push("LOOPBACK");
    }
    if flags & 0x10 != 0 {
        parts.push("POINTOPOINT");
    }
    if flags & 0x40 != 0 {
        parts.push("RUNNING");
    }
    if flags & 0x100 != 0 {
        parts.push("PROMISC");
    }
    if flags & 0x1000 != 0 {
        parts.push("MULTICAST");
    }
    parts.join(",")
}

pub(crate) fn format_iface_summary(iface: &InterfaceEntry) -> String {
    // The interface name and state are the values (white, unwrapped);
    // the mtu= and mac= keys ride grey with their values unwrapped.
    let mut parts = vec![iface.name.clone()];
    if let Some(ref state) = iface.state {
        parts.push(state.clone());
    }
    if let Some(mtu) = iface.mtu {
        parts.push(kv("mtu=", &mtu.to_string()));
    }
    if let Some(ref mac) = iface.mac {
        // Skip MAC for loopback (00:00:00:00:00:00)
        if mac != "00:00:00:00:00:00" {
            parts.push(kv("mac=", mac));
        }
    }
    parts.join(" ")
}

fn render_arp_section(lines: &mut Vec<String>, report: &NetReport, has_more: bool) {
    let branch = if has_more { "├" } else { "└" };
    lines.push(format!(
        "{branch}── {}",
        crate::output::ok_out("arp-neighbors")
    ));
    let indent = if has_more { "│" } else { " " };

    if report.arp_neighbors.is_empty() {
        // The absence line rides grey (the "no events" class).
        lines.push(format!(
            "{indent}   └── {}",
            crate::output::grey_out("none visible")
        ));
        return;
    }
    for (i, entry) in report.arp_neighbors.iter().enumerate() {
        let is_last = i + 1 == report.arp_neighbors.len();
        let leaf = if is_last { "└" } else { "├" };
        lines.push(format!(
            "{indent}   {leaf}── {} {} {}",
            entry.ip, entry.mac, entry.iface
        ));
    }
}

fn render_routes_section(lines: &mut Vec<String>, report: &NetReport, has_more: bool) {
    let branch = if has_more { "├" } else { "└" };
    lines.push(format!("{branch}── {}", crate::output::ok_out("routes")));
    let indent = if has_more { "│" } else { " " };

    if report.routes.is_empty() {
        // The absence line rides grey (the "no events" class).
        lines.push(format!(
            "{indent}   └── {}",
            crate::output::grey_out("none visible")
        ));
        return;
    }
    for (i, route) in report.routes.iter().enumerate() {
        let is_last = i + 1 == report.routes.len();
        let leaf = if is_last { "└" } else { "├" };
        // The route facts are the values (white); the via connective
        // and the metric= key ride grey.
        let metric_str = route
            .metric
            .map(|m| format!(" {}{m}", crate::output::grey_out("metric=")))
            .unwrap_or_default();
        lines.push(format!(
            "{indent}   {leaf}── {} {} {} {}{metric_str}",
            route.destination,
            crate::output::grey_out("via"),
            route.gateway,
            route.iface
        ));
    }
}

fn render_resolver_section(lines: &mut Vec<String>, report: &NetReport) {
    lines.push(format!("└── {}", crate::output::ok_out("resolver")));
    match &report.resolver {
        None => {
            // The absence lines ride grey (the "no events" class).
            lines.push(format!(
                "    └── {}",
                crate::output::grey_out("/etc/resolv.conf missing")
            ));
        }
        Some(cfg) => {
            if cfg.nameservers.is_empty() && cfg.search.is_empty() && cfg.options.is_empty() {
                lines.push(format!(
                    "    └── {}",
                    crate::output::grey_out("/etc/resolv.conf empty")
                ));
            } else {
                let mut sub: Vec<String> = Vec::new();
                for ns in &cfg.nameservers {
                    sub.push(kv("nameserver ", ns));
                }
                if !cfg.search.is_empty() {
                    sub.push(kv("search ", &cfg.search.join(" ")));
                }
                if !cfg.options.is_empty() {
                    sub.push(kv("options ", &cfg.options.join(" ")));
                }
                for (i, line) in sub.iter().enumerate() {
                    let is_last = i + 1 == sub.len();
                    let leaf = if is_last { "└" } else { "├" };
                    lines.push(format!("    {leaf}── {line}"));
                }
            }
        }
    }
}

pub(crate) fn human_bytes(b: u64) -> String {
    if b >= 1024 * 1024 * 1024 {
        format!("{:.2}GB", b as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if b >= 1024 * 1024 {
        format!("{:.1}MB", b as f64 / 1024.0 / 1024.0)
    } else if b >= 1024 {
        format!("{:.1}KB", b as f64 / 1024.0)
    } else {
        format!("{b}B")
    }
}
