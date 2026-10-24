// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Network interfaces, addresses, statistics, routes, and resolver.

use std::error::Error;
use std::fs;
use std::path::Path;

const SYS_CLASS_NET: &str = "/sys/class/net";
const PROC_NET_ROUTE: &str = "/proc/net/route";
const PROC_NET_IF_INET6: &str = "/proc/net/if_inet6";
const PROC_NET_ARP: &str = "/proc/net/arp";
const RESOLV_CONF: &str = "/etc/resolv.conf";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub name: String,
    pub state: Option<String>,
    pub mtu: Option<u32>,
    pub mac: Option<String>,
    pub flags: Option<u32>,
    pub iftype: Option<u32>,
    pub ipv4: Vec<String>,
    pub ipv6: Vec<String>,
    pub rx_bytes: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub rx_packets: Option<u64>,
    pub tx_packets: Option<u64>,
    pub rx_errors: Option<u64>,
    pub tx_errors: Option<u64>,
    pub rx_dropped: Option<u64>,
    pub tx_dropped: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    pub ip: String,
    pub hw_type: String,
    pub flags: String,
    pub mac: String,
    pub iface: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    pub iface: String,
    pub destination: String,
    pub gateway: String,
    pub flags: String,
    pub metric: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolverConfig {
    pub nameservers: Vec<String>,
    pub search: Vec<String>,
    pub options: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetReport {
    pub interfaces: Vec<InterfaceEntry>,
    pub arp_neighbors: Vec<ArpEntry>,
    pub routes: Vec<RouteEntry>,
    pub default_route: Option<String>,
    pub resolver: Option<ResolverConfig>,
}

pub fn run(print_json: bool) -> Result<(), Box<dyn Error>> {
    let report = collect_report();
    // The renderer branch (night-badass-9): the JSON lane speaks the
    // same report - the NetReport struct is the schema - as one typed
    // line; the text lane renders the tree. One collection, two
    // renderers, no second scan.
    if print_json {
        println!("{}", json::report_json(&report));
    } else {
        println!("{}", render_report(&report));
    }
    Ok(())
}

mod json;
mod render;

use render::render_report;
#[cfg(test)]
pub(crate) use render::{decode_flags, format_iface_summary, human_bytes};

fn collect_report() -> NetReport {
    let interfaces = read_interfaces();
    let arp_neighbors = read_arp();
    let routes = read_routes();
    let default_route = routes
        .iter()
        .find(|r| r.destination == "default")
        .map(|r| r.iface.clone());
    let resolver = read_resolver_config();

    NetReport {
        interfaces,
        arp_neighbors,
        routes,
        default_route,
        resolver,
    }
}

fn read_interfaces() -> Vec<InterfaceEntry> {
    let dir = match fs::read_dir(SYS_CLASS_NET) {
        Ok(d) => d,
        Err(_) => return vec![],
    };

    let mut entries: Vec<InterfaceEntry> = Vec::new();
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let iface_path = entry.path();

        let state = read_sysfs_str(&iface_path, "operstate");
        let mtu = read_sysfs_u32(&iface_path, "mtu");
        let mac = read_sysfs_str(&iface_path, "address");
        let flags = read_sysfs_u32(&iface_path, "flags");
        let iftype = read_sysfs_u32(&iface_path, "type");

        // Stats
        let rx_bytes = read_sysfs_u64(&iface_path, "statistics/rx_bytes");
        let tx_bytes = read_sysfs_u64(&iface_path, "statistics/tx_bytes");
        let rx_packets = read_sysfs_u64(&iface_path, "statistics/rx_packets");
        let tx_packets = read_sysfs_u64(&iface_path, "statistics/tx_packets");
        let rx_errors = read_sysfs_u64(&iface_path, "statistics/rx_errors");
        let tx_errors = read_sysfs_u64(&iface_path, "statistics/tx_errors");
        let rx_dropped = read_sysfs_u64(&iface_path, "statistics/rx_dropped");
        let tx_dropped = read_sysfs_u64(&iface_path, "statistics/tx_dropped");

        // Addresses — try IPv4 via /proc/net/fib_trie is complex; use if_inet6 for v6
        // For IPv4, fall back to parsing /proc/net/fib_trie (local IPs marked LOCAL)
        let ipv4 = read_ipv4_addresses(&name);
        let ipv6 = read_ipv6_addresses(&name);

        entries.push(InterfaceEntry {
            name,
            state,
            mtu,
            mac,
            flags,
            iftype,
            ipv4,
            ipv6,
            rx_bytes,
            tx_bytes,
            rx_packets,
            tx_packets,
            rx_errors,
            tx_errors,
            rx_dropped,
            tx_dropped,
        });
    }

    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
}

fn read_sysfs_str(iface_path: &Path, file: &str) -> Option<String> {
    let path = iface_path.join(file);
    let content = fs::read_to_string(path).ok()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

fn read_sysfs_u32(iface_path: &Path, file: &str) -> Option<u32> {
    let path = iface_path.join(file);
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse::<u32>().ok()
}

fn read_sysfs_u64(iface_path: &Path, file: &str) -> Option<u64> {
    let path = iface_path.join(file);
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse::<u64>().ok()
}

/// Parse /proc/net/if_inet6 to get IPv6 addresses per interface.
/// Format: addr_index prefix_len scope flags ifname
/// addr is 32 hex chars (no colons).
fn read_ipv6_addresses(iface_name: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    let Ok(content) = fs::read_to_string(PROC_NET_IF_INET6) else {
        return addrs;
    };
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        if fields[5] != iface_name {
            continue;
        }
        let raw = fields[0];
        if raw.len() != 32 {
            continue;
        }
        // Insert colon every 4 chars to form standard IPv6 notation
        let mut formatted = String::with_capacity(39);
        for (i, c) in raw.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                formatted.push(':');
            }
            formatted.push(c);
        }
        // Could canonicalize (compress zeros) but raw form is fine for display
        addrs.push(formatted);
    }
    addrs
}

/// Parse /proc/net/fib_trie to extract IPv4 addresses assigned to interfaces.
/// This is a best-effort heuristic: the file's structure is a tree of leaf
/// nodes with /32 host addresses marked "LOCAL". We pick unique LOCAL IPs.
fn read_ipv4_addresses(_iface_name: &str) -> Vec<String> {
    let mut addrs = Vec::new();
    let Ok(content) = fs::read_to_string("/proc/net/fib_trie") else {
        return addrs;
    };
    // Walk lines looking for "32 host LOCAL" preceded by an IP-like string.
    // This is fragile but works on Linux 4.x+.
    let lines: Vec<&str> = content.lines().collect();
    let mut i = 0;
    while i + 1 < lines.len() {
        let _cur = lines[i].trim();
        let next = lines[i + 1].trim();
        // Pattern: "32 host LOCAL" follows an IP-containing line.
        // We look for the IP in the line *before* the "32 host LOCAL" line.
        if next.contains("32 host") && next.contains("LOCAL") {
            // Walk backwards to find a line that looks like an IP
            if i > 0 {
                let candidate = lines[i - 1].trim();
                if let Some(ip) = extract_ip_from_fib_line(candidate)
                    && !addrs.contains(&ip)
                    && ip != "127.0.0.1"
                    && ip != "0.0.0.0"
                {
                    addrs.push(ip);
                }
            }
        }
        i += 1;
    }
    addrs
}

fn extract_ip_from_fib_line(line: &str) -> Option<String> {
    // Lines look like: "|--127.0.0.1" or "127.0.0.1" or just an IP
    let trimmed = line
        .trim_start_matches("|--")
        .trim_start_matches("|")
        .trim();
    if trimmed.is_empty() {
        return None;
    }
    // Take first whitespace-separated token
    let token = trimmed.split_whitespace().next()?;
    // Validate it's an IPv4
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    for p in parts {
        if p.parse::<u8>().is_err() {
            return None;
        }
    }
    Some(token.to_owned())
}

/// Read /proc/net/arp for L2 neighbors.
fn read_arp() -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    let Ok(content) = fs::read_to_string(PROC_NET_ARP) else {
        return entries;
    };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 {
            continue;
        }
        entries.push(ArpEntry {
            ip: fields[0].to_owned(),
            hw_type: fields[1].to_owned(),
            flags: fields[2].to_owned(),
            mac: fields[3].to_owned(),
            iface: fields[5].to_owned(),
        });
    }
    entries
}

/// Read /proc/net/route (IPv4 routing table).
fn read_routes() -> Vec<RouteEntry> {
    let mut routes = Vec::new();
    let Ok(content) = fs::read_to_string(PROC_NET_ROUTE) else {
        return routes;
    };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 {
            continue;
        }
        let iface = fields[0].to_owned();
        let dest_hex = fields[1];
        let gw_hex = fields[2];
        let flags = fields[3].to_owned();
        let metric = fields[6].parse::<u32>().ok();

        let destination = if dest_hex == "00000000" {
            "default".to_owned()
        } else {
            hex_to_ipv4(dest_hex).unwrap_or_else(|| dest_hex.to_owned())
        };
        let gateway = if gw_hex == "00000000" {
            "0.0.0.0".to_owned()
        } else {
            hex_to_ipv4(gw_hex).unwrap_or_else(|| gw_hex.to_owned())
        };

        routes.push(RouteEntry {
            iface,
            destination,
            gateway,
            flags,
            metric,
        });
    }
    routes
}

/// Convert little-endian hex (from /proc/net/route) to dotted IPv4.
fn hex_to_ipv4(hex: &str) -> Option<String> {
    if hex.len() != 8 {
        return None;
    }
    let n = u32::from_str_radix(hex, 16).ok()?;
    // /proc/net/route stores IPs in little-endian (network byte order in reverse)
    let a = (n & 0xFF) as u8;
    let b = ((n >> 8) & 0xFF) as u8;
    let c = ((n >> 16) & 0xFF) as u8;
    let d = ((n >> 24) & 0xFF) as u8;
    Some(format!("{a}.{b}.{c}.{d}"))
}

/// Parse /etc/resolv.conf for nameservers, search domains, options.
fn read_resolver_config() -> Option<ResolverConfig> {
    let content = fs::read_to_string(RESOLV_CONF).ok()?;
    let mut nameservers = Vec::new();
    let mut search = Vec::new();
    let mut options = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }
        let mut parts = trimmed.split_whitespace();
        match parts.next() {
            Some("nameserver") => {
                if let Some(ns) = parts.next() {
                    nameservers.push(ns.to_owned());
                }
            }
            Some("search") => {
                search.extend(parts.map(str::to_owned));
            }
            Some("options") => {
                options.extend(parts.map(str::to_owned));
            }
            _ => {}
        }
    }
    Some(ResolverConfig {
        nameservers,
        search,
        options,
    })
}

#[cfg(test)]
#[path = "../../test/commands/net_tests.rs"]
mod tests;
