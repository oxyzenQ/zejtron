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
        // The state zejtron renders (night-dragon-lts-2): loopback's
        // operstate is "unknown" on every host (RFC 2863 exempts it
        // from operstate reporting), so for lo the flags' own IFF_UP
        // bit carries the administrative truth instead - "up", the
        // word the reader expects beside traffic counters that move.
        let state = resolved_state(&name, state, flags);

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

/// IFF_UP from linux/if.h - the administrative up bit the flags
/// file carries (hex, no 0x prefix). Loopback's operstate is
/// "unknown" by kernel design, so this bit is the truth zejtron
/// renders for lo (night-dragon-lts-2).
const IFF_UP: u32 = 0x1;

/// The state zejtron renders for an interface: the kernel's own
/// operstate word, except loopback - RFC 2863 exempts lo from
/// operstate reporting (it reads "unknown" on every host), so the
/// flags' IFF_UP bit carries the administrative truth there
/// instead. An unreadable flags file never guesses: the kernel's
/// own word rides through untouched.
fn resolved_state(name: &str, operstate: Option<String>, flags: Option<u32>) -> Option<String> {
    match (name, operstate.as_deref(), flags) {
        ("lo", Some("unknown"), Some(bits)) => {
            Some(if bits & IFF_UP != 0 { "up" } else { "down" }.to_owned())
        }
        _ => operstate,
    }
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
    parse_sysfs_u32(content.trim())
}

/// One sysfs u32, in both shapes the kernel writes: decimal with
/// no prefix (mtu "65536", type "772") and hex with the 0x prefix
/// (flags "0x9"). The hex arm (night-dragon-lts-2) repairs a
/// dormant-from-birth lane: `flags` was read on every host and
/// parsed on none - Rust's plain `str::parse` rejects the 0x
/// prefix - so the decoded flags row and the promiscuous-mode
/// warning that rides IFF_PROMISC never once rendered. Separated
/// from the file read so the two shapes are unit-pinnable.
fn parse_sysfs_u32(trimmed: &str) -> Option<u32> {
    match trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        Some(hex_digits) => u32::from_str_radix(hex_digits, 16).ok(),
        None => trimmed.parse::<u32>().ok(),
    }
}

fn read_sysfs_u64(iface_path: &Path, file: &str) -> Option<u64> {
    let path = iface_path.join(file);
    let content = fs::read_to_string(path).ok()?;
    content.trim().parse::<u64>().ok()
}

/// RFC 5952 form of one /proc/net/if_inet6 address (32 lowercase
/// hex digits, no colons): each 16-bit group drops its leading
/// zeros, and the single longest run of two or more all-zero groups
/// compresses to "::" - leftmost on ties, a lone zero group never
/// compresses (night-dragon-lts-4; the kernel's 32-character form
/// was rendered verbatim with colons spliced in, so the loopback
/// address rode as 0000:0000:...:0001 on every host and the
/// link-local prefix drowned the interface identifier). None for
/// any input that is not exactly 32 hex digits - the caller drops
/// the line rather than guessing at a malformed kernel row.
pub(crate) fn format_ipv6(hex: &str) -> Option<String> {
    let mut groups = [0u16; 8];
    for (index, group) in groups.iter_mut().enumerate() {
        *group = u16::from_str_radix(hex.get(index * 4..index * 4 + 4)?, 16).ok()?;
    }
    // The longest all-zero run of two or more groups, leftmost on
    // ties (RFC 5952 4.2.2): strict > keeps the earlier run, and a
    // run shorter than two never compresses (4.2.1).
    let mut best_start = usize::MAX;
    let mut best_len = 0;
    let mut index = 0;
    while index < 8 {
        if groups[index] == 0 {
            let start = index;
            while index < 8 && groups[index] == 0 {
                index += 1;
            }
            if index - start > best_len {
                best_len = index - start;
                best_start = start;
            }
        } else {
            index += 1;
        }
    }
    if best_len < 2 {
        best_start = usize::MAX;
    }
    let mut out = String::with_capacity(39);
    let mut index = 0;
    while index < 8 {
        if index == best_start {
            out.push_str("::");
            index += best_len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        // Lowercase hex without leading zeros: u16's Display prints
        // decimal, so the group renders through the hex formatter.
        out.push_str(&format!("{:x}", groups[index]));
        index += 1;
    }
    Some(out)
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
        if let Some(ip) = format_ipv6(raw) {
            addrs.push(ip);
        }
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
