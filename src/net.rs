// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: MIT

use std::error::Error;
use std::fs;
use std::path::Path;

const SYS_CLASS_NET: &str = "/sys/class/net";
const PROC_NET_ROUTE: &str = "/proc/net/route";
const RESOLV_CONF: &str = "/etc/resolv.conf";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceEntry {
    pub name: String,
    pub state: Option<String>,
    pub mtu: Option<u32>,
    pub mac: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetReport {
    pub interfaces: Vec<InterfaceEntry>,
    pub default_route: Option<String>,
    pub resolver_path: String,
    pub resolver_status: FileStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    Readable,
    Missing,
}

pub fn run() -> Result<(), Box<dyn Error>> {
    let report = collect_report();
    println!("{}", render_report(&report));
    Ok(())
}

fn collect_report() -> NetReport {
    let interfaces = read_interfaces();
    let default_route = read_default_route();
    let (resolver_path, resolver_status) = read_resolver();

    NetReport {
        interfaces,
        default_route,
        resolver_path,
        resolver_status,
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

        entries.push(InterfaceEntry {
            name,
            state,
            mtu,
            mac,
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

fn read_default_route() -> Option<String> {
    let content = fs::read_to_string(PROC_NET_ROUTE).ok()?;

    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let dest = fields[1];
        let flags = fields[3];

        if dest == "00000000" && flags.starts_with('0') {
            return Some(fields[0].to_owned());
        }
    }
    None
}

fn read_resolver() -> (String, FileStatus) {
    let path = RESOLV_CONF;
    match fs::metadata(path) {
        Ok(_) => {
            if fs::read_to_string(path).is_ok() {
                (path.to_owned(), FileStatus::Readable)
            } else {
                (path.to_owned(), FileStatus::Missing)
            }
        }
        Err(_) => (path.to_owned(), FileStatus::Missing),
    }
}

pub fn render_report(report: &NetReport) -> String {
    let mut lines = vec!["net".to_owned()];

    let has_routes = report.default_route.is_some();
    let has_resolver = !report.resolver_path.is_empty();

    render_interfaces_section(&mut lines, report, has_routes || has_resolver);

    render_default_route_section(&mut lines, report, has_resolver);

    render_resolver_section(&mut lines, report);

    lines.join("\n")
}

fn render_interfaces_section(lines: &mut Vec<String>, report: &NetReport, has_more: bool) {
    if report.interfaces.is_empty() {
        let branch = if has_more { "├" } else { "└" };
        lines.push(format!("{branch}── interfaces"));
        lines.push(format!(
            "{}   └── none visible",
            if has_more { "│" } else { " " }
        ));
        return;
    }

    let branch = if has_more { "├" } else { "└" };
    lines.push(format!("{branch}── interfaces"));
    let indent = if has_more { "│" } else { " " };

    for (i, iface) in report.interfaces.iter().enumerate() {
        let is_last = i + 1 == report.interfaces.len();
        let leaf = if is_last { "└" } else { "├" };
        let label = format_iface(iface);
        lines.push(format!("{indent}   {leaf}── {label}"));
    }
}

fn format_iface(iface: &InterfaceEntry) -> String {
    let mut parts = vec![iface.name.clone()];

    if let Some(ref state) = iface.state {
        parts.push(state.clone());
    }

    if let Some(mtu) = iface.mtu {
        parts.push(format!("mtu={mtu}"));
    }

    if let Some(ref mac) = iface.mac {
        parts.push(format!("mac={mac}"));
    }

    parts.join(" ")
}

fn render_default_route_section(lines: &mut Vec<String>, report: &NetReport, has_more: bool) {
    let branch = if has_more { "├" } else { "└" };
    lines.push(format!("{branch}── default-route"));

    match &report.default_route {
        Some(iface) => {
            let indent = if has_more { "│" } else { " " };
            lines.push(format!("{indent}   └── {iface}"));
        }
        None => {
            let indent = if has_more { "│" } else { " " };
            lines.push(format!("{indent}   └── none visible"));
        }
    }
}

fn render_resolver_section(lines: &mut Vec<String>, report: &NetReport) {
    lines.push("└── resolver".to_owned());

    let status_label = match report.resolver_status {
        FileStatus::Readable => "readable",
        FileStatus::Missing => "missing",
    };
    lines.push(format!("    └── {} {status_label}", report.resolver_path));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_iface_all_fields() {
        let iface = InterfaceEntry {
            name: "eth0".to_owned(),
            state: Some("up".to_owned()),
            mtu: Some(1500),
            mac: Some("aa:bb:cc:dd:ee:ff".to_owned()),
        };
        let result = format_iface(&iface);
        assert_eq!(result, "eth0 up mtu=1500 mac=aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn format_iface_name_only() {
        let iface = InterfaceEntry {
            name: "lo".to_owned(),
            state: None,
            mtu: None,
            mac: None,
        };
        assert_eq!(format_iface(&iface), "lo");
    }

    #[test]
    fn format_iface_state_and_mtu() {
        let iface = InterfaceEntry {
            name: "wlan0".to_owned(),
            state: Some("up".to_owned()),
            mtu: Some(1500),
            mac: None,
        };
        assert_eq!(format_iface(&iface), "wlan0 up mtu=1500");
    }

    #[test]
    fn render_empty_interfaces() {
        let report = NetReport {
            interfaces: vec![],
            default_route: None,
            resolver_path: "/etc/resolv.conf".to_owned(),
            resolver_status: FileStatus::Readable,
        };
        let output = render_report(&report);
        assert!(output.contains("none visible"));
    }

    #[test]
    fn render_single_interface_no_route() {
        let report = NetReport {
            interfaces: vec![InterfaceEntry {
                name: "lo".to_owned(),
                state: Some("unknown".to_owned()),
                mtu: Some(65536),
                mac: Some("00:00:00:00:00:00".to_owned()),
            }],
            default_route: None,
            resolver_path: "/etc/resolv.conf".to_owned(),
            resolver_status: FileStatus::Missing,
        };
        let output = render_report(&report);
        assert!(output.contains("lo unknown mtu=65536"));
        assert!(output.contains("none visible"));
        assert!(output.contains("missing"));
    }

    #[test]
    fn render_full_report() {
        let report = NetReport {
            interfaces: vec![
                InterfaceEntry {
                    name: "lo".to_owned(),
                    state: Some("unknown".to_owned()),
                    mtu: Some(65536),
                    mac: Some("00:00:00:00:00:00".to_owned()),
                },
                InterfaceEntry {
                    name: "wlan0".to_owned(),
                    state: Some("up".to_owned()),
                    mtu: Some(1500),
                    mac: None,
                },
            ],
            default_route: Some("wlan0".to_owned()),
            resolver_path: "/etc/resolv.conf".to_owned(),
            resolver_status: FileStatus::Readable,
        };
        let output = render_report(&report);
        let expected = [
            "net",
            "├── interfaces",
            "│   ├── lo unknown mtu=65536 mac=00:00:00:00:00:00",
            "│   └── wlan0 up mtu=1500",
            "├── default-route",
            "│   └── wlan0",
            "└── resolver",
            "    └── /etc/resolv.conf readable",
        ];
        assert_eq!(output, expected.join("\n"));
    }

    #[test]
    fn render_no_default_route() {
        let report = NetReport {
            interfaces: vec![InterfaceEntry {
                name: "eth0".to_owned(),
                state: Some("up".to_owned()),
                mtu: Some(1450),
                mac: None,
            }],
            default_route: None,
            resolver_path: "/etc/resolv.conf".to_owned(),
            resolver_status: FileStatus::Readable,
        };
        let output = render_report(&report);
        assert!(output.contains("├── default-route"));
        assert!(output.contains("none visible"));
    }

    #[test]
    fn render_resolver_missing() {
        let report = NetReport {
            interfaces: vec![],
            default_route: None,
            resolver_path: "/etc/resolv.conf".to_owned(),
            resolver_status: FileStatus::Missing,
        };
        let output = render_report(&report);
        assert!(output.contains("/etc/resolv.conf missing"));
    }

    #[test]
    fn no_malformed_tree_prefixes() {
        let report = NetReport {
            interfaces: vec![
                InterfaceEntry {
                    name: "lo".to_owned(),
                    state: Some("unknown".to_owned()),
                    mtu: Some(65536),
                    mac: None,
                },
                InterfaceEntry {
                    name: "eth0".to_owned(),
                    state: Some("up".to_owned()),
                    mtu: Some(1500),
                    mac: Some("aa:bb:cc:dd:ee:ff".to_owned()),
                },
            ],
            default_route: Some("eth0".to_owned()),
            resolver_path: "/etc/resolv.conf".to_owned(),
            resolver_status: FileStatus::Readable,
        };
        let output = render_report(&report);
        for line in output.lines() {
            assert!(!line.contains("├── └──"), "malformed: {line}");
            assert!(!line.contains("├── │"), "malformed: {line}");
            assert!(!line.contains("└── ├──"), "malformed: {line}");
            assert!(!line.contains("└── │"), "malformed: {line}");
        }
    }

    #[test]
    fn parse_route_default_gateway_line() {
        let input = "eth0\t00000000\t01000015\t0003\t0\t0\t0\t00000000\t0\t0\t0\n";
        assert!(route_line_has_default(input));
        assert_eq!(extract_route_iface(input), Some("eth0".to_owned()));
    }

    #[test]
    fn parse_route_non_default_line() {
        let input = "eth0\t01000015\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert!(!route_line_has_default(input));
    }

    fn route_line_has_default(line: &str) -> bool {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields.len() >= 3 && fields[1] == "00000000"
    }

    fn extract_route_iface(line: &str) -> Option<String> {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 3 && fields[1] == "00000000" {
            Some(fields[0].to_owned())
        } else {
            None
        }
    }
}
