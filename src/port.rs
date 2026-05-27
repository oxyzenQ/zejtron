use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

type OwnerMap = HashMap<u64, Vec<ProcessInfo>>;
type ProcScan = (Vec<SocketEntry>, OwnerMap, ScanStats);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl Protocol {
    fn label(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub protocol: Protocol,
    pub address: String,
    pub port: u16,
    pub state: Option<String>,
    pub inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub user: String,
    pub cwd: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketGroup {
    socket: SocketEntry,
    owners: Vec<ProcessInfo>,
    count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroupKey {
    protocol: Protocol,
    address: String,
    port: u16,
    state: Option<String>,
    owners: Vec<OwnerIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OwnerIdentity {
    pid: u32,
    name: String,
    user: String,
}

impl From<&ProcessInfo> for OwnerIdentity {
    fn from(process: &ProcessInfo) -> Self {
        Self {
            pid: process.pid,
            name: process.name.clone(),
            user: process.user.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortOptions {
    pub port: Option<u16>,
    pub tcp: bool,
    pub udp: bool,
    pub listen: bool,
    pub all: bool,
    pub numeric: bool,
    pub group: bool,
    pub no_pid: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PortFlags {
    pub tcp: bool,
    pub udp: bool,
    pub listen: bool,
    pub all: bool,
    pub numeric: bool,
    pub group: bool,
    pub no_pid: bool,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ScanStats {
    pub unreadable_processes: usize,
    pub unreadable_fds: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortError(String);

impl fmt::Display for PortError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for PortError {}

pub fn run(port: Option<&str>, flags: PortFlags) -> Result<(), Box<dyn Error>> {
    let options = parse_options(port, flags)?;
    let (sockets, owners, stats) = scan_proc()?;
    let selected = filter_sockets(&sockets, &options);
    let output = format_report(&selected, &owners, &stats, &options);
    println!("{output}");
    Ok(())
}

pub fn parse_options(port: Option<&str>, flags: PortFlags) -> Result<PortOptions, PortError> {
    if flags.listen && flags.all {
        return Err(PortError("--listen cannot be used with --all".to_owned()));
    }

    Ok(PortOptions {
        port: port.map(validate_port).transpose()?,
        tcp: flags.tcp,
        udp: flags.udp,
        listen: flags.listen,
        all: flags.all,
        numeric: flags.numeric,
        group: flags.group,
        no_pid: flags.no_pid,
    })
}

pub fn validate_port(input: &str) -> Result<u16, PortError> {
    let port: u16 = input
        .parse()
        .map_err(|_| PortError(format!("invalid port: {input}")))?;
    if port == 0 {
        return Err(PortError(format!("invalid port: {input}")));
    }
    Ok(port)
}

fn scan_proc() -> io::Result<ProcScan> {
    let mut sockets = Vec::new();
    for (path, protocol, ipv6) in [
        ("/proc/net/tcp", Protocol::Tcp, false),
        ("/proc/net/tcp6", Protocol::Tcp, true),
        ("/proc/net/udp", Protocol::Udp, false),
        ("/proc/net/udp6", Protocol::Udp, true),
    ] {
        match parse_proc_net_file(Path::new(path), protocol, ipv6) {
            Ok(mut entries) => sockets.append(&mut entries),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }

    let inodes: BTreeSet<u64> = sockets.iter().map(|socket| socket.inode).collect();
    let (owners, stats) = map_socket_owners(Path::new("/proc"), &inodes);
    Ok((sockets, owners, stats))
}

fn parse_proc_net_file(
    path: &Path,
    protocol: Protocol,
    ipv6: bool,
) -> io::Result<Vec<SocketEntry>> {
    let content = fs::read_to_string(path)?;
    Ok(parse_proc_net_content(&content, protocol, ipv6))
}

pub fn parse_proc_net_content(content: &str, protocol: Protocol, ipv6: bool) -> Vec<SocketEntry> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| parse_proc_net_line(line, protocol, ipv6))
        .collect()
}

pub fn parse_proc_net_line(line: &str, protocol: Protocol, ipv6: bool) -> Option<SocketEntry> {
    let columns: Vec<&str> = line.split_whitespace().collect();
    let local = *columns.get(1)?;
    let state_code = *columns.get(3)?;
    let inode = columns.get(9)?.parse().ok()?;
    let (address, port) = parse_local_address(local, ipv6)?;
    let state = match protocol {
        Protocol::Tcp => Some(tcp_state_name(state_code).to_owned()),
        Protocol::Udp => None,
    };

    Some(SocketEntry {
        protocol,
        address,
        port,
        state,
        inode,
    })
}

pub fn parse_local_address(input: &str, ipv6: bool) -> Option<(String, u16)> {
    let (address_hex, port_hex) = input.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let address = if ipv6 {
        parse_ipv6_address(address_hex)?
    } else {
        parse_ipv4_address(address_hex)?
    };
    Some((address, port))
}

fn parse_ipv4_address(input: &str) -> Option<String> {
    if input.len() != 8 {
        return None;
    }

    let raw = u32::from_str_radix(input, 16).ok()?;
    Some(Ipv4Addr::from(raw.to_le_bytes()).to_string())
}

fn parse_ipv6_address(input: &str) -> Option<String> {
    if input.len() != 32 {
        return None;
    }

    let mut bytes = [0_u8; 16];
    for (chunk_index, chunk) in input.as_bytes().chunks(8).enumerate() {
        let chunk = std::str::from_utf8(chunk).ok()?;
        let value = u32::from_str_radix(chunk, 16).ok()?;
        let start = chunk_index * 4;
        bytes[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

pub fn is_tcp_listen(state: Option<&str>) -> bool {
    state == Some("LISTEN")
}

fn tcp_state_name(state: &str) -> &'static str {
    match state {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        _ => "UNKNOWN",
    }
}

pub fn filter_sockets(sockets: &[SocketEntry], options: &PortOptions) -> Vec<SocketEntry> {
    let include_tcp = options.tcp || !options.udp;
    let include_udp = options.udp || !options.tcp;
    let listen_mode = !options.all;

    let mut selected: Vec<SocketEntry> = sockets
        .iter()
        .filter(|socket| match socket.protocol {
            Protocol::Tcp => include_tcp,
            Protocol::Udp => include_udp,
        })
        .filter(|socket| options.port.is_none_or(|port| socket.port == port))
        .filter(|socket| {
            if !listen_mode {
                return true;
            }
            match socket.protocol {
                Protocol::Tcp => is_tcp_listen(socket.state.as_deref()),
                Protocol::Udp => socket.port != 0,
            }
        })
        .cloned()
        .collect();

    selected.sort_by(|left, right| {
        left.port
            .cmp(&right.port)
            .then(left.protocol.cmp(&right.protocol))
            .then(left.address.cmp(&right.address))
    });
    selected
}

fn map_socket_owners(
    proc_root: &Path,
    wanted_inodes: &BTreeSet<u64>,
) -> (HashMap<u64, Vec<ProcessInfo>>, ScanStats) {
    let mut owners: HashMap<u64, Vec<ProcessInfo>> = HashMap::new();
    let mut stats = ScanStats::default();
    let Ok(entries) = fs::read_dir(proc_root) else {
        return (owners, stats);
    };

    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(pid) = file_name.to_str().and_then(|name| name.parse::<u32>().ok()) else {
            continue;
        };

        let process_dir = entry.path();
        let fd_dir = process_dir.join("fd");
        let fd_entries = match fs::read_dir(&fd_dir) {
            Ok(entries) => entries,
            Err(error) if is_permission_or_disappeared(&error) => {
                stats.unreadable_processes += 1;
                continue;
            }
            Err(_) => continue,
        };

        let mut matched_inodes = BTreeSet::new();
        for fd_entry in fd_entries {
            let Ok(fd_entry) = fd_entry else {
                stats.unreadable_fds += 1;
                continue;
            };
            let target = match fs::read_link(fd_entry.path()) {
                Ok(target) => target,
                Err(error) if is_permission_or_disappeared(&error) => {
                    stats.unreadable_fds += 1;
                    continue;
                }
                Err(_) => continue,
            };
            let Some(inode) = parse_socket_inode(&target) else {
                continue;
            };
            if wanted_inodes.contains(&inode) {
                matched_inodes.insert(inode);
            }
        }

        if matched_inodes.is_empty() {
            continue;
        }

        let process = read_process_info(&process_dir, pid);
        for inode in matched_inodes {
            owners.entry(inode).or_default().push(process.clone());
        }
    }

    for processes in owners.values_mut() {
        processes.sort_by_key(|process| process.pid);
    }
    (owners, stats)
}

fn is_permission_or_disappeared(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
    )
}

fn parse_socket_inode(path: &Path) -> Option<u64> {
    let text = path.to_string_lossy();
    let inode = text.strip_prefix("socket:[")?.strip_suffix(']')?;
    inode.parse().ok()
}

fn read_process_info(process_dir: &Path, pid: u32) -> ProcessInfo {
    let status = fs::read_to_string(process_dir.join("status")).unwrap_or_default();
    let name = parse_status_value(&status, "Name").unwrap_or_else(|| "unknown".to_owned());
    let uid = parse_status_value(&status, "Uid")
        .and_then(|value| value.split_whitespace().next().map(ToOwned::to_owned));
    let user = uid
        .as_deref()
        .and_then(resolve_username)
        .or_else(|| uid.map(|uid| format!("uid={uid}")))
        .unwrap_or_else(|| "uid=unknown".to_owned());
    let cwd = fs::read_link(process_dir.join("cwd")).ok();

    ProcessInfo {
        pid,
        name,
        user,
        cwd,
    }
}

fn parse_status_value(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn resolve_username(uid: &str) -> Option<String> {
    let passwd = fs::read_to_string("/etc/passwd").ok()?;
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        let name = fields.next()?;
        fields.next()?;
        let entry_uid = fields.next()?;
        (entry_uid == uid).then(|| name.to_owned())
    })
}

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
            lines.push(format!("No sockets found for port {port}."));
            return lines.join("\n");
        }
        lines.push(format!(":{port}"));
        append_socket_lines(&mut lines, sockets, owners, options, "");
    } else {
        lines.push("ports".to_owned());
        if sockets.is_empty() {
            lines.push("No sockets found.".to_owned());
            return lines.join("\n");
        }
        append_socket_lines(&mut lines, sockets, owners, options, "");
        let owner_count = unique_owner_count(sockets, owners);
        lines.push(String::new());
        lines.push(format!(
            "{} {} · {} {}",
            sockets.len(),
            plural(sockets.len(), "port", "ports"),
            owner_count,
            plural(owner_count, "owner", "owners")
        ));
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
            lines.push(format!("No sockets found for port {port}."));
            return lines.join("\n");
        }
        lines.push(format!(":{port}"));
    } else {
        lines.push("ports".to_owned());
        if sockets.is_empty() {
            lines.push("No sockets found.".to_owned());
            return lines.join("\n");
        }
    }

    let groups = group_sockets(sockets, owners);
    append_group_lines(&mut lines, &groups, options, "");

    let socket_count: usize = groups.iter().map(|group| group.count).sum();
    let owner_count = unique_group_owner_count(&groups);
    lines.push(String::new());
    lines.push(format!(
        "{} {} · {} {} · {} {}",
        groups.len(),
        plural(groups.len(), "group", "groups"),
        socket_count,
        plural(socket_count, "socket", "sockets"),
        owner_count,
        plural(owner_count, "owner", "owners")
    ));

    append_note(&mut lines, stats);
    lines.join("\n")
}

fn group_sockets(sockets: &[SocketEntry], owners: &OwnerMap) -> Vec<SocketGroup> {
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
        lines.push(format!("{indent}{branch} {}", format_socket(socket)));
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
        lines.push(format!("{indent}{branch} {}", format_group(group)));
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
        lines.push(format!("{indent}└── {}", format_unknown_owner()));
        return;
    };

    for (index, process) in processes.iter().enumerate() {
        let last = index + 1 == processes.len();
        let branch = if last { "└──" } else { "├──" };
        lines.push(format!(
            "{indent}{branch} {}",
            format_owner(process, options.no_pid)
        ));
        if options.port.is_some()
            && let Some(cwd) = &process.cwd
        {
            let cwd_indent = if last { "    " } else { "│   " };
            lines.push(format!("{indent}{cwd_indent}cwd {}", cwd.display()));
        }
    }
}

fn format_socket(socket: &SocketEntry) -> String {
    let endpoint = if socket.address.contains(':') {
        format!("[{}]:{}", socket.address, socket.port)
    } else {
        format!("{}:{}", socket.address, socket.port)
    };
    let mut value = format!("{} {}", socket.protocol.label(), endpoint,);
    if let Some(state) = &socket.state {
        value.push(' ');
        value.push_str(state);
    }
    value
}

pub fn format_owner(process: &ProcessInfo, no_pid: bool) -> String {
    if no_pid {
        format!("{} user={}", process.name, process.user)
    } else {
        format!("{} pid={} user={}", process.name, process.pid, process.user)
    }
}

pub fn format_unknown_owner() -> &'static str {
    "unknown"
}

pub fn should_show_unreadable_note(stats: &ScanStats) -> bool {
    stats.unreadable_processes > 0 || stats.unreadable_fds > 0
}

fn append_note(lines: &mut Vec<String>, stats: &ScanStats) {
    if should_show_unreadable_note(stats) {
        lines.push(String::new());
        lines.push(
            "note: some processes were not readable; try sudo for complete owner details"
                .to_owned(),
        );
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn socket(protocol: Protocol, port: u16, state: Option<&str>) -> SocketEntry {
        socket_with_inode(protocol, port, state, u64::from(port))
    }

    fn socket_with_inode(
        protocol: Protocol,
        port: u16,
        state: Option<&str>,
        inode: u64,
    ) -> SocketEntry {
        socket_at(protocol, "127.0.0.1", port, state, inode)
    }

    fn socket_at(
        protocol: Protocol,
        address: &str,
        port: u16,
        state: Option<&str>,
        inode: u64,
    ) -> SocketEntry {
        SocketEntry {
            protocol,
            address: address.to_owned(),
            port,
            state: state.map(ToOwned::to_owned),
            inode,
        }
    }

    fn options() -> PortOptions {
        PortOptions {
            port: None,
            tcp: false,
            udp: false,
            listen: false,
            all: false,
            numeric: false,
            group: false,
            no_pid: false,
        }
    }

    fn process(pid: u32, name: &str) -> ProcessInfo {
        ProcessInfo {
            pid,
            name: name.to_owned(),
            user: "rezky".to_owned(),
            cwd: None,
        }
    }

    #[test]
    fn parses_ipv4_local_address_hex_and_port() {
        assert_eq!(
            parse_local_address("0100007F:0BB8", false),
            Some(("127.0.0.1".to_owned(), 3000))
        );
    }

    #[test]
    fn parses_ipv6_line_without_panicking() {
        let line = "0: 00000000000000000000000000000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 42 1 0000000000000000 100 0 0 10 0";
        let entry = parse_proc_net_line(line, Protocol::Tcp, true).unwrap();
        assert_eq!(entry.port, 8080);
        assert_eq!(entry.state, Some("LISTEN".to_owned()));
    }

    #[test]
    fn detects_tcp_listen_state() {
        let line = "0: 0100007F:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 12345 1 0000000000000000 100 0 0 10 0";
        let entry = parse_proc_net_line(line, Protocol::Tcp, false).unwrap();
        assert!(is_tcp_listen(entry.state.as_deref()));
    }

    #[test]
    fn validates_port_range() {
        assert_eq!(validate_port("1").unwrap(), 1);
        assert_eq!(validate_port("65535").unwrap(), 65_535);
        assert!(validate_port("0").is_err());
        assert!(validate_port("65536").is_err());
        assert!(validate_port("abc").is_err());
    }

    #[test]
    fn filters_by_protocol() {
        let sockets = vec![
            socket(Protocol::Tcp, 80, Some("LISTEN")),
            socket(Protocol::Udp, 53, None),
        ];
        let tcp = PortOptions {
            tcp: true,
            ..options()
        };
        let udp = PortOptions {
            udp: true,
            tcp: false,
            ..tcp
        };

        assert_eq!(filter_sockets(&sockets, &tcp).len(), 1);
        assert_eq!(filter_sockets(&sockets, &tcp)[0].protocol, Protocol::Tcp);
        assert_eq!(filter_sockets(&sockets, &udp).len(), 1);
        assert_eq!(filter_sockets(&sockets, &udp)[0].protocol, Protocol::Udp);
    }

    #[test]
    fn tcp_and_udp_flags_include_both_protocols() {
        let sockets = vec![
            socket(Protocol::Tcp, 80, Some("LISTEN")),
            socket(Protocol::Udp, 53, None),
        ];
        let selected = filter_sockets(
            &sockets,
            &PortOptions {
                tcp: true,
                udp: true,
                ..options()
            },
        );

        assert_eq!(selected.len(), 2);
        assert!(
            selected
                .iter()
                .any(|socket| socket.protocol == Protocol::Tcp)
        );
        assert!(
            selected
                .iter()
                .any(|socket| socket.protocol == Protocol::Udp)
        );
    }

    #[test]
    fn default_and_listen_filter_match() {
        let sockets = vec![
            socket(Protocol::Tcp, 80, Some("LISTEN")),
            socket(Protocol::Tcp, 443, Some("ESTABLISHED")),
            socket(Protocol::Udp, 53, None),
            socket(Protocol::Udp, 0, None),
        ];
        let default = filter_sockets(&sockets, &options());
        let listen = filter_sockets(
            &sockets,
            &PortOptions {
                listen: true,
                ..options()
            },
        );

        assert_eq!(default, listen);
        assert_eq!(default.len(), 2);
        assert!(default.iter().any(|socket| socket.port == 80));
        assert!(default.iter().any(|socket| socket.port == 53));
        assert!(!default.iter().any(|socket| socket.port == 443));
        assert!(!default.iter().any(|socket| socket.port == 0));
    }

    #[test]
    fn all_includes_non_listening_tcp() {
        let sockets = vec![
            socket(Protocol::Tcp, 80, Some("LISTEN")),
            socket(Protocol::Tcp, 443, Some("ESTABLISHED")),
        ];
        let selected = filter_sockets(
            &sockets,
            &PortOptions {
                all: true,
                ..options()
            },
        );

        assert_eq!(selected.len(), 2);
        assert!(selected.iter().any(|socket| socket.port == 443));
    }

    #[test]
    fn filters_by_specific_port() {
        let sockets = vec![
            socket(Protocol::Tcp, 80, Some("LISTEN")),
            socket(Protocol::Udp, 53, None),
        ];
        let options = PortOptions {
            port: Some(53),
            ..options()
        };

        let selected = filter_sockets(&sockets, &options);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].port, 53);
    }

    #[test]
    fn specific_port_filter_combines_with_protocol_and_all_filters() {
        let sockets = vec![
            socket(Protocol::Tcp, 3000, Some("ESTABLISHED")),
            socket(Protocol::Udp, 3000, None),
            socket(Protocol::Tcp, 8080, Some("LISTEN")),
        ];
        let listening_tcp = filter_sockets(
            &sockets,
            &PortOptions {
                port: Some(3000),
                tcp: true,
                ..options()
            },
        );
        let all_tcp = filter_sockets(
            &sockets,
            &PortOptions {
                port: Some(3000),
                tcp: true,
                all: true,
                ..options()
            },
        );

        assert!(listening_tcp.is_empty());
        assert_eq!(all_tcp.len(), 1);
        assert_eq!(all_tcp[0].protocol, Protocol::Tcp);
        assert_eq!(all_tcp[0].port, 3000);
    }

    #[test]
    fn listen_and_all_conflict() {
        assert!(
            parse_options(
                None,
                PortFlags {
                    listen: true,
                    all: true,
                    ..PortFlags::default()
                },
            )
            .is_err()
        );
    }

    #[test]
    fn formats_owner_without_pid() {
        let process = ProcessInfo {
            pid: 1234,
            name: "node".to_owned(),
            user: "rezky".to_owned(),
            cwd: None,
        };
        assert_eq!(format_owner(&process, true), "node user=rezky");
    }

    #[test]
    fn formats_unknown_owner() {
        assert_eq!(format_unknown_owner(), "unknown");
    }

    #[test]
    fn report_summary_uses_rendered_socket_count_after_filtering() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 80, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 443, Some("ESTABLISHED"), 200),
        ];
        let selected = filter_sockets(&sockets, &options());
        let mut owners = OwnerMap::new();
        owners.insert(200, vec![process(7, "curl")]);

        let report = format_report(&selected, &owners, &ScanStats::default(), &options());

        assert!(report.contains("1 port · 0 owners"));
        assert!(!report.contains("443"));
    }

    #[test]
    fn owner_summary_counts_unique_known_rendered_processes() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 80, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Udp, 53, None, 200),
            socket_with_inode(Protocol::Udp, 5353, None, 300),
        ];
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process(7, "daemon")]);
        owners.insert(200, vec![process(7, "daemon")]);

        let report = format_report(&sockets, &owners, &ScanStats::default(), &options());

        assert!(report.contains("3 ports · 1 owner"));
    }

    #[test]
    fn cwd_is_only_rendered_for_specific_port_reports() {
        let sockets = vec![socket_with_inode(Protocol::Tcp, 3000, Some("LISTEN"), 100)];
        let mut process = process(1234, "node");
        process.cwd = Some(PathBuf::from("/home/rezky/project"));
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process]);

        let list_report = format_report(&sockets, &owners, &ScanStats::default(), &options());
        let detail_report = format_report(
            &sockets,
            &owners,
            &ScanStats::default(),
            &PortOptions {
                port: Some(3000),
                ..options()
            },
        );

        assert!(!list_report.contains("cwd /home/rezky/project"));
        assert!(detail_report.contains("cwd /home/rezky/project"));
    }

    #[test]
    fn report_respects_no_pid_owner_formatting() {
        let sockets = vec![socket_with_inode(Protocol::Tcp, 3000, Some("LISTEN"), 100)];
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process(1234, "node")]);

        let report = format_report(
            &sockets,
            &owners,
            &ScanStats::default(),
            &PortOptions {
                no_pid: true,
                ..options()
            },
        );

        assert!(report.contains("node user=rezky"));
        assert!(!report.contains("pid=1234"));
    }

    #[test]
    fn grouped_report_combines_repeated_sockets() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
        ];

        let report = format_report(
            &sockets,
            &OwnerMap::new(),
            &ScanStats::default(),
            &PortOptions {
                group: true,
                ..options()
            },
        );

        assert!(report.contains("tcp 127.0.0.1:53 LISTEN ×2"));
        assert!(report.contains("1 group · 2 sockets · 0 owners"));
        assert_eq!(report.matches("unknown").count(), 1);
    }

    #[test]
    fn grouped_report_keeps_different_owners_separate() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
        ];
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process(10, "unbound")]);
        owners.insert(200, vec![process(20, "dnsmasq")]);

        let report = format_report(
            &sockets,
            &owners,
            &ScanStats::default(),
            &PortOptions {
                group: true,
                ..options()
            },
        );

        assert_eq!(report.matches("tcp 127.0.0.1:53 LISTEN").count(), 2);
        assert!(!report.contains("×2"));
        assert!(report.contains("2 groups · 2 sockets · 2 owners"));
    }

    #[test]
    fn grouped_report_keeps_socket_identity_separate() {
        let sockets = vec![
            socket_at(Protocol::Tcp, "127.0.0.1", 53, Some("LISTEN"), 100),
            socket_at(Protocol::Tcp, "127.0.0.2", 53, Some("LISTEN"), 200),
            socket_at(Protocol::Tcp, "127.0.0.1", 54, Some("LISTEN"), 300),
            socket_at(Protocol::Tcp, "127.0.0.1", 53, Some("ESTABLISHED"), 400),
            socket_at(Protocol::Udp, "127.0.0.1", 53, None, 500),
        ];

        let report = format_report(
            &sockets,
            &OwnerMap::new(),
            &ScanStats::default(),
            &PortOptions {
                group: true,
                all: true,
                ..options()
            },
        );

        assert!(report.contains("5 groups · 5 sockets · 0 owners"));
        assert!(!report.contains('×'));
    }

    #[test]
    fn grouped_summary_counts_groups_sockets_and_unique_owners() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
            socket_with_inode(Protocol::Udp, 5353, None, 300),
        ];
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process(10, "unbound")]);
        owners.insert(200, vec![process(10, "unbound")]);

        let report = format_report(
            &sockets,
            &owners,
            &ScanStats::default(),
            &PortOptions {
                group: true,
                ..options()
            },
        );

        assert!(report.contains("2 groups · 3 sockets · 1 owner"));
    }

    #[test]
    fn grouped_report_respects_no_pid_owner_formatting() {
        let sockets = vec![socket_with_inode(Protocol::Tcp, 3000, Some("LISTEN"), 100)];
        let mut owners = OwnerMap::new();
        owners.insert(100, vec![process(1234, "node")]);

        let report = format_report(
            &sockets,
            &owners,
            &ScanStats::default(),
            &PortOptions {
                group: true,
                no_pid: true,
                ..options()
            },
        );

        assert!(report.contains("node user=rezky"));
        assert!(!report.contains("pid=1234"));
    }

    #[test]
    fn grouped_specific_port_keeps_detail_header() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
        ];

        let report = format_report(
            &sockets,
            &OwnerMap::new(),
            &ScanStats::default(),
            &PortOptions {
                port: Some(53),
                group: true,
                ..options()
            },
        );

        assert!(report.starts_with(":53\n"));
        assert!(report.contains("tcp 127.0.0.1:53 LISTEN ×2"));
        assert!(report.contains("1 group · 2 sockets · 0 owners"));
    }

    #[test]
    fn no_match_specific_port_omits_unreadable_note() {
        let report = format_report(
            &[],
            &OwnerMap::new(),
            &ScanStats {
                unreadable_processes: 1,
                unreadable_fds: 1,
            },
            &PortOptions {
                port: Some(22),
                ..options()
            },
        );

        assert_eq!(report, "No sockets found for port 22.");
    }

    #[test]
    fn grouped_no_match_specific_port_omits_unreadable_note() {
        let report = format_report(
            &[],
            &OwnerMap::new(),
            &ScanStats {
                unreadable_processes: 1,
                unreadable_fds: 1,
            },
            &PortOptions {
                port: Some(22),
                group: true,
                ..options()
            },
        );

        assert_eq!(report, "No sockets found for port 22.");
    }

    #[test]
    fn rendered_sockets_keep_unreadable_note() {
        let sockets = vec![socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100)];

        let report = format_report(
            &sockets,
            &OwnerMap::new(),
            &ScanStats {
                unreadable_processes: 1,
                unreadable_fds: 0,
            },
            &PortOptions {
                group: true,
                ..options()
            },
        );

        assert!(report.contains("tcp 127.0.0.1:53 LISTEN"));
        assert!(report.contains(
            "note: some processes were not readable; try sudo for complete owner details"
        ));
    }

    #[test]
    fn raw_report_does_not_group_by_default() {
        let sockets = vec![
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 100),
            socket_with_inode(Protocol::Tcp, 53, Some("LISTEN"), 200),
        ];

        let report = format_report(
            &sockets,
            &OwnerMap::new(),
            &ScanStats::default(),
            &options(),
        );

        assert_eq!(report.matches("tcp 127.0.0.1:53 LISTEN").count(), 2);
        assert!(report.contains("2 ports · 0 owners"));
        assert!(!report.contains('×'));
    }

    #[test]
    fn unreadable_note_logic() {
        assert!(!should_show_unreadable_note(&ScanStats::default()));
        assert!(should_show_unreadable_note(&ScanStats {
            unreadable_processes: 1,
            unreadable_fds: 0,
        }));
        assert!(should_show_unreadable_note(&ScanStats {
            unreadable_processes: 0,
            unreadable_fds: 1,
        }));
    }
}
