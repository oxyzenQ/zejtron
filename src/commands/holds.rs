// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

pub(crate) mod ledger;
mod procfs;

use procfs::{
    ProcRead, dev_major_minor, list_pids, read_fd_mode, read_proc_net_sockets, resolve_username,
    scan_pid_fds_for_file, scan_pid_fds_for_sockets, scan_pid_maps_for_file,
};
#[derive(Debug, Clone, PartialEq, Eq)]
enum Target {
    Port(u16),
    Path(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoldsError(String);

impl fmt::Display for HoldsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for HoldsError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Holder {
    pub(crate) pid: u32,
    pub(crate) name: String,
    pub(crate) user: String,
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Evidence {
    Fd(i32, FdMode),
    Mmap(MmapPerms),
}

/// FD access mode decoded from `/proc/<pid>/fdinfo/<fd>` flags field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FdMode {
    Read,
    Write,
    ReadWrite,
    Unknown,
}

impl FdMode {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Read => "r",
            Self::Write => "w",
            Self::ReadWrite => "rw",
            Self::Unknown => "?",
        }
    }

    pub(crate) fn from_flags(flags: u64) -> Self {
        // O_RDONLY=0, O_WRONLY=1, O_RDWR=2 — lower 2 bits of flags
        match flags & 0o3 {
            0 => Self::Read,
            1 => Self::Write,
            2 => Self::ReadWrite,
            _ => Self::Unknown,
        }
    }
}

/// mmap permissions decoded from `/proc/<pid>/maps` column 2 (e.g., "r-xp").
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MmapPerms {
    pub(crate) read: bool,
    pub(crate) write: bool,
    pub(crate) execute: bool,
    pub(crate) private: bool,
}

impl MmapPerms {
    pub(crate) fn label(&self) -> String {
        let mut s = String::with_capacity(4);
        s.push(if self.read { 'r' } else { '-' });
        s.push(if self.write { 'w' } else { '-' });
        s.push(if self.execute { 'x' } else { '-' });
        s.push(if self.private { 'p' } else { 's' });
        s
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        if s.len() != 4 {
            return None;
        }
        let bytes = s.as_bytes();
        Some(Self {
            read: bytes[0] == b'r',
            write: bytes[1] == b'w',
            execute: bytes[2] == b'x',
            private: bytes[3] == b'p',
        })
    }
}

impl Evidence {
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Fd(fd, mode) => format!("fd {fd} ({})", mode.label()),
            Self::Mmap(perms) => format!("mmap {}", perms.label()),
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ScanStats {
    pub(crate) unreadable_processes: usize,
    pub(crate) unreadable_fds: usize,
    pub(crate) unreadable_maps: usize,
}

impl ScanStats {
    pub(crate) fn has_unreadable(self) -> bool {
        self.unreadable_processes > 0 || self.unreadable_fds > 0 || self.unreadable_maps > 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FileId {
    dev: u64,
    inode: u64,
}

impl FileId {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            dev: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocketEntry {
    protocol: Protocol,
    port: u16,
    inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapEntry {
    dev_major: u32,
    dev_minor: u32,
    inode: u64,
    perms: MmapPerms,
}

pub fn run(target: &str, since: Option<&str>, print_json: bool) -> Result<(), Box<dyn Error>> {
    let target = parse_target(target)?;
    let (window, window_label) =
        crate::commands::lane::resolve_window(since).map_err(HoldsError)?;
    let output = match target {
        Target::Port(port) => ledger::build_port_report(port, window, window_label, print_json)?,
        Target::Path(path) => ledger::build_path_report(&path, window, window_label, print_json)?,
    };
    println!("{output}");
    Ok(())
}

fn parse_target(input: &str) -> Result<Target, HoldsError> {
    if input.chars().all(|character| character.is_ascii_digit()) {
        let port = input
            .parse::<u32>()
            .map_err(|_| HoldsError(format!("invalid port: {input}")))?;
        if !(1..=u32::from(u16::MAX)).contains(&port) {
            return Err(HoldsError(format!("invalid port: {input}")));
        }
        return Ok(Target::Port(port as u16));
    }

    Ok(Target::Path(PathBuf::from(input)))
}

pub(crate) fn scan_port_holders(port: u16) -> Result<(Vec<Holder>, ScanStats), HoldsError> {
    let sockets = read_proc_net_sockets().map_err(|error| HoldsError(error.to_string()))?;
    let target_inodes: BTreeSet<u64> = sockets
        .into_iter()
        .filter(|socket| socket.port == port)
        .map(|socket| socket.inode)
        .collect();

    if target_inodes.is_empty() {
        return Ok((Vec::new(), ScanStats::default()));
    }

    scan_socket_holders(&target_inodes, &passwd_map())
}

pub(crate) fn scan_path_holders(path: &Path) -> Result<(Vec<Holder>, ScanStats), HoldsError> {
    let metadata = fs::metadata(path).map_err(|error| {
        if error.kind() == io::ErrorKind::NotFound {
            HoldsError(format!("{}: no such file or directory", path.display()))
        } else {
            HoldsError(format!("{}: {error}", path.display()))
        }
    })?;
    let target = FileId::from_metadata(&metadata);
    let (target_major, target_minor) = dev_major_minor(target.dev);
    let pids = list_pids().map_err(|error| HoldsError(error.to_string()))?;
    let users = passwd_map();
    let mut holders = Vec::new();
    let mut stats = ScanStats::default();

    for pid in pids {
        let mut evidence = Vec::new();
        match scan_pid_fds_for_file(pid, target) {
            ProcRead::Ok(mut fds) => {
                evidence.extend(fds.drain(..).map(|(fd, mode)| Evidence::Fd(fd, mode)));
            }
            ProcRead::PermissionDenied => stats.unreadable_processes += 1,
            ProcRead::Gone => continue,
            ProcRead::Fatal(error) => return Err(HoldsError(error.to_string())),
        }

        match scan_pid_maps_for_file(pid, target_major, target_minor, target.inode) {
            ProcRead::Ok(Some(perms)) => evidence.push(Evidence::Mmap(perms)),
            ProcRead::Ok(None) => {}
            ProcRead::PermissionDenied => stats.unreadable_maps += 1,
            ProcRead::Gone => continue,
            ProcRead::Fatal(error) => return Err(HoldsError(error.to_string())),
        }

        if evidence.is_empty() {
            continue;
        }

        evidence.sort();
        evidence.dedup();
        if let Some(holder) = read_holder(pid, evidence, &users) {
            holders.push(holder);
        }
    }

    holders.sort_by_key(|holder| holder.pid);
    Ok((holders, stats))
}

/// The one /etc/passwd read per scan: every holder's user label rides
/// this map instead of re-reading the file per holder
/// (night-total-lts-3).
fn passwd_map() -> HashMap<u32, String> {
    crate::system::passwd_users().unwrap_or_default()
}

fn scan_socket_holders(
    target_inodes: &BTreeSet<u64>,
    users: &HashMap<u32, String>,
) -> Result<(Vec<Holder>, ScanStats), HoldsError> {
    let pids = list_pids().map_err(|error| HoldsError(error.to_string()))?;
    let mut holders = Vec::new();
    let mut stats = ScanStats::default();

    for pid in pids {
        match scan_pid_fds_for_sockets(pid, target_inodes) {
            ProcRead::Ok(fds) if !fds.is_empty() => {
                let mut evidence: Vec<Evidence> = fds
                    .into_iter()
                    .map(|fd| {
                        let mode = read_fd_mode(pid, fd);
                        Evidence::Fd(fd, mode)
                    })
                    .collect();
                evidence.sort();
                evidence.dedup();
                if let Some(holder) = read_holder(pid, evidence, users) {
                    holders.push(holder);
                }
            }
            ProcRead::Ok(_) => {}
            ProcRead::PermissionDenied => stats.unreadable_processes += 1,
            ProcRead::Gone => {}
            ProcRead::Fatal(error) => return Err(HoldsError(error.to_string())),
        }
    }

    holders.sort_by_key(|holder| holder.pid);
    Ok((holders, stats))
}

fn read_holder(pid: u32, evidence: Vec<Evidence>, users: &HashMap<u32, String>) -> Option<Holder> {
    let process_dir = PathBuf::from(format!("/proc/{pid}"));
    let status = match fs::read_to_string(process_dir.join("status")) {
        Ok(status) => status,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return None,
        Err(_) => String::new(),
    };
    let name = crate::system::read_status_name(&status).unwrap_or_else(|| "unknown".to_owned());
    let uid = crate::system::read_status_value(&status, "Uid")
        .and_then(|value| value.split_whitespace().next().map(str::to_owned));
    let user = uid
        .as_deref()
        .and_then(|uid| resolve_username(uid, users))
        .or_else(|| uid.map(|uid| format!("uid={uid}")))
        .unwrap_or_else(|| "uid=unknown".to_owned());
    let cwd = fs::read_link(process_dir.join("cwd")).ok();

    Some(Holder {
        pid,
        name,
        user,
        cwd,
        evidence,
    })
}

#[cfg(test)]
#[path = "../../test/commands/holds_tests.rs"]
mod tests;
