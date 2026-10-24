// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! holds' /proc readers and parsers (night-improve-18: the
//! 600-line no-mercy cap's split - one concern, one module).
//! Pure move from src/commands/holds.rs: the per-pid fd/map/net
//! scanners, the proc-net parsers, and the small uid/dev helpers.
//! `super::` is the holds module; visibility widened to
//! pub(super) exactly where the parent calls in.

use super::{FdMode, FileId, MmapPerms, Protocol, SocketEntry};
use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;

pub(super) enum ProcRead<T> {
    Ok(T),
    PermissionDenied,
    Gone,
    Fatal(io::Error),
}

pub(super) fn classify_proc_error<T>(error: io::Error) -> ProcRead<T> {
    match error.kind() {
        io::ErrorKind::NotFound => ProcRead::Gone,
        io::ErrorKind::PermissionDenied => ProcRead::PermissionDenied,
        _ => ProcRead::Fatal(error),
    }
}

pub(super) fn list_pids() -> io::Result<Vec<u32>> {
    let mut pids = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        if let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    Ok(pids)
}

pub(super) fn scan_pid_fds_for_file(pid: u32, target: FileId) -> ProcRead<Vec<(i32, FdMode)>> {
    let fd_entries = match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => entries,
        Err(error) => return classify_proc_error(error),
    };
    let mut fds = Vec::new();

    for fd_entry in fd_entries {
        let fd_entry = match fd_entry {
            Ok(entry) => entry,
            Err(error) => {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    return ProcRead::PermissionDenied;
                }
                continue;
            }
        };
        let Some(fd) = fd_entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        match fs::metadata(fd_entry.path()) {
            Ok(metadata) if FileId::from_metadata(&metadata) == target => {
                let mode = read_fd_mode(pid, fd);
                fds.push((fd, mode));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return ProcRead::PermissionDenied;
            }
            Err(_) => {}
        }
    }

    fds.sort_unstable_by_key(|a| a.0);
    ProcRead::Ok(fds)
}

/// Read `/proc/<pid>/fdinfo/<fd>` and parse the `flags:` field to determine
/// the FD access mode (O_RDONLY=0, O_WRONLY=1, O_RDWR=2). Returns
/// FdMode::Unknown when fdinfo is unreadable or the flags line is missing.
pub(super) fn read_fd_mode(pid: u32, fd: i32) -> FdMode {
    let Ok(content) = fs::read_to_string(format!("/proc/{pid}/fdinfo/{fd}")) else {
        return FdMode::Unknown;
    };
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("flags:") {
            let flags = rest.trim().parse::<u64>().unwrap_or(0);
            return FdMode::from_flags(flags);
        }
    }
    FdMode::Unknown
}

pub(super) fn scan_pid_fds_for_sockets(
    pid: u32,
    target_inodes: &BTreeSet<u64>,
) -> ProcRead<Vec<i32>> {
    let fd_entries = match fs::read_dir(format!("/proc/{pid}/fd")) {
        Ok(entries) => entries,
        Err(error) => return classify_proc_error(error),
    };
    let mut fds = Vec::new();

    for fd_entry in fd_entries {
        let fd_entry = match fd_entry {
            Ok(entry) => entry,
            Err(error) => {
                if error.kind() == io::ErrorKind::PermissionDenied {
                    return ProcRead::PermissionDenied;
                }
                continue;
            }
        };
        let Some(fd) = fd_entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            continue;
        };
        let target = match fs::read_link(fd_entry.path()) {
            Ok(target) => target,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                return ProcRead::PermissionDenied;
            }
            Err(_) => continue,
        };
        if parse_socket_inode(&target).is_some_and(|inode| target_inodes.contains(&inode)) {
            fds.push(fd);
        }
    }

    fds.sort_unstable();
    ProcRead::Ok(fds)
}

pub(super) fn scan_pid_maps_for_file(
    pid: u32,
    target_major: u32,
    target_minor: u32,
    target_inode: u64,
) -> ProcRead<Option<MmapPerms>> {
    // night-dragon-1: the whole maps file used to be materialized
    // into a Vec<MapEntry> before the first-match scan - one heap
    // allocation per pid and full-file parsing even when the match
    // sat on the first line. On a 10,000-process host that turned
    // one holds scan into tens of thousands of allocations and
    // parse-everything work. The stream now parses one line at a
    // time and returns the moment the first dev/inode match is
    // known, so the per-pid cost is one BufReader and no Vec. The
    // answer is the same first-match-in-file-order perms the Vec
    // form returned: the line filters are conjunctive, so checking
    // the inode before the dev only changes which lines are
    // rejected, never which line matches first.
    let file = match fs::File::open(format!("/proc/{pid}/maps")) {
        Ok(file) => file,
        Err(error) => return classify_proc_error(error),
    };
    let reader = io::BufReader::new(file);

    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => return classify_proc_error(error),
        };
        let mut parts = line.split_whitespace();
        parts.next(); // address range (col 1)
        let perms_str = parts.next(); // perms (col 2: "r-xp")
        parts.next(); // offset (col 3)
        let Some(dev) = parts.next() else {
            continue;
        };
        let Some(inode) = parts.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        if inode == 0 || inode != target_inode {
            continue;
        }
        let Some((dev_major, dev_minor)) = parse_dev_hex(dev) else {
            continue;
        };
        if dev_major != target_major || dev_minor != target_minor {
            continue;
        }
        let perms = perms_str.and_then(MmapPerms::parse).unwrap_or(MmapPerms {
            read: false,
            write: false,
            execute: false,
            private: true,
        });
        return ProcRead::Ok(Some(perms));
    }

    ProcRead::Ok(None)
}

pub(super) fn read_proc_net_sockets() -> io::Result<Vec<SocketEntry>> {
    let mut sockets = Vec::new();
    for (path, protocol) in [
        ("/proc/net/tcp", Protocol::Tcp),
        ("/proc/net/tcp6", Protocol::Tcp),
        ("/proc/net/udp", Protocol::Udp),
        ("/proc/net/udp6", Protocol::Udp),
    ] {
        match parse_proc_net_file(Path::new(path), protocol) {
            Ok(mut entries) => sockets.append(&mut entries),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    Ok(sockets)
}

pub(super) fn parse_proc_net_file(path: &Path, protocol: Protocol) -> io::Result<Vec<SocketEntry>> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut entries = Vec::new();

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if index == 0 {
            continue;
        }
        if let Some(entry) = parse_proc_net_line(&line, protocol) {
            entries.push(entry);
        }
    }
    Ok(entries)
}

pub(super) fn parse_proc_net_line(line: &str, protocol: Protocol) -> Option<SocketEntry> {
    let columns: Vec<&str> = line.split_whitespace().collect();
    let local = *columns.get(1)?;
    let inode = columns.get(9)?.parse().ok()?;
    let (_, port_hex) = local.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    Some(SocketEntry {
        protocol,
        port,
        inode,
    })
}

pub(super) fn parse_socket_inode(path: &Path) -> Option<u64> {
    let text = path.to_string_lossy();
    let inode = text.strip_prefix("socket:[")?.strip_suffix(']')?;
    inode.parse().ok()
}

pub(super) fn resolve_username(uid: &str, users: &HashMap<u32, String>) -> Option<String> {
    let uid = uid.parse::<u32>().ok()?;
    users.get(&uid).cloned()
}

pub(super) fn dev_major_minor(dev: u64) -> (u32, u32) {
    let major = ((dev & 0x0000_0000_000f_ff00) >> 8) | ((dev & 0xffff_f000_0000_0000) >> 32);
    let minor = (dev & 0x0000_0000_0000_00ff) | ((dev & 0x0000_0000_fff0_0000) >> 12);
    (major as u32, minor as u32)
}

pub(super) fn parse_dev_hex(dev: &str) -> Option<(u32, u32)> {
    let (major, minor) = dev.split_once(':')?;
    Some((
        u32::from_str_radix(major, 16).ok()?,
        u32::from_str_radix(minor, 16).ok()?,
    ))
}
