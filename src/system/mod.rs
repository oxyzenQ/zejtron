// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Shared process-context helper — the single source of truth for
//! investigator-grade process introspection.
//!
//! Every other subcommand (proc, port, holds, why, touch) needs the same
//! data about a target PID: its kernel name, full command line, parent
//! chain to PID 1, real+effective UID, cgroup (systemd unit), netns/pidns
//! membership, state, memory, threads. Reading each /proc file once here
//! and exposing a structured `ProcessContext` keeps every consumer
//! consistent and avoids duplicated parsing across modules.
//!
//! Functions here are kept even when not yet wired into every subcommand —
//! they form the foundation for upcoming depth upgrades (port owner
//! context, holds holder context, why synthesis).

#![allow(dead_code)]

pub mod pacman;
pub mod pathguard;
use std::fs;
use std::path::Path;

/// Process state character from `/proc/<pid>/stat` field 3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcState {
    Running,
    Sleep,
    Uninterruptible,
    Zombie,
    Traced,
    Stopped,
    Paging,
    Dead,
    Idle,
    Unknown,
}

impl ProcState {
    pub fn from_char(c: char) -> Self {
        match c {
            'R' => Self::Running,
            'S' => Self::Sleep,
            'D' => Self::Uninterruptible,
            'Z' => Self::Zombie,
            'T' => Self::Traced,
            't' => Self::Stopped,
            'P' => Self::Paging,
            'X' | 'x' => Self::Dead,
            'I' => Self::Idle,
            _ => Self::Unknown,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Running => "R",
            Self::Sleep => "S",
            Self::Uninterruptible => "D",
            Self::Zombie => "Z",
            Self::Traced => "T",
            Self::Stopped => "t",
            Self::Paging => "P",
            Self::Dead => "X",
            Self::Idle => "I",
            Self::Unknown => "?",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Sleep => "sleeping",
            Self::Uninterruptible => "uninterruptible-disk-sleep",
            Self::Zombie => "zombie",
            Self::Traced => "traced/stopped",
            Self::Stopped => "stopped",
            Self::Paging => "paging",
            Self::Dead => "dead",
            Self::Idle => "idle",
            Self::Unknown => "unknown",
        }
    }
}

/// A user/group name resolution cache. Reads `/etc/passwd` once and looks
/// up UID → username. Returns the numeric string when no entry is found or
/// when the file is unreadable (e.g., unprivileged user inside a container).
pub fn lookup_username(uid: u32) -> String {
    let Ok(contents) = fs::read_to_string("/etc/passwd") else {
        return uid.to_string();
    };
    for line in contents.lines() {
        // passwd format: name:password:uid:gid:gecos:home:shell
        let mut parts = line.split(':');
        let Some(name) = parts.next() else { continue };
        let _ = parts.next(); // password (x or *)
        let Some(uid_str) = parts.next() else {
            continue;
        };
        let Ok(parsed_uid) = uid_str.parse::<u32>() else {
            continue;
        };
        if parsed_uid == uid {
            return name.to_owned();
        }
    }
    uid.to_string()
}

/// The real UID of the current process, read from /proc/self/status
/// (the Uid: row's second field is the effective uid). `None` when
/// procfs is unreadable - callers degrade, never guess.
pub fn effective_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        let Some(rest) = line.strip_prefix("Uid:") else {
            continue;
        };
        let mut fields = rest.split_whitespace();
        fields.next();
        return fields.next()?.parse::<u32>().ok();
    }
    None
}

/// Root refusal wording for the surfaces where root is the hazard
/// (night-improve-16). A network fetch under sudo inherits root's
/// environment wholesale, and a filesystem write under sudo plants
/// root-owned files the invoking user cannot read back - the sibling
/// pattern from zelynic's update guard, imported verbatim: pure
/// function of the euid fact so both the decision and the wording
/// are unit-pinned (CI never runs as root, the tests still pin
/// every byte).
pub fn root_refusal(euid_is_root: bool, surface: &str) -> Option<String> {
    if euid_is_root {
        Some(format!(
            "root refused — {surface}, do not use sudo\n  tip: re-run without sudo"
        ))
    } else {
        None
    }
}

/// The guard the fatal surfaces call before their first side effect:
/// `Err(refusal)` on euid 0, `Ok(())` on every non-root identity.
/// The night-improve-16 audit pinned the fatal set at three:
/// `--check-update` (network fetch) and the two environment-snapshot
/// writes of the era (filesystem writes into the data dir). The v80
/// surface reduction (night-improve-0) retired both snapshot
/// surfaces, so the fatal set is one: `--check-update`. Every other
/// surface in the binary is read-only by construction -
/// journalctl/package-db queries only - and stays unguarded on
/// purpose; this doc line is the audit record, keep it true when
/// surfaces change.
pub fn refuse_root(surface: &str) -> Result<(), String> {
    match root_refusal(effective_uid() == Some(0), surface) {
        Some(refusal) => Err(refusal),
        None => Ok(()),
    }
}

/// Read `/proc/<pid>/cmdline` and split on NUL bytes into argv tokens.
/// Returns `None` if the file is unreadable or empty.
///
/// `/proc/<pid>/cmdline` is NUL-separated (not newline). An empty file
/// means the process is a kernel thread (`[kworker/...]`) — in that case
/// callers should fall back to the `Name` field from `/proc/<pid>/status`.
pub fn read_cmdline(proc_root: &Path, pid: u32) -> Option<String> {
    let path = proc_root.join(pid.to_string()).join("cmdline");
    let bytes = fs::read(&path).ok()?;
    // Kernel threads have empty cmdline.
    if bytes.is_empty() {
        return None;
    }
    // Replace trailing NULs, then split on NUL, join with space.
    let trimmed = bytes.trim_ascii_end();
    if trimmed.is_empty() {
        return None;
    }
    let mut tokens = Vec::new();
    let mut start = 0;
    for (i, &b) in trimmed.iter().enumerate() {
        if b == 0 {
            if i > start
                && let Ok(s) = std::str::from_utf8(&trimmed[start..i])
            {
                tokens.push(s.to_owned());
            }
            start = i + 1;
        }
    }
    if start < trimmed.len()
        && let Ok(s) = std::str::from_utf8(&trimmed[start..])
    {
        tokens.push(s.to_owned());
    }
    if tokens.is_empty() {
        None
    } else {
        Some(tokens.join(" "))
    }
}

/// Extract the systemd unit name from a cgroup string.
///
/// cgroup v2 paths look like:
///   `0::/system.slice/nginx.service`
///   `0::/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service`
///   `0::/system.slice/systemd-resolved.service`
///
/// Returns the last component ending in `.service`, `.socket`, `.scope`,
/// `.mount`, `.swap`, `.timer`, or `.target`. Returns `None` when no
/// recognizable unit suffix is found (e.g., kernel threads, cgroup v1
/// legacy paths without unit names).
pub fn extract_systemd_unit(cgroup: &str) -> Option<String> {
    let suffixes = [
        ".service", ".socket", ".scope", ".mount", ".swap", ".timer", ".target",
    ];
    // Walk path components in reverse, return first match
    for component in cgroup.split('/').rev() {
        for suffix in &suffixes {
            if component.ends_with(suffix) && component.len() > suffix.len() {
                return Some(component.to_owned());
            }
        }
    }
    None
}

/// Read `/proc/<pid>/cgroup` and extract the systemd unit name.
pub fn read_systemd_unit(proc_root: &Path, pid: u32) -> Option<String> {
    let cgroup = fs::read_to_string(proc_root.join(pid.to_string()).join("cgroup")).ok()?;
    // Take the last non-empty line (usually the unified v2 line)
    let last = cgroup.lines().rev().find(|l| !l.trim().is_empty())?;
    // Format: `0::/system.slice/nginx.service` — take everything after the last `:`
    let path = last.rsplit_once(':').map(|(_, p)| p).unwrap_or(last);
    extract_systemd_unit(path)
}

/// A condensed process context. Built once per target PID and consumed by
/// every subcommand that needs to display "this is who did it" information.
#[derive(Debug, Clone)]
pub struct ProcessContext {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: Option<String>,
    pub uid: u32,
    pub euid: u32,
    pub state: ProcState,
    pub vm_rss_kb: u64,
    pub vm_size_kb: u64,
    pub vm_swap_kb: u64,
    pub threads: u64,
    pub cgroup: Option<String>,
    pub netns_inode: Option<u64>,
    pub pidns_inode: Option<u64>,
}

impl ProcessContext {
    /// Render as a single-line summary suitable for tree leaves.
    /// Example: `nginx pid=1234 user=www-data state=R rss=8MB cmd="nginx -g 'daemon off;'"`
    pub fn summary_line(&self, username: &str) -> String {
        let mut parts = Vec::new();
        parts.push(format!("pid={}", self.pid));
        parts.push(format!("user={username}"));
        parts.push(format!("state={}", self.state.label()));
        if self.vm_rss_kb > 0 {
            parts.push(format!("rss={}", human_kb(self.vm_rss_kb)));
        }
        if let Some(ref cmd) = self.cmdline {
            parts.push(format!("cmd={}", quote_if_needed(cmd)));
        } else {
            parts.push(format!("cmd={}", self.name));
        }
        parts.join(" ")
    }

    /// Render as a multi-line evidence block (the `why` renderer).
    pub fn evidence_block(&self, username: &str) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!("name: {}", self.name));
        if let Some(ref cmd) = self.cmdline {
            lines.push(format!("cmdline: {cmd}"));
        }
        lines.push(format!("pid: {} (ppid={})", self.pid, self.ppid));
        lines.push(format!(
            "user: {} (uid={} euid={})",
            username, self.uid, self.euid
        ));
        lines.push(format!(
            "state: {} ({})",
            self.state.label(),
            self.state.description()
        ));
        if self.vm_rss_kb > 0 || self.vm_size_kb > 0 {
            lines.push(format!(
                "memory: rss={} vsize={} swap={}",
                human_kb(self.vm_rss_kb),
                human_kb(self.vm_size_kb),
                human_kb(self.vm_swap_kb)
            ));
        }
        if self.threads > 1 {
            lines.push(format!("threads: {}", self.threads));
        }
        if let Some(ref cg) = self.cgroup {
            lines.push(format!("cgroup: {cg}"));
        }
        if let Some(ns) = self.netns_inode {
            lines.push(format!("netns: inode={ns}"));
        }
        if let Some(ns) = self.pidns_inode {
            lines.push(format!("pidns: inode={ns}"));
        }
        lines
    }
}

/// Read everything we need about a single PID: status (name, ppid, uid,
/// euid, memory, threads) and stat (state char). Also reads cmdline,
/// cgroup, and ns/{net,pid} symlinks.
///
/// Returns `None` if `/proc/<pid>/status` is unreadable. Other fields
/// degrade gracefully (None / 0) when their files are missing.
pub fn read_context(proc_root: &Path, pid: u32) -> Option<ProcessContext> {
    let dir = proc_root.join(pid.to_string());
    let status = fs::read_to_string(dir.join("status")).ok()?;
    let name = parse_status_field(&status, "Name")?;
    let ppid = parse_status_number_u32(&status, "PPid")?;
    let (uid, euid) = parse_uid_pair(&status)?;
    let vm_rss_kb = parse_status_number(&status, "VmRSS").unwrap_or(0);
    let vm_size_kb = parse_status_number(&status, "VmSize").unwrap_or(0);
    let vm_swap_kb = parse_status_number(&status, "VmSwap").unwrap_or(0);
    let threads = parse_status_number(&status, "Threads").unwrap_or(1);

    // State from /proc/<pid>/stat (status has no state char).
    let state = read_stat_state(&dir).unwrap_or(ProcState::Unknown);

    let cmdline = read_cmdline(proc_root, pid);
    let cgroup = read_cgroup(&dir);
    let (netns_inode, pidns_inode) = read_ns_inodes(&dir);

    Some(ProcessContext {
        pid,
        ppid,
        name,
        cmdline,
        uid,
        euid,
        state,
        vm_rss_kb,
        vm_size_kb,
        vm_swap_kb,
        threads,
        cgroup,
        netns_inode,
        pidns_inode,
    })
}

/// Walk parent chain from `start_pid` up to PID 1 (or until unreadable).
/// Returns the chain in order: [start_pid, ppid, ..., 1].
/// Skips over self and stops at PID 1.
pub fn parent_chain(proc_root: &Path, start_pid: u32) -> Vec<ProcessContext> {
    let mut chain = Vec::new();
    let mut current = start_pid;
    let mut seen = std::collections::HashSet::new();
    while let Some(ctx) = read_context(proc_root, current) {
        if !seen.insert(current) {
            break; // cycle guard
        }
        let next = ctx.ppid;
        chain.push(ctx);
        if current == 1 || next == 0 || next == current {
            break;
        }
        current = next;
    }
    chain
}

// ── helpers ──────────────────────────────────────────────────────────

fn parse_status_field(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|v| !v.is_empty())
        .map(str::to_owned)
}

fn parse_status_number(status: &str, key: &str) -> Option<u64> {
    let value = parse_status_field(status, key)?;
    // VmRSS: 1234 kB
    let parts: Vec<&str> = value.split_whitespace().collect();
    let n = parts.first()?;
    n.parse::<u64>().ok()
}

fn parse_status_number_u32(status: &str, key: &str) -> Option<u32> {
    parse_status_number(status, key).and_then(|n| n.try_into().ok())
}

fn parse_uid_pair(status: &str) -> Option<(u32, u32)> {
    // Uid: real effective saved fs
    let value = parse_status_field(status, "Uid")?;
    let mut parts = value.split_whitespace();
    let real = parts.next()?.parse::<u32>().ok()?;
    let eff = parts.next().unwrap_or("0").parse::<u32>().ok().unwrap_or(0);
    Some((real, eff))
}

fn read_stat_state(dir: &Path) -> Option<ProcState> {
    let stat = fs::read_to_string(dir.join("stat")).ok()?;
    // Field 3 is the state char, enclosed in parens-aware format:
    // pid (comm) state ...
    // comm can contain spaces and parens, so we find the LAST ')'.
    let close_paren = stat.rfind(')')?;
    let after = &stat[close_paren + 1..];
    let state_char = after.trim_start().chars().next()?;
    Some(ProcState::from_char(state_char))
}

fn read_cgroup(dir: &Path) -> Option<String> {
    let contents = fs::read_to_string(dir.join("cgroup")).ok()?;
    // Take the last non-empty line (usually the one for the user slice /
    // service scope). Multiple lines exist for v1 hierarchy.
    let mut last: Option<&str> = None;
    for line in contents.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty() {
            last = Some(trimmed);
        }
    }
    last.map(|l| l.to_owned())
}

fn read_ns_inodes(dir: &Path) -> (Option<u64>, Option<u64>) {
    let netns = read_ns_inode(dir, "net");
    let pidns = read_ns_inode(dir, "pid");
    (netns, pidns)
}

fn read_ns_inode(dir: &Path, ns: &str) -> Option<u64> {
    let path = dir.join("ns").join(ns);
    let meta = fs::symlink_metadata(&path).ok()?;
    use std::os::unix::fs::MetadataExt;
    Some(meta.ino())
}

fn human_kb(kb: u64) -> String {
    if kb >= 1024 * 1024 {
        format!("{:.1}GB", kb as f64 / 1024.0 / 1024.0)
    } else if kb >= 1024 {
        format!("{:.0}MB", kb as f64 / 1024.0)
    } else {
        format!("{kb}KB")
    }
}

fn quote_if_needed(s: &str) -> String {
    if s.contains(' ') || s.contains('"') || s.contains('\'') {
        // Use single quotes if no single quote inside; otherwise double-escape.
        if !s.contains('\'') {
            format!("'{s}'")
        } else {
            format!("\"{}\"", s.replace('"', "\\\""))
        }
    } else {
        s.to_owned()
    }
}

#[cfg(test)]
#[path = "../../test/system/system_tests.rs"]
mod tests;
