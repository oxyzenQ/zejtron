// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! Shared process-context helper - the single source of truth for
//! investigator-grade process introspection.
//!
//! The inventory below is exactly what the binary calls; the
//! night-total-lts-3 audit removed the unwired remainder (the
//! ProcessContext builder, the parent-chain walker, and their private
//! status-field parsers) that a former blanket dead-code allowance
//! kept hidden: the feature freeze leaves no "upcoming depth upgrade"
//! for unwired helpers to be a foundation for, and every retired
//! surface's helpers went with it. The `commands/` modules own their
//! status parsing today; anything a second consumer needs graduates
//! into this module at that moment, not before.

pub mod pacman;
pub mod pathguard;
use std::fs;
use std::path::Path;

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
///
/// The audit record (night-improve-16, restated by the v80 surface
/// reduction night-improve-0 and kept true since): the fatal set is
/// exactly one surface - `--check-update`, the network fetch, whose
/// refusal this module's caller in `update` composes from
/// [`root_refusal`] + [`effective_uid`]. Every other surface in the
/// binary is read-only by construction - journalctl/package-db
/// queries only - and stays unguarded on purpose; keep this line
/// true when surfaces change.
pub fn root_refusal(euid_is_root: bool, surface: &str) -> Option<String> {
    if euid_is_root {
        Some(format!(
            "root refused — {surface}, do not use sudo\n  tip: re-run without sudo"
        ))
    } else {
        None
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

#[cfg(test)]
#[path = "../../test/system/system_tests.rs"]
mod tests;
