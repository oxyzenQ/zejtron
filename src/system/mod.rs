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
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::Path;

/// The one `/etc/passwd` reader: uid -> username, built once per
/// invocation and shared by every consumer that renders an owner.
/// The night-total-lts-3 dedupe collapsed four parsers into this one
/// (touch's map builder, system's per-call lookup_username, and the
/// per-call resolve_username twins in holds and port) - and the hot
/// one, `recent`, had been re-reading and re-parsing the file once
/// PER ROW of its output.
pub fn passwd_users() -> io::Result<HashMap<u32, String>> {
    parse_passwd_users(&fs::read_to_string("/etc/passwd")?)
}

/// The pure parser behind [`passwd_users`]: passwd format
/// `name:password:uid:gid:gecos:home:shell`, empty names and
/// unparsable uids skipped.
pub fn parse_passwd_users(contents: &str) -> io::Result<HashMap<u32, String>> {
    let mut users = HashMap::new();
    for line in contents.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next().filter(|name| !name.is_empty()) else {
            continue;
        };
        fields.next();
        let Some(uid) = fields.next().and_then(|uid| uid.parse::<u32>().ok()) else {
            continue;
        };
        users.insert(uid, name.to_owned());
    }
    Ok(users)
}

/// The display name for a uid: the passwd entry, or the numeric
/// string when the map has no entry (unprivileged container, foreign
/// uid) - callers degrade, never guess.
pub fn uid_to_user(uid: u32, users: &HashMap<u32, String>) -> String {
    users.get(&uid).cloned().unwrap_or_else(|| uid.to_string())
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

/// The one `/proc/<pid>/status` field reader behind every consumer:
/// the value after `key:`, trimmed, empty refused. The
/// night-total-lts-3 dedupe collapsed three byte-identical private
/// copies (proc, holds/procfs, port/owners) into this module so the
/// status grammar has one definition and one place to harden.
///
/// The reader stays FAITHFUL on purpose: several fields are
/// multi-value lines (Uid is tab-separated), so bytes pass through
/// unmodified and every parser keeps its structure. Neutralizing
/// hostile text is the display layer's job - the free-form Name
/// field goes through [`read_status_name`], cmdlines through
/// [`sanitize_display`] inside [`read_cmdline`].
pub fn read_status_value(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

/// The display-bound reader for the one status field whose value is
/// free-form hostile text: the process Name (comm). A local process
/// controls those bytes via prctl, and the Name renders on the proc
/// tree, the holds/why actor rows, and the port owner rows - so this
/// is the one field the terminal-safety neutralizer runs on at the
/// read boundary (night-total-lts-3, the CWE-150 pass).
pub fn read_status_name(status: &str) -> Option<String> {
    read_status_value(status, "Name").map(|name| sanitize_display(&name))
}

/// The terminal-safety neutralizer for every hostile-sourced string
/// that reaches a rendered row - process names, cmdlines, audit comm
/// values, cgroup units, cwd and symlink targets, filenames from
/// trees other users write. A local process controls its own comm and
/// argv byte for byte, and an escape sequence that survives into the
/// terminal can forge the evidence stream zejtron exists to report
/// (CWE-150, the same class the update check's `tag_is_safe` already
/// refuses for the release tag).
///
/// The neutral form keeps the evidence readable: every Unicode control
/// character (C0, DEL, and the C1 range - `char::is_control`) renders
/// as its `escape_debug` form (`ESC` becomes the six printable
/// characters `\u{1b}`), so the hostile byte stays visible in the row
/// without ever reaching the terminal as a control. Honest data pays
/// one scan and comes back byte-identical.
pub fn sanitize_display(input: &str) -> String {
    // The fast path: honest text is the overwhelming common case, and
    // one `any` scan proves it without a per-char rebuild.
    if !input.chars().any(char::is_control) {
        return input.to_owned();
    }
    input
        .chars()
        .map(|c| {
            if c.is_control() {
                c.escape_debug().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// Read `/proc/<pid>/cmdline` and split on NUL bytes into argv tokens.
/// Returns `None` if the file is unreadable or empty.
///
/// `/proc/<pid>/cmdline` is NUL-separated (not newline). An empty file
/// means the process is a kernel thread (`[kworker/...]`) — in that case
/// callers should fall back to the `Name` field from `/proc/<pid>/status`.
pub fn read_cmdline(proc_root: &Path, pid: u32) -> Option<String> {
    let path = proc_root.join(pid.to_string()).join("cmdline");
    parse_cmdline_bytes(&fs::read(&path).ok()?)
}

/// The pure parser behind [`read_cmdline`]: raw `/proc/<pid>/cmdline`
/// bytes in, argv tokens out. Split on NUL, NUL-separated (not
/// newline); an empty byte stream means the process is a kernel
/// thread and the caller falls back to the `Name` field from
/// `/proc/<pid>/status`. Separated from the filesystem read so the
/// fuzz lane drives the exact byte grammar the kernel serves
/// (night-improve-43): hostile bytes, non-UTF-8 argv, NUL edge cases,
/// all of it lands here first - and the composed result exits through
/// [`sanitize_display`] like every other hostile-sourced string.
pub fn parse_cmdline_bytes(bytes: &[u8]) -> Option<String> {
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
        Some(sanitize_display(&tokens.join(" ")))
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
