// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

//! The audit/journal evidence lane for `touch` (the night-improve-12b
//! 600-line split: the core report lives in the parent module, the
//! audit.log and journalctl parsers live here - a pure move, the
//! evidence contract unchanged).

use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

use super::{EvidenceSource, ProcessEvidence, TouchInfo, uid_to_user};

pub(crate) fn try_audit_log(
    display_path: &Path,
    lookup_path: &Path,
    users: &HashMap<u32, String>,
) -> Option<TouchInfo> {
    let audit_path = Path::new("/var/log/audit/audit.log");
    let file = fs::File::open(audit_path).ok()?;
    let reader = io::BufReader::new(file);
    let lookup = lookup_path.to_string_lossy();

    #[derive(Default)]
    struct AuditEvent {
        sec: u64,
        uid: Option<u32>,
        comm: Option<String>,
        pid: Option<u32>,
        syscall: Option<u64>,
        a1: Option<u64>,
        a2: Option<u64>,
        has_target_path: bool,
        success: Option<bool>,
    }

    let mut events: HashMap<String, AuditEvent> = HashMap::new();
    let mut last_match: Option<(u64, String)> = None;

    for line in reader.lines().map_while(Result::ok) {
        let Some(msg_id) = extract_audit_msg_id(&line) else {
            continue;
        };
        let is_syscall = line.contains("type=SYSCALL");
        let is_path = line.contains("type=PATH");
        if !is_syscall && !is_path {
            continue;
        }

        let entry = events.entry(msg_id.clone()).or_default();
        if entry.sec == 0
            && let Some(sec) = extract_audit_seconds(&line)
        {
            entry.sec = sec;
        }

        if is_syscall {
            entry.syscall = extract_kv_u64(&line, "syscall");
            entry.uid = extract_kv_u32(&line, "uid");
            // The comm value is attacker-controlled process metadata
            // (prctl can set any bytes); it renders as the process name
            // on the touch rows - sanitize_display keeps escape
            // sequences out of the terminal (night-total-lts-3).
            entry.comm =
                extract_kv_string(&line, "comm").map(|c| crate::system::sanitize_display(&c));
            entry.pid = extract_kv_u32(&line, "pid");
            entry.a1 = extract_kv_hex_u64(&line, "a1");
            entry.a2 = extract_kv_hex_u64(&line, "a2");
            entry.success = extract_kv_string(&line, "success").map(|value| value == "yes");
        }

        if is_path
            && let Some(name) = extract_kv_string(&line, "name")
            && name == lookup
        {
            entry.has_target_path = true;
        }

        if entry.has_target_path
            && entry.success == Some(true)
            && entry
                .syscall
                .is_some_and(|syscall| audit_event_is_modification(syscall, entry.a1, entry.a2))
            && entry.sec > 0
        {
            let update = match &last_match {
                Some((last_sec, _)) => entry.sec >= *last_sec,
                None => true,
            };
            if update {
                last_match = Some((entry.sec, msg_id));
            }
        }
    }

    let (sec, id) = last_match?;
    let event = events.get(&id)?;
    let actor = event
        .uid
        .map(|uid| uid_to_user(uid, users))
        .unwrap_or_else(|| "unknown".to_owned());
    let process = event.comm.clone().map(|name| ProcessEvidence {
        name,
        pid: event.pid,
    });

    Some(TouchInfo {
        path: display_path.to_path_buf(),
        modified: UNIX_EPOCH + Duration::from_secs(sec),
        source: EvidenceSource::Audit,
        actor,
        process,
        meta: None,
    })
}

pub(crate) fn try_journalctl(
    display_path: &Path,
    lookup_path: &Path,
    users: &HashMap<u32, String>,
) -> Option<TouchInfo> {
    try_journalctl_command("journalctl", display_path, lookup_path, users)
}

fn try_journalctl_command(
    command: &str,
    display_path: &Path,
    lookup_path: &Path,
    users: &HashMap<u32, String>,
) -> Option<TouchInfo> {
    let escaped = escape_journal_regex(&lookup_path.to_string_lossy());
    let output = Command::new(command)
        .arg("--no-pager")
        .arg("-o")
        .arg("export")
        .arg("-r")
        .arg("--grep")
        .arg(escaped)
        .arg("-n")
        .arg("1")
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return None;
    }

    let mut fields = HashMap::new();
    for line in stdout.lines() {
        if line.trim().is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once('=') {
            fields.insert(key.to_owned(), value.to_owned());
        }
    }

    let microseconds = fields
        .get("__REALTIME_TIMESTAMP")
        .and_then(|value| value.parse::<u64>().ok())?;
    let actor = fields
        .get("_UID")
        .and_then(|uid| uid.parse::<u32>().ok())
        .map(|uid| uid_to_user(uid, users))
        .unwrap_or_else(|| "unknown".to_owned());
    let process_name = fields
        .get("_COMM")
        .cloned()
        .or_else(|| fields.get("SYSLOG_IDENTIFIER").cloned());
    let process_pid = fields.get("_PID").and_then(|pid| pid.parse::<u32>().ok());
    let process = process_name.map(|name| ProcessEvidence {
        name,
        pid: process_pid,
    });

    Some(TouchInfo {
        path: display_path.to_path_buf(),
        modified: UNIX_EPOCH + Duration::from_micros(microseconds),
        source: EvidenceSource::Journal,
        actor,
        process,
        meta: None,
    })
}

const MODIFY_SYSCALLS_X86_64: &[u64] = &[76, 77, 82, 87, 90, 92, 260, 263, 264, 268, 280, 316];
const MODIFY_SYSCALLS_AARCH64: &[u64] = &[46, 48, 49, 52, 53, 54, 55, 56, 58, 59, 64, 67];
// The deletion family (night-frontier-Z11): the syscalls that remove
// the path or move it away. x86_64: rename=82, unlink=87, unlinkat=263,
// renameat=264, renameat2=316. aarch64 rides the asm-generic table (the
// tree's own SYSCALL_OPENAT_AARCH64=56 is the same numbering), where the
// legacy unlink does not exist: unlinkat=35, renameat=38, renameat2=276.
const DELETION_SYSCALLS_X86_64: &[u64] = &[82, 87, 263, 264, 316];
const DELETION_SYSCALLS_AARCH64: &[u64] = &[35, 38, 276];
const SYSCALL_OPEN_X86_64: u64 = 2;
const SYSCALL_OPENAT_X86_64: u64 = 257;
const SYSCALL_OPENAT_AARCH64: u64 = 56;

fn audit_event_is_modification(syscall: u64, a1: Option<u64>, a2: Option<u64>) -> bool {
    match std::env::consts::ARCH {
        "x86_64" => {
            if syscall == SYSCALL_OPEN_X86_64 {
                return open_flags_modify(a1.unwrap_or(0));
            }
            if syscall == SYSCALL_OPENAT_X86_64 {
                return open_flags_modify(a2.unwrap_or(0));
            }
            MODIFY_SYSCALLS_X86_64.contains(&syscall)
        }
        "aarch64" => {
            if syscall == SYSCALL_OPENAT_AARCH64 {
                return open_flags_modify(a2.unwrap_or(0));
            }
            MODIFY_SYSCALLS_AARCH64.contains(&syscall)
        }
        _ => {
            if syscall == SYSCALL_OPEN_X86_64 {
                return open_flags_modify(a1.unwrap_or(0));
            }
            if syscall == SYSCALL_OPENAT_X86_64 {
                return open_flags_modify(a2.unwrap_or(0));
            }
            MODIFY_SYSCALLS_X86_64.contains(&syscall)
        }
    }
}

fn open_flags_modify(flags: u64) -> bool {
    const O_WRONLY: u64 = 0o1;
    const O_RDWR: u64 = 0o2;
    const O_TRUNC: u64 = 0o1000;
    const O_CREAT: u64 = 0o100;

    (flags & (O_WRONLY | O_RDWR | O_TRUNC | O_CREAT)) != 0
}

/// The deletion predicate (night-frontier-Z11): true when the syscall
/// number is one of the arch's path-removing family. The default arm
/// mirrors `audit_event_is_modification`'s x86_64 fallback.
fn audit_event_is_deletion(syscall: u64) -> bool {
    match std::env::consts::ARCH {
        "x86_64" => DELETION_SYSCALLS_X86_64.contains(&syscall),
        "aarch64" => DELETION_SYSCALLS_AARCH64.contains(&syscall),
        _ => DELETION_SYSCALLS_X86_64.contains(&syscall),
    }
}

/// The deletion probe (night-frontier-Z11): the audit log's latest
/// successful deletion record naming the path at or after
/// `cutoff_secs`, returned as the record's unix seconds. The live
/// lane's reconciliation asks this when the event ring holds no
/// unlink or rename for the anchor inode - a yes is the two lanes'
/// disagreement, named in the Unaccounted block. The anchor-inode
/// guard holds the benign delete-and-recreate shape out: a PATH
/// record naming the target path carries the record's own inode, and
/// one that disagrees with the scan's anchor describes a DIFFERENT
/// object that wore the same name - not this object's deletion. A
/// record with no inode on its PATH line matches on the name alone
/// (the honest default), and a rename-over prints the same
/// conservative miss. `None` when the log is unreadable or nothing
/// in-window matches - the probe is a read, never a guess.
pub(crate) fn try_audit_deletion(lookup_path: &Path, inode: u64, cutoff_secs: i64) -> Option<u64> {
    audit_deletion_in_log(
        Path::new("/var/log/audit/audit.log"),
        &lookup_path.to_string_lossy(),
        inode,
        cutoff_secs,
    )
}

/// The parameterized probe body: the same scan the fixed-path wrapper
/// runs, against a caller-named log - the journal command's own
/// testability shape (`try_journalctl_command`), so the pins can feed
/// a fixture file instead of the host's audit trail.
pub(crate) fn audit_deletion_in_log(
    log_path: &Path,
    lookup: &str,
    inode: u64,
    cutoff_secs: i64,
) -> Option<u64> {
    #[derive(Default)]
    struct DeletionEvent {
        sec: u64,
        syscall: Option<u64>,
        success: Option<bool>,
        has_target_path: bool,
        target_inode_ok: bool,
    }

    let file = fs::File::open(log_path).ok()?;
    let reader = io::BufReader::new(file);
    let mut events: HashMap<String, DeletionEvent> = HashMap::new();
    let mut last_match: Option<(u64, String)> = None;

    for line in reader.lines().map_while(Result::ok) {
        let Some(msg_id) = extract_audit_msg_id(&line) else {
            continue;
        };
        let is_syscall = line.contains("type=SYSCALL");
        let is_path = line.contains("type=PATH");
        if !is_syscall && !is_path {
            continue;
        }

        let entry = events.entry(msg_id.clone()).or_default();
        if entry.sec == 0
            && let Some(sec) = extract_audit_seconds(&line)
        {
            entry.sec = sec;
        }

        if is_syscall {
            entry.syscall = extract_kv_u64(&line, "syscall");
            entry.success = extract_kv_string(&line, "success").map(|value| value == "yes");
        }

        if is_path
            && let Some(name) = extract_kv_string(&line, "name")
            && name == lookup
        {
            entry.has_target_path = true;
            // The anchor-inode guard: a PATH record that names its own
            // inode must name the anchor's; a record with no inode
            // field matches on the name alone.
            match extract_kv_u64(&line, "inode") {
                Some(record_inode) => entry.target_inode_ok |= record_inode == inode,
                None => entry.target_inode_ok = true,
            }
        }

        if entry.has_target_path
            && entry.target_inode_ok
            && entry.success == Some(true)
            && entry.syscall.is_some_and(audit_event_is_deletion)
            && entry.sec > 0
            && (entry.sec as i64) >= cutoff_secs
        {
            let update = match &last_match {
                Some((last_sec, _)) => entry.sec >= *last_sec,
                None => true,
            };
            if update {
                last_match = Some((entry.sec, msg_id));
            }
        }
    }

    let (sec, _id) = last_match?;
    Some(sec)
}

fn extract_audit_msg_id(line: &str) -> Option<String> {
    let start = line.find("msg=audit(")?;
    let rest = &line[start + "msg=audit(".len()..];
    let end = rest.find(')')?;
    Some(rest[..end].to_owned())
}

fn extract_audit_seconds(line: &str) -> Option<u64> {
    let start = line.find("msg=audit(")?;
    let rest = &line[start + "msg=audit(".len()..];
    let end = rest.find(':')?;
    rest[..end].split('.').next()?.parse().ok()
}

fn extract_kv_string(line: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=");
    let index = line.find(&needle)?;
    let rest = &line[index + needle.len()..];

    if let Some(rest) = rest.strip_prefix('"') {
        let end = rest.find('"')?;
        return Some(rest[..end].to_owned());
    }

    let end = rest.find(' ').unwrap_or(rest.len());
    Some(rest[..end].to_owned())
}

fn extract_kv_u64(line: &str, key: &str) -> Option<u64> {
    extract_kv_string(line, key)?.parse().ok()
}

fn extract_kv_u32(line: &str, key: &str) -> Option<u32> {
    extract_kv_string(line, key)?.parse().ok()
}

fn extract_kv_hex_u64(line: &str, key: &str) -> Option<u64> {
    u64::from_str_radix(&extract_kv_string(line, key)?, 16).ok()
}

fn escape_journal_regex(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '.' | '^' | '$' | '|' | '?' | '*' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '\\'
            | '-' => {
                escaped.push('\\');
                escaped.push(character);
            }
            _ => escaped.push(character),
        }
    }
    escaped
}

#[cfg(test)]
#[path = "../../../test/commands/touch/audit_tests.rs"]
mod tests;
