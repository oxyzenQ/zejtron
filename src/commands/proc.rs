// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fs;
use std::io;
use std::path::Path;

mod forest;

use forest::{build_forest, limit_depth, matching_process_ids, prune_for_matches};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Process {
    pub name: String,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub cmdline: Option<String>,
    pub state: String,
    pub vm_rss_kb: u64,
    pub vm_size_kb: u64,
    pub threads: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanReport {
    pub processes: Vec<Process>,
    pub unreadable_statuses: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessForest {
    pub processes: BTreeMap<u32, Process>,
    pub roots: Vec<u32>,
    pub children: BTreeMap<u32, Vec<u32>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetUser {
    pub name: String,
    pub uid: u32,
}

impl TargetUser {
    pub fn label(&self) -> String {
        let uid_label = format!("uid={}", self.uid);
        if self.name == uid_label {
            uid_label
        } else {
            format!("{} {}", self.name, uid_label)
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ProcFlags {
    pub me: bool,
    pub depth: Option<usize>,
    pub find: Option<String>,
    pub no_pid: bool,
    pub no_color: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ViewOptions {
    max_depth: Option<usize>,
    find: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcError(String);

impl fmt::Display for ProcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ProcError {}

pub fn run(user_or_uid: Option<&str>, flags: ProcFlags) -> Result<(), Box<dyn Error>> {
    run_inner(user_or_uid, flags).map_err(|error| ProcError(error).into())
}

fn run_inner(user_or_uid: Option<&str>, flags: ProcFlags) -> Result<(), String> {
    let find = validate_find(flags.find)?;

    let target = resolve_target(flags.me, user_or_uid)?;
    let view = ViewOptions {
        max_depth: flags.depth,
        find,
    };
    // The snapshot's disclosure is the product, by design: every row
    // (username, uid, pid, cmdline) is kernel-exposed process
    // metadata - the same disclosure class as ps(1) - and the reader
    // is the invoking user's own terminal, never a persisted log.
    // CodeQL's cleartext-logging rule taints this print from NAME
    // heuristics alone (the passwd_entries call and the *_uid
    // identifiers); the flagged data is the account name and the
    // cmdlines, not credential material, and nothing the kernel
    // hides from this uid is ever shown. Triaged 2026-10-19
    // (night-improve-33); the verdict and the reasoning live in
    // SECURITY.md's hardening posture.
    print!("{}", render_snapshot(&target, !flags.no_pid, &view)?);
    Ok(())
}

fn validate_find(find: Option<String>) -> Result<Option<String>, String> {
    match find {
        Some(pattern) if pattern.trim().is_empty() => {
            Err("--find requires a non-empty pattern".to_owned())
        }
        Some(pattern) => Ok(Some(pattern)),
        None => Ok(None),
    }
}

pub fn resolve_target(me: bool, user_or_uid: Option<&str>) -> Result<TargetUser, String> {
    match (me, user_or_uid) {
        (true, None) => current_user(),
        (false, Some(value)) => resolve_user_or_uid(value),
        (true, Some(_)) => Err("use either --me or USER_OR_UID, not both".to_owned()),
        (false, None) => Err("expected USER_OR_UID or --me".to_owned()),
    }
}

pub fn resolve_user_or_uid(input: &str) -> Result<TargetUser, String> {
    if input.is_empty() {
        return Err("empty user or UID".to_owned());
    }

    if input.chars().all(|character| character.is_ascii_digit()) {
        let uid = input
            .parse::<u32>()
            .map_err(|_| format!("invalid UID: {input}"))?;
        let name = username_for_uid(uid).unwrap_or_else(|| format!("uid={uid}"));
        return Ok(TargetUser { name, uid });
    }

    passwd_entries()
        .ok()
        .and_then(|entries| {
            entries
                .into_iter()
                .find(|entry| entry.name == input)
                .map(|entry| TargetUser {
                    name: entry.name,
                    uid: entry.uid,
                })
        })
        .ok_or_else(|| format!("unknown user: {input}"))
}

pub fn current_user() -> Result<TargetUser, String> {
    let uid = current_uid().ok_or_else(|| "failed to resolve current UID".to_owned())?;
    let name = username_for_uid(uid).unwrap_or_else(|| format!("uid={uid}"));
    Ok(TargetUser { name, uid })
}

fn current_uid() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    parse_status_value(&status, "Uid")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

fn username_for_uid(uid: u32) -> Option<String> {
    passwd_entries()
        .ok()?
        .into_iter()
        .find(|entry| entry.uid == uid)
        .map(|entry| entry.name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswdEntry {
    name: String,
    uid: u32,
}

fn passwd_entries() -> io::Result<Vec<PasswdEntry>> {
    parse_passwd_entries(&fs::read_to_string("/etc/passwd")?)
}

fn parse_passwd_entries(contents: &str) -> io::Result<Vec<PasswdEntry>> {
    let mut entries = Vec::new();
    for line in contents.lines() {
        let mut fields = line.split(':');
        let Some(name) = fields.next().filter(|name| !name.is_empty()) else {
            continue;
        };
        fields.next();
        let Some(uid) = fields.next().and_then(|uid| uid.parse::<u32>().ok()) else {
            continue;
        };
        entries.push(PasswdEntry {
            name: name.to_owned(),
            uid,
        });
    }
    Ok(entries)
}

fn render_snapshot(
    target: &TargetUser,
    show_pid: bool,
    view: &ViewOptions,
) -> Result<String, String> {
    let report = scan_processes_for_uid(target.uid)?;
    Ok(render_report(target, report, show_pid, view))
}

fn render_report(
    target: &TargetUser,
    report: ScanReport,
    show_pid: bool,
    view: &ViewOptions,
) -> String {
    let mut forest = build_forest(report.processes);

    if let Some(pattern) = &view.find {
        let matches = matching_process_ids(&forest, pattern);
        if matches.is_empty() {
            return format!("No processes matched '{pattern}'.\n");
        }
        forest = prune_for_matches(&forest, &matches);
    }

    forest = limit_depth(&forest, view.max_depth);

    let mut output = render_forest(target, &forest, show_pid);
    output.push('\n');

    if report.unreadable_statuses > 0 {
        output.push_str(render_unreadable_note());
        output.push('\n');
    }

    output.push_str(&render_summary(&forest));
    output.push('\n');

    output
}

pub fn scan_processes_for_uid(target_uid: u32) -> Result<ScanReport, String> {
    scan_processes_for_uid_at(Path::new("/proc"), target_uid)
}

fn scan_processes_for_uid_at(proc_root: &Path, target_uid: u32) -> Result<ScanReport, String> {
    let mut processes = Vec::new();
    let mut unreadable_statuses = 0;
    let entries = fs::read_dir(proc_root)
        .map_err(|error| format!("failed to read {}: {error}", proc_root.display()))?;

    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };

        let status_path = entry.path().join("status");
        let contents = match fs::read_to_string(status_path) {
            Ok(contents) => contents,
            Err(error) => {
                if error.kind() != io::ErrorKind::NotFound {
                    unreadable_statuses += 1;
                }
                continue;
            }
        };

        let Ok(mut process) = parse_status(&contents) else {
            continue;
        };

        if process.pid == pid && process.uid == target_uid {
            // Enrich with cmdline (from /proc/<pid>/cmdline) and state char
            // (from /proc/<pid>/stat field 3).
            process.cmdline = crate::system::read_cmdline(proc_root, pid);
            process.state = read_state_char(&entry.path()).unwrap_or_else(|| "?".to_owned());
            processes.push(process);
        }
    }

    processes.sort_by_key(|process| process.pid);
    Ok(ScanReport {
        processes,
        unreadable_statuses,
    })
}

pub fn parse_status(contents: &str) -> Result<Process, String> {
    let name = parse_status_value(contents, "Name");
    let pid = parse_status_number(contents, "Pid")?.ok_or_else(|| "missing Pid".to_owned())?;
    let ppid = parse_status_number(contents, "PPid")?.ok_or_else(|| "missing PPid".to_owned())?;
    let uid = parse_status_value(contents, "Uid")
        .and_then(|value| value.split_whitespace().next().map(str::to_owned))
        .ok_or_else(|| "missing Uid".to_owned())?
        .parse::<u32>()
        .map_err(|_| "invalid real UID".to_owned())?;

    // State — read from /proc/<pid>/stat (status has no state char). The
    // caller passes the status contents only, so we read stat separately in
    // scan_processes_for_uid_at. Here we default to "?" and let the scanner
    // fill it in.
    let vm_rss_kb = parse_status_u64(contents, "VmRSS").unwrap_or(0);
    let vm_size_kb = parse_status_u64(contents, "VmSize").unwrap_or(0);
    let threads = parse_status_u64(contents, "Threads").unwrap_or(1);

    Ok(Process {
        name: name.ok_or_else(|| "missing Name".to_owned())?,
        pid,
        ppid,
        uid,
        cmdline: None,         // filled in by scanner after parse_status
        state: "?".to_owned(), // filled in by scanner from /proc/<pid>/stat
        vm_rss_kb,
        vm_size_kb,
        threads,
    })
}

fn parse_status_value(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}:");
    status
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(str::trim))
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
}

fn parse_status_number(contents: &str, key: &str) -> Result<Option<u32>, String> {
    let Some(value) = parse_status_value(contents, key) else {
        return Ok(None);
    };
    value
        .parse::<u32>()
        .map(Some)
        .map_err(|_| format!("invalid {key}"))
}

/// Like parse_status_number but returns u64 (for memory/threads fields).
fn parse_status_u64(contents: &str, key: &str) -> Option<u64> {
    let value = parse_status_value(contents, key)?;
    // VmRSS: 1234 kB — take first whitespace-separated token
    value
        .split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok())
}

/// Read the state character from `/proc/<pid>/stat` field 3.
/// The comm field (field 2) can contain spaces and parens, so we find the
/// LAST ')' and take the char right after it.
fn read_state_char(proc_dir: &std::path::Path) -> Option<String> {
    let stat = fs::read_to_string(proc_dir.join("stat")).ok()?;
    let close_paren = stat.rfind(')')?;
    let after = &stat[close_paren + 1..];
    let state_char = after.trim_start().chars().next()?;
    let label = match state_char {
        'R' => "R",
        'S' => "S",
        'D' => "D",
        'Z' => "Z",
        'T' => "T",
        't' => "t",
        _ => "?",
    };
    Some(label.to_owned())
}

pub fn render_forest(target: &TargetUser, forest: &ProcessForest, show_pid: bool) -> String {
    let mut output = format!("{}\n", target.label());

    for (index, pid) in forest.roots.iter().enumerate() {
        render_process(
            &mut output,
            forest,
            *pid,
            "",
            index + 1 == forest.roots.len(),
            show_pid,
        );
    }

    output
}

pub fn render_summary(forest: &ProcessForest) -> String {
    format!(
        "{} roots · {} processes",
        forest.roots.len(),
        forest.processes.len()
    )
}

fn render_unreadable_note() -> &'static str {
    "note: some processes were not readable; try sudo for a complete tree"
}

fn render_process(
    output: &mut String,
    forest: &ProcessForest,
    pid: u32,
    prefix: &str,
    is_last: bool,
    show_pid: bool,
) {
    let Some(process) = forest.processes.get(&pid) else {
        return;
    };

    let branch = if is_last { "└── " } else { "├── " };
    output.push_str(&format!("{prefix}{branch}{}", process.name));

    if show_pid {
        output.push_str(&format!(" pid={}", process.pid));
    }
    // Always show state — it's a single char and very high signal (Z = zombie!)
    output.push_str(&format!(" state={}", process.state));

    output.push('\n');

    let next_prefix = if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };

    let Some(children) = forest.children.get(&pid) else {
        return;
    };

    for (index, child_pid) in children.iter().enumerate() {
        render_process(
            output,
            forest,
            *child_pid,
            &next_prefix,
            index + 1 == children.len(),
            show_pid,
        );
    }
}

#[cfg(test)]
#[path = "../../test/commands/proc_tests.rs"]
mod tests;
