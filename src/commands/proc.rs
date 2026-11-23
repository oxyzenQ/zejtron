// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::Path;

mod forest;
// The renderer (the no-mercy LOC law's pure move): the tree render,
// the find/prune/depth shaping, and the footer live in their own
// module, verbatim - the parent keeps the scan, the target grammar,
// and the JSON lane.
mod render;

use crate::output::spinner::{Spinner, Style};
use forest::{build_forest, matching_process_ids, prune_for_matches};
use render::render_report;

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

/// The scan's subject (night-open-target-1): a resolved user, or the
/// whole process table when the verb is invoked without a target.
/// The pipeline ask - `zejtron proc --print-json | jq`,
/// `zejtron proc --find ssh` - names no user by design, and the
/// required-target grammar answered every one of those invocations
/// with a usage error instead of data. No target is the ps(1) shape:
/// the whole table, every uid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    User(TargetUser),
    All,
}

impl Subject {
    /// The header label: the user's own `name uid=N` line, or the
    /// all-users form the target-less invocation renders.
    pub fn label(&self) -> String {
        match self {
            Subject::User(user) => user.label(),
            Subject::All => "all users".to_owned(),
        }
    }

    /// The uid filter the scan applies: `None` is every uid.
    pub fn uid(&self) -> Option<u32> {
        match self {
            Subject::User(user) => Some(user.uid),
            Subject::All => None,
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
    pub print_json: bool,
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
    // The advertised --no-color flag, honored (night-improve-37): the
    // flag was parsed and documented but never wired - this call is
    // the wiring. The mono override forces both output lanes plain
    // for the rest of the process, byte-identical to a piped run.
    if flags.no_color {
        crate::output::disable_color();
    }

    let find = validate_find(flags.find)?;

    let subject = resolve_subject(flags.me, user_or_uid)?;
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
    // (night-improve-33) and generalized to the whole command
    // surface 2026-10-24 (night-badass-7); the verdict and the
    // reasoning live in SECURITY.md's hardening posture, the rule is
    // excluded at scan time (.github/codeql/codeql-config.yml), and
    // the CodeQL triage lane (codeql-triage.yml) closes anything
    // raised before that exclusion. Renaming honest domain
    // vocabulary to dodge a name heuristic stays rejected.
    // The renderer branch (night-badass-9): the JSON lane speaks the
    // same scan - the same target, the same --find selection - as one
    // typed line; the text lane renders the forest tree. --depth is a
    // render limiter (it prunes the drawn tree), so the flat JSON
    // list carries the scan's full selection and ignores it; --no-pid
    // and --no-color are text-render concerns and ride unused on the
    // JSON lane.
    if flags.print_json {
        let output = snapshot_json(&subject, &view)?;
        println!("{output}");
        return Ok(());
    }
    print!("{}", render_snapshot(&subject, !flags.no_pid, &view)?);
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

/// The target grammar (night-open-target-1): `--me`, a user or UID,
/// or neither - the neither arm is the whole-table scan. The
/// both-given refusal stays: one subject, not two.
pub fn resolve_subject(me: bool, user_or_uid: Option<&str>) -> Result<Subject, String> {
    match (me, user_or_uid) {
        (true, None) => Ok(Subject::User(current_user()?)),
        (false, Some(value)) => Ok(Subject::User(resolve_user_or_uid(value)?)),
        (true, Some(_)) => Err("use either --me or USER_OR_UID, not both".to_owned()),
        (false, None) => Ok(Subject::All),
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
    crate::system::read_status_value(&status, "Uid")?
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
    subject: &Subject,
    show_pid: bool,
    view: &ViewOptions,
) -> Result<String, String> {
    // The loading lane (night-ux-orion-2): the process scan is this
    // command's large-data load - a walk of the subject's /proc
    // entries that on a busy host (containers, a loaded CI runner)
    // crosses the lazy threshold and used to sit silent, a frozen-
    // looking terminal inviting the Ctrl+C that is a bug of
    // perception. The helix narrates the walk; the arm/finish bracket
    // wraps exactly the scan call, and a fast scan never draws - the
    // fast path's stderr stays byte for byte silent.
    let indicator = Spinner::arm("scanning processes", Style::Helix);
    let scanned = scan_processes(subject.uid());
    indicator.finish();
    let report = scanned?;
    Ok(render_report(subject, report, show_pid, view))
}

/// The JSON lane's snapshot (night-badass-9): the same scan the text
/// forest renders, flat and typed. The tree is a render of this set,
/// so the list carries the scan's processes with the --find selection
/// applied through the same matcher the tree prunes with (matched
/// families, ancestors kept), ascending by pid (the scan's own
/// order, and the BTreeMap's). --depth stays the render limiter it
/// is: the flat list is the data, not the drawing.
fn snapshot_json(subject: &Subject, view: &ViewOptions) -> Result<String, String> {
    // The loading lane (night-ux-orion-2): the JSON lane rides the
    // same scan and the same narration bracket as the text lane -
    // one loading face, both renders.
    let indicator = Spinner::arm("scanning processes", Style::Helix);
    let scanned = scan_processes(subject.uid());
    indicator.finish();
    let report = scanned?;
    let mut selected: Vec<Process> = report.processes;
    if let Some(pattern) = &view.find {
        let forest = build_forest(std::mem::take(&mut selected));
        let matches = matching_process_ids(&forest, pattern);
        let pruned = prune_for_matches(&forest, &matches);
        selected = pruned.processes.into_values().collect();
    }
    Ok(processes_json(
        subject,
        &selected,
        report.unreadable_statuses,
    ))
}

/// The process scan as one JSON line: the subject's own label (the
/// text header's words), the typed rows (pid, ppid, comm, uid, state,
/// the memory and thread counters, the fresh cmdline or null), and
/// the unreadable-status count - the same honesty the text note
/// renders, as a number the automation lane can gate on.
fn processes_json(subject: &Subject, processes: &[Process], unreadable_statuses: usize) -> String {
    use crate::evidence::json::{write_array, write_opt_string, write_string};
    let mut out = String::with_capacity(160 * processes.len().max(1));
    out.push_str("{\"subject\":");
    write_string(&mut out, &subject.label());
    out.push_str(",\"processes\":");
    write_array(&mut out, processes.len(), |out, index| {
        let process = &processes[index];
        out.push_str("{\"pid\":");
        let _ = write!(out, "{}", process.pid);
        out.push_str(",\"ppid\":");
        let _ = write!(out, "{}", process.ppid);
        out.push_str(",\"comm\":");
        write_string(out, &process.name);
        out.push_str(",\"uid\":");
        let _ = write!(out, "{}", process.uid);
        out.push_str(",\"state\":");
        write_string(out, &process.state);
        out.push_str(",\"vm_rss_kb\":");
        let _ = write!(out, "{}", process.vm_rss_kb);
        out.push_str(",\"vm_size_kb\":");
        let _ = write!(out, "{}", process.vm_size_kb);
        out.push_str(",\"threads\":");
        let _ = write!(out, "{}", process.threads);
        out.push_str(",\"cmdline\":");
        write_opt_string(out, process.cmdline.as_deref());
        out.push('}');
    });
    out.push_str(",\"unreadable_statuses\":");
    let _ = write!(out, "{unreadable_statuses}");
    out.push('}');
    out
}

pub fn scan_processes(target_uid: Option<u32>) -> Result<ScanReport, String> {
    scan_processes_at(Path::new("/proc"), target_uid)
}

fn scan_processes_at(proc_root: &Path, target_uid: Option<u32>) -> Result<ScanReport, String> {
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

        if process.pid == pid && target_uid.is_none_or(|uid| process.uid == uid) {
            // Enrich with cmdline (from /proc/<pid>/cmdline) and state char
            // (from /proc/<pid>/stat field 3).
            process.cmdline = crate::system::read_cmdline(proc_root, pid);
            process.state = read_state_char(&entry.path()).unwrap_or_else(|| "?".to_owned());
            processes.push(process);
        }
    }

    processes.sort_by_key(|process| process.pid);
    // The verb's own diagnostic lane (night-total-hardening-1): the
    // scan reports what it saw - kept processes, unreadable statuses
    // skipped, the uid the filter ran for (all uids for the whole-
    // table ask, night-open-target-1). stderr only, the ledger's
    // stdout stays byte-clean.
    let subject_note = match target_uid {
        Some(uid) => format!("target uid {uid}"),
        None => "all uids".to_owned(),
    };
    crate::output::verbose::vlog!(
        "proc",
        "scanned /proc: {} processes kept, {} unreadable statuses ({subject_note})",
        processes.len(),
        unreadable_statuses
    );
    Ok(ScanReport {
        processes,
        unreadable_statuses,
    })
}

pub fn parse_status(contents: &str) -> Result<Process, String> {
    let name = crate::system::read_status_name(contents);
    let pid = parse_status_number(contents, "Pid")?.ok_or_else(|| "missing Pid".to_owned())?;
    let ppid = parse_status_number(contents, "PPid")?.ok_or_else(|| "missing PPid".to_owned())?;
    let uid = crate::system::read_status_value(contents, "Uid")
        .and_then(|value| value.split_whitespace().next().map(str::to_owned))
        .ok_or_else(|| "missing Uid".to_owned())?
        .parse::<u32>()
        .map_err(|_| "invalid real UID".to_owned())?;

    // State — read from /proc/<pid>/stat (status has no state char). The
    // caller passes the status contents only, so we read stat separately in
    // scan_processes_at. Here we default to "?" and let the scanner
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

fn parse_status_number(contents: &str, key: &str) -> Result<Option<u32>, String> {
    let Some(value) = crate::system::read_status_value(contents, key) else {
        return Ok(None);
    };
    value
        .parse::<u32>()
        .map(Some)
        .map_err(|_| format!("invalid {key}"))
}

/// Like parse_status_number but returns u64 (for memory/threads fields).
fn parse_status_u64(contents: &str, key: &str) -> Option<u64> {
    let value = crate::system::read_status_value(contents, key)?;
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

/// The stat starttime reader (night-frontier-Z11): field 22, the
/// process's birth in clock ticks since boot - the anti-recycling
/// anchor the live lane's recorded-pid attribution compares the
/// event's CLOCK_MONOTONIC stamp against (both clocks freeze while
/// the host sleeps, so a suspend cannot forge an age). Pure over the
/// stat line, the same testability shape `read_state_char`'s parsing
/// rides; the IO wrapper reads the file.
pub(crate) fn starttime_boot_ns_from_stat(stat: &str) -> Option<u64> {
    let close_paren = stat.rfind(')')?;
    let after = &stat[close_paren + 1..];
    // After the comm's closing paren the next field is state (field
    // 3); starttime is field 22 - nineteen fields past it.
    let birth_ticks = after.split_whitespace().nth(19)?.parse::<u64>().ok()?;
    // USER_HZ is 100 for the /proc ABI on every architecture Linux
    // ships (include/uapi/asm-generic/param.h), so the tick divide is
    // the birth's own granularity. The multiply rides u128: a
    // multi-year uptime's tick count overflows u64 nanoseconds.
    Some((birth_ticks as u128 * 1_000_000_000 / 100) as u64)
}

/// The process's birth in boot-relative nanoseconds, read from its
/// own `/proc/<pid>/stat`. `None` when the process is gone or the
/// stat line is unreadable - the recycle compare then rides as
/// unmatched (the honest default, never a guessed recycling).
pub(crate) fn process_starttime_boot_ns(proc_root: &Path, pid: u32) -> Option<u64> {
    let stat = fs::read_to_string(proc_root.join(pid.to_string()).join("stat")).ok()?;
    starttime_boot_ns_from_stat(&stat)
}

#[cfg(test)]
#[path = "../../test/commands/proc_tests.rs"]
mod tests;
