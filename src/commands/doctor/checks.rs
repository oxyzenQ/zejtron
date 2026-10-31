// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The doctor's individual environment checks (the night-improve-12b
//! 600-line split: the report/summary lanes live in the parent
//! module, the per-check probes live here - a pure move, every
//! verdict contract unchanged).

use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::process::Command;

use super::{CheckResult, CheckStatus};
use crate::output::noun_for;

pub(super) fn check_kernel_distro() -> CheckResult {
    let kernel = kernel_release().unwrap_or_else(|| "unknown".to_owned());
    let distro = distro_name().unwrap_or_else(|| "unknown".to_owned());
    CheckResult {
        status: CheckStatus::Ok,
        check: "kernel",
        message: format!("{kernel} | {distro}"),
    }
}

/// The kernel's release, probed once and shared: the kernel check's
/// message composes it with the distro, and the JSON lane's root
/// facts read the same probe (one source, two surfaces).
pub(super) fn kernel_release() -> Option<String> {
    let out = Command::new("uname").arg("-r").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if s.is_empty() { None } else { Some(s) }
}

/// The host's distro name, read once and shared: the kernel check's
/// message and the JSON lane's root facts speak the same value.
pub(super) fn distro_name() -> Option<String> {
    let content = fs::read_to_string("/etc/os-release").ok()?;
    let mut name = None;
    let mut version = None;
    for line in content.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            return Some(v.trim_matches('"').to_owned());
        }
        if let Some(v) = line.strip_prefix("NAME=") {
            name = Some(v.trim_matches('"').to_owned());
        }
        if let Some(v) = line.strip_prefix("VERSION=") {
            version = Some(v.trim_matches('"').to_owned());
        }
    }
    match (name, version) {
        (Some(n), Some(v)) => Some(format!("{n} {v}")),
        (Some(n), None) => Some(n),
        _ => None,
    }
}

pub(super) fn check_container() -> CheckResult {
    let mut evidence = Vec::new();
    // /.dockerenv is the classic Docker marker
    if Path::new("/.dockerenv").exists() {
        evidence.push("/.dockerenv".to_owned());
    }
    // /run/.containerenv is the podman marker
    if Path::new("/run/.containerenv").exists() {
        evidence.push("/run/.containerenv".to_owned());
    }
    // /proc/1/cgroup containing /docker/ or /kubepods/ indicates a container
    if let Ok(cg) = fs::read_to_string("/proc/1/cgroup")
        && (cg.contains("/docker/") || cg.contains("/kubepods/") || cg.contains("/lxc/"))
    {
        evidence.push("cgroup indicates container".to_owned());
    }
    // /proc/1/sched shows the init process name; in containers it's not "systemd" or "init"
    if let Ok(sched) = fs::read_to_string("/proc/1/sched") {
        let first_line = sched.lines().next().unwrap_or("");
        // In a real host, PID 1 is usually systemd/init. In a container it's
        // typically the entrypoint binary.
        if !first_line.contains("systemd")
            && !first_line.contains("init")
            && !first_line.contains("/sbin/init")
            && !first_line.is_empty()
        {
            // Only flag if other evidence also present, to avoid false positives
            // on minimal hosts
            if !evidence.is_empty() {
                // The sched first line rides the kernel's
                // "name (pid, #threads: N)" shape: the evidence item
                // already says "pid 1", and the host-namespace pid and
                // thread count are noise nested inside the row's
                // evidence parens (night-improve-43) - the init name
                // is the signal, so it rides alone.
                let init_name = first_line.split(" (").next().unwrap_or(first_line);
                evidence.push(format!("pid 1: {init_name}"));
            }
        }
    }

    if evidence.is_empty() {
        CheckResult {
            status: CheckStatus::Ok,
            check: "container",
            message: "bare-metal or VM (no container markers found)".to_owned(),
        }
    } else {
        CheckResult {
            status: CheckStatus::Warn,
            check: "container",
            message: format!("running inside container ({})", evidence.join(", ")),
        }
    }
}

pub(super) fn check_os() -> CheckResult {
    if std::env::consts::OS == "linux" {
        return CheckResult {
            status: CheckStatus::Ok,
            check: "os",
            message: "linux".to_owned(),
        };
    }

    CheckResult {
        status: CheckStatus::Fail,
        check: "os",
        message: format!("unsupported OS: {}", std::env::consts::OS),
    }
}

pub(super) fn check_procfs(proc_path: &Path) -> CheckResult {
    match fs::metadata(proc_path) {
        Ok(metadata) if metadata.is_dir() => CheckResult {
            status: CheckStatus::Ok,
            check: "procfs",
            message: format!("{} present", proc_path.display()),
        },
        Ok(_) => CheckResult {
            status: CheckStatus::Fail,
            check: "procfs",
            message: format!("{} is not a directory", proc_path.display()),
        },
        Err(error) => CheckResult {
            status: CheckStatus::Fail,
            check: "procfs",
            message: format!("{} not accessible: {error}", proc_path.display()),
        },
    }
}

pub(super) fn check_visible_pids(proc_path: &Path) -> CheckResult {
    match count_visible_pids(proc_path) {
        Ok(0) => CheckResult {
            status: CheckStatus::Fail,
            check: "pids",
            message: "no visible processes".to_owned(),
        },
        Ok(count) if count < 3 => CheckResult {
            status: CheckStatus::Warn,
            check: "pids",
            message: format!("{count} processes visible; procfs may be restricted"),
        },
        Ok(count) => CheckResult {
            status: CheckStatus::Ok,
            check: "pids",
            message: format!("{count} processes visible"),
        },
        Err(error) => CheckResult {
            status: CheckStatus::Fail,
            check: "pids",
            message: format!("cannot scan {}: {error}", proc_path.display()),
        },
    }
}

fn count_visible_pids(proc_path: &Path) -> io::Result<usize> {
    let mut count = 0;
    for entry in fs::read_dir(proc_path)? {
        let entry = entry?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.chars().all(|character| character.is_ascii_digit()))
        {
            count += 1;
        }
    }
    Ok(count)
}

pub(super) fn check_proc_access(comm_path: &Path) -> CheckResult {
    match fs::read_to_string(comm_path) {
        Ok(_) => CheckResult {
            status: CheckStatus::Ok,
            check: "proc_access",
            message: format!("can read {}", comm_path.display()),
        },
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => CheckResult {
            status: CheckStatus::Warn,
            check: "proc_access",
            message: format!("permission denied reading {}", comm_path.display()),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => CheckResult {
            status: CheckStatus::Warn,
            check: "proc_access",
            message: format!("{} not found", comm_path.display()),
        },
        Err(error) => CheckResult {
            status: CheckStatus::Warn,
            check: "proc_access",
            message: format!("error reading {}: {error}", comm_path.display()),
        },
    }
}

pub(super) fn check_proc_net(proc_net: &Path) -> CheckResult {
    let files = ["tcp", "udp", "tcp6", "udp6"];
    let mut parsed = 0usize;
    let mut sockets = 0usize;

    for file in files {
        if let Ok(count) = count_proc_net_sockets(&proc_net.join(file)) {
            parsed += 1;
            sockets += count;
        }
    }

    // The check's subject is the net surface's readability, not
    // traffic on it. A fresh container netns (the exact shape the
    // Container E2E lane runs) carries every file with zero socket
    // rows - that is the surface working, not failing, so the
    // socket count only decorates the message and the parsed-file
    // count decides the verdict. The FAIL verdict stays reserved
    // for the broken-procfs shape: not one /proc/net file readable.
    if parsed == 0 {
        return CheckResult {
            status: CheckStatus::Fail,
            check: "proc_net",
            message: "no /proc/net socket files could be parsed".to_owned(),
        };
    }

    if parsed == files.len() {
        return CheckResult {
            status: CheckStatus::Ok,
            check: "proc_net",
            message: format!(
                "{sockets} {} parsed",
                noun_for(sockets, "socket", "sockets")
            ),
        };
    }

    let unavailable = files.len() - parsed;
    CheckResult {
        status: CheckStatus::Warn,
        check: "proc_net",
        message: format!(
            "{sockets} {} parsed; {unavailable} {} unavailable",
            noun_for(sockets, "socket", "sockets"),
            noun_for(unavailable, "proc-net file", "proc-net files")
        ),
    }
}

fn count_proc_net_sockets(path: &Path) -> io::Result<usize> {
    let file = fs::File::open(path)?;
    let reader = io::BufReader::new(file);
    let mut count = 0usize;

    for (index, line) in reader.lines().enumerate() {
        let line = line?;
        if index == 0 {
            continue;
        }
        if proc_net_line_has_socket(&line) {
            count += 1;
        }
    }

    Ok(count)
}

fn proc_net_line_has_socket(line: &str) -> bool {
    let columns: Vec<&str> = line.split_whitespace().collect();
    if columns.len() < 10 {
        return false;
    }
    let Some(local) = columns.get(1) else {
        return false;
    };
    let Some((_, port_hex)) = local.split_once(':') else {
        return false;
    };
    u16::from_str_radix(port_hex, 16).is_ok() && columns[9].parse::<u64>().is_ok()
}

pub(super) fn check_holders(fd_path: &Path) -> CheckResult {
    match fs::read_dir(fd_path) {
        Ok(_) => CheckResult {
            status: CheckStatus::Ok,
            check: "holders",
            message: "current process fd directory readable".to_owned(),
        },
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => CheckResult {
            status: CheckStatus::Warn,
            check: "holders",
            message: "fd scanning appears restricted; sudo may reveal more holder details"
                .to_owned(),
        },
        Err(error) => CheckResult {
            status: CheckStatus::Warn,
            check: "holders",
            message: format!("fd scan smoke failed: {error}"),
        },
    }
}

pub(super) fn check_audit_log(path: &Path) -> CheckResult {
    match fs::metadata(path) {
        Ok(_) => match fs::File::open(path) {
            Ok(_) => CheckResult {
                status: CheckStatus::Ok,
                check: "audit_log",
                message: "audit log readable".to_owned(),
            },
            Err(error) => CheckResult {
                status: CheckStatus::Warn,
                check: "audit_log",
                message: format!("audit log unavailable: {error}"),
            },
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => CheckResult {
            status: CheckStatus::Warn,
            check: "audit_log",
            message: "audit log unavailable: not found".to_owned(),
        },
        Err(error) => CheckResult {
            status: CheckStatus::Warn,
            check: "audit_log",
            message: format!("audit log unavailable: {error}"),
        },
    }
}

pub(super) fn check_journalctl(command: &str) -> CheckResult {
    check_command_version(
        "journalctl",
        command,
        &["--version"],
        "available",
        "unavailable or not usable",
    )
}

pub(super) fn check_systemctl(command: &str) -> CheckResult {
    check_command_version(
        "systemctl",
        command,
        &[
            "list-units",
            "--type=service",
            "--no-legend",
            "--no-pager",
            "--plain",
        ],
        "available and systemd is usable",
        "unavailable or not usable",
    )
}

fn check_command_version(
    check: &'static str,
    command: &str,
    args: &[&str],
    ok_message: &str,
    warn_message: &str,
) -> CheckResult {
    match Command::new(command).args(args).output() {
        Ok(output) if output.status.success() => CheckResult {
            status: CheckStatus::Ok,
            check,
            message: ok_message.to_owned(),
        },
        Ok(output) => {
            let detail = first_output_line(&output.stderr, &output.stdout)
                .unwrap_or_else(|| "command returned non-zero".to_owned());
            CheckResult {
                status: CheckStatus::Warn,
                check,
                message: format!("{warn_message}: {detail}"),
            }
        }
        Err(error) => CheckResult {
            status: CheckStatus::Warn,
            check,
            message: format!("{warn_message}: {error}"),
        },
    }
}

fn first_output_line(stderr: &[u8], stdout: &[u8]) -> Option<String> {
    let stderr = String::from_utf8_lossy(stderr);
    let stdout = String::from_utf8_lossy(stdout);
    stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(str::to_owned)
}

#[cfg(test)]
#[path = "../../../test/commands/doctor/checks_tests.rs"]
mod tests;
