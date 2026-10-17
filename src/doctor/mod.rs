// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::error::Error;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckStatus {
    Ok,
    Warn,
    Fail,
}

impl CheckStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Ok => "OK",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CheckResult {
    status: CheckStatus,
    check: &'static str,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Summary {
    ok: usize,
    warn: usize,
    fail: usize,
}

pub fn run(git_hash: &str) -> Result<(), Box<dyn Error>> {
    let checks = collect_checks(git_hash);
    let summary = summarize(&checks);
    println!("{}", format_report(&checks, summary, git_hash));
    // Non-zero exit on FAIL so CI / automation can gate on doctor.
    if summary.fail > 0 {
        return Err("doctor checks failed".into());
    }
    Ok(())
}

fn collect_checks(git_hash: &str) -> Vec<CheckResult> {
    vec![
        check_os(),
        check_kernel_distro(),
        check_container(),
        check_procfs(Path::new("/proc")),
        check_visible_pids(Path::new("/proc")),
        check_proc_access(Path::new("/proc/1/comm")),
        check_proc_net(Path::new("/proc/net")),
        check_holders(Path::new("/proc/self/fd")),
        check_audit_log(Path::new("/var/log/audit/audit.log")),
        check_journalctl("journalctl"),
        check_systemctl("systemctl"),
        check_build_metadata(git_hash),
    ]
}

mod checks;

use checks::{
    check_audit_log, check_container, check_holders, check_journalctl, check_kernel_distro,
    check_os, check_proc_access, check_proc_net, check_procfs, check_systemctl, check_visible_pids,
};

fn format_report(checks: &[CheckResult], summary: Summary, git_hash: &str) -> String {
    let build = build_label(git_hash);
    let mut lines = vec![
        "Doctor report:".to_owned(),
        mode_label(crate::process::effective_uid()),
        "STATUS  CHECK                 MESSAGE".to_owned(),
    ];

    for check in checks {
        lines.push(format_check_row(check));
    }

    lines.push(String::new());
    lines.push(format_summary(summary));
    lines.push(format!("Build: {build}"));
    lines.join("\n")
}

fn format_check_row(check: &CheckResult) -> String {
    // Pad first, color second: the status label rides a fixed-width
    // column, and escape bytes inside the padded slot would break the
    // alignment for every row below it. The pad applies to the plain
    // label text; the tier color wraps the padded cell. In Mono mode
    // the wrappers are the identity, byte-identical to the old row.
    let padded_label = format!("{:<6}", check.status.label());
    let label = match check.status {
        CheckStatus::Ok => crate::output::ok(&padded_label),
        CheckStatus::Warn => crate::output::warn(&padded_label),
        CheckStatus::Fail => crate::output::error(&padded_label),
    };
    format!("{}  {:<20} {}", label, check.check, check.message)
}

fn summarize(checks: &[CheckResult]) -> Summary {
    let mut summary = Summary {
        ok: 0,
        warn: 0,
        fail: 0,
    };

    for check in checks {
        match check.status {
            CheckStatus::Ok => summary.ok += 1,
            CheckStatus::Warn => summary.warn += 1,
            CheckStatus::Fail => summary.fail += 1,
        }
    }

    summary
}

fn format_summary(summary: Summary) -> String {
    format!(
        "Summary: ok={} warn={} fail={}",
        summary.ok, summary.warn, summary.fail
    )
}

fn mode_label(uid: Option<u32>) -> String {
    if uid == Some(0) {
        "Mode: privileged".to_owned()
    } else {
        "Mode: unprivileged (partial results expected)".to_owned()
    }
}

fn build_label(git_hash: &str) -> String {
    format!(
        "zejtron v{} ({})",
        env!("CARGO_PKG_VERSION"),
        short_hash(git_hash)
    )
}

fn short_hash(hash: &str) -> &str {
    let hash = hash.trim();
    if hash.is_empty() {
        "unknown"
    } else {
        hash.get(0..7).unwrap_or(hash)
    }
}

fn check_build_metadata(git_hash: &str) -> CheckResult {
    // The doctor's build row carries the same build facts the -V
    // report does (the sibling doctor's BUILD block parity): label,
    // short sha, and the Hinnant build-time stamp when the build
    // script stamped one. The degraded "unknown" stamp is omitted
    // rather than reported - an absent fact is not a failing check.
    let stamp = option_env!("ZEJTRON_BUILD_TIME").unwrap_or("unknown");
    let message = if stamp == "unknown" {
        build_label(git_hash)
    } else {
        format!("{} built {stamp}", build_label(git_hash))
    };
    CheckResult {
        status: CheckStatus::Ok,
        check: "build_meta",
        message,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(status: CheckStatus, check: &'static str, message: &str) -> CheckResult {
        CheckResult {
            status,
            check,
            message: message.to_owned(),
        }
    }

    #[test]
    fn summary_count_formatting() {
        let checks = [
            result(CheckStatus::Ok, "one", "ok"),
            result(CheckStatus::Warn, "two", "warn"),
            result(CheckStatus::Fail, "three", "fail"),
        ];

        assert_eq!(
            format_summary(summarize(&checks)),
            "Summary: ok=1 warn=1 fail=1"
        );
    }

    #[test]
    fn status_row_formatting() {
        assert_eq!(
            format_check_row(&result(CheckStatus::Warn, "journalctl", "missing")),
            "WARN    journalctl           missing"
        );
    }

    #[test]
    fn mode_labels_are_stable() {
        assert_eq!(mode_label(Some(0)), "Mode: privileged");
        assert_eq!(
            mode_label(Some(1000)),
            "Mode: unprivileged (partial results expected)"
        );
        assert_eq!(
            mode_label(None),
            "Mode: unprivileged (partial results expected)"
        );
    }

    #[test]
    fn build_metadata_row() {
        let check = check_build_metadata("abcdef123");

        assert_eq!(check.status, CheckStatus::Ok);
        assert_eq!(check.check, "build_meta");
        assert!(check.message.contains("zejtron v"));
        assert!(check.message.contains("(abcdef1)"));
    }

    #[test]
    fn stable_output_shape() {
        let checks = [result(CheckStatus::Ok, "os", "linux")];
        let output = format_report(&checks, summarize(&checks), "abcdef123");

        assert!(output.starts_with("Doctor report:\nMode: "));
        assert!(output.contains("STATUS  CHECK                 MESSAGE"));
        assert!(output.contains("OK      os                   linux"));
        assert!(output.contains("Summary: ok=1 warn=0 fail=0"));
        assert!(output.contains("Build: zejtron v"));
    }
}
