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

pub fn run(
    git_hash: &str,
    attach: bool,
    detach: bool,
    symptom: Option<&str>,
    raw: bool,
) -> Result<(), Box<dyn Error>> {
    // The eBPF verbs (night-improve-1): attach/detach print their own
    // result and skip the snapshot report. The verbs exist in every
    // build - a featureless binary answers with the honest refusal
    // and a non-zero exit, never a fake success, and a feature binary
    // on an incapable host names the reason it refused.
    if attach {
        return match crate::ebpf::attach() {
            Ok(summary) => {
                println!("{summary}");
                Ok(())
            }
            Err(refusal) => Err(refusal.into()),
        };
    }
    if detach {
        return match crate::ebpf::detach() {
            Ok(summary) => {
                println!("{summary}");
                Ok(())
            }
            Err(refusal) => Err(refusal.into()),
        };
    }

    // The symptom lane (night-improve-4, Part B): the answer surface.
    // A symptom report replaces the readiness report; --raw without a
    // symptom is a usage error, never a silently ignored flag.
    if let Some(name) = symptom {
        return symptom::run(name, raw).map_err(Into::into);
    }
    if raw {
        return Err(
            "--raw requires --symptom (it appends the raw /proc reads the \
                     memory report rode on)"
                .into(),
        );
    }

    let checks = collect_checks(git_hash);
    let summary = summarize(&checks);
    // The snapshot report closes with the [eBPF] section
    // (night-improve-1): always present, always honest about what
    // this binary and this host can do.
    let report = format_report(&checks, summary, git_hash);
    let section = ebpf::section();
    println!("{report}\n{section}");
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
mod ebpf;
mod memory;
mod symptom;

use checks::{
    check_audit_log, check_container, check_holders, check_journalctl, check_kernel_distro,
    check_os, check_proc_access, check_proc_net, check_procfs, check_systemctl, check_visible_pids,
};

fn format_report(checks: &[CheckResult], summary: Summary, git_hash: &str) -> String {
    // The report frame (night-weekly-maintenance-2, the sibling
    // doctor's masterclass law): the banner opens the report, the KV
    // rows align their keys to one column, and the keys stay PLAIN -
    // the family paints values, never keys. The mode value rides
    // grey (the locked scheme's secondary content); the check rows,
    // the summary, and the build fact ride [`format_check_row`],
    // [`format_summary`], and the plain frame below. In Mono every
    // wrap is the identity, byte-identical to the pinned shape.
    let build = build_label(git_hash);
    let mut lines = vec![
        crate::output::banner("zejtron System Doctor"),
        String::new(),
        format!(
            "  {:<17}{}",
            "Mode:",
            crate::output::grey_out(&mode_value(crate::system::effective_uid()))
        ),
    ];

    for check in checks {
        lines.push(format_check_row(check));
    }

    lines.push(String::new());
    lines.push(format_summary(summary));
    lines.push(format!("  {:<17}{build}", "Build:"));
    lines.join("\n")
}

fn format_check_row(check: &CheckResult) -> String {
    // The KV row (night-weekly-maintenance-2): the key is the check
    // name, plain and aligned; the status token rides a fixed-width
    // slot wrapped in its BOLD tier (the sibling doctor's verdict
    // seats - OK bold green, WARN bold yellow, FAIL bold red); the
    // message is the value and stays unwrapped. Pad first, color
    // second: escape bytes inside a padded slot would break the
    // alignment for every row below it. In Mono mode the wrappers
    // are the identity, byte-identical to the plain row. The
    // wrappers are the stdout lane's (the data surfaces speak
    // through stdout), so a piped doctor renders plain bytes.
    let padded_label = format!("{:<6}", check.status.label());
    let label = match check.status {
        CheckStatus::Ok => crate::output::ok_bold_out(&padded_label),
        CheckStatus::Warn => crate::output::warn_bold_out(&padded_label),
        CheckStatus::Fail => crate::output::error_bold_out(&padded_label),
    };
    format!(
        "  {:<17}{}{}",
        format!("{}:", check.check),
        label,
        check.message
    )
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
    // The KV row for the counts: the ok=/warn=/fail= keys ride grey
    // (inline annotations) with their counts unwrapped - the values;
    // the row's own key rides the plain KV frame.
    format!(
        "  {:<17}{}{} {}{} {}{}",
        "Summary:",
        crate::output::grey_out("ok="),
        summary.ok,
        crate::output::grey_out("warn="),
        summary.warn,
        crate::output::grey_out("fail="),
        summary.fail
    )
}

fn mode_value(uid: Option<u32>) -> String {
    if uid == Some(0) {
        "privileged".to_owned()
    } else {
        "unprivileged (partial results expected)".to_owned()
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
#[path = "../../../test/commands/doctor/doctor_tests.rs"]
mod tests;
