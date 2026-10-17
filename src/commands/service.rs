// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

use std::error::Error;
use std::fmt;
use std::io;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceUnit {
    pub name: String,
    pub load: String,
    pub active: String,
    pub sub: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFlags {
    pub unit: Option<String>,
    pub system: bool,
    pub user: bool,
    pub failed: bool,
    pub all: bool,
    pub filter: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceScope {
    System,
    User,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceOptions {
    scope: ServiceScope,
    failed: bool,
    all: bool,
    filter: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError(String);

impl fmt::Display for ServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for ServiceError {}

pub fn run(flags: ServiceFlags) -> Result<(), Box<dyn Error>> {
    // Parse options once. The unit field is consumed by parse_options via Clone.
    let unit_name = flags.unit.clone();
    let options = parse_options(flags)?;

    // If a unit name is given, show detail mode (systemctl show <unit>).
    if let Some(unit) = unit_name.as_deref() {
        let detail = query_unit_detail(&options, unit)?;
        let output = format_unit_detail(&detail);
        println!("{output}");
        return Ok(());
    }

    let output = if options.failed {
        let failed = filter_services(
            query_services(&options, QueryMode::Failed)?,
            &options.filter,
        );
        format_failed_report(&failed, options.filter.as_deref())
    } else if options.all {
        let services = filter_services(query_services(&options, QueryMode::All)?, &options.filter);
        format_all_report(&services, options.filter.as_deref())
    } else {
        let running = filter_running_services(query_services(&options, QueryMode::Default)?);
        let running = filter_services(running, &options.filter);
        let failed = filter_services(
            query_services(&options, QueryMode::Failed)?,
            &options.filter,
        );
        format_default_report(&running, &failed, options.filter.as_deref())
    };
    println!("{output}");
    Ok(())
}

/// Detailed unit info gathered from `systemctl show <unit>`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnitDetail {
    pub name: String,
    pub description: String,
    pub load_state: String,
    pub active_state: String,
    pub sub_state: String,
    pub main_pid: Option<u32>,
    pub exec_start: String,
    pub fragment_path: String,
    pub active_enter_timestamp: String,
    pub n_restarts: Option<u64>,
    pub memory_current: Option<u64>,
    pub cpu_usage_nsec: Option<u64>,
    pub tasks_current: Option<u64>,
    pub wants: Vec<String>,
    pub requires: Vec<String>,
    pub wanted_by: Vec<String>,
}

fn query_unit_detail(options: &ServiceOptions, unit: &str) -> Result<UnitDetail, ServiceError> {
    let mut cmd = Command::new("systemctl");
    if options.scope == ServiceScope::User {
        cmd.arg("--user");
    }
    cmd.args(["show", unit]);
    let output = cmd.output().map_err(|e| ServiceError(e.to_string()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(ServiceError(stderr.trim().to_owned()));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_unit_show(&stdout, unit))
}

fn parse_unit_show(show_output: &str, unit: &str) -> UnitDetail {
    let mut detail = UnitDetail {
        name: unit.to_owned(),
        ..Default::default()
    };
    for line in show_output.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Description" => detail.description = value.to_owned(),
            "LoadState" => detail.load_state = value.to_owned(),
            "ActiveState" => detail.active_state = value.to_owned(),
            "SubState" => detail.sub_state = value.to_owned(),
            "MainPID" => detail.main_pid = value.parse().ok(),
            "ExecStart" => detail.exec_start = value.to_owned(),
            "FragmentPath" => detail.fragment_path = value.to_owned(),
            "ActiveEnterTimestamp" => detail.active_enter_timestamp = value.to_owned(),
            "NRestarts" => detail.n_restarts = value.parse().ok(),
            "MemoryCurrent" => {
                if value != "[not set]" && value != "0" {
                    detail.memory_current = value.parse().ok();
                }
            }
            "CPUUsageNSec" => {
                if value != "[not set]" {
                    detail.cpu_usage_nsec = value.parse().ok();
                }
            }
            "TasksCurrent" => {
                if value != "[not set]" && value != "18446744073709551615" {
                    detail.tasks_current = value.parse().ok();
                }
            }
            "Wants" => {
                detail.wants = value.split_whitespace().map(str::to_owned).collect();
            }
            "Requires" => {
                detail.requires = value.split_whitespace().map(str::to_owned).collect();
            }
            "WantedBy" => {
                detail.wanted_by = value.split_whitespace().map(str::to_owned).collect();
            }
            _ => {}
        }
    }
    detail
}

fn format_unit_detail(detail: &UnitDetail) -> String {
    let mut lines = vec![detail.name.clone()];
    if !detail.description.is_empty() {
        lines.push(format!("├── description: {}", detail.description));
    }
    lines.push(format!(
        "├── state: load={} active={} sub={}",
        detail.load_state, detail.active_state, detail.sub_state
    ));
    if let Some(pid) = detail.main_pid
        && pid > 0
    {
        lines.push(format!("├── main-pid: {pid}"));
    }
    if !detail.exec_start.is_empty() {
        lines.push(format!("├── exec-start: {}", detail.exec_start));
    }
    if !detail.fragment_path.is_empty() {
        lines.push(format!("├── fragment: {}", detail.fragment_path));
    }
    if !detail.active_enter_timestamp.is_empty() {
        lines.push(format!(
            "├── active-since: {}",
            detail.active_enter_timestamp
        ));
    }
    if let Some(restarts) = detail.n_restarts
        && restarts > 0
    {
        lines.push(format!("├── restarts: {restarts}"));
    }
    if let Some(mem) = detail.memory_current {
        lines.push(format!("├── memory: {}", human_bytes(mem)));
    }
    if let Some(cpu_ns) = detail.cpu_usage_nsec {
        let cpu_secs = cpu_ns as f64 / 1_000_000_000.0;
        lines.push(format!("├── cpu-time: {cpu_secs:.2}s"));
    }
    if let Some(tasks) = detail.tasks_current {
        lines.push(format!("├── tasks: {tasks}"));
    }
    if !detail.wants.is_empty() {
        lines.push(format!("├── wants: {}", detail.wants.join(", ")));
    }
    if !detail.requires.is_empty() {
        lines.push(format!("├── requires: {}", detail.requires.join(", ")));
    }
    if !detail.wanted_by.is_empty() {
        lines.push(format!("└── wanted-by: {}", detail.wanted_by.join(", ")));
    } else if lines.last().map(|l| l.starts_with("├──")).unwrap_or(false) {
        // Fix the last ├── to └──
        if let Some(last) = lines.last_mut() {
            *last = last.replacen("├──", "└──", 1);
        }
    }
    lines.join("\n")
}

fn human_bytes(b: u64) -> String {
    if b >= 1024 * 1024 * 1024 {
        format!("{:.2}GB", b as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if b >= 1024 * 1024 {
        format!("{:.1}MB", b as f64 / 1024.0 / 1024.0)
    } else if b >= 1024 {
        format!("{:.1}KB", b as f64 / 1024.0)
    } else {
        format!("{b}B")
    }
}

fn parse_options(flags: ServiceFlags) -> Result<ServiceOptions, ServiceError> {
    if flags.system && flags.user {
        return Err(ServiceError(
            "--system cannot be used with --user".to_owned(),
        ));
    }

    Ok(ServiceOptions {
        scope: if flags.user {
            ServiceScope::User
        } else {
            ServiceScope::System
        },
        failed: flags.failed,
        all: flags.all,
        filter: flags.filter,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryMode {
    Default,
    Failed,
    All,
}

fn query_services(
    options: &ServiceOptions,
    mode: QueryMode,
) -> Result<Vec<ServiceUnit>, Box<dyn Error>> {
    let mut command = Command::new("systemctl");
    if options.scope == ServiceScope::User {
        command.arg("--user");
    }

    match mode {
        QueryMode::Default => {
            command.args([
                "list-units",
                "--type=service",
                "--no-legend",
                "--no-pager",
                "--plain",
            ]);
        }
        QueryMode::Failed => {
            command.args([
                "--failed",
                "--type=service",
                "--no-legend",
                "--no-pager",
                "--plain",
            ]);
        }
        QueryMode::All => {
            command.args([
                "list-units",
                "--type=service",
                "--all",
                "--no-legend",
                "--no-pager",
                "--plain",
            ]);
        }
    }

    let output = match command.output() {
        Ok(output) => output,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(Box::new(ServiceError(
                "systemctl not found. Zejtron service requires systemd/systemctl.".to_owned(),
            )));
        }
        Err(error) => return Err(Box::new(error)),
    };

    if !output.status.success() {
        return Err(Box::new(ServiceError(format_systemctl_error(
            &String::from_utf8_lossy(&output.stderr),
            &String::from_utf8_lossy(&output.stdout),
        ))));
    }

    Ok(parse_systemctl_units(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn format_systemctl_error(stderr: &str, stdout: &str) -> String {
    let message = stderr
        .lines()
        .chain(stdout.lines())
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("systemctl command failed");
    format!("systemctl failed: {message}")
}

pub fn parse_systemctl_units(output: &str) -> Vec<ServiceUnit> {
    output.lines().filter_map(parse_systemctl_line).collect()
}

pub fn parse_systemctl_line(line: &str) -> Option<ServiceUnit> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    let mut columns = line.split_whitespace();
    let name = columns.next()?.trim_start_matches('●');
    let load = columns.next()?;
    let active = columns.next()?;
    let sub = columns.next()?;
    let description = columns.collect::<Vec<_>>().join(" ");

    if !name.ends_with(".service") {
        return None;
    }

    Some(ServiceUnit {
        name: name.to_owned(),
        load: load.to_owned(),
        active: active.to_owned(),
        sub: sub.to_owned(),
        description: description.to_owned(),
    })
}

pub fn filter_services(services: Vec<ServiceUnit>, filter: &Option<String>) -> Vec<ServiceUnit> {
    let Some(filter) = filter.as_deref().filter(|value| !value.is_empty()) else {
        return services;
    };
    let filter = filter.to_lowercase();
    services
        .into_iter()
        .filter(|unit| unit.name.to_lowercase().contains(&filter))
        .collect()
}

pub fn filter_running_services(services: Vec<ServiceUnit>) -> Vec<ServiceUnit> {
    services
        .into_iter()
        .filter(|unit| unit.active == "active" && unit.sub == "running")
        .collect()
}

pub fn format_default_report(
    running: &[ServiceUnit],
    failed: &[ServiceUnit],
    filter: Option<&str>,
) -> String {
    if running.is_empty()
        && failed.is_empty()
        && let Some(filter) = filter
    {
        return format!("No services matched '{filter}'.");
    }

    let mut lines = vec!["services".to_owned()];
    lines.push("├── running".to_owned());
    append_unit_tree(&mut lines, running, "│   ", UnitRender::Sub);
    lines.push("└── failed".to_owned());
    append_unit_tree(&mut lines, failed, "    ", UnitRender::Sub);
    lines.push(String::new());
    lines.push(format!(
        "{} {} · {} {}",
        running.len(),
        plural(running.len(), "running", "running"),
        failed.len(),
        plural(failed.len(), "failed", "failed")
    ));
    lines.join("\n")
}

pub fn format_failed_report(failed: &[ServiceUnit], filter: Option<&str>) -> String {
    if failed.is_empty() {
        return if let Some(filter) = filter {
            format!("No services matched '{filter}'.")
        } else {
            "No failed services.".to_owned()
        };
    }

    let mut lines = vec!["failed services".to_owned()];
    append_unit_tree(&mut lines, failed, "", UnitRender::Sub);
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        failed.len(),
        plural(failed.len(), "failed", "failed")
    ));
    lines.join("\n")
}

pub fn format_all_report(services: &[ServiceUnit], filter: Option<&str>) -> String {
    if services.is_empty() {
        return if let Some(filter) = filter {
            format!("No services matched '{filter}'.")
        } else {
            "No services found.".to_owned()
        };
    }

    let mut lines = vec!["services".to_owned()];
    append_unit_tree(&mut lines, services, "", UnitRender::ActiveSub);
    lines.push(String::new());
    lines.push(format!(
        "{} {}",
        services.len(),
        plural(services.len(), "service", "services")
    ));
    lines.join("\n")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitRender {
    Sub,
    ActiveSub,
}

fn append_unit_tree(
    lines: &mut Vec<String>,
    units: &[ServiceUnit],
    indent: &str,
    render: UnitRender,
) {
    if units.is_empty() {
        lines.push(format!("{indent}└── none"));
        return;
    }

    for (index, unit) in units.iter().enumerate() {
        let branch = if index + 1 == units.len() {
            "└──"
        } else {
            "├──"
        };
        lines.push(format!("{indent}{branch} {}", format_unit(unit, render)));
    }
}

fn format_unit(unit: &ServiceUnit, render: UnitRender) -> String {
    match render {
        UnitRender::Sub => format!("{} {}", unit.name, unit.sub),
        UnitRender::ActiveSub => format!("{} {}/{}", unit.name, unit.active, unit.sub),
    }
}

fn plural<'a>(count: usize, singular: &'a str, plural: &'a str) -> &'a str {
    if count == 1 { singular } else { plural }
}

#[cfg(test)]
#[path = "../../test/commands/service_tests.rs"]
mod tests;
