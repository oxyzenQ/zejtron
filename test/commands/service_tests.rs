// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! service unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/service.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

fn unit(name: &str, active: &str, sub: &str) -> ServiceUnit {
    ServiceUnit {
        name: name.to_owned(),
        load: "loaded".to_owned(),
        active: active.to_owned(),
        sub: sub.to_owned(),
        description: String::new(),
    }
}

#[test]
fn parses_normal_systemctl_line() {
    let line = "NetworkManager.service loaded active running Network Manager";
    let unit = parse_systemctl_line(line).unwrap();

    assert_eq!(unit.name, "NetworkManager.service");
    assert_eq!(unit.load, "loaded");
    assert_eq!(unit.active, "active");
    assert_eq!(unit.sub, "running");
    assert_eq!(unit.description, "Network Manager");
}

#[test]
fn parses_description_with_spaces() {
    let line = "unbound.service loaded active running Validating recursive DNS resolver";
    let unit = parse_systemctl_line(line).unwrap();

    assert_eq!(unit.description, "Validating recursive DNS resolver");
}

#[test]
fn skips_malformed_empty_and_non_service_lines() {
    let output = "\nmalformed\nbasic.target loaded active active Basic System\nsshd.service loaded active running OpenSSH server\n";
    let units = parse_systemctl_units(output);

    assert_eq!(units.len(), 1);
    assert_eq!(units[0].name, "sshd.service");
    assert_eq!(units[0].description, "OpenSSH server");
}

#[test]
fn filter_is_case_insensitive_by_unit_name() {
    let services = vec![
        unit("NetworkManager.service", "active", "running"),
        unit("unbound.service", "active", "running"),
    ];

    let filtered = filter_services(services, &Some("network".to_owned()));

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].name, "NetworkManager.service");
}

#[test]
fn default_renderer_shows_running_and_failed() {
    let running = vec![
        unit("NetworkManager.service", "active", "running"),
        unit("unbound.service", "active", "running"),
    ];
    let failed = vec![unit("bad.service", "failed", "failed")];

    let report = format_default_report(&running, &failed, None);

    assert!(report.contains("├── running"));
    assert!(report.contains("NetworkManager.service running"));
    assert!(report.contains("└── failed"));
    assert!(report.contains("bad.service failed"));
    assert!(report.contains("2 running · 1 failed"));
}

#[test]
fn default_filter_excludes_active_exited_services() {
    let services = vec![
        unit("NetworkManager.service", "active", "running"),
        unit("systemd-random-seed.service", "active", "exited"),
        unit("dead.service", "inactive", "dead"),
    ];

    let running = filter_running_services(services);

    assert_eq!(
        running,
        vec![unit("NetworkManager.service", "active", "running")]
    );
}

#[test]
fn filter_applies_after_default_mode_selection() {
    let services = vec![
        unit("systemd-journald.service", "active", "running"),
        unit("systemd-random-seed.service", "active", "exited"),
    ];
    let running = filter_running_services(services);
    let filtered = filter_services(running, &Some("systemd".to_owned()));
    let report = format_default_report(&filtered, &[], Some("systemd"));

    assert!(report.contains("systemd-journald.service running"));
    assert!(!report.contains("systemd-random-seed.service"));
    assert!(report.contains("1 running · 0 failed"));
}

#[test]
fn failed_only_renderer_handles_none() {
    assert_eq!(format_failed_report(&[], None), "No failed services.");
}

#[test]
fn all_renderer_uses_active_sub_format_and_summary() {
    let services = vec![
        unit("one.service", "active", "running"),
        unit("two.service", "inactive", "dead"),
        unit("oneshot.service", "active", "exited"),
    ];

    let report = format_all_report(&services, None);

    assert!(report.contains("one.service active/running"));
    assert!(report.contains("two.service inactive/dead"));
    assert!(report.contains("oneshot.service active/exited"));
    assert!(report.contains("3 services"));
}

#[test]
fn all_filter_can_show_exited_units() {
    let services = vec![
        unit("systemd-journald.service", "active", "running"),
        unit("systemd-random-seed.service", "active", "exited"),
    ];
    let filtered = filter_services(services, &Some("random".to_owned()));

    let report = format_all_report(&filtered, Some("random"));

    assert!(report.contains("systemd-random-seed.service active/exited"));
    assert!(report.contains("1 service"));
}

#[test]
fn system_and_user_conflict() {
    let error = parse_options(ServiceFlags {
        system: true,
        user: true,
        failed: false,
        all: false,
        filter: None,
        unit: None,
    })
    .unwrap_err();

    assert_eq!(error.to_string(), "--system cannot be used with --user");
}

#[test]
fn systemctl_missing_error_format_is_stable() {
    let error =
        ServiceError("systemctl not found. Zejtron service requires systemd/systemctl.".to_owned());

    assert_eq!(
        error.to_string(),
        "systemctl not found. Zejtron service requires systemd/systemctl."
    );
}

#[test]
fn systemctl_unusable_error_format_is_stable() {
    assert_eq!(
        format_systemctl_error(
            "System has not been booted with systemd as init system (PID 1).",
            ""
        ),
        "systemctl failed: System has not been booted with systemd as init system (PID 1)."
    );
    assert_eq!(
        format_systemctl_error("", "Failed to connect to bus: No medium found"),
        "systemctl failed: Failed to connect to bus: No medium found"
    );
}

#[test]
fn filter_no_match_message_is_clean() {
    assert_eq!(
        format_default_report(&[], &[], Some("unbound")),
        "No services matched 'unbound'."
    );
}

#[test]
fn parse_unit_show_extracts_fields() {
    let show_output = "Id=nginx.service\n\
Description=The NGINX HTTP and reverse proxy server\n\
LoadState=loaded\n\
ActiveState=active\n\
SubState=running\n\
MainPID=1234\n\
ExecStart={ path=/usr/sbin/nginx ; argv[]=nginx -g 'daemon off;' }\n\
FragmentPath=/usr/lib/systemd/system/nginx.service\n\
ActiveEnterTimestamp=Mon 2026-01-15 14:23:01 UTC\n\
NRestarts=3\n\
MemoryCurrent=8388608\n\
CPUUsageNSec=5000000000\n\
TasksCurrent=5\n\
Wants=network.target\n\
Requires=\n\
WantedBy=multi-user.target\n";
    let detail = parse_unit_show(show_output, "nginx.service");
    assert_eq!(detail.name, "nginx.service");
    assert_eq!(
        detail.description,
        "The NGINX HTTP and reverse proxy server"
    );
    assert_eq!(detail.load_state, "loaded");
    assert_eq!(detail.active_state, "active");
    assert_eq!(detail.sub_state, "running");
    assert_eq!(detail.main_pid, Some(1234));
    assert!(detail.exec_start.contains("nginx"));
    assert_eq!(
        detail.fragment_path,
        "/usr/lib/systemd/system/nginx.service"
    );
    assert_eq!(detail.n_restarts, Some(3));
    assert_eq!(detail.memory_current, Some(8388608));
    assert_eq!(detail.cpu_usage_nsec, Some(5_000_000_000));
    assert_eq!(detail.tasks_current, Some(5));
    assert_eq!(detail.wants, vec!["network.target"]);
    assert_eq!(detail.wanted_by, vec!["multi-user.target"]);
}

#[test]
fn format_unit_detail_renders_all_fields() {
    let detail = UnitDetail {
        name: "nginx.service".to_owned(),
        description: "NGINX server".to_owned(),
        load_state: "loaded".to_owned(),
        active_state: "active".to_owned(),
        sub_state: "running".to_owned(),
        main_pid: Some(1234),
        exec_start: "nginx -g 'daemon off;'".to_owned(),
        fragment_path: "/usr/lib/systemd/system/nginx.service".to_owned(),
        active_enter_timestamp: "Mon 2026-01-15 14:23:01 UTC".to_owned(),
        n_restarts: Some(3),
        memory_current: Some(8388608),
        cpu_usage_nsec: Some(5_000_000_000),
        tasks_current: Some(5),
        wants: vec!["network.target".to_owned()],
        requires: vec![],
        wanted_by: vec!["multi-user.target".to_owned()],
    };
    let out = format_unit_detail(&detail);
    assert!(out.contains("nginx.service"));
    assert!(out.contains("description: NGINX server"));
    assert!(out.contains("state: load=loaded active=active sub=running"));
    assert!(out.contains("main-pid: 1234"));
    assert!(out.contains("exec-start: nginx"));
    assert!(out.contains("fragment: /usr/lib/systemd/system/nginx.service"));
    assert!(out.contains("restarts: 3"));
    assert!(out.contains("memory: 8.0MB"));
    assert!(out.contains("cpu-time: 5.00s"));
    assert!(out.contains("tasks: 5"));
    assert!(out.contains("wants: network.target"));
    assert!(out.contains("wanted-by: multi-user.target"));
}
