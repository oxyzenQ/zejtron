// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! proc unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/proc.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use std::collections::BTreeSet;
use std::time::Duration;
use tempfile::TempDir;

fn target() -> TargetUser {
    TargetUser {
        name: "rezky".to_owned(),
        uid: 1000,
    }
}

fn process(name: &str, pid: u32, ppid: u32) -> Process {
    Process {
        name: name.to_owned(),
        pid,
        ppid,
        uid: 1000,
        cmdline: None,
        state: "?".to_owned(),
        vm_rss_kb: 0,
        vm_size_kb: 0,
        threads: 1,
    }
}

fn report() -> ScanReport {
    ScanReport {
        processes: vec![
            process("bash", 20, 1),
            process("python3", 30, 20),
            process("codex", 40, 30),
            process("worker", 50, 40),
        ],
        unreadable_statuses: 0,
    }
}

fn view(max_depth: Option<usize>, find: Option<&str>) -> ViewOptions {
    ViewOptions {
        max_depth,
        find: find.map(str::to_owned),
    }
}

use super::live::{WINDOW_CEILING, WINDOW_DEFAULT, WINDOW_FLOOR, clamp_window, window_label};

#[test]
fn the_lifecycle_window_defaults_to_30s() {
    assert_eq!(WINDOW_DEFAULT, Duration::from_secs(30));
}

#[test]
fn the_lifecycle_window_clamps_into_1s_10m() {
    // The pinned clamps: 0s -> 1s, 1h -> 600s - and the in-range
    // values pass through untouched.
    assert_eq!(clamp_window(Duration::from_secs(0)), WINDOW_FLOOR);
    assert_eq!(
        clamp_window(Duration::from_secs(3600)),
        Duration::from_secs(600)
    );
    assert_eq!(
        clamp_window(Duration::from_secs(90)),
        Duration::from_secs(90)
    );
    assert_eq!(WINDOW_CEILING, Duration::from_secs(600));
}

#[test]
fn the_lifecycle_window_label_is_compact() {
    assert_eq!(window_label(Duration::from_secs(30)), "30s");
    assert_eq!(window_label(Duration::from_secs(600)), "10m");
    assert_eq!(window_label(Duration::from_secs(45)), "45s");
}

#[test]
fn watch_behaves_like_live() {
    assert!(is_live_mode(false, true));
    assert!(is_live_mode(true, false));
    assert!(!is_live_mode(false, false));
}

#[test]
fn since_requires_live_mode() {
    // The snapshot path refuses --since by name - the flag belongs
    // to the lifecycle window, never a silently ignored request.
    let err = run_inner(
        None,
        ProcFlags {
            since: Some("30s".to_owned()),
            ..Default::default()
        },
    )
    .expect_err("--since without --live must be refused");
    assert!(err.contains("--since requires --live"), "{err}");
}

#[test]
fn the_lifecycle_stream_refuses_snapshot_shaping_flags_by_name() {
    // Host-wide by design: the snapshot flags do not apply to --live,
    // each named, none silently ignored.
    for flags in [
        ProcFlags {
            live: true,
            me: true,
            ..Default::default()
        },
        ProcFlags {
            live: true,
            depth: Some(2),
            ..Default::default()
        },
        ProcFlags {
            live: true,
            find: Some("py".to_owned()),
            ..Default::default()
        },
        ProcFlags {
            live: true,
            no_pid: true,
            ..Default::default()
        },
        ProcFlags {
            live: true,
            no_color: true,
            ..Default::default()
        },
    ] {
        let err = run_inner(None, flags).expect_err("snapshot flags must not ride --live");
        assert!(err.contains("does not apply"), "{err}");
    }
    let err = run_inner(
        Some("rezky"),
        ProcFlags {
            live: true,
            ..Default::default()
        },
    )
    .expect_err("USER_OR_UID must not ride --live");
    assert!(err.contains("does not apply"), "{err}");
}

#[test]
fn resolves_numeric_uid_target() {
    assert_eq!(
        resolve_user_or_uid("4294967295").unwrap(),
        TargetUser {
            name: "uid=4294967295".to_owned(),
            uid: u32::MAX,
        }
    );
}

#[test]
fn resolves_me_to_current_user() {
    let user = resolve_target(true, None).unwrap();
    assert_eq!(user.uid, current_uid().unwrap());
}

#[test]
fn rejects_missing_target() {
    assert_eq!(
        resolve_target(false, None),
        Err("expected USER_OR_UID or --me".to_owned())
    );
}

#[test]
fn rejects_me_with_explicit_target() {
    assert_eq!(
        resolve_target(true, Some("root")),
        Err("use either --me or USER_OR_UID, not both".to_owned())
    );
}

#[test]
fn parses_passwd_entries() {
    assert_eq!(
        parse_passwd_entries(
            "root:x:0:0:root:/root:/bin/bash\nrezky:x:1000:1000::/home/rezky:/bin/zsh\n"
        )
        .unwrap(),
        vec![
            PasswdEntry {
                name: "root".to_owned(),
                uid: 0,
            },
            PasswdEntry {
                name: "rezky".to_owned(),
                uid: 1000,
            },
        ]
    );
}

#[test]
fn parses_linux_status_fields() {
    let contents = "\
Name:\tbash
Umask:\t0022
State:\tS (sleeping)
Pid:\t1234
PPid:\t1000
Uid:\t1000\t1000\t1000\t1000
";

    assert_eq!(
        parse_status(contents).unwrap(),
        Process {
            name: "bash".to_owned(),
            pid: 1234,
            ppid: 1000,
            uid: 1000,
            cmdline: None,
            state: "?".to_owned(),
            vm_rss_kb: 0,
            vm_size_kb: 0,
            threads: 1,
        }
    );
}

#[test]
fn rejects_status_without_required_fields() {
    assert_eq!(
        parse_status("Name:\tbash\nPid:\t1234\n").unwrap_err(),
        "missing PPid"
    );
}

#[test]
fn tracks_unreadable_statuses_without_real_proc() {
    let proc_root = TempDir::new().unwrap();
    let readable_pid = proc_root.path().join("1234");
    let unreadable_pid = proc_root.path().join("5678");
    fs::create_dir_all(&readable_pid).unwrap();
    fs::create_dir_all(unreadable_pid.join("status")).unwrap();
    fs::write(
        readable_pid.join("status"),
        "Name:\tbash\nPid:\t1234\nPPid:\t1\nUid:\t1000\t1000\t1000\t1000\n",
    )
    .unwrap();

    let report = scan_processes_for_uid_at(proc_root.path(), 1000).unwrap();

    assert_eq!(report.processes.len(), 1);
    assert_eq!(report.unreadable_statuses, 1);
}

#[test]
fn treats_process_as_root_when_parent_is_not_in_filtered_set() {
    let forest = build_forest(vec![
        process("bash", 20, 1),
        process("python3", 30, 20),
        process("cargo", 25, 20),
    ]);

    assert_eq!(forest.roots, vec![20]);
    assert_eq!(forest.children.get(&20), Some(&vec![25, 30]));
}

#[test]
fn treats_self_parent_as_root() {
    let forest = build_forest(vec![process("initlike", 1, 1)]);

    assert_eq!(forest.roots, vec![1]);
    assert!(forest.children.is_empty());
}

#[test]
fn finds_process_names_case_insensitively() {
    let forest = build_forest(vec![
        process("bash", 20, 1),
        process("Codex", 30, 20),
        process("cargo", 40, 20),
    ]);

    assert_eq!(matching_process_ids(&forest, "codex"), BTreeSet::from([30]));
}

#[test]
fn pruning_keeps_ancestors_and_descendants_of_matches() {
    let forest = build_forest(vec![
        process("bash", 20, 1),
        process("python3", 30, 20),
        process("codex", 40, 30),
        process("worker", 50, 40),
    ]);
    let pruned = prune_for_matches(&forest, &BTreeSet::from([40]));

    assert_eq!(pruned.roots, vec![20]);
    assert!(pruned.processes.contains_key(&20));
    assert!(pruned.processes.contains_key(&30));
    assert!(pruned.processes.contains_key(&40));
    assert!(pruned.processes.contains_key(&50));
}

#[test]
fn limits_depth_zero_to_no_processes() {
    let forest = build_forest(vec![process("bash", 20, 1)]);
    let limited = limit_depth(&forest, Some(0));

    assert!(limited.roots.is_empty());
    assert!(limited.processes.is_empty());
}

#[test]
fn limits_depth_two_to_roots_and_direct_children() {
    let forest = build_forest(vec![
        process("bash", 20, 1),
        process("python3", 30, 20),
        process("worker", 40, 30),
    ]);
    let limited = limit_depth(&forest, Some(2));

    assert_eq!(limited.roots, vec![20]);
    assert_eq!(limited.processes.len(), 2);
    assert!(limited.processes.contains_key(&20));
    assert!(limited.processes.contains_key(&30));
    assert!(!limited.processes.contains_key(&40));
}

#[test]
fn renders_tree_with_pid() {
    let output = render_forest(
        &target(),
        &build_forest(vec![
            process("bash", 20, 1),
            process("python3", 30, 20),
            process("cargo", 25, 20),
        ]),
        true,
    );

    // state=? because test Process defaults to "?"
    assert!(output.contains("bash pid=20 state=?"));
    assert!(output.contains("cargo pid=25 state=?"));
    assert!(output.contains("python3 pid=30 state=?"));
}

#[test]
fn renders_tree_without_pid() {
    let output = render_forest(
        &target(),
        &build_forest(vec![process("bash", 20, 1), process("python3", 30, 20)]),
        false,
    );

    assert!(output.contains("bash state=?"));
    assert!(output.contains("python3 state=?"));
    assert!(!output.contains(" pid="));
}

#[test]
fn renders_stable_summary() {
    let forest = build_forest(vec![
        process("bash", 20, 1),
        process("python3", 30, 20),
        process("cargo", 25, 20),
    ]);

    assert_eq!(render_summary(&forest), "1 roots · 3 processes");
}

#[test]
fn depth_zero_renders_header_and_summary_only() {
    let output = render_report(&target(), report(), true, &view(Some(0), None));

    assert_eq!(output, "rezky uid=1000\n\n0 roots · 0 processes\n");
}

#[test]
fn depth_combines_with_no_pid() {
    let output = render_report(&target(), report(), false, &view(Some(2), None));

    // state=? always shown
    assert_eq!(
        output,
        "rezky uid=1000\n└── bash state=?\n    └── python3 state=?\n\n1 roots · 2 processes\n"
    );
    assert!(!output.contains(" pid="));
}

#[test]
fn find_no_match_returns_clean_message() {
    let output = render_report(&target(), report(), true, &view(None, Some("missing")));

    assert_eq!(output, "No processes matched 'missing'.\n");
}
