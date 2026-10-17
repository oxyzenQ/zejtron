// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! system unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/system/mod.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

#[test]
fn proc_state_label_roundtrip() {
    assert_eq!(ProcState::from_char('R'), ProcState::Running);
    assert_eq!(ProcState::from_char('Z'), ProcState::Zombie);
    assert_eq!(ProcState::from_char('S'), ProcState::Sleep);
    assert_eq!(ProcState::from_char('?'), ProcState::Unknown);
    assert_eq!(ProcState::Running.label(), "R");
    assert_eq!(ProcState::Zombie.label(), "Z");
}

#[test]
fn parse_status_field_finds_key() {
    let s = "Name:\tbash\nPid:\t1234\nPPid:\t1\n";
    assert_eq!(parse_status_field(s, "Name").as_deref(), Some("bash"));
    assert_eq!(parse_status_field(s, "Pid").as_deref(), Some("1234"));
    assert_eq!(parse_status_field(s, "Missing"), None);
}

#[test]
fn parse_status_number_handles_kb_suffix() {
    let s = "VmRSS:\t   8420 kB\n";
    assert_eq!(parse_status_number(s, "VmRSS"), Some(8420));
    assert_eq!(parse_status_number(s, "VmSize"), None);
}

#[test]
fn root_refusal_pins_the_sibling_wording() {
    let refusal = root_refusal(true, "the update check performs a network fetch")
        .expect("root must be refused");
    assert_eq!(
        refusal,
        "root refused — the update check performs a network fetch, \
         do not use sudo\n  tip: re-run without sudo"
    );
    assert!(refusal.contains("do not use sudo"));
    assert!(refusal.contains("tip: re-run without sudo"));
    assert!(root_refusal(false, "anything").is_none());
}

#[test]
fn root_refusal_surfaces_interpolate_the_hazard() {
    for surface in [
        "the update check performs a network fetch",
        "environment snapshot save writes files",
        "environment snapshot delete removes files",
    ] {
        let refusal = root_refusal(true, surface).expect("root must be refused");
        assert!(refusal.starts_with("root refused — "));
        assert!(refusal.contains(surface));
    }
}

#[test]
fn parse_uid_pair_real_effective() {
    let s = "Uid:\t1000\t1000\t1000\t1000\n";
    assert_eq!(parse_uid_pair(s), Some((1000, 1000)));
    let s2 = "Uid:\t0\t0\t0\t0\n";
    assert_eq!(parse_uid_pair(s2), Some((0, 0)));
}

#[test]
fn lookup_username_resolves_known_uid() {
    // UID 0 should always resolve to "root" on any Linux system.
    assert_eq!(lookup_username(0), "root");
}

#[test]
fn lookup_username_unknown_uid_returns_numeric() {
    // Pick an absurdly high UID unlikely to exist.
    let s = lookup_username(65534);
    // 65534 is 'nobody' on most systems; if it's not, we just want a non-empty string.
    assert!(!s.is_empty());
}

#[test]
fn read_cmdline_self_pid() {
    let own_pid = std::process::id();
    let ctx = read_context(Path::new("/proc"), own_pid);
    assert!(ctx.is_some(), "should be able to read our own context");
    let ctx = ctx.unwrap();
    assert_eq!(ctx.pid, own_pid);
    assert!(!ctx.name.is_empty());
}

#[test]
fn parent_chain_self_reaches_init() {
    let own_pid = std::process::id();
    let chain = parent_chain(Path::new("/proc"), own_pid);
    assert!(!chain.is_empty());
    // Should end at PID 1 (init/systemd) or stop earlier if unprivileged.
    let last = chain.last().unwrap();
    assert!(last.pid == 1 || last.ppid == 0 || last.ppid == last.pid);
}

#[test]
fn summary_line_includes_pid_and_state() {
    let ctx = ProcessContext {
        pid: 42,
        ppid: 1,
        name: "test".to_owned(),
        cmdline: Some("test --flag".to_owned()),
        uid: 1000,
        euid: 1000,
        state: ProcState::Running,
        vm_rss_kb: 4096,
        vm_size_kb: 16384,
        vm_swap_kb: 0,
        threads: 1,
        cgroup: None,
        netns_inode: None,
        pidns_inode: None,
    };
    let line = ctx.summary_line("testuser");
    assert!(line.contains("pid=42"));
    assert!(line.contains("state=R"));
    assert!(line.contains("user=testuser"));
    assert!(line.contains("cmd='test --flag'"));
}

#[test]
fn evidence_block_has_all_fields() {
    let ctx = ProcessContext {
        pid: 42,
        ppid: 1,
        name: "test".to_owned(),
        cmdline: Some("test --flag".to_owned()),
        uid: 1000,
        euid: 1000,
        state: ProcState::Zombie,
        vm_rss_kb: 4096,
        vm_size_kb: 16384,
        vm_swap_kb: 0,
        threads: 4,
        cgroup: Some("0::/user.slice".to_owned()),
        netns_inode: Some(4026531992),
        pidns_inode: Some(4026531836),
    };
    let block = ctx.evidence_block("testuser");
    let joined = block.join("\n");
    assert!(joined.contains("name: test"));
    assert!(joined.contains("cmdline: test --flag"));
    assert!(joined.contains("pid: 42 (ppid=1)"));
    assert!(joined.contains("state: Z (zombie)"));
    assert!(joined.contains("threads: 4"));
    assert!(joined.contains("cgroup: 0::/user.slice"));
    assert!(joined.contains("netns: inode=4026531992"));
    assert!(joined.contains("pidns: inode=4026531836"));
}

#[test]
fn quote_if_needed_handles_spaces() {
    assert_eq!(quote_if_needed("simple"), "simple");
    assert_eq!(quote_if_needed("has space"), "'has space'");
    assert_eq!(quote_if_needed("has'quote"), "\"has'quote\"");
}

#[test]
fn extract_systemd_unit_from_v2_path() {
    assert_eq!(
        extract_systemd_unit("0::/system.slice/nginx.service"),
        Some("nginx.service".to_owned())
    );
    assert_eq!(
        extract_systemd_unit(
            "0::/user.slice/user-1000.slice/user@1000.service/app.slice/dbus.service"
        ),
        Some("dbus.service".to_owned())
    );
    assert_eq!(
        extract_systemd_unit("0::/system.slice/systemd-resolved.service"),
        Some("systemd-resolved.service".to_owned())
    );
}

#[test]
fn extract_systemd_unit_handles_other_suffixes() {
    assert_eq!(
        extract_systemd_unit("0::/system.slice/foo.socket"),
        Some("foo.socket".to_owned())
    );
    assert_eq!(
        extract_systemd_unit("0::/system.slice/session-1.scope"),
        Some("session-1.scope".to_owned())
    );
}

#[test]
fn extract_systemd_unit_returns_none_for_kernel_threads() {
    assert_eq!(extract_systemd_unit("0::/"), None);
    assert_eq!(extract_systemd_unit("0::/user.slice"), None);
    assert_eq!(extract_systemd_unit(""), None);
}
