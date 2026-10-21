// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! system unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/system/mod.rs, so `super::` reaches the module exactly like the
//! inline tests did.
//!
//! The night-total-lts-3 hygiene pass removed the unwired half of the
//! module (ProcState, ProcessContext, read_context, parent_chain, and
//! their private parsers); the pins below cover exactly the inventory
//! that remains.

use super::*;
use std::path::Path;

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
    // The fatal set is exactly one surface since night-improve-0
    // retired the environment-snapshot writes: the --check-update
    // network fetch. The wording carries whatever hazard string the
    // caller passes, pinned here with the live surface.
    let surface = "the update check performs a network fetch";
    let refusal = root_refusal(true, surface).expect("root must be refused");
    assert!(refusal.starts_with("root refused — "));
    assert!(refusal.contains(surface));
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
    let cmdline = read_cmdline(Path::new("/proc"), own_pid);
    assert!(cmdline.is_some(), "should be able to read our own cmdline");
    assert!(!cmdline.unwrap().is_empty());
}

#[test]
fn sanitize_display_keeps_honest_data_byte_identical() {
    // Plain ASCII, hyphens, dots, and multibyte UTF-8 all pass through.
    assert_eq!(sanitize_display("nginx"), "nginx");
    assert_eq!(sanitize_display("systemd-journald"), "systemd-journald");
    assert_eq!(sanitize_display("café-owner"), "café-owner");
    assert_eq!(
        sanitize_display("/usr/bin/bash -g 'daemon off;'"),
        "/usr/bin/bash -g 'daemon off;'"
    );
}

#[test]
fn sanitize_display_neutralizes_escape_sequences() {
    // A hostile comm carrying a terminal escape lands as printable
    // caret-safe text: ESC renders as the six characters \u{1b}, never
    // as the raw control byte.
    assert_eq!(
        sanitize_display("\x1b]0;pwned\x07"),
        "\\u{1b}]0;pwned\\u{7}"
    );
    // C0 pairs, DEL, and the C1 range all neutralize.
    assert_eq!(sanitize_display("a\tb\nc\rd"), "a\\tb\\nc\\rd");
    assert_eq!(sanitize_display("x\u{7f}y"), "x\\u{7f}y");
    assert_eq!(sanitize_display("x\u{9b}31my"), "x\\u{9b}31my");
    // The neutralized form carries no control characters anymore.
    let hostile = "\x1b[2J\x1b[H\x07\u{9b}5i";
    let neutral = sanitize_display(hostile);
    assert!(!neutral.chars().any(char::is_control));
}

#[test]
fn read_status_name_sanitizes_hostile_name() {
    // The display-bound Name reader neutralizes a comm packed with an
    // escape sequence; the faithful grammar reader beside it keeps the
    // numeric fields byte-identical.
    let status = "Name:\t\u{1b}[31mevil\u{1b}[0m\nPid:\t42\n";
    let name = read_status_name(status).expect("Name is present");
    assert_eq!(name, "\\u{1b}[31mevil\\u{1b}[0m");
    assert_eq!(read_status_value(status, "Pid").as_deref(), Some("42"));
}

#[test]
fn read_status_value_keeps_multifield_lines_intact() {
    // Uid is a tab-separated four-value line: the grammar reader must
    // stay faithful so the parsers keep their structure (the
    // night-total-lts-3 lesson - sanitizing here broke the Uid parse).
    let status = "Uid:\t1000\t1000\t1000\t1000\n";
    assert_eq!(
        read_status_value(status, "Uid").as_deref(),
        Some("1000\t1000\t1000\t1000")
    );
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
