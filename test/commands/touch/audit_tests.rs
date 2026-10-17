// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! audit unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/touch/audit.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

#[test]
fn extracts_audit_fields() {
    let line = r#"type=SYSCALL msg=audit(1700000000.123:456): uid=1000 pid=1234 comm="nano" syscall=257 success=yes a2=8001"#;

    assert_eq!(
        extract_audit_msg_id(line),
        Some("1700000000.123:456".to_owned())
    );
    assert_eq!(extract_audit_seconds(line), Some(1_700_000_000));
    assert_eq!(extract_kv_u32(line, "uid"), Some(1000));
    assert_eq!(extract_kv_u32(line, "pid"), Some(1234));
    assert_eq!(extract_kv_string(line, "comm"), Some("nano".to_owned()));
    assert_eq!(extract_kv_hex_u64(line, "a2"), Some(0x8001));
}

#[test]
fn open_flags_detect_modification() {
    assert!(open_flags_modify(0o1));
    assert!(open_flags_modify(0o2));
    assert!(open_flags_modify(0o100));
    assert!(open_flags_modify(0o1000));
    assert!(!open_flags_modify(0));
}

#[test]
fn journal_regex_escapes_specials() {
    assert_eq!(escape_journal_regex("/etc/foo.bar"), r"/etc/foo\.bar");
    assert_eq!(escape_journal_regex("test[0]"), r"test\[0\]");
}

#[test]
fn missing_journalctl_is_optional() {
    let users = HashMap::new();
    let info = try_journalctl_command(
        "zejtron-missing-journalctl-test-command",
        Path::new("/tmp/example"),
        Path::new("/tmp/example"),
        &users,
    );

    assert_eq!(info, None);
}
