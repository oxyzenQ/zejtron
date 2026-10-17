// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! update unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/update/mod.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

#[test]
fn extracts_tag_name() {
    assert_eq!(
        extract_tag_name(r#"{"tag_name":"v2.4.3"}"#),
        Some("v2.4.3".to_string())
    );
}

#[test]
fn tag_safety_rejects_control_characters_and_accepts_printable() {
    // Every control byte class a terminal-attack payload would
    // ride: ESC (0x1b), newline, carriage return, tab, NUL, DEL.
    assert!(!tag_is_safe("\x1b]52;c;"));
    assert!(!tag_is_safe("v1\n.0"));
    assert!(!tag_is_safe("v1\r.0"));
    assert!(!tag_is_safe("v1\t.0"));
    assert!(!tag_is_safe("v1\0.0"));
    assert!(!tag_is_safe("v1\x7f.0"));
    // Honest tags pass, including non-ASCII multibyte (only
    // control bytes fail - the 0x80+ range rides UTF-8 legally).
    assert!(tag_is_safe("v80.0.0"));
    assert!(tag_is_safe("v11.0.0-beta.1"));
    assert!(tag_is_safe("v11.0.0-caf\u{e9}"));
}

#[test]
fn compares_versions() {
    assert_eq!(compare_versions("2.4.3", "v2.4.3"), UpdateStatus::UpToDate);
    assert_eq!(
        compare_versions("2.4.2", "v2.4.3"),
        UpdateStatus::UpdateAvailable
    );
    assert_eq!(
        compare_versions("2.5.0", "v2.4.3"),
        UpdateStatus::CurrentIsNewer
    );
}
