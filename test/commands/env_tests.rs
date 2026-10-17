// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! env unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/commands/env.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;
use tempfile::tempdir;

fn snapshot(entries: &[(&str, &str)]) -> Snapshot {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

#[test]
fn validates_snapshot_names() {
    for name in ["base", "terminal-1", "work.env", "foo_bar"] {
        assert!(validate_snapshot_name(name).is_ok());
    }
    for name in ["", ".", "..", "bad/name", "bad name", "bad:name"] {
        assert!(validate_snapshot_name(name).is_err());
    }
}

#[test]
fn serializes_snapshot_sorted_by_key() {
    let data = snapshot(&[("ZED", "1"), ("ALPHA", "2"), ("PATH", "/usr/bin")]);

    assert_eq!(serialize_snapshot(&data), "ALPHA=2\nPATH=/usr/bin\nZED=1\n");
}

#[test]
fn parses_snapshot_values_with_equals() {
    let parsed = parse_snapshot("TOKEN=a=b=c\nEMPTY=\n").unwrap();

    assert_eq!(parsed["TOKEN"], "a=b=c");
    assert_eq!(parsed["EMPTY"], "");
}

#[test]
fn diffs_added_removed_changed_and_same() {
    let saved = snapshot(&[("OLD", "1"), ("PATH", "/bin"), ("SHELL", "zsh")]);
    let current = snapshot(&[("NEW", "2"), ("PATH", "/usr/bin:/bin"), ("SHELL", "zsh")]);

    let diff = diff_snapshots(&saved, &current);

    assert_eq!(diff.added["NEW"], "2");
    assert_eq!(diff.removed["OLD"], "1");
    assert_eq!(diff.changed["PATH"].saved, "/bin");
    assert_eq!(diff.changed["PATH"].current, "/usr/bin:/bin");
    assert_eq!(diff.same["SHELL"], "zsh");
}

#[test]
fn show_same_renders_unchanged_section() {
    let diff = diff_snapshots(
        &snapshot(&[("SHELL", "zsh")]),
        &snapshot(&[("SHELL", "zsh")]),
    );

    let report = format_diff("base", &diff, true);

    assert!(report.contains("same"));
    assert!(report.contains("SHELL=zsh"));
    assert!(report.contains("0 differences"));
}

#[test]
fn no_differences_without_show_same_is_clean() {
    let diff = diff_snapshots(
        &snapshot(&[("SHELL", "zsh")]),
        &snapshot(&[("SHELL", "zsh")]),
    );

    assert_eq!(
        format_diff("base", &diff, false),
        "No environment differences from 'base'."
    );
}

#[test]
fn filter_is_case_insensitive() {
    let data = snapshot(&[("PATH", "/usr/bin"), ("HOME", "/home/rezky")]);
    let filtered = filter_environment(&data, Some("path"));

    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered["PATH"], "/usr/bin");
}

#[test]
fn renders_keys_only() {
    let report = format_environment(
        &snapshot(&[("HOME", "/home/rezky"), ("PATH", "/bin")]),
        true,
    );

    assert!(report.contains("├── HOME"));
    assert!(report.contains("└── PATH"));
    assert!(!report.contains("HOME=/home/rezky"));
}

#[test]
fn missing_snapshot_error_message_is_clear() {
    let dir = tempdir().unwrap();
    let error = load_snapshot("base", dir.path()).unwrap_err().to_string();

    assert_eq!(error, "No saved environment snapshot named 'base'.");
}

#[test]
fn delete_missing_snapshot_returns_false() {
    let dir = tempdir().unwrap();

    assert!(!delete_snapshot("base", dir.path()).unwrap());
}

#[test]
fn save_list_and_delete_snapshot_with_temp_dir() {
    let dir = tempdir().unwrap();
    save_snapshot("base", &snapshot(&[("PATH", "/bin")]), dir.path()).unwrap();

    assert_eq!(list_snapshots(dir.path()).unwrap(), vec!["base"]);
    assert_eq!(load_snapshot("base", dir.path()).unwrap()["PATH"], "/bin");
    assert!(delete_snapshot("base", dir.path()).unwrap());
    assert!(list_snapshots(dir.path()).unwrap().is_empty());
}

#[test]
fn mask_secret_values_redacts_token_keys() {
    let snap = snapshot(&[
        ("PATH", "/usr/bin"),
        ("GITHUB_TOKEN", "ghp_abcdefghijklmnopqrstuvwxyz0123456789AB"),
        ("DATABASE_URL", "postgres://user:s3cret@host/db"),
        ("MY_PASSWORD", "hunter2"),
    ]);
    let masked = mask_secret_values(snap);
    assert_eq!(masked["PATH"], "/usr/bin");
    assert_eq!(masked["GITHUB_TOKEN"], "***REDACTED***");
    assert_eq!(masked["MY_PASSWORD"], "***REDACTED***");
    // DATABASE_URL key is not secret, value should pass through
    assert!(masked["DATABASE_URL"].contains("s3cret"));
}

#[test]
fn redact_secret_patterns_catches_aws_keys() {
    // Build a fake AWS access key: AKIA + 16 chars (concatenated to avoid
    // any external redaction filters on real-looking credentials).
    let fake_aws = format!("{}{}", "AKIA", "A".repeat(16));
    let v = redact_secret_patterns(&format!("aws key {fake_aws} here"));
    assert!(v.contains("***REDACTED***"));
    assert!(!v.contains(&fake_aws));
}

#[test]
fn redact_secret_patterns_catches_jwt() {
    let jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature";
    let v = redact_secret_patterns(jwt);
    assert!(v.contains("***REDACTED***"));
    assert!(!v.contains("signature"));
}

#[test]
fn redact_secret_patterns_catches_pem_blocks() {
    // Build PEM header via concatenation to bypass any external filter
    // that may strip real PEM markers from source.
    let begin = format!("-----{}-----", "BEGIN RSA PRIVATE KEY");
    let end = format!("-----{}-----", "END RSA PRIVATE KEY");
    let pem = format!(
        "{begin}
MIIabc...
{end}"
    );
    let v = redact_secret_patterns(&pem);
    assert_eq!(v, "***PEM-KEY-REDACTED***");
}

#[test]
fn read_proc_environ_self_pid() {
    let own_pid = std::process::id();
    let snap = read_proc_environ(own_pid).unwrap();
    // At minimum, PATH should be in our environment.
    assert!(snap.contains_key("PATH"));
}

#[test]
fn read_proc_environ_missing_pid_errors() {
    // PID 99999999 is unlikely to exist.
    let r = read_proc_environ(99999999);
    assert!(r.is_err());
}
