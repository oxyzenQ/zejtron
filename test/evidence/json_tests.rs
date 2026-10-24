// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The JSON lane's tests: the escaping rules, the null-timestamp
//! law, the lane qualifier mapping, the typed action objects
//! (night-badass-5), and the one full-report byte pin - the same
//! report, the same bytes, forever.

use super::*;

#[test]
fn escapes_quotes_backslashes_and_control_bytes() {
    let mut out = String::new();
    write_string(&mut out, "he said \"hi\"\\done\n\t\u{01}e\u{0c}z");
    assert_eq!(out, "\"he said \\\"hi\\\"\\\\done\\n\\t\\u0001e\\fz\"");
}

#[test]
fn utf8_passes_through_untouched() {
    let mut out = String::new();
    write_string(&mut out, "— (pid 1, root) résumé");
    assert_eq!(out, "\"— (pid 1, root) résumé\"");
}

#[test]
fn absent_timestamps_serialize_json_null() {
    let row = super::super::row::EvidenceRow::new(
        None,
        super::super::row::EvidenceKind::Modified { via: None },
        "\u{2014}",
        super::super::row::Provenance::Measured,
    );
    let mut out = String::new();
    write_row(&mut out, &row);
    assert!(
        out.contains("\"unix_secs\":null"),
        "absent unix_secs must be JSON null, got {out}"
    );
    assert!(
        out.contains("\"timestamp_utc\":null"),
        "absent timestamp_utc must be JSON null, got {out}"
    );
    assert!(
        out.contains("\"provenance\":\"measured\""),
        "the tier tag rides verbatim, got {out}"
    );
    assert!(
        out.contains("\"action\":{\"kind\":\"modified\",\"via\":null}"),
        "the typed action carries its absent qualifier as null, got {out}"
    );
}

#[test]
fn the_unqualified_lanes_serialize_json_null() {
    assert_eq!(lane_name(Mode::Live), None);
    assert_eq!(lane_name(Mode::Mixed), None);
    assert_eq!(lane_name(Mode::SnapshotJournal), Some("journal fallback"));
    assert_eq!(
        lane_name(Mode::SnapshotNoLane),
        Some("no event lane available")
    );
}

#[test]
fn the_typed_actions_serialize_their_raw_fields() {
    // The night-badass-5 law: numbers stay numbers, strings stay
    // strings, the kind word is the vocabulary's one token. These
    // are the shapes the enterprise lane (Datadog, Grafana, jq)
    // filters on - pinned byte for byte.
    let cases: &[(super::super::row::EvidenceKind, &str)] = &[
        (
            super::super::row::EvidenceKind::Size { bytes: 884 },
            "{\"kind\":\"size\",\"bytes\":884}",
        ),
        (
            super::super::row::EvidenceKind::Owner {
                user: "rezky".to_owned(),
                group: "rezky".to_owned(),
                uid: 1000,
                gid: 1000,
            },
            "{\"kind\":\"owner\",\"user\":\"rezky\",\"group\":\"rezky\",\"uid\":1000,\"gid\":1000}",
        ),
        (
            super::super::row::EvidenceKind::Inode {
                id: 1_624_968,
                dev: 66_308,
            },
            "{\"kind\":\"inode\",\"id\":1624968,\"dev\":66308}",
        ),
        (
            super::super::row::EvidenceKind::Permissions {
                octal: "0644".to_owned(),
            },
            "{\"kind\":\"perms\",\"octal\":\"0644\"}",
        ),
        (
            super::super::row::EvidenceKind::Type {
                file_type: "regular file".to_owned(),
            },
            "{\"kind\":\"type\",\"file_type\":\"regular file\"}",
        ),
        (
            super::super::row::EvidenceKind::Wrote {
                via: Some("writev"),
            },
            "{\"kind\":\"wrote\",\"via\":\"writev\"}",
        ),
        (
            super::super::row::EvidenceKind::Runs {
                cmd: None,
                unit: Some("sshd".to_owned()),
            },
            "{\"kind\":\"runs\",\"cmd\":null,\"unit\":\"sshd\"}",
        ),
        (
            super::super::row::EvidenceKind::Cwd { path: None },
            "{\"kind\":\"cwd\",\"path\":null}",
        ),
        (
            super::super::row::EvidenceKind::JournalMention,
            "{\"kind\":\"journal-mention\"}",
        ),
    ];
    for (kind, want) in cases {
        let mut out = String::new();
        write_kind(&mut out, kind);
        assert_eq!(&out, want, "the typed action drifted");
    }
}

#[test]
fn every_kind_word_has_one_text_phrase_and_one_json_object() {
    // The two renderings of one variant: the phrase is the locked
    // text grammar, the JSON object is the typed form - both from
    // the same enum value, so they cannot disagree.
    let owner = super::super::row::EvidenceKind::Owner {
        user: "rezky".to_owned(),
        group: "rezky".to_owned(),
        uid: 1000,
        gid: 1000,
    };
    assert_eq!(owner.phrase(), "owner rezky:rezky (uid 1000, gid 1000)");
    let size = super::super::row::EvidenceKind::Size { bytes: 884 };
    assert_eq!(size.phrase(), "size 884 bytes");
    assert_eq!(size.kind_word(), "size");
    let modified = super::super::row::EvidenceKind::Modified {
        via: Some("audit log"),
    };
    assert_eq!(modified.phrase(), "modified (audit log)");
    let cwd = super::super::row::EvidenceKind::Cwd { path: None };
    assert_eq!(cwd.phrase(), "cwd (unreadable)");
    let runs = super::super::row::EvidenceKind::Runs {
        cmd: Some("/usr/sbin/sshd".to_owned()),
        unit: Some("sshd".to_owned()),
    };
    assert_eq!(runs.phrase(), "runs /usr/sbin/sshd (unit sshd)");
}

#[test]
fn the_report_serializes_one_deterministic_line() {
    let report = EvidenceReport {
        subject: "/etc/resolv.conf".to_owned(),
        mode: Mode::SnapshotJournal,
        window_label: "10s".to_owned(),
        measured: vec![super::super::row::EvidenceRow::new(
            Some(1_760_463_767),
            super::super::row::EvidenceKind::Type {
                file_type: "file".to_owned(),
            },
            "\u{2014}",
            super::super::row::Provenance::Measured,
        )],
        changes: super::super::ChangesSection {
            rows: vec![super::super::row::EvidenceRow::new(
                Some(1_760_463_770),
                super::super::row::EvidenceKind::Opened,
                "systemd (pid 1, root)",
                super::super::row::Provenance::Observed,
            )],
            unavailable: false,
        },
        unaccounted: vec![super::super::UnaccountedEntry::new(
            2,
            "processes",
            "unreadable - try sudo for complete holder details",
        )],
        verdict: super::super::Verdict {
            supports: "1 process holds the path now (systemd)".to_owned(),
            cannot_support: "changes the log does not record - actor inference is best-effort"
                .to_owned(),
        },
    };
    let json = report_json(&report);
    // One line: no raw newline may leak from any value or structure.
    assert!(
        !json.contains('\n'),
        "the JSON lane is one line, got {json}"
    );
    // The full byte pin: the same report, the same bytes, forever.
    // ledger_version 2 = the typed action object (night-badass-5).
    assert_eq!(
        json,
        "{\"ledger_version\":2,\"subject\":\"/etc/resolv.conf\",\"mode\":\"snapshot\",\
\"lane\":\"journal fallback\",\"window\":\"10s\",\"measured\":[{\"unix_secs\":1760463767,\
\"timestamp_utc\":\"2025-10-14 17:42:47 (UTC)\",\"action\":{\"kind\":\"type\",\
\"file_type\":\"file\"},\"actor\":\
\"\u{2014}\",\"provenance\":\"measured\"}],\"changes\":{\"unavailable\":false,\
\"rows\":[{\"unix_secs\":1760463770,\"timestamp_utc\":\"2025-10-14 17:42:50 (UTC)\",\
\"action\":{\"kind\":\"opened\"},\"actor\":\"systemd (pid 1, root)\",\
\"provenance\":\"observed\"}]},\"unaccounted\":[{\"count\":2,\"category\":\"processes\",\
\"reason\":\"unreadable - try sudo for complete holder details\"}],\"verdict\":{\
\"supports\":\"1 process holds the path now (systemd)\",\"cannot_support\":\"changes the \
log does not record - actor inference is best-effort\"}}"
    );
}
