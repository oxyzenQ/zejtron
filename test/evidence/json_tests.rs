// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The JSON lane's tests: the escaping rules, the null-timestamp
//! law, the lane qualifier mapping, the flat typed rows and the
//! typed actor (night-badass-6), and the one full-report byte pin -
//! the same report, the same bytes, forever.

use super::*;

use super::super::row::EvidenceActor;

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
        EvidenceActor::none(),
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
    // The flat row (night-badass-6): the kind and its fields at the
    // row root, the pure-state actor JSON null.
    assert!(
        out.contains("\"kind\":\"modified\",\"via\":null,\"actor\":null"),
        "the flat kind and the null actor, got {out}"
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
fn the_typed_actions_serialize_their_raw_fields_at_the_row_root() {
    // The night-badass-5 law, flattened by night-badass-6: numbers
    // stay numbers, strings stay strings, the kind token and its
    // raw fields sit at the row root. These are the shapes the
    // enterprise lane (Datadog, Grafana, jq) filters on - pinned
    // byte for byte, through the same write_row the real lane runs.
    let cases: &[(super::super::row::EvidenceKind, &str)] = &[
        (
            super::super::row::EvidenceKind::Size { bytes: 884 },
            "{\"unix_secs\":null,\"timestamp_utc\":null,\"kind\":\"size\",\"bytes\":884,\"actor\":null,\"provenance\":\"measured\"}",
        ),
        (
            super::super::row::EvidenceKind::Owner {
                user: "rezky".to_owned(),
                group: "rezky".to_owned(),
                uid: 1000,
                gid: 1000,
            },
            "{\"unix_secs\":null,\"timestamp_utc\":null,\"kind\":\"owner\",\"user\":\"rezky\",\"group\":\"rezky\",\"uid\":1000,\"gid\":1000,\"actor\":null,\"provenance\":\"measured\"}",
        ),
        (
            super::super::row::EvidenceKind::Inode {
                id: 1_624_968,
                dev: 66_308,
            },
            "{\"unix_secs\":null,\"timestamp_utc\":null,\"kind\":\"inode\",\"id\":1624968,\"dev\":66308,\"actor\":null,\"provenance\":\"measured\"}",
        ),
        (
            super::super::row::EvidenceKind::Permissions {
                octal: "0644".to_owned(),
            },
            "{\"unix_secs\":null,\"timestamp_utc\":null,\"kind\":\"perms\",\"octal\":\"0644\",\"actor\":null,\"provenance\":\"measured\"}",
        ),
        (
            super::super::row::EvidenceKind::Type {
                file_type: "regular file".to_owned(),
            },
            "{\"unix_secs\":null,\"timestamp_utc\":null,\"kind\":\"type\",\"file_type\":\"regular file\",\"actor\":null,\"provenance\":\"measured\"}",
        ),
        (
            super::super::row::EvidenceKind::Wrote {
                via: Some("writev"),
            },
            "{\"unix_secs\":null,\"timestamp_utc\":null,\"kind\":\"wrote\",\"via\":\"writev\",\"actor\":null,\"provenance\":\"observed\"}",
        ),
        (
            super::super::row::EvidenceKind::Runs {
                cmd: None,
                unit: Some("sshd".to_owned()),
            },
            "{\"unix_secs\":null,\"timestamp_utc\":null,\"kind\":\"runs\",\"cmd\":null,\"unit\":\"sshd\",\"actor\":null,\"provenance\":\"measured\"}",
        ),
        (
            super::super::row::EvidenceKind::Cwd { path: None },
            "{\"unix_secs\":null,\"timestamp_utc\":null,\"kind\":\"cwd\",\"path\":null,\"actor\":null,\"provenance\":\"measured\"}",
        ),
        (
            super::super::row::EvidenceKind::JournalMention,
            "{\"unix_secs\":null,\"timestamp_utc\":null,\"kind\":\"journal-mention\",\"actor\":null,\"provenance\":\"inferred\"}",
        ),
    ];
    for (kind, want) in cases {
        let provenance = if matches!(
            kind,
            super::super::row::EvidenceKind::Wrote { .. }
                | super::super::row::EvidenceKind::JournalMention
        ) {
            if matches!(kind, super::super::row::EvidenceKind::Wrote { .. }) {
                super::super::row::Provenance::Observed
            } else {
                super::super::row::Provenance::Inferred
            }
        } else {
            super::super::row::Provenance::Measured
        };
        let row = super::super::row::EvidenceRow::new(
            None,
            kind.clone(),
            EvidenceActor::none(),
            provenance,
        );
        let mut out = String::new();
        write_row(&mut out, &row);
        assert_eq!(&out, want, "the flat typed row drifted");
    }
}

#[test]
fn the_typed_actor_serializes_its_raw_fields() {
    // The night-badass-6 law: the actor is the name/pid/user object
    // with JSON null for each part the source did not name, and
    // JSON null for the whole actor when the row is pure state -
    // the shapes `jq 'select(.actor.pid == 2985)'` filters on.
    let cases: &[(EvidenceActor, &str)] = &[
        (
            EvidenceActor::process("brave", 2985, "rezky"),
            "{\"name\":\"brave\",\"pid\":2985,\"user\":\"rezky\"}",
        ),
        (
            EvidenceActor::recorded(Some("CROND".to_owned()), None, Some("root".to_owned())),
            "{\"name\":\"CROND\",\"pid\":null,\"user\":\"root\"}",
        ),
        (
            EvidenceActor::recorded(None, None, Some("root".to_owned())),
            "{\"name\":null,\"pid\":null,\"user\":\"root\"}",
        ),
        (EvidenceActor::none(), "null"),
    ];
    for (actor, want) in cases {
        let mut out = String::new();
        write_actor(&mut out, actor);
        assert_eq!(&out, want, "the typed actor drifted");
    }
}

#[test]
fn every_actor_form_renders_the_locked_text_grammar() {
    // The two renderings of one actor: Display is the locked text
    // column, byte-identical to the pre-typed strings.
    let cases: &[(EvidenceActor, &str)] = &[
        (
            EvidenceActor::process("brave", 2985, "rezky"),
            "brave (pid 2985, rezky)",
        ),
        (
            EvidenceActor::recorded(Some("CROND".to_owned()), None, Some("root".to_owned())),
            "CROND (root)",
        ),
        (
            EvidenceActor::recorded(Some("cat".to_owned()), Some(9), None),
            "cat (pid 9)",
        ),
        (
            EvidenceActor::recorded(None, None, Some("root".to_owned())),
            "root",
        ),
        (EvidenceActor::none(), "\u{2014}"),
    ];
    for (actor, want) in cases {
        assert_eq!(&actor.to_string(), want, "the text actor grammar drifted");
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
            EvidenceActor::none(),
            super::super::row::Provenance::Measured,
        )],
        changes: super::super::ChangesSection {
            rows: vec![super::super::row::EvidenceRow::new(
                Some(1_760_463_770),
                super::super::row::EvidenceKind::Opened,
                EvidenceActor::process("systemd", 1, "root"),
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
    // ledger_version 3 = the flat row and the typed actor
    // (night-badass-6).
    assert_eq!(
        json,
        "{\"ledger_version\":3,\"subject\":\"/etc/resolv.conf\",\"mode\":\"snapshot\",\
\"lane\":\"journal fallback\",\"window\":\"10s\",\"measured\":[{\"unix_secs\":1760463767,\
\"timestamp_utc\":\"2025-10-14 17:42:47 (UTC)\",\"kind\":\"type\",\
\"file_type\":\"file\",\"actor\":\
null,\"provenance\":\"measured\"}],\"changes\":{\"unavailable\":false,\
\"rows\":[{\"unix_secs\":1760463770,\"timestamp_utc\":\"2025-10-14 17:42:50 (UTC)\",\
\"kind\":\"opened\",\"actor\":{\"name\":\"systemd\",\"pid\":1,\"user\":\"root\"},\
\"provenance\":\"observed\"}]},\"unaccounted\":[{\"count\":2,\"category\":\"processes\",\
\"reason\":\"unreadable - try sudo for complete holder details\"}],\"verdict\":{\
\"supports\":\"1 process holds the path now (systemd)\",\"cannot_support\":\"changes the \
log does not record - actor inference is best-effort\"}}"
    );
}
