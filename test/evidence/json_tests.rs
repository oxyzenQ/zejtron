// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! The JSON lane's tests: the escaping rules, the null-timestamp
//! law, the lane qualifier mapping, and the one full-report byte
//! pin - the same report, the same bytes, forever.

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
        "modified",
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
fn the_report_serializes_one_deterministic_line() {
    let report = EvidenceReport {
        subject: "/etc/resolv.conf".to_owned(),
        mode: Mode::SnapshotJournal,
        window_label: "10s".to_owned(),
        measured: vec![super::super::row::EvidenceRow::new(
            Some(1760463767),
            "type file",
            "\u{2014}",
            super::super::row::Provenance::Measured,
        )],
        changes: super::super::ChangesSection {
            rows: vec![super::super::row::EvidenceRow::new(
                Some(1760463770),
                "opened by the kernel event",
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
    assert_eq!(
        json,
        "{\"ledger_version\":1,\"subject\":\"/etc/resolv.conf\",\"mode\":\"snapshot\",\
\"lane\":\"journal fallback\",\"window\":\"10s\",\"measured\":[{\"unix_secs\":1760463767,\
\"timestamp_utc\":\"2025-10-14 17:42:47 (UTC)\",\"action\":\"type file\",\"actor\":\
\"\u{2014}\",\"provenance\":\"measured\"}],\"changes\":{\"unavailable\":false,\
\"rows\":[{\"unix_secs\":1760463770,\"timestamp_utc\":\"2025-10-14 17:42:50 (UTC)\",\
\"action\":\"opened by the kernel event\",\"actor\":\"systemd (pid 1, root)\",\
\"provenance\":\"observed\"}]},\"unaccounted\":[{\"count\":2,\"category\":\"processes\",\
\"reason\":\"unreadable - try sudo for complete holder details\"}],\"verdict\":{\
\"supports\":\"1 process holds the path now (systemd)\",\"cannot_support\":\"changes the \
log does not record - actor inference is best-effort\"}}"
    );
}
