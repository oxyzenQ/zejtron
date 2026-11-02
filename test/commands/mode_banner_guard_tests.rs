// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

//! The Mode banner guard (the buyer verification defect class): every CLI verb
//! that accepts `--since` and renders event-window data must open its
//! human-readable output with the `Mode:` transparency banner - the
//! line that says whether the window was watched live or assembled
//! from a snapshot fallback. `port` was the one surface that missed
//! it (fixed in src/commands/port/window.rs); this test is the net
//! that keeps the whole class honest - a future verb that grows a
//! `--since` without a banner fails here.
//!
//! The verbs without a banner, by design, so the class boundary
//! stays explicit: `path`/`proc`/`net` are pure snapshot readers with
//! no event lane to name and no degradation to hide; `recent`'s
//! `--since` is a file-age filter (the m/h/d mtime grammar, not the
//! s/m/h window grammar), not an event window; `doctor` prints its
//! own `Mode:` lines in exactly the sections that degrade (the
//! memory and delta lanes); and port's explicit escape hatches
//! (`--snapshot-only`, `--events-only`) name their lane state by
//! construction - the refusal line or the event section itself.
//!
//! Wired from src/commands/mod.rs - the hub that sees every verb.

use std::collections::HashMap;
use std::fs;
use std::time::Duration;

use crate::test_tempdir::TempDir;

/// port's real default-shape entry (parse_options +
/// format_port_output), reached without naming port's private model
/// types: type inference feeds the empty selection, the explicit 1s
/// window bounds the attached-host capture wait, and both capture
/// arms are banner-first, so the assertion holds in every
/// environment - only a real regression can fail it.
fn port_default_output() -> String {
    let options = crate::commands::port::parse_options(
        None,
        crate::commands::port::PortFlags {
            since: Some("1s".to_owned()),
            ..crate::commands::port::PortFlags::default()
        },
    )
    .expect("the window grammar accepts 1s");
    let sockets = Vec::new();
    let owners = HashMap::new();
    let stats = Default::default();
    crate::commands::port::window::format_port_output(&sockets, &owners, &stats, &options)
}

/// The evidence family's banner seat: the Mode line is the report's
/// second line, right under the subject header. Lane-agnostic on
/// purpose - every mode the ladder can pick prints it.
fn banner_line(output: &str) -> &str {
    output.lines().nth(1).unwrap_or_default()
}

#[test]
fn mode_line_is_printed_on_all_event_window_verbs() {
    // port --since: the banner is the FIRST line (before the ports
    // list) - the buyer verification fix itself, through the real entry point.
    let port = port_default_output();
    let port_first = port.lines().next().unwrap_or_default();
    assert!(
        port_first.starts_with("Mode: "),
        "port --since must open with the Mode banner, got: {port_first:?}"
    );

    // why --since (a port target: the deterministic lane-free shape).
    let why = crate::commands::why::ledger::build_port_report(
        54321,
        Duration::from_secs(10),
        "10s".to_owned(),
        false,
        false,
        false,
    )
    .expect("the port scan itself cannot fail here");
    assert!(
        banner_line(&why).starts_with("Mode: "),
        "why --since must print the Mode banner, got: {:?}",
        banner_line(&why)
    );

    // holds --since (a port target: same determinism).
    let holds = crate::commands::holds::ledger::build_port_report(
        54321,
        Duration::from_secs(10),
        "10s".to_owned(),
        false,
    )
    .expect("the port scan itself cannot fail here");
    assert!(
        banner_line(&holds).starts_with("Mode: "),
        "holds --since must print the Mode banner, got: {:?}",
        banner_line(&holds)
    );

    // touch --since (a path target through the real builder; the
    // lane ladder is environment-dependent, the banner is not).
    let directory = TempDir::new().unwrap();
    let path = directory.path().join("mode-banner-probe");
    fs::write(&path, "probe").unwrap();
    let touch = crate::commands::touch::ledger::build_report(
        &path,
        Duration::from_secs(1),
        "1s".to_owned(),
        false,
    )
    .expect("a written temp file always reports");
    assert!(
        banner_line(&touch).starts_with("Mode: "),
        "touch --since must print the Mode banner, got: {:?}",
        banner_line(&touch)
    );
}
