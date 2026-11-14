// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only
//
//! The determinism certificate's fixtures (night-frontier-Z2, E1):
//! the law "two conformant runs diff to empty" rendered as a living
//! proof. Three canonical surfaces - the Evidence Ledger, the
//! doctor's ram report, the port event section - are built from
//! FIXED synthetic facts and rendered here; the test asserts the
//! in-process double render is byte-identical, and - when
//! ZEJTRON_CERT_OUT names a directory - writes each rendering to a
//! file so the CI certificate leg can render them in TWO INDEPENDENT
//! INVOCATIONS and diff the two directories empty. The cross-
//! invocation diff is the certificate: same fixture, two processes,
//! same bytes.
//!
//! HERMETICITY IS THE POINT, and the fixtures are shaped by it: a
//! fixture renders wall-clock times only where the shape itself
//! names them absent. The ram fixture rides the not-attached lane
//! with no pre anchor (no exit rows, no skew line - the live
//! offset's own law would make a clock-time fixture a flaky pin,
//! and a certificate that flakes is not a certificate); the port
//! fixture is the empty-window shape (rows would render under the
//! live offset by the same law). The sections that consult the host
//! (the drop census, the exit ring) enter as explicit `None`
//! parameters - the seams' own fixture axes - so the renderings
//! depend on the fixture alone, on every host, with or without a
//! camera planted.
//!
//! The certificate script (scripts/ci/determinism-certificate.sh)
//! owns the two-invocation protocol and the verdict; this module
//! owns the fixtures and the in-process half.

use super::row::{EvidenceActor, EvidenceKind, EvidenceRow, Provenance};
use super::{ChangesSection, EvidenceReport, Mode, UnaccountedEntry, Verdict};
use std::fmt::Write as _;

/// Where the certificate writes (the CI leg sets it; a plain
/// `cargo test` run skips the file half and keeps the in-process
/// assertions).
fn certificate_out() -> Option<std::path::PathBuf> {
    std::env::var_os("ZEJTRON_CERT_OUT")
        .map(std::path::PathBuf::from)
        .filter(|dir| !dir.as_os_str().is_empty())
}

/// The Evidence Ledger's canonical fixture: one row per provenance
/// tier, one Unaccounted entry per boundary class, the two-line
/// verdict - the whole grammar at its smallest honest size.
fn evidence_report() -> EvidenceReport {
    EvidenceReport {
        subject: "/var/tmp/watched.log".to_owned(),
        mode: Mode::Live,
        window_label: "10s".to_owned(),
        measured: vec![
            EvidenceRow::new(
                Some(1_800_000_000),
                EvidenceKind::Size { bytes: 884 },
                EvidenceActor::process("reader".to_owned(), 4242, "rezky".to_owned()),
                Provenance::Measured,
            ),
            EvidenceRow::new(
                Some(1_800_000_001),
                EvidenceKind::Owner {
                    user: "rezky".to_owned(),
                    group: "rezky".to_owned(),
                    uid: 1000,
                    gid: 1000,
                },
                EvidenceActor::process("reader".to_owned(), 4242, "rezky".to_owned()),
                Provenance::Measured,
            ),
        ],
        changes: ChangesSection {
            rows: vec![
                EvidenceRow::new(
                    Some(1_800_000_010),
                    EvidenceKind::Opened,
                    EvidenceActor::process("writer".to_owned(), 4243, "rezky".to_owned()),
                    Provenance::Observed,
                ),
                EvidenceRow::new(
                    Some(1_800_000_011),
                    EvidenceKind::Wrote { via: Some("writev") },
                    EvidenceActor::recorded(Some("writer".to_owned()), Some(4243), None),
                    Provenance::Observed,
                ),
                EvidenceRow::new(
                    Some(1_800_000_012),
                    EvidenceKind::Unlinked,
                    EvidenceActor::recorded(Some("janitor".to_owned()), Some(4244), None),
                    Provenance::Observed,
                ),
            ],
            unavailable: false,
        },
        unaccounted: vec![
            UnaccountedEntry::new(
                1,
                "event window",
                "unavailable without root - falling back to snapshot mode",
            ),
            UnaccountedEntry::new(
                3,
                "ring drops",
                "file_events reserve failures since attach - events the kernel \
                 saw but the ring could not hold; the window above may be \
                 missing records the same way",
            ),
        ],
        verdict: Verdict {
            supports: "the file was opened, written, and unlinked inside the \
                       window by the processes named above"
                .to_owned(),
            cannot_support: "who renamed it away afterwards - no rename crossed \
                             the watched window"
                .to_owned(),
        },
    }
}

/// The doctor ram report's canonical fixture: the not-attached lane,
/// no pre anchor, no census - every camera consultation enters as
/// its honest absence, so the rendering depends on the fixture
/// alone.
fn ram_report() -> String {
    use crate::commands::doctor::memory::{MemInfo, MemorySample};
    let sample = MemorySample {
        meminfo: Some(MemInfo {
            total_kib: 1_024,
            free_kib: 512,
            available_kib: 768,
            cached_kib: 128,
            buffers_kib: 16,
            s_reclaimable_kib: 32,
            s_unreclaim_kib: 8,
            shmem_kib: 64,
        }),
        ..Default::default()
    };
    crate::commands::doctor::memory::ledger::render(&sample, false)
}

/// The port event section's canonical fixture: the empty-window
/// shape, every camera axis explicit `None` (the seam's own
/// contract) - the rendering depends on the fixture alone.
fn port_report() -> String {
    crate::commands::port::format_event_section_with_exits(
        &[],
        std::time::Duration::from_secs(60),
        false,
        None,
        None,
        None,
        None,
    )
}

/// One certificate fixture set: name + rendering, in a fixed order
/// (the manifest and the diff are stable).
fn fixtures() -> Vec<(&'static str, String)> {
    vec![
        ("evidence-ledger", super::render::render_report(&evidence_report())),
        ("doctor-ram", ram_report()),
        ("port-events", port_report()),
    ]
}

#[test]
fn the_certificate_fixtures_render_byte_identical_twice() {
    // The in-process half of the law: a render is a pure function of
    // its fixture. Every fixture, rendered twice, byte-identical -
    // the property the cross-invocation certificate rides.
    for (name, first) in fixtures() {
        let (second_name, second) = fixtures()
            .into_iter()
            .find(|(candidate, _)| *candidate == name)
            .expect("the fixture list is stable within one call");
        assert_eq!(second_name, name);
        assert_eq!(first, second, "fixture {name} rendered differently twice");
    }
}

#[test]
fn the_certificate_fixtures_consult_no_camera() {
    // Hermeticity, pinned where it matters: no fixture may consult a
    // live camera lane. The ram fixture rides the not-attached state
    // (its mode line says so), and the port fixture renders the
    // empty-window shape (a served window would render under the
    // live offset by the Z2 law - a clock-time fixture would be a
    // flaky pin, and a flaky certificate is not a certificate).
    for (name, rendering) in fixtures() {
        assert!(
            !rendering.contains("Mode: snapshot + post-mortem"),
            "fixture {name} rendered a live lane state - the fixtures name \
             their camera absences, they never consult a camera"
        );
    }
    let (_, port) = fixtures()
        .into_iter()
        .find(|(name, _)| *name == "port-events")
        .expect("the port fixture rides the fixed list");
    assert!(
        port.contains("(no events in the window)"),
        "the port fixture is the empty-window shape: {port}"
    );
}

#[test]
fn the_certificate_writes_its_renderings_when_asked() {
    // The cross-invocation half: when the environment names an output
    // directory, every fixture's rendering lands there under a fixed
    // name, plus the manifest. The CI certificate leg renders into
    // two directories from two independent invocations and diffs
    // them empty - this test only guarantees the bytes are written
    // deterministically (same call, same bytes, the first test's
    // law).
    let Some(out) = certificate_out() else {
        return;
    };
    std::fs::create_dir_all(&out).expect("the certificate output directory opens");
    let mut manifest = String::new();
    for (name, rendering) in fixtures() {
        std::fs::write(out.join(format!("{name}.txt")), &rendering)
            .expect("the certificate fixture writes");
        let _ = writeln!(manifest, "{name} {}", rendering.len());
    }
    std::fs::write(out.join("manifest.txt"), &manifest).expect("the certificate manifest writes");
}
