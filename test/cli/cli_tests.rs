// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

//! cli unit pins. Lives under the single test/ tree
//! (night-improve-18, the discipline contract: every test
//! file belongs under test/) and is #[path]-wired from
//! src/cli/mod.rs, so `super::` reaches the module exactly like the
//! inline tests did.

use super::*;

/// The Pro mode section is on the help surface (night-improve-25).
#[test]
fn help_carries_pro_mode_section() {
    let help = help_command().render_help().to_string();
    assert!(help.contains("Pro mode:"));
}

/// The hidden aliases are disclosed in Pro mode - the one surface
/// that names them next to the flags they alias.
#[test]
fn pro_mode_discloses_every_hidden_alias() {
    let help = help_command().render_help().to_string();
    for alias in ["--check-updated", "--watch"] {
        assert!(
            help.contains(alias),
            "Pro mode must disclose the hidden alias {alias}"
        );
    }
}

/// The estate is complete: every flag-owning verb has its group,
/// and the advanced knobs are spelled on the surface.
#[test]
fn pro_mode_covers_every_flag_owning_verb() {
    let help = help_command().render_help().to_string();
    for group in ["recent:", "port:", "proc:", "global:"] {
        assert!(help.contains(group), "Pro mode must own the {group} group");
    }
    for spelling in [
        "--limit N",
        "--listen",
        "--interval SECONDS",
        "--depth N",
        "--find PATTERN",
    ] {
        assert!(
            help.contains(spelling),
            "Pro mode must spell the advanced flag {spelling}"
        );
    }
}

#[test]
fn parses_net() {
    let cli = Cli::try_parse_from(["zejtron", "net"]).unwrap();
    assert!(matches!(cli.command, Some(Commands::Net)));
}

#[test]
fn parses_proc_me() {
    let cli = Cli::try_parse_from(["zejtron", "proc", "--me"]).unwrap();

    match cli.command {
        Some(Commands::Proc {
            me, user_or_uid, ..
        }) => {
            assert!(me);
            assert_eq!(user_or_uid, None);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parses_holds_target() {
    let cli = Cli::try_parse_from(["zejtron", "holds", "/tmp/file with spaces"]).unwrap();

    match cli.command {
        Some(Commands::Holds { target }) => {
            assert_eq!(target, "/tmp/file with spaces");
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parses_doctor() {
    let cli = Cli::try_parse_from(["zejtron", "doctor"]).unwrap();

    assert!(matches!(cli.command, Some(Commands::Doctor)));
}

#[test]
fn parses_touch_path() {
    let cli = Cli::try_parse_from(["zejtron", "touch", "/tmp/file with spaces"]).unwrap();

    match cli.command {
        Some(Commands::Touch { path }) => {
            assert_eq!(path, PathBuf::from("/tmp/file with spaces"));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parses_why_target() {
    let cli = Cli::try_parse_from(["zejtron", "why", "/tmp/file with spaces"]).unwrap();

    match cli.command {
        Some(Commands::Why { target }) => {
            assert_eq!(target, "/tmp/file with spaces");
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parses_proc_watch_alias_and_interval() {
    let cli =
        Cli::try_parse_from(["zejtron", "proc", "--me", "--watch", "--interval", "3"]).unwrap();

    match cli.command {
        Some(Commands::Proc {
            watch, interval, ..
        }) => {
            assert!(watch);
            assert_eq!(interval, Some(3));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parses_proc_filters_and_no_pid() {
    let cli = Cli::try_parse_from([
        "zejtron", "proc", "rezky", "--depth", "2", "--find", "python", "--no-pid",
    ])
    .unwrap();

    match cli.command {
        Some(Commands::Proc {
            user_or_uid,
            depth,
            find,
            no_pid,
            ..
        }) => {
            assert_eq!(user_or_uid.as_deref(), Some("rezky"));
            assert_eq!(depth, Some(2));
            assert_eq!(find.as_deref(), Some("python"));
            assert!(no_pid);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}
