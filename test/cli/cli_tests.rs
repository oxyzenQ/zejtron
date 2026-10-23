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
    // --watch died with the lifecycle surface (night-improve-34); no
    // alias of it survives to disclose.
    assert!(
        help.contains("--check-updated"),
        "Pro mode must disclose the hidden alias --check-updated"
    );
    assert!(
        !help.contains("--watch"),
        "the removed --watch alias must not reappear in Pro mode help"
    );
}

/// The estate is complete: every flag-owning verb has its group,
/// and the advanced knobs are spelled on the surface.
#[test]
fn pro_mode_covers_every_flag_owning_verb() {
    let help = help_command().render_help().to_string();
    for group in ["recent:", "port:", "proc:", "doctor:", "global:"] {
        assert!(help.contains(group), "Pro mode must own the {group} group");
    }
    for spelling in [
        "--limit N",
        "--listen",
        "--since DURATION",
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
        Some(Commands::Holds { target, .. }) => {
            assert_eq!(target, "/tmp/file with spaces");
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parses_doctor() {
    let cli = Cli::try_parse_from(["zejtron", "doctor"]).unwrap();

    assert!(matches!(cli.command, Some(Commands::Doctor { .. })));
}

#[test]
fn parses_doctor_attach_and_detach() {
    let cli = Cli::try_parse_from(["zejtron", "doctor", "--attach"]).unwrap();
    match cli.command {
        Some(Commands::Doctor {
            attach,
            detach,
            symptom,
            raw,
        }) => {
            assert!(attach);
            assert!(!detach);
            assert!(symptom.is_none());
            assert!(!raw);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["zejtron", "doctor", "--detach"]).unwrap();
    match cli.command {
        Some(Commands::Doctor {
            attach,
            detach,
            symptom,
            raw,
        }) => {
            assert!(!attach);
            assert!(detach);
            assert!(symptom.is_none());
            assert!(!raw);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn doctor_attach_and_detach_conflict() {
    // Both verbs at once is a usage error: clap's conflicts_with, the
    // honest answer (never a silent last-one-wins).
    assert!(Cli::try_parse_from(["zejtron", "doctor", "--attach", "--detach"]).is_err());
}

#[test]
fn parses_doctor_symptom_and_raw() {
    // The symptom lane (night-improve-4): --symptom parses, --raw
    // parses, and the two verbs conflict with the symptom.
    let cli = Cli::try_parse_from(["zejtron", "doctor", "--symptom", "ram"]).unwrap();
    match cli.command {
        Some(Commands::Doctor {
            attach,
            detach,
            symptom,
            raw,
        }) => {
            assert!(!attach);
            assert!(!detach);
            assert_eq!(symptom.as_deref(), Some("ram"));
            assert!(!raw);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from(["zejtron", "doctor", "--symptom", "ram", "--raw"]).unwrap();
    match cli.command {
        Some(Commands::Doctor { symptom, raw, .. }) => {
            assert_eq!(symptom.as_deref(), Some("ram"));
            assert!(raw);
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn doctor_symptom_conflicts_with_the_verbs() {
    assert!(Cli::try_parse_from(["zejtron", "doctor", "--symptom", "ram", "--attach"]).is_err());
    assert!(Cli::try_parse_from(["zejtron", "doctor", "--symptom", "ram", "--detach"]).is_err());
}

#[test]
fn parses_touch_path() {
    let cli = Cli::try_parse_from(["zejtron", "touch", "/tmp/file with spaces"]).unwrap();

    match cli.command {
        Some(Commands::Touch { path, .. }) => {
            assert_eq!(path, PathBuf::from("/tmp/file with spaces"));
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn parses_why_target() {
    let cli = Cli::try_parse_from(["zejtron", "why", "/tmp/file with spaces"]).unwrap();

    match cli.command {
        Some(Commands::Why { target, .. }) => {
            assert_eq!(target, "/tmp/file with spaces");
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn the_live_flags_are_gone_from_the_grammar() {
    // night-improve-34 removed the lifecycle surface: --watch (the
    // old --live alias), the lifecycle --since window, and --interval
    // before them. None of the three parses any more - the honest
    // unknown-argument error is the answer, no deprecation alias.
    assert!(Cli::try_parse_from(["zejtron", "proc", "--watch"]).is_err());
    assert!(Cli::try_parse_from(["zejtron", "proc", "--live"]).is_err());
    assert!(Cli::try_parse_from(["zejtron", "proc", "--since", "45s"]).is_err());
    assert!(Cli::try_parse_from(["zejtron", "proc", "--watch", "--interval", "3"]).is_err());
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

/// The diagnostic trace flag (night-hunter-4): global, so it parses
/// before OR after the subcommand, and the default is off.
#[test]
fn parses_verbose_global_position() {
    let after = Cli::try_parse_from(["zejtron", "why", "/etc/passwd", "-v"]).unwrap();
    assert!(after.verbose, "-v must parse after the subcommand");

    let before = Cli::try_parse_from(["zejtron", "-v", "why", "/etc/passwd"]).unwrap();
    assert!(before.verbose, "-v must parse before the subcommand");

    let long = Cli::try_parse_from(["zejtron", "doctor", "--verbose"]).unwrap();
    assert!(long.verbose, "--verbose must parse like -v");

    let off = Cli::try_parse_from(["zejtron", "why", "/etc/passwd"]).unwrap();
    assert!(!off.verbose, "the diagnostic lane must default to off");
}

/// The help surfaces disclose the diagnostic flag: clap's Options
/// block (via the global -h render) and the Pro mode global group.
#[test]
fn help_discloses_verbose() {
    let help = help_command().render_help().to_string();
    assert!(help.contains("--verbose"), "help must disclose --verbose");
    assert!(
        help.contains("-v, --verbose"),
        "Pro mode must spell the -v, --verbose grammar"
    );
}

/// The spelling one clap flag renders under: the short form with its
/// comma when a long form rides beside it, the long form, then the
/// value names verbatim (Pro mode's value tokens are bare - N,
/// DURATION - by the section's own convention).
fn pro_mode_flag_spelling(arg: &clap::Arg) -> Option<String> {
    if arg.is_positional() || arg.get_id() == "help" {
        // Positionals are targets, not flags; -h/--help is clap's own
        // machinery (one help authority, every render carries it).
        return None;
    }
    let mut spelling = String::new();
    if let Some(short) = arg.get_short() {
        spelling.push('-');
        spelling.push(short);
        if arg.get_long().is_some() {
            spelling.push_str(", ");
        }
    }
    if let Some(long) = arg.get_long() {
        spelling.push_str("--");
        spelling.push_str(long);
    }
    // Only the value-taking actions render a value placeholder; the
    // SetTrue flags keep a phantom derived value name that clap's
    // help never shows (the -V/--version row is the live case).
    let value_taking = matches!(
        arg.get_action(),
        clap::ArgAction::Set | clap::ArgAction::Append
    );
    if let Some(names) = arg.get_value_names().filter(|_| value_taking) {
        for name in names {
            spelling.push(' ');
            spelling.push_str(name);
        }
    }
    Some(spelling)
}

/// The estate is complete against the clap tree itself (night-hunter-5):
/// every flag argument of every verb, and every top-level flag, is
/// spelled on the Pro mode surface. The walk is the audit - a flag
/// added to any verb without its Pro mode row fails here, not in an
/// operator's terminal (the owner's QC found port's --since,
/// --events-only, and --snapshot-only missing exactly this way).
#[test]
fn pro_mode_covers_every_clap_flag() {
    let mut cmd = Cli::command();
    cmd.build();
    let plain = pro_mode::painted();

    let mut checked = 0usize;
    // Top-level args first: the globals (-V, -v) and the top-level
    // --check-update - the "global:" group owns them.
    for arg in cmd.get_arguments() {
        if let Some(spelling) = pro_mode_flag_spelling(arg) {
            assert!(
                plain.contains(spelling.as_str()),
                "Pro mode must spell the top-level flag {spelling}"
            );
            checked += 1;
        }
    }
    // Then every verb's own args. Global flags propagate into the
    // subcommands at build time - they were already walked at the top,
    // so the sub walk skips them (they belong to the one "global:"
    // group, not to every verb's).
    for sub in cmd.get_subcommands() {
        for arg in sub.get_arguments() {
            if arg.is_global_set() {
                continue;
            }
            if let Some(spelling) = pro_mode_flag_spelling(arg) {
                assert!(
                    plain.contains(spelling.as_str()),
                    "Pro mode must spell {spelling} (the {} verb's own flag)",
                    sub.get_name()
                );
                checked += 1;
            }
        }
    }
    assert!(
        checked >= 29,
        "the walk must have checked the real estate, got {checked}"
    );
}
