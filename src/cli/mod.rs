// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

pub(crate) mod pro_mode;
pub mod styles;
pub(crate) mod ux;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use std::path::PathBuf;

fn branded_command() -> clap::Command {
    let mut cmd = Cli::command();
    if crate::output::capability() == crate::output::ColorCapability::Color16 {
        cmd = cmd.styles(styles::clap_styles_16());
    }
    // The Pro mode section paints at render time (night-improve-38):
    // grey grammar on a color stdout, the exact plain bytes on a
    // pipe - never a frozen string on either lane.
    cmd.after_help(pro_mode::painted())
}

/// Parse argv through the branded builder. The UX bridge downstream
/// ([`ux::exit_clap_error`]) owns everything that is not `Ok`.
pub(crate) fn parse_branded() -> Result<Cli, clap::error::Error> {
    let matches = branded_command().try_get_matches_from(std::env::args_os())?;
    Cli::from_arg_matches(&matches)
}

/// The branded command for direct help renders (main's bare-`zejtron`
/// branch, the test pins): the same capability rule as
/// [`parse_branded`], one truth, no drift between the entries.
pub(crate) fn help_command() -> clap::Command {
    branded_command()
}

#[derive(Debug, Parser)]
#[command(
    name = "zejtron",
    about = "Unified Linux introspection toolkit for paths, ports, processes, files, services, and diagnostics. Boring and serious.",
    disable_version_flag = true,
    // The mature help surface (night-improve-15, sibling shape): one
    // help authority - the -h/--help flags - and no auto-generated
    // `help` subcommand row padding the commands list on every
    // top-level render. night-improve-25 adds the Pro mode section:
    // the complete flag estate, grouped by the verbs that own each
    // flag, rendered plain through clap's after_help.
    disable_help_subcommand = true,
    styles = crate::cli::styles::clap_styles()
)]
pub struct Cli {
    #[arg(
        short = 'V',
        long = "version",
        global = true,
        help = "Print complete version and build information"
    )]
    pub version: bool,

    // Top-level only (night-improve-15, sibling shape): a network
    // flag has no business parsing after a subcommand, and demoting
    // it removes one noise row from every subcommand's help.
    #[arg(
        long = "check-update",
        alias = "check-updated",
        help = "Check the latest upstream release"
    )]
    pub check_update: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "Trace where a command comes from")]
    Path {
        #[arg(value_name = "COMMAND", help = "Command name to find in PATH")]
        command: String,
    },
    #[command(about = "Show recently modified files")]
    Recent {
        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,
        #[arg(
            long,
            value_name = "N",
            default_value_t = 20,
            help = "Maximum files to show"
        )]
        limit: usize,
        #[arg(
            long,
            value_name = "DURATION",
            help = "Only show files modified since this duration"
        )]
        since: Option<String>,
    },
    #[command(about = "Show listening ports and process owners")]
    Port {
        #[arg(value_name = "PORT", help = "Port number to inspect")]
        port: Option<String>,
        #[arg(long, help = "Show TCP sockets")]
        tcp: bool,
        #[arg(long, help = "Show UDP sockets")]
        udp: bool,
        #[arg(long, conflicts_with = "all", help = "Show listening or bound sockets")]
        listen: bool,
        #[arg(long, help = "Show all parsed sockets")]
        all: bool,
        #[arg(long, help = "Use numeric addresses and ports")]
        numeric: bool,
        #[arg(long, help = "Group repeated rendered socket rows")]
        group: bool,
        #[arg(long, help = "Hide process IDs in owner lines")]
        no_pid: bool,
        #[arg(
            value_name = "DURATION",
            long,
            help = "Event window width (s/m/h, default 60s, clamped to [1s, 1h])"
        )]
        since: Option<String>,
        #[arg(
            long,
            conflicts_with = "snapshot_only",
            help = "Show only the event window (no snapshot)"
        )]
        events_only: bool,
        #[arg(long, help = "Show only the snapshot (the phase-1 behavior)")]
        snapshot_only: bool,
    },
    #[command(about = "Inspect process trees by user or UID")]
    Proc {
        #[arg(
            value_name = "USER_OR_UID",
            help = "Username or numeric UID to inspect"
        )]
        user_or_uid: Option<String>,
        #[arg(
            long,
            conflicts_with = "user_or_uid",
            help = "Show processes owned by the current user"
        )]
        me: bool,
        #[arg(long, help = "Continuously refresh the process tree")]
        live: bool,
        #[arg(long, help = "Alias for --live")]
        watch: bool,
        #[arg(
            long,
            value_name = "SECONDS",
            help = "Live refresh interval in seconds"
        )]
        interval: Option<u64>,
        #[arg(
            long,
            allow_hyphen_values = true,
            value_name = "N",
            help = "Limit rendered tree depth"
        )]
        depth: Option<usize>,
        #[arg(
            long,
            value_name = "PATTERN",
            help = "Show process families matching a case-insensitive name substring"
        )]
        find: Option<String>,
        #[arg(long, help = "Hide pid=<PID> labels")]
        no_pid: bool,
        #[arg(long, help = "Disable ANSI color output")]
        no_color: bool,
    },
    #[command(about = "Show processes holding a file, device, or port")]
    Holds {
        #[arg(
            value_name = "TARGET",
            help = "Filesystem path or port number to inspect"
        )]
        target: String,
    },
    #[command(about = "Inspect last modification evidence for a path (read-only)")]
    Touch {
        #[arg(value_name = "PATH", help = "Path to inspect without modifying it")]
        path: PathBuf,
    },
    #[command(about = "Explain visible evidence for a path or port (read-only)")]
    Why {
        #[arg(
            value_name = "TARGET",
            help = "Filesystem path or port number to explain"
        )]
        target: String,
    },
    #[command(about = "Check zejtron system capability/readiness")]
    Doctor {
        #[arg(long, help = "Attach the eBPF tap (the privileged one-shot)")]
        attach: bool,
        #[arg(
            long,
            conflicts_with = "attach",
            help = "Detach the eBPF tap (unpin everything, idempotent)"
        )]
        detach: bool,
    },
    #[command(about = "Inspect network interfaces and routing context (read-only)")]
    Net,
}

impl Cli {
    pub fn command() -> clap::Command {
        <Self as CommandFactory>::command()
    }
}

#[cfg(test)]
#[path = "../../test/cli/cli_tests.rs"]
mod tests;
