// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) mod examples;
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
    // The example rows paint at render time (night-improve-35): the
    // verb's about carries its example line, green verb token on the
    // grey grammar line, the exact plain bytes on a pipe.
    examples::paint_verbs(&mut cmd);
    // The verb version lane (night-total-hardening-1): one real clap
    // version flag, global, with the short-circuiting Version action -
    // `-V` now fires the moment the parser meets it, the way `-h`
    // always has, BEFORE the required-positional validation that used
    // to answer `zejtron path -V` (and proc, holds, touch, why) with
    // a missing-argument error instead of the build report. The root
    // keeps disable_version_flag: the derive adds no second version
    // flag, and main's manual `cli.version` report path is retired
    // with the field - every -V now rides this one arg and renders
    // through the UX bridge's DisplayVersion arm (the painted report,
    // exit 0, stdout). display_order pins the row where the old manual
    // flag sat, so the help bytes do not move.
    // The version string rides a program-lifetime static: clap 4.6's
    // Str only carries &'static str (no From<String>), and a CLI
    // hands this exact report out for the whole process lifetime
    // anyway - the ~300 bytes are the binary's own rodata, once. The
    // OnceLock holds the one String as static storage (the same
    // shape capability() rides): the Box::leak it replaced tripped
    // Miri's leak detector on every test that builds the branded
    // command, and re-allocated a fresh copy per call.
    cmd = cmd.version(version_text()).arg(
        clap::Arg::new("version")
            .short('V')
            .long("version")
            .global(true)
            .action(clap::ArgAction::Version)
            .display_order(0)
            .help("Print complete version and build information"),
    );
    // The row-order pins (night-total-hardening-1): the old derive
    // field order (version, verbose, check-update) numbered the
    // globals 0, 1, 2, and every verb's help interleaved those values
    // with the verb's own auto-numbered flags. With the version field
    // gone from the derive, the two survivors would renumber and the
    // help rows would drift. These explicit orders restore the exact
    // pre-change row order on every surface, byte for byte.
    cmd = cmd
        .mut_arg("verbose", |arg| arg.display_order(1))
        .mut_arg("check_update", |arg| arg.display_order(2));
    // The banner opens the reference (night-T-2, the sibling's
    // frame): the family's one title-line shape, bold brand purple,
    // before the about prose - the same `━━━ <title> ━━━` frame every
    // report surface carries.
    cmd = cmd.before_help(brand_banner());
    // The Pro mode section paints at render time (night-improve-38):
    // grey grammar on a color stdout, the exact plain bytes on a
    // pipe - never a frozen string on either lane. The Quick
    // examples section (night-improve-35) closes the render.
    cmd.after_help(format!(
        "{}{}",
        pro_mode::painted(),
        examples::quick_section()
    ))
}

/// The help banner: the reference's opening title line, the same
/// `━━━ <title> ━━━` bold-purple frame every report surface carries
/// ([`crate::output::banner`], night-T-2). The stdout-lane gate is
/// the one shared predicate with the Pro mode section, so a piped
/// render and a NO_COLOR environment keep the exact plain bytes.
fn brand_banner() -> String {
    crate::output::banner("zejtron — read-only evidence ledger for the Linux host")
}

/// The version report as a program-lifetime str. clap's version arg
/// needs &'static str, and the report is identical for the whole
/// process - the OnceLock builds it once and keeps it alive as
/// static storage, so repeated branded_command() calls share one
/// copy and nothing is leaked (the one-shot Box::leak this replaces
/// allocated a fresh ~408-byte string per call and failed the Miri
/// leak check).
fn version_text() -> &'static str {
    static VERSION: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    VERSION.get_or_init(crate::info::version_report_text)
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
    about = "Read-only evidence ledger for the Linux host. Native kernel readers, eBPF event windows, zero external wrappers. Boring and serious.",
    // The usage grammar in the sibling's shape (night-T-2): one line,
    // the whole top-level grammar plus one concrete e.g. invocation -
    // the same spelling each verb's own usage line carries below.
    override_usage = "zejtron [command] or [options] e.g zejtron port -v",
    disable_version_flag = true,
    // The mature help surface (night-improve-15, sibling shape): one
    // help authority - the -h/--help flags - and no auto-generated
    // `help` subcommand row padding the commands list on every
    // top-level render. night-improve-25 adds the Pro mode section:
    // the complete options estate, grouped by the verbs that own each
    // option, rendered plain through clap's after_help.
    disable_help_subcommand = true,
    styles = crate::cli::styles::clap_styles()
)]
pub struct Cli {
    // The diagnostic trace lane (night-hunter-4): a global flag so it
    // parses before or after any subcommand. stderr-only by law - the
    // Evidence Ledger's stdout stays byte-clean on a pipe.
    #[arg(
        short = 'v',
        long = "verbose",
        global = true,
        help = "Print engine diagnostics to stderr (stdout stays ledger-clean)"
    )]
    pub verbose: bool,

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
    #[command(
        about = "Where does a command come from?",
        override_usage = "zejtron path <command> or [options] e.g zejtron path sh"
    )]
    Path {
        #[arg(value_name = "COMMAND", help = "Command name to find in PATH")]
        command: String,
        #[arg(long, help = "Print the path resolution as JSON (one line, jq-ready)")]
        print_json: bool,
    },
    #[command(
        about = "What changed here lately?",
        override_usage = "zejtron recent [path] or [options] e.g zejtron recent --since 1h"
    )]
    Recent {
        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,
        #[arg(
            long,
            value_name = "N",
            default_value_t = 20,
            // The ceiling (night-total-hardening-1): a "maximum files
            // to show" ask beyond a million is a log-shaped problem,
            // not an evidence-shaped one - the same law the port
            // window's one-hour ceiling carries. truncate() itself is
            // allocation-free, so the bound is the LTS posture, not a
            // crash guard: absurd numerics get a named refusal at
            // parse time instead of a silent accept.
            value_parser =
                clap::builder::RangedI64ValueParser::<usize>::new().range(0..=1000000),
            help = "Maximum files to show (0-1000000)"
        )]
        limit: usize,
        #[arg(
            long,
            value_name = "DURATION",
            help = "Only show files modified since this duration"
        )]
        since: Option<String>,
        #[arg(
            long,
            help = "Print the recent-files report as JSON (one line, jq-ready)"
        )]
        print_json: bool,
    },
    #[command(
        about = "Which ports are open, and who owns them?",
        override_usage = "zejtron port [port] or [options] e.g zejtron port --tcp"
    )]
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
        #[arg(long, help = "Print the port report as JSON (one line, jq-ready)")]
        print_json: bool,
    },
    #[command(
        about = "What is running, and under whom?",
        // The required group leads: a target is either a user or --me.
        override_usage = "zejtron proc <user or --me> or [options] e.g zejtron proc --me",
    )]
    #[command(group = clap::ArgGroup::new("proc_target").required(true).multiple(false).args(["user_or_uid", "me"]))]
    Proc {
        #[arg(
            value_name = "USER_OR_UID",
            help = "Username or numeric UID to inspect"
        )]
        user_or_uid: Option<String>,
        #[arg(long, help = "Show processes owned by the current user")]
        me: bool,
        #[arg(
            long,
            allow_hyphen_values = true,
            value_name = "N",
            // The ceiling (night-total-hardening-1): the old 1..
            // floor answered the owner's own probe - `proc --me
            // --depth 1000000000000000` - with a silent accept (the
            // render naturally caps at the real tree, but the tool
            // pretended a quadrillion-deep ask was reasonable). 1024
            // is the LTS ceiling: the kernel's own PID space tops at
            // 4194304, and no process forest on any host can hold a
            // 1025-deep ancestor chain - every real ask fits, every
            // absurd ask is a parse-time refusal with the range in
            // the message.
            value_parser = clap::value_parser!(u64).range(1..=1024),
            help = "Limit rendered tree depth (1-1024)"
        )]
        depth: Option<u64>,
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
        #[arg(long, help = "Print the process scan as JSON (one line, jq-ready)")]
        print_json: bool,
    },
    #[command(
        about = "Who holds this file, port, or device?",
        override_usage = "zejtron holds <target> or [options] e.g zejtron holds /etc/resolv.conf"
    )]
    Holds {
        #[arg(
            value_name = "TARGET",
            help = "Filesystem path or port number to inspect"
        )]
        target: String,
        #[arg(
            value_name = "DURATION",
            long,
            help = "Event window width (s/m/h, default 10s, clamped to [1s, 1h])"
        )]
        since: Option<String>,
        #[arg(long, help = "Print the Evidence Ledger as JSON (one line, jq-ready)")]
        print_json: bool,
    },
    #[command(
        about = "When did this path last change?",
        override_usage = "zejtron touch <path> or [options] e.g zejtron touch /etc/hosts"
    )]
    Touch {
        #[arg(value_name = "PATH", help = "Path to inspect without modifying it")]
        path: PathBuf,
        #[arg(
            value_name = "DURATION",
            long,
            help = "Event window width (s/m/h, default 10s, clamped to [1s, 1h])"
        )]
        since: Option<String>,
        #[arg(long, help = "Print the Evidence Ledger as JSON (one line, jq-ready)")]
        print_json: bool,
    },
    #[command(
        about = "Evidence report for a path or port.",
        override_usage = "zejtron why <target> or [options] e.g zejtron why /etc/passwd"
    )]
    Why {
        #[arg(
            value_name = "TARGET",
            help = "Filesystem path or port number to explain"
        )]
        target: String,
        #[arg(
            value_name = "DURATION",
            long,
            help = "Event window width (s/m/h, default 10s, clamped to [1s, 1h])"
        )]
        since: Option<String>,
        #[arg(
            long,
            help = "Append how zejtron knows each row (the explainability ladder)"
        )]
        trace: bool,
        #[arg(long, help = "Append the raw kernel events as drained (drill-down)")]
        raw: bool,
        #[arg(
            long,
            conflicts_with_all = ["trace", "raw"],
            help = "Print the Evidence Ledger as JSON (one line, jq-ready)"
        )]
        print_json: bool,
    },
    #[command(
        about = "Host readiness and symptom analysis.",
        override_usage = "zejtron doctor [options] e.g zejtron doctor --symptom ram"
    )]
    Doctor {
        #[arg(
            long,
            conflicts_with = "symptom",
            help = "Attach the eBPF probe (the privileged one-shot)"
        )]
        attach: bool,
        #[arg(
            long,
            conflicts_with = "attach",
            help = "Detach the eBPF probe (unpin everything, idempotent)"
        )]
        detach: bool,
        #[arg(
            long,
            value_name = "SYMPTOM",
            conflicts_with_all = ["attach", "detach"],
            help = "Analyze a symptom instead of the readiness check (ram | cpu | disk | network | gpu | slow)"
        )]
        symptom: Option<String>,
        #[arg(
            long,
            conflicts_with_all = ["attach", "detach"],
            help = "With --symptom: append the raw /proc reads (drill-down)"
        )]
        raw: bool,
        #[arg(
            long,
            conflicts_with_all = ["attach", "detach", "raw"],
            help = "Print the doctor report as JSON (one line, jq-ready)"
        )]
        print_json: bool,
    },
    #[command(
        about = "Which interfaces exist, and how does traffic route?",
        override_usage = "zejtron net [options] e.g zejtron net"
    )]
    Net {
        #[arg(long, help = "Print the network report as JSON (one line, jq-ready)")]
        print_json: bool,
    },
}

impl Cli {
    pub fn command() -> clap::Command {
        <Self as CommandFactory>::command()
    }
}

#[cfg(test)]
#[path = "../../test/cli/cli_tests.rs"]
mod tests;
