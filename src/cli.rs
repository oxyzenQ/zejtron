use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "zejtron",
    about = "A small Linux terminal toolkit for tracing paths, ports, env, recent files, and services.",
    disable_version_flag = true
)]
pub struct Cli {
    #[arg(
        short = 'V',
        long = "version",
        global = true,
        help = "Print version information"
    )]
    pub version: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "Inspect and compare environment variables")]
    Env {
        #[command(subcommand)]
        command: Option<EnvCommands>,
        #[arg(long, help = "Show variable names only")]
        keys: bool,
        #[arg(long, value_name = "TEXT", help = "Filter variables by key substring")]
        filter: Option<String>,
        #[arg(long, help = "Alias for --keys")]
        no_values: bool,
    },
    #[command(about = "Trace where a command comes from")]
    Path {
        #[arg(value_name = "COMMAND")]
        command: String,
    },
    #[command(about = "Show listening ports and process owners")]
    Port {
        #[arg(value_name = "PORT")]
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
    },
    #[command(about = "Show recently modified files")]
    Recent {
        #[arg(value_name = "PATH", default_value = ".")]
        path: PathBuf,
        #[arg(long, value_name = "N", default_value_t = 20)]
        limit: usize,
        #[arg(long, value_name = "DURATION")]
        since: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum EnvCommands {
    #[command(about = "Save current environment snapshot")]
    Save {
        #[arg(value_name = "NAME")]
        name: String,
    },
    #[command(about = "List saved environment snapshots")]
    List,
    #[command(about = "Delete saved environment snapshot")]
    Delete {
        #[arg(value_name = "NAME")]
        name: String,
    },
    #[command(about = "Compare saved environment snapshot with current environment")]
    Diff {
        #[arg(value_name = "NAME")]
        name: String,
        #[arg(long, help = "Show unchanged variables")]
        show_same: bool,
    },
}

impl Cli {
    pub fn command() -> clap::Command {
        <Self as CommandFactory>::command()
    }
}
