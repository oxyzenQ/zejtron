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
    #[command(about = "Trace where a command comes from")]
    Path {
        #[arg(value_name = "COMMAND")]
        command: String,
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

impl Cli {
    pub fn command() -> clap::Command {
        <Self as CommandFactory>::command()
    }
}
