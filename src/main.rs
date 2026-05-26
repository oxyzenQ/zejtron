mod cli;
mod path;
mod recent;
mod version;

use clap::Parser;

fn main() {
    let cli = cli::Cli::parse();

    if cli.version {
        println!("{}", version::version_text(env!("ZEJTRON_GIT_HASH")));
        return;
    }

    let result = match cli.command {
        Some(cli::Commands::Path { command }) => path::run(&command),
        Some(cli::Commands::Recent { path, limit, since }) => {
            recent::run(&path, limit, since.as_deref())
        }
        None => {
            let mut cmd = cli::Cli::command();
            cmd.print_help().map(|_| println!()).map_err(Into::into)
        }
    };

    if let Err(error) = result {
        eprintln!("zejtron: {error}");
        std::process::exit(1);
    }
}
