mod cli;
mod env;
mod path;
mod port;
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
        Some(cli::Commands::Env {
            command,
            keys,
            filter,
            no_values,
        }) => env::run(command, keys || no_values, filter.as_deref()),
        Some(cli::Commands::Path { command }) => path::run(&command),
        Some(cli::Commands::Port {
            port,
            tcp,
            udp,
            listen,
            all,
            numeric,
            group,
            no_pid,
        }) => port::run(
            port.as_deref(),
            port::PortFlags {
                tcp,
                udp,
                listen,
                all,
                numeric,
                group,
                no_pid,
            },
        ),
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
