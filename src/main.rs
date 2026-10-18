// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

mod cli;
mod commands;
mod info;
mod output;
mod system;
mod update;

fn main() {
    // Parse through the UX bridge (night-improve-19, the sibling's
    // zelynic contract): usage errors get the migration redirects,
    // the case-insensitive flag rescue, the one-tip contract, and the
    // brand styles at render time - exit 2. Help/version requests
    // keep clap's own stdout + exit 0 path. Runtime failures below
    // keep the labeled red renderer and exit 1.
    let cli = match cli::parse_branded() {
        Ok(cli) => cli,
        Err(e) => cli::ux::exit_clap_error(e),
    };

    if cli.version {
        info::print_version_report();
        return;
    }

    if cli.check_update {
        if let Err(error) = update::check_update(env!("CARGO_PKG_VERSION")) {
            output::eprintln_error_labeled(&format!("update check failed: {error}"));
            std::process::exit(1);
        }
        return;
    }

    let result = match cli.command {
        Some(cli::Commands::Path { command }) => commands::path::run(&command),
        Some(cli::Commands::Recent { path, limit, since }) => {
            commands::recent::run(&path, limit, since.as_deref())
        }
        Some(cli::Commands::Port {
            port,
            tcp,
            udp,
            listen,
            all,
            numeric,
            group,
            no_pid,
        }) => commands::port::run(
            port.as_deref(),
            commands::port::PortFlags {
                tcp,
                udp,
                listen,
                all,
                numeric,
                group,
                no_pid,
            },
        ),
        Some(cli::Commands::Proc {
            user_or_uid,
            me,
            live,
            watch,
            interval,
            depth,
            find,
            no_pid,
            no_color,
        }) => commands::proc::run(
            user_or_uid.as_deref(),
            commands::proc::ProcFlags {
                me,
                live,
                watch,
                interval,
                depth,
                find,
                no_pid,
                no_color,
            },
        ),
        Some(cli::Commands::Holds { target }) => commands::holds::run(&target),
        Some(cli::Commands::Touch { path }) => commands::touch::run(&path),
        Some(cli::Commands::Why { target }) => commands::why::run(&target),
        Some(cli::Commands::Doctor) => commands::doctor::run(env!("ZEJTRON_GIT_HASH")),
        Some(cli::Commands::Net) => commands::net::run(),
        None => {
            // The branded builder, not the raw derive command: the
            // bare help render obeys the same capability rule as -h.
            cli::help_command()
                .print_help()
                .map(|_| println!())
                .map_err(Into::into)
        }
    };

    if let Err(error) = result {
        output::eprintln_error_labeled(&error.to_string());
        std::process::exit(1);
    }
}
