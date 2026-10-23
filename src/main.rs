// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only

mod cli;
mod commands;
mod ebpf;
mod evidence;
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

    // The diagnostic trace lane (night-hunter-4): armed once, from
    // the global flag, before any surface runs. The -v logs ride
    // stderr only; the Evidence Ledger's stdout stays pipe-clean.
    output::verbose::init(cli.verbose);

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
            since,
            events_only,
            snapshot_only,
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
                since,
                events_only,
                snapshot_only,
            },
        ),
        Some(cli::Commands::Proc {
            user_or_uid,
            me,
            depth,
            find,
            no_pid,
            no_color,
        }) => commands::proc::run(
            user_or_uid.as_deref(),
            commands::proc::ProcFlags {
                me,
                depth,
                find,
                no_pid,
                no_color,
            },
        ),
        Some(cli::Commands::Holds {
            target,
            since,
            print_json,
        }) => commands::holds::run(&target, since.as_deref(), print_json),
        Some(cli::Commands::Touch {
            path,
            since,
            print_json,
        }) => commands::touch::run(&path, since.as_deref(), print_json),
        Some(cli::Commands::Why {
            target,
            since,
            trace,
            raw,
            print_json,
        }) => commands::why::run(&target, since.as_deref(), trace, raw, print_json),
        Some(cli::Commands::Doctor {
            attach,
            detach,
            symptom,
            raw,
        }) => commands::doctor::run(
            env!("ZEJTRON_GIT_HASH"),
            attach,
            detach,
            symptom.as_deref(),
            raw,
        ),
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
