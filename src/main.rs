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
    // The UNIX pipe law (night-dragon-6): a CLI piped into a consumer
    // that closes early (jq, head) must die the UNIX way - SIGPIPE,
    // silent, exit 141 - never a Rust panic and a backtrace. std
    // ignores SIGPIPE at startup and turns the failed write into a
    // print panic ("failed printing to stdout: Broken pipe"); the
    // SIG_DFL reset, before any other logic, hands the write failure
    // back to the kernel's default disposition - the contract git,
    // curl, and every other pipe citizen on the host follows. The
    // libc pull is the dependency policy's own escape hatch (the
    // Cargo.toml note under aya), arriving at its first raw syscall.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

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
        Some(cli::Commands::Path {
            command,
            print_json,
        }) => commands::path::run(&command, print_json),
        Some(cli::Commands::Recent {
            path,
            limit,
            since,
            print_json,
        }) => commands::recent::run(&path, limit, since.as_deref(), print_json),
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
            print_json,
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
                print_json,
            },
        ),
        Some(cli::Commands::Proc {
            user_or_uid,
            me,
            depth,
            find,
            no_pid,
            no_color,
            print_json,
        }) => commands::proc::run(
            user_or_uid.as_deref(),
            commands::proc::ProcFlags {
                me,
                depth,
                find,
                no_pid,
                no_color,
                print_json,
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
            print_json,
        }) => commands::doctor::run(
            env!("ZEJTRON_GIT_HASH"),
            attach,
            detach,
            symptom.as_deref(),
            raw,
            print_json,
        ),
        Some(cli::Commands::Net { print_json }) => commands::net::run(print_json),
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
