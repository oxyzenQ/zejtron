// SPDX-FileCopyrightText: 2025-2026 rezky_nightky (oxyzenQ)
// SPDX-License-Identifier: AGPL-3.0-only OR Commercial
//
//! The Z11 detonation fixture's loader (night-frontier-Z11, phase c,
//! D8). Test-fixture only - it never ships in any binary. The chain:
//!
//! 1. load the fixture object (the fexit program and its control
//!    map, built by the same aya-ebpf toolchain the probes use);
//! 2. spawn the marker process (a plain shell loop appending to the
//!    watched file - the action the camera must record);
//! 3. write the marker's pid into the control map (0 = inert);
//! 4. load and attach the fentry program (the BTF-resolved hide);
//! 5. hold the estate for the collection window, then exit - the
//!    drop detaches the link and frees the program, the micro-VM's
//!    kernel carries nothing out.
//!
//! The stdout contract is the sentinel shape the detect script
//! parses: `PIDHIDE-PLANTED marker=<pid>` when the hide is live,
//! `PIDHIDE-REFUSED <reason>` when the kernel refused the load or
//! the attach (a named outcome, not a crash - the detect script
//! reports it and still runs the negative legs).

use std::process::Command;
use std::time::Duration;

use aya::{
    maps::Array,
    programs::FEntry,
    Btf, EbpfLoader, VerifierLogLevel,
};

/// The marker's working file: the path the detect script asks `why`
/// about, the one the camera's write probe tracks.
const MARKER_FILE: &str = "/opt/zejtron/.sandbox/marker-file";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: pidhide-loader <object.o> <hold-seconds>");
        std::process::exit(2);
    }
    let object = args[1].clone();
    let hold: u64 = match args[2].parse() {
        Ok(secs) => secs,
        Err(_) => {
            eprintln!("usage: pidhide-loader <object.o> <hold-seconds>");
            std::process::exit(2);
        }
    };
    match plant(&object, hold) {
        Ok(()) => {}
        Err(reason) => {
            eprintln!("PIDHIDE-REFUSED {reason}");
            std::process::exit(1);
        }
    }
}

/// The plant chain - every refusal is a named error string, never a
/// panic, so the CI log reads the cause without a backtrace. The
/// sentinel rides the attach, not the hold: the hide is live the
/// moment the link plants, and the detect script's sentinel wait
/// (ten one-second reads) must catch it while the hold is still
/// running - the first shape printed after the hold, and the wait
/// starved (the artifact named the plant, the leg's parse never saw
/// it, and the `why` ran as the hold expired with the hide already
/// detached).
fn plant(object: &str, hold_secs: u64) -> Result<(), String> {
    // The load rides the verifier's basic log: the default level
    // (DEBUG|STATS) makes the kernel write every state line into
    // user memory, and on the 5.15 floor a failed log write returns
    // EFAULT OVER THE VERDICT - bpf_check's own tail names EFAULT
    // whenever the log write died, even over a clean verification.
    // The first shape's batch walk generated exactly that flood (the
    // state lines of an unbounded-stride walk), so the walk is gone
    // from the program and DEBUG (level 1) keeps the log small: a
    // clean program loads whole, and a refusal prints its complete
    // named output in the CI log.
    let mut bpf = EbpfLoader::new()
        .verifier_log_level(VerifierLogLevel::DEBUG)
        .load_file(object)
        .map_err(|e| format!("the fixture object failed to load: {e}"))?;

    // The marker first: its pid is the control map's one input. A
    // plain shell loop appends to the watched file for longer than
    // the detect script's collection window, so the camera's write
    // probe records the hidden actor's action.
    let marker_file = MARKER_FILE;
    let loop_script = format!(
        "rm -f {marker_file}; \
         i=0; while [ $i -lt 400 ]; do \
           printf 'x\\n' >> {marker_file} 2>/dev/null || break; \
           sleep 0.05; i=$((i+1)); \
         done"
    );
    let marker = Command::new("/bin/sh")
        .arg("-c")
        .arg(&loop_script)
        .spawn()
        .map_err(|e| format!("the marker process failed to spawn: {e}"))?;
    let marker_pid = marker.id();

    // The control map: one u64 slot, 0 = inert. Written before the
    // attach so the program can never observe an unset target.
    let mut targets: Array<_, u64> = Array::try_from(
        bpf.map_mut("targets")
            .ok_or_else(|| "the fixture object carries no 'targets' map".to_owned())?,
    )
    .map_err(|e| format!("'targets' is not an array map: {e}"))?;
    targets
        .set(0, &(marker_pid as u64), 0)
        .map_err(|e| format!("the target pid write failed: {e}"))?;

    // The hide: BTF-resolved fentry on the kernel's own getdents64
    // callback (filldir64) - the per-entry seat the batch walk
    // replacement rides, the one whose BTF the floor kernel (5.15)
    // and 6.x both carry.
    let btf = Btf::from_sys_fs()
        .map_err(|e| format!("the kernel's BTF is unreadable: {e}"))?;
    let program: &mut FEntry = bpf
        .program_mut("pidhide")
        .ok_or_else(|| "the fixture object carries no 'pidhide' program".to_owned())?
        .try_into()
        .map_err(|e| format!("'pidhide' is not an fentry program: {e}"))?;
    program
        .load("filldir64", &btf)
        .map_err(|e| format!("the verifier refused the pidhide program: {e}"))?;
    program
        .attach()
        .map_err(|e| format!("the pidhide attach failed: {e}"))?;

    // The sentinel: the hide is live NOW, while the hold below keeps
    // the estate planted for the collection window.
    println!("PIDHIDE-PLANTED marker={marker_pid}");

    // Hold the estate for the collection window. The marker's own
    // loop outlives this hold; the drop at scope exit detaches the
    // link and frees the program - the micro-VM's kernel carries
    // nothing out of the test.
    std::thread::sleep(Duration::from_secs(hold_secs));
    drop(bpf);
    Ok(())
}
