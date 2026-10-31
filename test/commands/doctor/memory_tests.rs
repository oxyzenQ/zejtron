// SPDX-FileCopyrightText: 2026 rezky_nightky
// SPDX-License-Identifier: GPL-3.0-only
//
//! The memory symptom's /proc parser pins (night-improve-4, Part B):
//! every parser is driven with synthetic /proc text, so the pins hold
//! on every host regardless of what the host's own tables carry. The
//! residual arithmetic is pinned here too - it is the one number the
//! whole report leans on.

use super::*;

#[test]
fn meminfo_parses_the_fields_the_report_rides_on() {
    let contents = "\
MemTotal:       16384000 kB
MemFree:         8192000 kB
MemAvailable:   12288000 kB
Buffers:         204800 kB
Cached:         4300800 kB
SwapCached:            0 kB
Shmem:           409600 kB
SReclaimable:    307200 kB
SUnreclaim:      102400 kB
HugePages_Total:       0
";
    let mem = parse_meminfo(contents).expect("the synthetic meminfo parses");
    assert_eq!(mem.total_kib, 16_384_000);
    assert_eq!(mem.free_kib, 8_192_000);
    assert_eq!(mem.available_kib, 12_288_000);
    assert_eq!(mem.buffers_kib, 204_800);
    assert_eq!(mem.cached_kib, 4_300_800);
    assert_eq!(mem.shmem_kib, 409_600);
    assert_eq!(mem.s_reclaimable_kib, 307_200);
    assert_eq!(mem.s_unreclaim_kib, 102_400);
}

#[test]
fn meminfo_missing_a_required_field_is_none() {
    // MemAvailable absent (pre-3.14 kernels): the report degrades to
    // the named absence, never a zero-filled guess.
    assert!(parse_meminfo("MemTotal: 100 kB\nMemFree: 10 kB\n").is_none());
    assert!(parse_meminfo("").is_none());
}

#[test]
fn smaps_rollup_parses_the_pss_family() {
    let contents = "\
Rss:              101880 kB
Pss:               65536 kB
Pss_Anon:          49152 kB
Pss_File:           8192 kB
Pss_Shmem:          8192 kB
Shared_Clean:          0 kB
Private_Dirty:     20480 kB
";
    let (pss, anon, file, shmem, rss) =
        parse_smaps_rollup(contents).expect("the synthetic rollup parses");
    assert_eq!(pss, 65_536);
    assert_eq!(anon, 49_152);
    assert_eq!(file, 8_192);
    assert_eq!(shmem, 8_192);
    assert_eq!(rss, 101_880);
}

#[test]
fn tmpfs_mount_parser_keeps_only_tmpfs_and_decodes_escapes() {
    // The \012 line (night-dragon-lts-1): the kernel's mangle()
    // escapes newline in mount points as the literal four bytes
    // \012; the decoder previously missed that arm, so the mount
    // point kept the escape verbatim and the walk never found the
    // directory.
    let contents = "\
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64 0 0
devpts /dev/pts devpts rw,nosuid,noexec,relatime 0 0
tmpfs /run tmpfs rw,nosuid,nodev,noexec,relatime,mode=755,inode64 0 0
tmpfs /tmp/with\\040space tmpfs rw 0 0
tmpfs /tmp/tab\\011sep tmpfs rw 0 0
tmpfs /tmp/nl\\012sep tmpfs rw 0 0
tmpfs /tmp/back\\134slash tmpfs rw 0 0
tmpfs /run/user/1000 tmpfs rw,nosuid,nodev,relatime,size=163840k,mode=700,uid=1000 0 0
";
    let mounts = parse_tmpfs_mounts(contents);
    assert_eq!(
        mounts,
        vec![
            "/dev/shm".to_owned(),
            "/run".to_owned(),
            "/run/user/1000".to_owned(),
            "/tmp/back\\slash".to_owned(),
            "/tmp/nl\nsep".to_owned(),
            "/tmp/tab\tsep".to_owned(),
            "/tmp/with space".to_owned(),
        ]
    );
}

#[test]
fn tmpfs_raw_entries_are_verbatim_lines() {
    let contents = "\
proc /proc proc rw 0 0
tmpfs /dev/shm tmpfs rw,nosuid,nodev,inode64 0 0
tmpfs /run tmpfs rw,mode=755 0 0
";
    let entries = parse_tmpfs_mounts_entries(contents);
    assert_eq!(entries.len(), 2);
    assert!(entries[0].starts_with("tmpfs /dev/shm tmpfs"));
    assert!(entries[1].starts_with("tmpfs /run tmpfs"));
}

#[test]
fn slabinfo_parses_top_caches_by_num_objs_times_objsize() {
    // The real kernel layout (mm/slab_common.c): name active_objs
    // num_objs objsize objperslab pagesperslab : tunables : slabdata.
    // night-dragon-lts-1: this fixture previously carried a phantom
    // <objperpad> column and identical values at columns 3 and 4, so
    // it could not discriminate objsize from objperslab - the parser
    // read the packing count as the size and every slab footprint
    // was wrong. The columns now differ (dentry: objsize 192,
    // objperslab 24), so the pin bites in both directions.
    let contents = "\
slabinfo - version: 2.1
# name            <active_objs> <num_objs> <objsize> <objperslab> <pagesperslab> : tunables : slabdata
dentry           234561 234561    192  24     1 : tunables    0   0   0 : slabdata   9774 9774  0
inode_cache      123456 123456    640  12     2 : tunables    0   0   0 : slabdata  10288 10288  0
tiny_cache            8      8     32  512    4 : tunables    0   0   0 : slabdata      1    1  0
";
    let rows = parse_slabinfo(contents);
    // dentry: 234561 * 192 = 45,035,712 B = 43,980 KiB; inode: 77,160
    // KiB; tiny: 8 * 32 = 256 B = 0 KiB. Descending by size, name
    // tiebreak. (The pre-fix parser computed dentry as 234561 * 24
    // = 5,496 KiB and tiny as 8 * 512 = 4 KiB - both wrong.)
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].cache, "inode_cache");
    assert_eq!(rows[0].size_kib, 123456 * 640 / 1024);
    assert_eq!(rows[1].cache, "dentry");
    assert_eq!(rows[1].size_kib, 234561 * 192 / 1024);
    assert_eq!(rows[2].cache, "tiny_cache");
    assert_eq!(rows[2].size_kib, 0);
}

#[test]
fn slabinfo_top_five_cap_applies() {
    let mut contents = String::from("slabinfo - version: 2.1\n# header\n");
    // Real layout: num_objs * objsize with objsize = 1024 keeps the
    // sizes distinct (100..107 KiB); objperslab = 8 and
    // pagesperslab = 4 differ from objsize so the pin discriminates
    // the columns (the pre-fix parser read column 4 and computed
    // 0 KiB rows for every cache here).
    for i in 0..8u64 {
        contents.push_str(&format!(
            "cache{i} 1 {objs} 1024 8 4 : tunables 0 0 0 : slabdata 1 1 0\n",
            objs = 100 + i
        ));
    }
    let rows = parse_slabinfo(&contents);
    assert_eq!(rows.len(), 5);
    // The five largest win, descending.
    assert_eq!(rows[0].cache, "cache7");
    assert_eq!(rows[0].size_kib, 107);
    assert_eq!(rows[4].cache, "cache3");
}

#[test]
fn residual_is_unavailable_minus_process_anon_and_shmem() {
    // night-dragon-lts-1 rewrite: the base is the kernel's
    // unavailable set (total - MemAvailable), and only the
    // process-owned parts that genuinely sit inside it (Pss_Anon,
    // Pss_Shmem) come off. A 16 GiB host with a 4 GiB unavailable
    // set: the readable processes carry 1.5 GiB of anon/shmem
    // (plus 0.5 GiB of file-backed PSS, which the kernel mostly
    // counts as available and which must NOT be subtracted) -> the
    // residual is 2.5 GiB.
    let mut sample = MemorySample {
        meminfo: Some(MemInfo {
            total_kib: 16 * 1024 * 1024,
            free_kib: 12 * 1024 * 1024,
            available_kib: 12 * 1024 * 1024,
            cached_kib: 1280 * 1024,
            buffers_kib: 200 * 1024,
            shmem_kib: 256 * 1024,
            s_reclaimable_kib: 300 * 1024,
            s_unreclaim_kib: 100 * 1024,
        }),
        ..Default::default()
    };
    sample.pss = vec![
        ProcessPss {
            pid: 1,
            name: "a".to_owned(),
            pss_kib: 1280 * 1024,
            anon_kib: 1024 * 1024,
            file_kib: 256 * 1024,
            shmem_kib: 0,
            rss_kib: 0,
        },
        ProcessPss {
            pid: 2,
            name: "b".to_owned(),
            pss_kib: 704 * 1024,
            anon_kib: 256 * 1024,
            file_kib: 0,
            shmem_kib: 256 * 1024,
            rss_kib: 0,
        },
    ];
    // 4 GiB unavailable - (1 GiB + 256 MiB anon + 256 MiB shmem)
    // = 2.5 GiB. The 256 MiB of file-backed PSS stays in the
    // residual: it was never in the unavailable base.
    let expected = 4 * 1024 * 1024 - (1024 + 256 + 256) * 1024;
    assert_eq!(residual_kib(&sample), Some(expected));
}

#[test]
fn residual_survives_a_cache_rich_host_instead_of_saturating_to_zero() {
    // The pre-fix regression (night-dragon-lts-1): this shape is a
    // live reading from a real host - the reclaimable buckets
    // (page cache, buffers, SReclaimable, SUnreclaim) total 2.7 GiB
    // while the unavailable set is only 540 MiB. The old formula
    // subtracted the buckets from a base that never contained them
    // (MemAvailable already counts reclaimable memory as
    // available), so the residual saturated to 0 B on every
    // cache-rich host and the 15% verdict threshold could never
    // fire. The honest residual here: 540 MiB unavailable minus the
    // processes' 384 MiB anon/shmem = 156 MiB of kernel-side and
    // unattributed memory.
    let mut sample = MemorySample {
        meminfo: Some(MemInfo {
            total_kib: 4_138_560,
            free_kib: 300_000,
            available_kib: 3_597_696,
            cached_kib: 2_644_676,
            buffers_kib: 21_936,
            shmem_kib: 60_000,
            s_reclaimable_kib: 136_732,
            s_unreclaim_kib: 17_964,
        }),
        ..Default::default()
    };
    sample.pss = vec![ProcessPss {
        pid: 1,
        name: "a".to_owned(),
        pss_kib: 500 * 1024,
        anon_kib: 320 * 1024,
        file_kib: 100 * 1024,
        shmem_kib: 64 * 1024,
        rss_kib: 0,
    }];
    let unavailable = 4_138_560 - 3_597_696;
    let expected = unavailable - (320 + 64) * 1024;
    assert_eq!(residual_kib(&sample), Some(expected));
    assert!(
        expected > 0,
        "the cache-rich host must report a real residual"
    );
}

#[test]
fn residual_never_underflows_and_needs_meminfo() {
    // No meminfo: no residual - the named absence, not a zero.
    assert_eq!(residual_kib(&MemorySample::default()), None);
    // Process-owned anon/shmem larger than the unavailable set: the
    // saturating floor is 0 - a negative residual would be a number
    // the report cannot defend.
    let mut sample = MemorySample {
        meminfo: Some(MemInfo {
            total_kib: 1000,
            free_kib: 0,
            available_kib: 900,
            cached_kib: 900,
            buffers_kib: 900,
            shmem_kib: 0,
            s_reclaimable_kib: 900,
            s_unreclaim_kib: 900,
        }),
        ..Default::default()
    };
    sample.pss = vec![ProcessPss {
        pid: 1,
        name: "a".to_owned(),
        pss_kib: 500,
        anon_kib: 500,
        file_kib: 0,
        shmem_kib: 500,
        rss_kib: 0,
    }];
    assert_eq!(residual_kib(&sample), Some(0));
}

#[test]
fn holders_label_names_pids_or_the_namespace_boundary() {
    let held = TmpfsFile {
        path: "/dev/shm/x".to_owned(),
        size_bytes: 10,
        holders: vec![123, 456],
    };
    let label = holders_label(&held);
    assert!(label.starts_with("held by PID 123 ("), "{label}");
    assert!(label.contains("456 ("), "{label}");

    let unheld = TmpfsFile {
        path: "/dev/shm/y".to_owned(),
        size_bytes: 10,
        holders: Vec::new(),
    };
    assert_eq!(
        holders_label(&unheld),
        "held by no process in this namespace"
    );
}

#[test]
fn holders_label_collapses_long_lists() {
    let held = TmpfsFile {
        path: "/dev/shm/z".to_owned(),
        size_bytes: 10,
        holders: vec![1, 2, 3, 4, 5],
    };
    let label = holders_label(&held);
    assert!(label.contains("and 2 more"), "{label}");
}
