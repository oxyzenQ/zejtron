/* SPDX-FileCopyrightText: 2026 rezky_nightky
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The off-path action helper (night-frontier-Z7, D4; the memfd mode
 * is night-frontier-Z9, D6): the C77 root leg's actor for the live
 * window proofs. Three real off-path writes:
 *   mmap   - ftruncate to one page, mmap MAP_SHARED/PROT_WRITE, store
 *            one byte, unmap - the write fault fires the kernel's own
 *            dirty path (no write(2) crosses anywhere);
 *   splice - a real pipe is filled and splice(2) moves the bytes into
 *            the file's descriptor (no write(2) crosses);
 *   memfd  - memfd_create(2), the control file carries the memfd's
 *            /proc/<pid>/fd path (the actor's OWN pid: the why window
 *            runs in another process, so /proc/self would name the
 *            reader, not the holder), the actor waits for "go" in
 *            that file, then two real MAP_SHARED stores cross the
 *            memory-backed mapping: the fresh-mapping store (the
 *            non-present fault arm) and the read-then-store ride
 *            (the write-protection arm). The why window queries the
 *            /proc path the control file names - the tracked_inodes
 *            gate keys on the memfd's own (inode, device).
 * Exit codes: 0 = the action ran; 2 = usage; 3 = open failed;
 * 4 = mmap failed; 5 = splice failed; 6 = memfd setup failed;
 * 7 = the memfd mmap failed. The leg greps the why window's
 * raw output for the row labels - the camera naming the silent paths.
 */
#define _GNU_SOURCE /* splice(2) lives under __USE_GNU; newer gcc makes the implicit declaration an error, which would silently void the live legs */
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
	if (argc < 3)
		return 2;
	const char *mode = argv[1];
	const char *path = argv[2];
	if (strcmp(mode, "memfd") == 0) {
		int mfd = (int)syscall(SYS_memfd_create, "zejtron-proof", 0U);
		if (mfd < 0)
			return 6;
		if (ftruncate(mfd, 4096) != 0)
			return 6;
		int cf = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (cf < 0)
			return 6;
		dprintf(cf, "/proc/%d/fd/%d\n", (int)getpid(), mfd);
		close(cf);
		int waited = 0;
		while (waited < 50) {
			int g = open(path, O_RDONLY);
			char buf[16] = {0};
			if (g >= 0) {
				ssize_t n = read(g, buf, sizeof(buf) - 1);
				(void)n;
				close(g);
			}
			if (strstr(buf, "go"))
				break;
			usleep(100000);
			waited++;
		}
		char *p = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, mfd, 0);
		if (p == MAP_FAILED)
			return 7;
		p[0] = 'M';
		if (munmap(p, 4096) != 0)
			return 7;
		p = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, mfd, 0);
		if (p == MAP_FAILED)
			return 7;
		volatile char touched = p[0];
		(void)touched;
		p[1] = 'M';
		if (munmap(p, 4096) != 0)
			return 7;
		close(mfd);
		return 0;
	}
	int fd = open(path, O_RDWR);
	if (fd < 0)
		return 3;
	if (strcmp(mode, "mmap") == 0) {
		if (ftruncate(fd, 4096) != 0)
			return 3;
		char *p = mmap(NULL, 4096, PROT_WRITE, MAP_SHARED, fd, 0);
		if (p == MAP_FAILED)
			return 4;
		p[0] = 'Z';
		if (munmap(p, 4096) != 0)
			return 4;
	} else if (strcmp(mode, "splice") == 0) {
		int pipefd[2];
		if (pipe(pipefd) != 0)
			return 5;
		if (write(pipefd[1], "spliced into the tracked file", 29) < 0) {
			close(pipefd[1]);
			close(pipefd[0]);
			return 5;
		}
		close(pipefd[1]);
		ssize_t moved = splice(pipefd[0], NULL, fd, NULL, 64, 0);
		close(pipefd[0]);
		if (moved < 0)
			return 5;
	} else {
		close(fd);
		return 2;
	}
	close(fd);
	return 0;
}
