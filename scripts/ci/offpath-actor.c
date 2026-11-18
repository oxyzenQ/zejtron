/* SPDX-FileCopyrightText: 2026 rezky_nightky
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The off-path action helper (night-frontier-Z7, D4): the C77 root
 * leg's actor for the live window proofs. Two real off-path writes
 * on the file named by argv[2]:
 *   mmap   - ftruncate to one page, mmap MAP_SHARED/PROT_WRITE, store
 *            one byte, unmap - the write fault fires the kernel's own
 *            dirty path (no write(2) crosses anywhere);
 *   splice - a real pipe is filled and splice(2) moves the bytes into
 *            the file's descriptor (no write(2) crosses).
 * Exit codes: 0 = the action ran; 2 = usage; 3 = open failed;
 * 4 = mmap failed; 5 = splice failed. The leg greps the why window's
 * raw output for the row labels - the camera naming the silent paths.
 */
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char **argv) {
	if (argc < 3)
		return 2;
	const char *mode = argv[1];
	const char *path = argv[2];
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
