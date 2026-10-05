/* SPDX-License-Identifier: GPL-2.0 */
/*
 * kdgwatchd —— double-fork 拉起 busybox inotifyd。
 *
 * KernelSU 的 `su -c` 会话结束会清掉普通后台任务（setsid / start-stop-daemon
 * 都活不过）。本程序脱离会话、关 fd、再 exec inotifyd，作为独立守护活着。
 */
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	pid_t pid;
	int fd;

	if (argc < 2) {
		fprintf(stderr, "usage: kdgwatchd <inotifyd> <watch.sh> <path:mask>\n");
		return 2;
	}

	pid = fork();
	if (pid < 0)
		return 1;
	if (pid > 0)
		return 0;

	if (setsid() < 0)
		return 1;

	pid = fork();
	if (pid < 0)
		return 1;
	if (pid > 0)
		return 0;

	umask(0);
	if (chdir("/") < 0)
		return 1;
	fd = open("/dev/null", O_RDWR);
	if (fd >= 0) {
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd > 2)
			close(fd);
	}
	execv(argv[1], argv + 1);
	return 127;
}
