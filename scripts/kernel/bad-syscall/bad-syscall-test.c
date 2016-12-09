/*
 * Based on the testcase provided in LP: #339743 -- specifically, we're
 * interested in the return code for an invalid syscall invoked
 * i386-style with int $0x80; in the bug report above, the amd64 kernel
 * returned the invalid syscall number (i.e. 666666 in the code below)
 * instead of -ENOSYS.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	int ret;
	int syscall = 666666;

	asm("int $0x80": "=a" (ret): "a" (syscall));

	if (ret != -ENOSYS) {
		printf("FAIL: syscall(%d) returned %d (%s)\n",
				syscall, ret, strerror(-ret));
		return 1;
	}

	printf("ok\n");
	return 0;
}
