/*
 * Simple reproducer program for LP: #504164
 *
 * Copyright (C) 2015, Canonical, Ltd.
 * Author: Colin Ian King <colin.king@canonical.com>
 * Author: Steve Beattie <steve.beattie@canonical.com>
 * License: GPLv3
 *
 * gcc aslr-crash.c -fPIE -pie -o aslr-crash
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/resource.h>

#define	SZ	(1024 * 1024 * 8)
	
int big_stack(void)
{
	int x = 0;
	char *ptr, stack[SZ];

	for (ptr = stack; ptr < stack + SZ; ptr += 4096)
		*ptr = x;

	return x;
}

int main()
{
	struct rlimit stack_rlimit;
	int err;

	err = getrlimit(RLIMIT_STACK, &stack_rlimit);
	if (err != 0) {
		perror("Failed to get stack rlimit:");
		exit(1);
	}

	if (stack_rlimit.rlim_cur <= (SZ + 4096)) {
		stack_rlimit.rlim_cur = SZ * 2;
		err = setrlimit(RLIMIT_STACK, &stack_rlimit);
		if (err != 0) {
			perror("Failed to set stack rlimit:");
			exit(1);
		}
	}

	err = big_stack();
						
	exit(0);
}


