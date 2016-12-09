/*
   userns.c - a very simple test of user_namespace(7) functionality

   Copyright 2016 Canonical, Ltd.
   Author: Steve Beattie <steve.beattie@canonical.com>
*/

#define _GNU_SOURCE
#include <sys/utsname.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>

void usage()
{
	printf("Usage: userns [options]\n");
	printf("Options are:\n");
	printf("  -U        Create user namespace\n");
	printf("  -i        Create IPC namespace\n");
	printf("  -m        Create mount namespace\n");
	printf("  -n        Create network namespace\n");
	printf("  -p        Create PID namespace\n");
	printf("  -u        Create UTS namespace\n");
	printf("  -h        This message\n");
}

#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];    /* Space for child's stack */

int child_func(void *arg)
{
	printf("PASS: succeeded\n");
	return 0;
}

int main(int argc, char *argv[])
{
	int flags = 0, opt;
	pid_t child;

	while ((opt = getopt(argc, argv, "Uhimnpu")) != -1) {
	    switch (opt) {
		case 'U': flags |= CLONE_NEWUSER;
			  break;
		case 'i': flags |= CLONE_NEWIPC;
			  break;
        	case 'm': flags |= CLONE_NEWNS;
			  break;
		case 'n': flags |= CLONE_NEWNET;
			  break;
		case 'p': flags |= CLONE_NEWPID;
			  break;
		case 'u': flags |= CLONE_NEWUTS;
			  break;
		case 'h':
		default:
			usage();
	    }
	}

	if (flags == 0) {
		usage();
		exit(0);
	}

	child = clone(child_func, child_stack + STACK_SIZE,
			flags | SIGCHLD, NULL);

	if (child == -1) {
		perror("FAIL: clone failed: ");
		exit(1);
	}

	if (waitpid(child, NULL, 0) == -1) {
		perror("FAIL: waitpid: ");
		exit(1);
	}

	return 0;
}

