/* Copyright 2010 Canonical, Ltd
   License: GPLv3
   Authors:
	Kees Cook <kees.cook@canonical.com>
	Stefan Bader <stefan.bader@canonical.com>

   Looks for gap between stack and mlock stack region

*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

void find_stack(unsigned long *prior_end, unsigned long *stack_start)
{
    unsigned long stack = 0;
    unsigned long end = 0;
    FILE *maps;
    char buf[128];

    sprintf(buf, "/proc/%d/maps", getpid());
    if (!(maps = fopen(buf,"r"))) {
        perror(buf);
        exit(2);
    }
    while (!stack && fgets(buf, 128, maps)) {
        //printf("%s", buf);
        if (strstr(buf,"[stack]")) {
            stack = strtoul(buf, NULL, 16);
            break;
        }

        char * dash = strchr(buf,'-');
        if (dash) {
            dash++;
            end = strtoul(dash, NULL, 16);
        }
        else {
            end = 0;
        }
    }
    fclose(maps);

    if (!stack) {
        fprintf(stderr,"Could not find '[stack]' in /proc/self/maps!\n");
        exit(3);
    }

    //printf("prior end: %p\n", (void*)end);
    if (prior_end) {
        *prior_end   = end;
    }
    //printf("stack start: %p\n", (void*)stack);
    if (stack_start) {
        *stack_start = stack;
    }
}

int main(void)
{
	char	__attribute__((unused)) buf1[128];
	char	buf2[128];
	char	__attribute__((unused)) buf3[128];
	unsigned long after_prior_end;
	unsigned long before_stack, after_stack;
	int matches;

	buf1[0] = 0;
	buf2[0] = 0;
	buf3[0] = 0;

	find_stack(NULL, &before_stack);
	mlock(buf2, 128);
	find_stack(&after_prior_end, &after_stack);

	matches = (before_stack == after_stack) ||  /* no split happened, or */
              (after_prior_end == after_stack); /* no gap happened */

	munlock(buf2, 128);

	if (!matches) {
		fprintf(stderr,"gap exists in stack VMAs (%p != %p)!\n", (void*)after_prior_end, (void*)after_stack);
	}
    	else {
        	printf("ok: no gap\n");
    	}
	return !matches;
}
