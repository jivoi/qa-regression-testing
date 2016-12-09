/* Compile: gcc -fPIC -pie -o aslr aslr.c -ldl */
/* Run:     ./aslr [stack|libs|text|brk|mmap|vdso]      */
/*
 * Copyright 2007-2009, Canonical, Ltd.
 * Author: Kees Cook <kees@ubuntu.com>
 * License: GPLv3
 *
 * If "libs" is randomzied, it almost certainly means that "mmap" is too,
 * since they both should be using kernel mmap heap allocations.
 *
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <inttypes.h>

void launch(char * prog, char * buf, int size)
{
    FILE *proc;
    if (!(proc = popen(prog, "r"))) {
            perror(prog);
            exit(1);
    }
    if (!fgets(buf, size, proc)) {
        snprintf(buf,size, "self-exec failed!\n");
    }
    if ( pclose(proc) < 0 ) {
        perror(prog);
    }
}

void usage(char *argv[])
{
    const char *options = "(stack|vdso|text|brk|mmap|libs|pie)";
    fprintf(stderr,"External Usage: %s [rekey] %s [--verbose]\n",argv[0],options);
    fprintf(stderr,"Interal Usage:\n");
    fprintf(stderr,"   normal:      %s --report %s\n",argv[0],options);
    fprintf(stderr,"   rekey:       %s --different %s check_address\n",argv[0],options);
    exit(1);
}

#define AREA_MAPS  0
#define AREA_STACK 1
#define AREA_VDSO  2
#define AREA_TEXT  3
#define AREA_BRK   4
#define AREA_MMAP  5
#define AREA_LIBS  6
#define AREA_PIE   7

int validate_area(char *area, char * argv[])
{
    if (!strcmp(area,"maps"))  return AREA_MAPS;
    if (!strcmp(area,"stack")) return AREA_STACK;
    if (!strcmp(area,"vdso"))  return AREA_VDSO;
    if (!strcmp(area,"text"))  return AREA_TEXT;
    if (!strcmp(area,"brk"))   return AREA_BRK;
    if (!strcmp(area,"mmap"))  return AREA_MMAP;
    if (!strcmp(area,"libs"))  return AREA_LIBS;
    if (!strcmp(area,"pie"))   return AREA_PIE;
    usage(argv); /* This never returns. */
    return 0;
}

/* This function intentionally leaks allocations. */
uintptr_t area_pointer(int area)
{
    uintptr_t ptr;
    char stack_str[128];
    int stack_int = 12;

    /* Try to defeat compiler optimizations and always put stack to work. */
    sprintf(stack_str, "%d", stack_int * area);

    switch (area) {
        case AREA_TEXT:
            /* where did some function end up in memory? */
            return (uintptr_t)&usage;
        case AREA_BRK:
            /* where does small heap-allocated memory end up? */
            // this should be a brk (less than 128K alloc)
            ptr = (uintptr_t)malloc(1024);
            /* Due to text randomization, our brk may appear randomized,
               when in fact it is statically offset from the text address.
               Compensate for this by subtracting the text address before
               reporting. */
            return ptr - area_pointer(AREA_TEXT);
        case AREA_MMAP:
            /* where does large heap-allocated memory end up? */
            // this should be a mmap (more than 128K alloc)
            return (uintptr_t)malloc(1024*1024);
        case AREA_LIBS:
            /* where is this function loaded? */
            return (uintptr_t)dlsym(RTLD_DEFAULT, "dlsym");
        case AREA_STACK:
            /*
             * GCC warns about returning stack addresses, but this should
             * obfuscate it.
             */
            ptr = (uintptr_t)stack_str;
            return ptr;
        case AREA_MAPS:
            /* AREA_MAPS just dumps the maps file... */
            /* Fall-through... */
        case AREA_VDSO: {
            FILE *fp = NULL;
            char buf[128];

            /* locate the vdso from the maps file */
            fp = fopen("/proc/self/maps","r");
            if (fp) {
                while (fgets(buf,128,fp)) {
                    if (area == AREA_MAPS) printf("%s", buf);
                    if (strstr(buf, "[vdso]\n")) {
                        char * dash = strchr(buf,'-');
                        if (dash) {
                            *dash='\0';
                            return strtoul(buf, NULL, 16);
                        }
                    }
                }
                fclose(fp);
                if (area == AREA_MAPS)
                    exit(0);

                /* Only way to get here would be to miss [vdso]. */
                fprintf(stderr, "[vdso] missing from /proc/self/maps!?\n");
                exit(2);
            }
            perror("/proc/self/maps");
            exit(2);
            break;
        }
        case AREA_PIE: {
            /*
             * Full PIE ASLR means that text is randomized separately
             * from mmap. To show this, just calculate a delta between
             * the two locations, similar to how we check brk ASLR.
             */
	    fprintf(stderr, "[pie] AREA_MMAP: %p\tAREA_TEXT: %p\n", area_pointer(AREA_MMAP),
			    area_pointer(AREA_TEXT));
            return area_pointer(AREA_MMAP) - area_pointer(AREA_TEXT);
        }
        default:
            fprintf(stderr, "Internal error: Unknown area report requested (%d)\n", area);
            exit(255);
            break;
    }

    return 0;
}

/*
 * Returns a string containing the hex representation of the computed
 * address.
 */
char *area_report(int area)
{
    char *ptr;

    if (asprintf(&ptr, "%#0*" PRIxPTR, (int)sizeof(unsigned long) * 2,
                       area_pointer(area)) < 0) {
        perror("asprintf");
        exit(1);
    }

    return ptr;
}

int main(int argc, char * argv[])
{
    char * area_str;
    int area, optind;
    char * ptr = NULL;
    int rekey = 0, report = 0, different = 0;

    if (argc<2) usage(argv);

    optind = 1;
    area_str = argv[optind++];
    if (area_str[0] == '-') {
        if (!strcmp(area_str, "--report")) report = 1;
        if (!strcmp(area_str, "--different"))  different = 1;
        area_str = argv[optind++];
    }
    if (!strcmp(area_str,"rekey")) {
        rekey = 1;
        area_str = argv[optind++];
    }
    area = validate_area(area_str,argv);

    if (report) {
        ptr = area_report(area);
        printf("%s\n", ptr);
    }
    else if (different) {
        void * unexpected = NULL;
        unexpected = (void*)strtoul(argv[optind],NULL,16);
        ptr = area_report(area);
        if (ptr == unexpected) {
            printf("FAIL: prior ASLR of %s was also %p!\n", area_str, ptr);
            exit(1);
        }
        else {
            printf("ok: prior ASLR of %s was %p.  Got %p this time.\n", area_str, unexpected, ptr);
        }
    }
    else {
        int verbose = 0;
        char * eol;
        char prog[128];
        char report_one[128], report_two[128], report_three[128];

        if (argc>2 && !strcmp(argv[2], "--verbose")) verbose = 1;
        if (argc>3 && !strcmp(argv[3], "--verbose")) verbose = 1;

        if (verbose) { printf("Checking ASLR %sof %s:\n", rekey ? "rekeying " : "", area_str); }

        if (!rekey) {
            snprintf(prog, 128, "%s --report %s", argv[0], area_str);
            launch(prog, report_one, 128);
            launch(prog, report_two, 128);
            launch(prog, report_three, 128);

            /* drop trailing LF */
            if ((eol=strchr(report_one,'\n'))) *eol='\0';
            if ((eol=strchr(report_two,'\n'))) *eol='\0';
            if ((eol=strchr(report_three,'\n'))) *eol='\0';

            if (verbose) {
                    printf("\t%s\n", report_one);
                    printf("\t%s\n", report_two);
                    printf("\t%s\n", report_three);
            }

            if (report_one[0] && report_two[0] && report_three[0] &&
                strcmp(report_one, report_two) == 0 &&
                strcmp(report_one, report_three) == 0 &&
                strcmp(report_three, report_two) == 0) {
                printf("FAIL: ASLR not functional (%s always at %s)\n", area_str, report_one);
                return 1;
            }
            else {
                printf("ok: ASLR of %s functional\n", area_str);
            }
        }
        else { /* rekey checking */
            ptr = area_report(area);
            execl(argv[0], argv[0], "--different", area_str, ptr, NULL);
            perror(argv[0]);
            exit(127);
        }
    }

    return 0;
}
