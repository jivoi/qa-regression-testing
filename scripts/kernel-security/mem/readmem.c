#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/mman.h>

/* Hardy is weird and needs this undefined! */
#undef _POSIX_SOURCE
#include <sys/capability.h>

int seekread(int fd, unsigned long addr, unsigned int *value)
{
    int seen;

    printf("%p ... ", (void*)addr);
    fflush(NULL);

    if (lseek(fd, addr, SEEK_SET) != addr) {
        perror("seek");
        exit(2);
    }

    alarm(1);
    seen = read(fd, value, sizeof(*value));
    alarm(0);

    return seen;
}

unsigned long start_of_kernel(void)
{
    char buf[128];
    FILE *iomem;
    unsigned long start = 0;

    iomem = fopen("/proc/iomem", "r");
    if (!iomem) {
        perror("/proc/iomem");
        exit(100);
    }

    while (fgets(buf, 128, iomem)) {
        if (strstr(buf,"Kernel code\n") ||
            strstr(buf,"Kernel text\n")) {
            start = strtoul(buf, NULL, 16);
            fprintf(stderr, "%s", buf);
            break;
        }
    }
    fclose(iomem);

    if (!start) {
        fprintf(stderr, "No kernel code text segment found in /proc/iomem\n");
        return (getpagesize() << 2);
    }

    return start;
}

int safe_rawio()
{
    cap_t caps;
    cap_flag_value_t value;

    caps = cap_get_proc();
    if (caps == NULL)
        return 0;

    /* Don't have CAP_SYS_ADMIN? Fail -- we want to test with privs. */
    if (cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &value) || !value)
        return 0;

    cap_free(caps);

/* Handle hardy's ancient libcap-dev by just using capgetp() for all builds. */
#if 1
    caps = cap_init();
    if (capgetp(1, caps))
#else
    caps = cap_get_pid(1);
    if (caps == NULL)
#endif
        return 0;
    /* init doesn't have CAP_SYS_RAWIO? Assume we can't get at /dev/mem. */
    if (cap_get_flag(caps, CAP_SYS_RAWIO, CAP_EFFECTIVE, &value) || value)
        return 0;

    cap_free(caps);
    return 1;
}

int main(int argc, char * argv[])
{
    int fd, rc = 5, seen, fault = 0;
    unsigned int value;
    unsigned long addr;

    if (safe_rawio()) {
        printf("Having CAP_SYS_ADMIN without CAP_RAWIO, failing safe.\n");
        return 0;
    }

    if ( (fd=open("/dev/mem", O_RDONLY)) < 0 ) {
        perror("/dev/mem");
        return 1;
    }

    // scan mem list, starting a little bit above the bottom of the range
    for (addr = start_of_kernel(); !fault ; addr <<= 1) {
        seen = seekread(fd, addr, &value);
        if (seen < 0) {
            switch (errno) {
            case EFAULT:
                // non-mapped memory region, so stop scanning
                printf("missing (EFAULT), ran off end of physical memory?\n");
                fault = 1;
                break;
            case EINVAL:
                // non-mapped memory region, so stop scanning
                printf("missing (EINVAL), ran off end of physical memory?\n");
                fault = 1;
                break;
            case EPERM:
                // disallowed memory region! STRICT_MEM is working, exit 0
                printf("good: EPERM\n");
                return 0;
            default:
                // unexpected error
                perror("read");
                return 3;
            }
        }
        else if (seen != sizeof(value)) {
            printf("incomplete read (%u/%u)\n", seen,
                   (unsigned int)sizeof(value));
            return 255;
        }
        else {
            printf("readable\n");
            // successfully read memory, so keep scanning
            rc = 4;
        }
    }

    if (rc == 4) {
        // in the case of reading everything, see if instead we're just getting
        // blanked reads (Xen seems to do this). So, attempt to read a specific
        // non-zero value and test to see if it is non-zero after the read.
        seen = 0;
        value = 0;
        if (argc > 1) {
            addr = strtoul(argv[1], NULL, 16);
            seen = seekread(fd, addr, &value);
            printf("0x%x\n", value);
        }
        if (seen == sizeof(value)) {
            if (value != 0) {
                printf("FAIL: scanned memory without EPERMs, and can read actual values\n");
                rc = 7;
            }
            else {
                printf("weird: scanned memory without EPERMs, but target value is non-zero\n");
                rc = 6;
            }
        }
        else {
            printf("FAIL: scanned memory, got successful reads, and no EPERMs\n");
        }
    }
    else {
        printf("FAIL: scanned memory, no successful reads, but also no EPERMs\n");
    }
    return rc;
}

