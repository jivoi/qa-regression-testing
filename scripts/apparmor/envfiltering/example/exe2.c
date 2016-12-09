#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <libgen.h>

int main(int argc, char * argv[])
{
    char *dname_exe;
    char *dname;
    char *args[2];
    pid_t child;

    /* rudimentary error checking */
    if (argc < 2) {
        fprintf(stderr,"Usage: %s [u|U|p|P|c|C|i]\n", argv[0]);
        exit(1);
    }
    if (access(argv[1], R_OK|X_OK) != 0) {
        perror("access failed");
        exit(1);
    }

    dname_exe = dirname(strdup(argv[0]));
    dname = dirname(strdup(argv[1]));
    /* Allow execute of anything in the same directory as this executable */
    if (strcmp(dname_exe, dname) != 0) {
        fprintf(stderr,"%s != %s\n", dname_exe, dname);
        exit(1);
    }

    setenv("LD_PRELOAD", "gotcha", 1);
    setenv("LD_LIBRARY_PATH", "gotcha", 1);
    setenv("PATH", "gotcha", 1);

    args[0] = argv[1];
    args[1] = 0x0;
    printf ("%s:\n", args[0]);
    execv(args[0], args);
    perror("exec failed");
    exit(1);
}
