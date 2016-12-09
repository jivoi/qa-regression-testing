#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>

int start_child(char **args, char *exe) {
    pid_t child;
    setenv("LD_PRELOAD", "gotcha", 1);
    setenv("LD_LIBRARY_PATH", "gotcha", 1);
    setenv("PATH", "gotcha", 1);
    setenv("GTK_MODULES", "gotcha", 1);
    setenv("PERL5LIB", "gotcha", 1);
    setenv("CLASSPATH", "gotcha", 1);
    setenv("PYTHONHOME", "gotcha", 1);
    setenv("RUBYLIB", "gotcha", 1);
    setenv("BROWSER", "gotcha", 1);
    setenv("NOTDANGEROUS", "gotcha", 1);

    child = fork();
    if (child < 0) {
        perror("fork failed");
        exit(1);
    }
    if (child == 0) {
        printf ("%s:\n", exe);
        args[0] = exe;
        execv(exe, args);
    }

    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("PATH");
    unsetenv("GTK_MODULES");
    unsetenv("PERL5LIB");
    unsetenv("CLASSPATH");
    unsetenv("PYTHONHOME");
    unsetenv("RUBYLIB");
    unsetenv("BROWSER");
    unsetenv("NOTDANGEROUS");

    sleep(1);

    return 0;
}

int main(int argc, char * argv[])
{
    char *Ux = "~/tmp/aa/ux/Ux";
    char *ux = "~/tmp/aa/ux/ux";
    char *ix = "~/tmp/aa/ux/ix";
    char *args[2];
    args[1] = 0x0;

    start_child(args, ux);
    start_child(args, Ux);
    start_child(args, ix);

    return 0;
}
