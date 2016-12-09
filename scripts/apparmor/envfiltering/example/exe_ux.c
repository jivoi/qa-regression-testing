#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>

int main(int argc, char * argv[])
{
    extern char **environ;
    printf ("LD_PRELOAD=%s\n", getenv("LD_PRELOAD"));
    printf ("LD_LIBRARY_PATH=%s\n", getenv("LD_LIBRARY_PATH"));
    printf ("PATH=%s\n", getenv("PATH"));
    printf ("GTK_MODULES=%s\n", getenv("GTK_MODULES"));
    printf ("PERL5LIB=%s\n", getenv("PERL5LIB"));
    printf ("CLASSPATH=%s\n", getenv("CLASSPATH"));
    printf ("PYTHONHOME=%s\n", getenv("PYTHONHOME"));
    printf ("RUBYLIB=%s\n", getenv("RUBYLIB"));
    printf ("BROWSER=%s\n", getenv("BROWSER"));
    printf ("NOTDANGEROUS=%s\n", getenv("NOTDANGEROUS"));

    return 0;
}
