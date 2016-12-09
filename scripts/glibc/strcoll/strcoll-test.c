/* based on https://sourceware.org/bugzilla/show_bug.cgi?id=14547 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

int main() {

char *ptr = setlocale(LC_ALL, "C");
if(!ptr) {
    printf("error setting locale\n");
    return -1;
}

printf("doing test #1\n");
if (strcoll("ABCDEFG", "ABCDEFG") != 0)
    return -1;

printf("doing test #2\n");
if (strcoll("XX a XX", "XX B XX") < 0)
    return -1;

printf("doing test #3\n");
if (strcoll("XX B XX", "XX a XX") > 0)
    return -1;

printf("doing test #4\n");
if (strcoll("B", "a") > 0)
    return -1;

printf("doing test #5\n");
if (strcoll("a", "B") < 0)
    return -1;

return 0;
}

