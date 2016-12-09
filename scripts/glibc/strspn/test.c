/* testcase for https://bugs.launchpad.net/ubuntu/+source/eglibc/+bug/615953 
   based on testcase in https://bugzilla.redhat.com/show_bug.cgi?id=624852
 */

#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[])
{
	char strtext[] = "12345abc";
	char accept[] = "0123456789";
	size_t ret;

	ret = strspn(strtext, accept);
	printf("PASSED, made it past strspn(); ret = %zd\n", ret);
	
	return 0;
}
