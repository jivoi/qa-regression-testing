/* Testcase from
   https://bugs.launchpad.net/ubuntu/maverick/+source/eglibc/+bug/672352
 */

#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

int main(void) {
    struct addrinfo ai,*res;

    memset(&ai,0, sizeof(ai));
    ai.ai_flags = AI_PASSIVE | AI_ADDRCONFIG;
    ai.ai_family = PF_UNSPEC;
    ai.ai_socktype = SOCK_STREAM;

   return getaddrinfo("localhost", "5900", &ai, &res);
}
