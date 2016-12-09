#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sasl/saslutil.h>
#include <assert.h>

char *plain = "This is a test of the emergency boardcast system.  In the event of a real emergency, you would have been hit with a board!!\n";
char *encoded = "VGhpcyBpcyBhIHRlc3Qgb2YgdGhlIGVtZXJnZW5jeSBib2FyZGNhc3Qgc3lzdGVtLiAgSW4gdGhlIGV2ZW50IG9mIGEgcmVhbCBlbWVyZ2VuY3ksIHlvdSB3b3VsZCBoYXZlIGJlZW4gaGl0IHdpdGggYSBib2FyZCEhCg==";

void fill(unsigned int len, int expected)
{
    char *attempt;
    unsigned int outlen;
    int rc;

    if (!(attempt = (char*)malloc(len))) {
        perror("malloc");
        exit(1);
    }

    printf("Trying %d ...\n", len);

    // fill with crap
    memset(attempt, '!', len);

    outlen = 0;
    rc = sasl_encode64(plain, strlen(plain), attempt, len, &outlen);
    printf("\texpected rc: %d rc: %d\n", expected, rc);
    if (rc == SASL_OK) {
        printf("\tavailable: %u expected out: %zu: out: %u\n", len, strlen(encoded), outlen);
        // verify the output is the expected length without NULL term.
        assert(outlen == strlen(encoded));
        // verify the output is terminated.
        assert(attempt[strlen(encoded)] == '\0');
        // verify the output is the same.
        assert(strcmp(attempt, encoded)==0);
    }
    // verify encoding worked
    assert(rc == expected);
    printf("\tok\n");
    free(attempt);
}

int main(int argc, char * argv[])
{
    fill(32, SASL_BUFOVER);
    fill(strlen(encoded), SASL_BUFOVER);
    fill(strlen(encoded)+1, SASL_OK);
    fill(1024, SASL_OK);
    return 0;
}

