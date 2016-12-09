#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <fcntl.h>
#include <errno.h>
#include <libgen.h>
#include <sys/stat.h>

#define ERROR           -1
#define MAXELEMENTS     256

typedef struct {
    char *elements[MAXELEMENTS];
    int pos;
} stack;

void initStack(stack *s) {
    s->pos = -1;
}

void addToStack(stack *s, char *p) {
    s->pos++;
    if (s->pos >= MAXELEMENTS) {
        fprintf(stderr, "Too many elements\n");
        exit(ERROR);
    }
    s->elements[s->pos] = strdup(p);
    if (!s->elements[s->pos]) {
        fprintf(stderr, "Not enough memory\n");
        exit(ERROR);
    }
}

void destroyStack(stack *s) {
    for (; s->pos >= 0; s->pos--)
        free(s->elements[s->pos]);
}

int checkPath(char *fn, char t) {
    int rc = 0;
    struct stat statbuf;
    char *fn_tmp = NULL;
    int fn_r_count;
    int test_fd;
    char *dname;

    if (t == 'r') { /* check read path */
        if (stat(fn, &statbuf) < 0) {
            rc = ERROR;
        } else {
            if ((test_fd = open(fn, O_RDONLY)) == -1) {
                rc = 1;
            } else {
                rc = 0;
                close(test_fd);
            }
        }
    } else {
        /* check write path */

        /* File does not exist. Try to create it */
        if (stat(fn, &statbuf) < 0) {
            if (errno == ENOENT || errno == ENOTDIR) {
                fprintf(stderr, "(creating %s) ", fn);
                fn_tmp = strdup(fn);
                if (!fn_tmp) {
                    fprintf(stderr, "Not enough memory\n");
                    rc = ERROR;
                    goto exit1;
                }
                dname = dirname(fn_tmp);
                if (stat(dname, &statbuf) < 0) {
                    if (errno == ENOENT) {
                        fprintf(stderr, "%s doesn't exist\n", dname);
                    }
                    rc = ERROR;
                } else if (!S_ISDIR(statbuf.st_mode)) {
                    fprintf(stderr, "%s is not a directory\n", dname);
                    rc = ERROR;
                }
                free(fn_tmp);
                if (rc == ERROR) {
                    goto exit1;
                }

                if ((test_fd = open(fn, O_WRONLY | O_CREAT,
                     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) == -1) {
                    rc = 1;
                    goto exit1;
                }
                close(test_fd);
            }
        } else {
            if ((test_fd = open(fn, O_WRONLY)) == -1) {
                rc = 1;
                goto exit1;
            }
            close(test_fd);
        }

        /* check read path if read/write */
        /* By this point, we either errored out or the file exists. Now try
         * to read it */
        if (t == 'W') {
            if ((test_fd = open(fn, O_RDONLY)) == -1) {
                rc = 1;
	        goto exit1;
            }
            close(test_fd);
        }
    }

  exit1:
    return rc;

}

int checkPaths(char t, char *arr[], int size) {
    int i;
    int rc = 0;
    int res = 0;

    if (size < 0)
        return 0;

    switch(t) {
        case 'r':
            fprintf(stderr, "Read paths:\n");
            break;
        case 'w':
            fprintf(stderr, "Write paths:\n");
            break;
        case 'W':
            fprintf(stderr, "Read/Write paths:\n");
            break;
    }
    for (i=0; i >= 0 && i<size+1 && arr[i] != NULL; i++) {
        fprintf(stderr, " %s: ", arr[i]);
        res = checkPath(arr[i], t);
        if (res == 0) {
            fprintf(stderr, "pass\n");
        } else if (res < 0) {
            fprintf(stderr, "ERROR\n");
            goto exit1;
        } else {
            fprintf(stderr, "fail\n");
            rc = res;
        }
    }

  exit1:
    return rc;
}

int checkEnv(char *arr[], int size) {
    int rc = 0;
    int i;
    char *key = NULL;
    char *val = NULL;
    char *enval;
    char *s = NULL;

    if (size < 0)
        return 0;

    fprintf(stderr, "Environment:\n");
    for (i=0; i >= 0 && i<size+1 && arr[i] != NULL; i++) {
        if (strchr(arr[i], '=') == NULL) {
            rc = ERROR;
            goto exit1;
        }
        s = strdup(arr[i]);
        if (!s) {
            rc = ERROR;
            goto exit1;
        }
        key = strsep(&s, "=");
        val = s;

        fprintf(stderr, " %s=%s: ", key, s);

        enval = getenv(key);
        if (enval == NULL) {
            fprintf(stderr, "ERROR\n");
            rc = ERROR;
        } else if (strcmp(val, enval) != 0) {
            fprintf(stderr, "fail\n");
            rc = 1;
        } else {
            fprintf(stderr, "pass\n");
        }
	free(key);
        if (rc == ERROR) {
            break;
        }
    }

  exit1:
    return rc;
}

void usage(char *exe) {
    printf("Usage: %s [-r readpath] [-w writepath] [-W rwpath]\n\n", exe);
    printf("Parent directory must already exist for all paths. When\n");
    printf("specifying -r, <readpath> must exist.\n\n");
    printf("Returns '0' if access is allowed, 1 if it is not and %d ", ERROR);
    printf("if error.\n");
    return;
}

int main(int argc, char * argv[])
{
    int rc = 0;
    int res = 0;
    int opt;
    int i;
    stack fn_r;
    initStack(&fn_r);
    stack fn_w;
    initStack(&fn_w);
    stack fn_rw;
    initStack(&fn_rw);
    stack fn_e;
    initStack(&fn_e);

    while ((opt = getopt(argc, argv, "e:r:w:W:")) != -1) {
        switch (opt) {
        case 'e':
            addToStack(&fn_e, optarg);
            break;
	case 'r':
            addToStack(&fn_r, optarg);
            break;
	case 'w':
            addToStack(&fn_w, optarg);
            break;
	case 'W':
            addToStack(&fn_rw, optarg);
            break;
        default:
            usage(argv[0]);
            exit(ERROR);
        }
    }

    res = checkPaths('r', fn_r.elements, fn_r.pos);
    if (res != 0) {
        rc = res;
        if (res < 0) {
            goto exit1;
        }
    }
    res = checkPaths('w', fn_w.elements, fn_w.pos);
    if (res != 0) {
        rc = res;
        if (res < 0) {
            goto exit1;
        }
    }
    res = checkPaths('W', fn_rw.elements, fn_rw.pos);
    if (res != 0) {
        rc = res;
        if (res < 0) {
            goto exit1;
        }
    }
    res = checkEnv(fn_e.elements, fn_e.pos);
    if (res != 0) {
        rc = res;
        if (res < 0) {
            goto exit1;
        }
    }

  exit1:
    destroyStack(&fn_r);
    destroyStack(&fn_w);
    destroyStack(&fn_rw);
    destroyStack(&fn_e);

    return rc;
}
