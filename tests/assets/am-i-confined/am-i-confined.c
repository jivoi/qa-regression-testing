#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <linux/limits.h>
#include <libgen.h>

#define BUF_SIZE 2048

int main(int argc, char * argv[])
{
    char *current = "/proc/self/attr/current";
    struct stat statbuf;
    int fd, rbytes, fd_test;
    size_t len;
    char buf[BUF_SIZE + 1];
    char *pkgname;
    char *app_id;
    char *tmp;
    char *path;
    char *dir;
    int rc = 0;

    /* check env */
    if (getenv("HOME") == NULL) {
        fprintf(stderr, "getenv(HOME) empty\n");
        rc = 3;
        goto exit;
    }
    if (getenv("APP_ID") == NULL) {
        fprintf(stderr, "getenv(APP_ID) empty\n");
        rc = 3;
        goto exit;
    }

    fprintf(stderr, "%s exists... ", current);
    if (stat(current, &statbuf) == -1) {
        perror("stat");
        rc = 3;
        goto exit;
    }
    fprintf(stderr, "ok\n");

    fprintf(stderr, "Opening %s... ", current);
    fd = open(current, O_RDONLY);
    if (fd == -1) {
        perror("open\n");
        rc = 3;
        goto exit;
    }
    fprintf(stderr, "ok\n");

    fprintf(stderr, "Reading %s... ", current);
    rbytes = read(fd, &buf, BUF_SIZE);
    if (rbytes == -1) {
        perror("read");
        rc = 3;
        goto exit1;
    }
    buf[rbytes-1] = '\0'; /* remove the final newline unconditionally */
    fprintf(stderr, "ok\n");

    app_id = getenv("APP_ID");
    tmp = strdup(app_id);
    if (tmp == NULL) {
        perror("read");
        rc = 3;
        goto exit1;
    }
    pkgname = strsep(&tmp, "_");
    if (pkgname == NULL) {
        fprintf(stderr, "strsep\n");
        rc = 3;
        goto exit2;
    }

    /* strlen("/.local/share/") + strlen("/pass") = 19 */
    len = strlen(getenv("HOME")) + strlen(pkgname) + 19;
    path = malloc(len * sizeof(char) + 1);
    if (!path) {
        perror("malloc");
        rc = 3;
        goto exit2;
    }
    dir = malloc(len * sizeof(char) + 1);
    if (!dir) {
        perror("malloc");
        rc = 3;
        goto exit3;
    }
    if (snprintf(path, len + 1,
		 "%s/.local/share/%s/pass", getenv("HOME"), pkgname
		) >= len + 1) {
        fprintf(stderr, "truncated\n");
        rc = 3;
	goto exit3;
    } else {
        fprintf(stderr, "Test path: %s\n", path);
    }

    fprintf(stderr, "Profile: %s\n", buf);
    if (strcmp(buf, "unconfined") == 0) {
        /* if not confined */
        printf("FAIL (unconfined)\n");
        rc = 1;
    } else if (strlen(app_id) != strspn(buf, app_id)) {
        /* if confined under a different profile */
        printf("FAIL (wrong profile)\n");
        rc = 2;
    } else {
        strcpy(dir, path);
        dir = dirname(dir);
        fprintf(stderr, "Test dir: %s\n", dir);
        if (mkdir(dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == -1) {
            perror("mkdir");
	    rc = 3;
	    goto exit4;
	}
        fd_test = open(path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
        if (fd_test == -1) {
            perror("open fd_test\n");
            rc = 3;
            goto exit4;
	}
	close(fd_test);
        printf("pass\n");
    }

  exit4:
    free(dir);
  exit3:
    free(path);
  exit2:
    free(pkgname);
  exit1:
    close(fd);
  exit:
    return rc;
}
