/* Copyright 2011, Will Drewry
 * License: BSD
 * update/adjusted by Kees Cook
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <asm/unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>

#include <sys/prctl.h>

/* Get/set process seccomp mode */
/* #define PR_GET_SECCOMP	21 */
/* #define PR_SET_SECCOMP	22 */
# define PR_SECCOMP_FILTER_SYSCALL 0
# define PR_SECCOMP_FILTER_EVENT 1

/* Get/set process seccomp filters */
#define PR_GET_SECCOMP_FILTER	35
#define PR_SET_SECCOMP_FILTER	36
#define PR_CLEAR_SECCOMP_FILTER	37

#if defined(__i386__) || defined(__x86_64__)

/* Cheat to deal with x86_64 syscall names */
#ifndef __NR_fstat64
# define __NR_fstat64 __NR_fstat
#endif
#ifndef __NR_mmap2
# define __NR_mmap2 __NR_mmap
#endif

int event_id = -1;

long add_filter(int nr, char *filter) {
  return prctl(PR_SET_SECCOMP_FILTER, PR_SECCOMP_FILTER_SYSCALL, nr, filter);
}

long deny(int nr);
long drop_filter(int nr, char *filter) {
  char foo[256];
  if (filter == NULL)
    return deny(nr);
  snprintf(foo, sizeof(foo), "!(%s)", filter);
  return add_filter(nr, foo);
}

long allow(int nr) {
  return add_filter(nr, "1");
}

long deny(int nr) {
  return prctl(PR_CLEAR_SECCOMP_FILTER, PR_SECCOMP_FILTER_SYSCALL, nr);
}

long apply_filters(bool on_exec) {
  return prctl(PR_SET_SECCOMP, 13);
}

/***** TESTS BEGIN ******/

int test_mode_one_ok(void) {
  long ret = prctl(PR_SET_SECCOMP, 1);
  syscall(__NR_exit, ret);
  return ret;   /* never reached. */
}

int test_mode_one_kill(void) {
  long ret = prctl(PR_SET_SECCOMP, 1);
  syscall(__NR_close, 0);
  return ret;   /* never reached. */
}

int test_add_filter_too_long(void) {
  long ret;
  char *f = malloc(8192);
  memset(f, 'A', 8192);
  ret = add_filter(__NR_exit, f);
  free(f);
  return !ret;
}

int test_add_filter_too_short(void) {
  long ret;
  ret = add_filter(__NR_exit, "");
  return !ret;
}

int test_add_filter_null(void) {
  long ret;
  ret = add_filter(__NR_exit, NULL);
  return !ret;
}

int test_add_bool_apply(void) {
  long ret = allow(__NR_exit);
  ret |= apply_filters(false);
  if (ret) {
    printf("Failed to enter mode 2: %ld\n", ret);
  }
  /* Should live */
  syscall(__NR_exit, 0);
  return ret;
}

#define noisy_allow(nr) \
  (allow(nr) ? printf("allow(" #nr ") failed!\n"), 1 : 0)

int test_keep_exec(void) {
  char * const argv[] = { "/proc/self/exe", "exec", NULL };
  int ret = noisy_allow(__NR_exit);
  ret |= noisy_allow(__NR_brk);
  ret |= noisy_allow(__NR_execve);
  ret |= noisy_allow(__NR_access);
  ret |= noisy_allow(__NR_uname);
  ret |= noisy_allow(__NR_open);
  ret |= noisy_allow(__NR_read);
  ret |= noisy_allow(__NR_fstat64);
  ret |= noisy_allow(__NR_mmap2);
  ret |= noisy_allow(__NR_close);
  ret |= noisy_allow(__NR_set_thread_area);
  ret |= noisy_allow(__NR_mprotect);
  ret |= noisy_allow(__NR_munmap);
  ret |= noisy_allow(__NR_prctl);
  if (ret) 
    printf("something failed\n");
  ret = apply_filters(true);
  if (ret)
    syscall(__NR_exit, ret);
  execv(argv[0], argv);
  return 1;
}

int test_keep_exec_drop(void) {
  char * const argv[] = { "/proc/self/exe", "exec2", NULL };
  int ret = noisy_allow(__NR_exit);
  ret |= noisy_allow(__NR_brk);
  ret |= noisy_allow(__NR_execve);
  ret |= noisy_allow(__NR_access);
  ret |= noisy_allow(__NR_uname);
  ret |= noisy_allow(__NR_open);
  ret |= noisy_allow(__NR_read);
  ret |= noisy_allow(__NR_fstat64);
  ret |= noisy_allow(__NR_mmap2);
  ret |= noisy_allow(__NR_close);
  ret |= noisy_allow(__NR_set_thread_area);
  ret |= noisy_allow(__NR_mprotect);
  ret |= noisy_allow(__NR_munmap);
  ret |= noisy_allow(__NR_prctl);
  if (ret) 
    printf("something failed\n");
  if (setresuid(1000, 1000, 1000)) {
    printf("Failed to drop root prior to apply\n");
    return 1;
  }
  ret = apply_filters(true);
  if (ret)
    syscall(__NR_exit, ret);
  execv(argv[0], argv);
  return 1;
}

int test_lose_exec(void) {
  long ret = allow(__NR_exit);
  char * const argv[] = { "/proc/self/exe", "exec", NULL };
  ret |= allow(__NR_brk);
  ret |= allow(__NR_execve);
  ret |= allow(__NR_access);
  ret |= allow(__NR_uname);
  ret |= allow(__NR_open);
  ret |= allow(__NR_read);
  ret |= allow(__NR_fstat64);
  ret |= allow(__NR_mmap2);
  ret |= allow(__NR_close);
  ret |= allow(__NR_set_thread_area);
  ret |= allow(__NR_mprotect);
  ret |= allow(__NR_munmap);
  ret |= allow(__NR_prctl);
  if (setresuid(1000, 1000, 1000)) {
    printf("Failed to drop root prior to apply\n");
    return 1;
  }
  ret |= apply_filters(true);
  if (ret)
    syscall(__NR_exit, ret);
  execv(argv[0], argv);
  return 1;
}

int test_add_bool_apply_drop(void) {
  long ret = allow(__NR_exit);
  ret |= allow(__NR_prctl);
  ret |= apply_filters(false);
  if (ret) {
    printf("Failed to enter mode 2: %ld\n", ret);
  }
  deny(__NR_prctl);
  /* Should live */
  syscall(__NR_exit, 0);
  return ret;
}

int test_add_bool_apply_drop_die(void) {
  long ret = allow(__NR_exit);
  ret |= allow(__NR_prctl);
  ret |= apply_filters(false);
  if (ret) {
    printf("Failed to enter mode 2: %ld\n", ret);
  }
  deny(__NR_exit);
  /* Should die */
  syscall(__NR_exit, 0);
  return ret;
}

int test_add_bool_apply_event(void) {
  //long ret = allow(__NR_exit);
  if (event_id == -1) {
    printf("could not read sys_enter_exit event id, skipping\n");
    return 0;
  }

  long ret = prctl(PR_SET_SECCOMP_FILTER, PR_SECCOMP_FILTER_EVENT,
                   event_id, "1");
  printf("set filter for exit with id %d: %ld %d\n", event_id, ret, errno);
  ret |= apply_filters(false);
  if (ret) {
    printf("Failed to enter mode 2: %ld\n", ret);
  }
  /* Should live */
  syscall(__NR_exit, 0);
  return ret;
}

int test_add_bool_apply_fail(void) {
  long ret = allow(__NR_exit);
  ret |= allow(__NR_close);
  ret |= allow(__NR_prctl);
  ret |= apply_filters(false);
  if (ret) {
    printf("Failed to enter mode 2: %ld\n", ret);
  }
  deny(__NR_close);
  allow(__NR_close);
  deny(__NR_prctl);
  /* Should die */
  syscall(__NR_close, 0);
  return ret;
}

int test_add_bool_on_exec_fail(void) {
  int status;
  pid_t pid;
  char * const argv[] = { "/proc/self/exe", "1", NULL };
  long ret = allow(__NR_brk);
  ret |= allow(__NR_access);
  ret |= allow(__NR_uname);
  ret |= allow(__NR_open);
  ret |= allow(__NR_read);
  ret |= allow(__NR_fstat64);
  ret |= allow(__NR_mmap2);
  ret |= allow(__NR_close);
  ret |= allow(__NR_set_thread_area);
  ret |= allow(__NR_mprotect);
  ret |= allow(__NR_munmap);
  ret |= apply_filters(true);
  if (ret) {
   printf("Failed to set all filters\n");
   return 1;
  }
  status = 0;
  pid = syscall(__NR_fork);
  if (pid == 0) {
    /* On exec applies _even_ if execv fails. */
    _exit(execv(argv[0], argv));
  }
  wait(&status);
  if (WIFSIGNALED(status) && WTERMSIG(status) == 9)
    return 0;
  return 1;
}

int test_add_bool_on_exec(void) {
  int status;
  pid_t pid;
  char * const argv[] = { "/proc/self/exe", "1", NULL };
  long ret = add_filter(__NR_brk, "1");
  ret |= add_filter(__NR_access, "1");
  ret |= add_filter(__NR_uname, "1");
  ret |= add_filter(__NR_open, "1");
  ret |= add_filter(__NR_read, "1");
  ret |= add_filter(__NR_fstat64, "1");
  ret |= add_filter(__NR_mmap2, "1");
  ret |= add_filter(__NR_close, "1");
  ret |= add_filter(__NR_set_thread_area, "1");
  ret |= add_filter(__NR_mprotect, "1");
  ret |= add_filter(__NR_munmap, "1");
  ret |= add_filter(__NR_exit, "1");
  ret |= apply_filters(true);
  if (ret) {
   printf("Failed to set all filters\n");
   return 1;
  }
  status = 0;
  pid = syscall(__NR_fork);
  if (pid == 0) {
    /* On exec applies _even_ if execv fails. Hrm. */
    _exit(execv(argv[0], argv));
  }
  wait(&status);
  if (WIFEXITED(status) && WEXITSTATUS(status) == 1)
    return 0;
  return 1;
}

int test_add_drop_bool_on_exec(void) {
  int status;
  pid_t pid;
  char * const argv[] = { "/proc/self/exe", "3", NULL };
  long ret = add_filter(__NR_brk, "1");
  ret |= add_filter(__NR_access, "1");
  ret |= add_filter(__NR_uname, "1");
  ret |= add_filter(__NR_open, "1");
  ret |= add_filter(__NR_read, "1");
  ret |= add_filter(__NR_fstat64, "1");
  ret |= add_filter(__NR_mmap2, "1");
  ret |= add_filter(__NR_close, "1");
  ret |= add_filter(__NR_set_thread_area, "1");
  ret |= add_filter(__NR_mprotect, "1");
  ret |= add_filter(__NR_munmap, "1");
  ret |= add_filter(__NR_prctl, "1");
  ret |= add_filter(__NR_exit, "1");
  ret |= apply_filters(true);
  if (ret) {
   printf("Failed to set all filters\n");
   return 1;
  }
  status = 0;
  pid = syscall(__NR_fork);
  if (pid == 0) {
    /* On exec applies _even_ if execv fails. Hrm. */
    execv(argv[0], argv);
    syscall(__NR_exit, 2);
  }
  wait(&status);
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
    return 0;
  return 1;
}

int test_add_drop_bool_on_exec_fail(void) {
  int status;
  pid_t pid;
  char * const argv[] = { "/proc/self/exe", "2", NULL };
  long ret = add_filter(__NR_brk, "1");
  ret |= add_filter(__NR_access, "1");
  ret |= add_filter(__NR_uname, "1");
  ret |= add_filter(__NR_open, "1");
  ret |= add_filter(__NR_read, "1");
  ret |= add_filter(__NR_fstat64, "1");
  ret |= add_filter(__NR_mmap2, "1");
  ret |= add_filter(__NR_close, "1");
  ret |= add_filter(__NR_set_thread_area, "1");
  ret |= add_filter(__NR_mprotect, "1");
  ret |= add_filter(__NR_munmap, "1");
  ret |= add_filter(__NR_prctl, "1");
  ret |= add_filter(__NR_exit, "1");
  ret |= apply_filters(true);
  if (ret) {
   printf("Failed to set all filters\n");
   return 1;
  }
  status = 0;
  pid = syscall(__NR_fork);
  if (pid == 0) {
    /* On exec applies _even_ if execv fails. Hrm. */
    execv(argv[0], argv);
    syscall(__NR_exit, 2);
  }
  wait(&status);
  if (WIFSIGNALED(status) && WTERMSIG(status) == 9)
    return 0;
  return 1;
}

int test_add_bool_apply_get(void) {
  long ret = allow(__NR_exit);
  char buf[256];
  ret |= allow(__NR_prctl);
  ret |= allow(__NR_write);
  //ret |= apply_filters(false);
  if (ret) {
    printf("Failed to prepare filters: %ld\n", ret);
  }
  ret = prctl(PR_GET_SECCOMP_FILTER, PR_SECCOMP_FILTER_SYSCALL,
               __NR_write, buf, sizeof(buf) - 1);
  ret |= strcmp("1", buf);
  syscall(__NR_exit, ret);
  return -1;
}

int test_add_bool_apply_add(void) {
  long ret = allow(__NR_exit);
  ret |= allow(__NR_prctl);
  ret |= allow(__NR_write);
  ret |= apply_filters(false);
  if (ret) {
    printf("Failed to prepare filters: %ld\n", ret);
  }
  ret = allow(__NR_read);
  syscall(__NR_exit, !ret);
  return -1;
}

int test_add_ftrace_apply(void) {
  long ret = add_filter(__NR_exit, "error_code == 0");
  if (ret) {
    printf("Failed to set __NR_exit 'error_code == 0'; %ld\n", ret);
    perror("prctl");
  }
  ret |= apply_filters(false);
  /* Should live to tell the tale */
  syscall(__NR_exit, 0);
  return 1;
}

int test_add_ftrace_apply_fail(void) {
  long ret = add_filter(__NR_exit, "error_code == 1");
  ret |= apply_filters(false);
  /* Should die */
  syscall(__NR_exit, 2);
  return ret;
}

int test_add_ftrace_on_exec(void) {
  int status;
  pid_t pid;
  char * const argv[] = { "/proc/self/exe", "1", NULL };
  long ret = add_filter(__NR_brk, "1");
  ret |= add_filter(__NR_access, "1");
  ret |= add_filter(__NR_uname, "1");
  ret |= add_filter(__NR_open, "1");
  ret |= add_filter(__NR_read, "1");
  ret |= add_filter(__NR_fstat64, "1");
  ret |= add_filter(__NR_mmap2, "1");
  ret |= add_filter(__NR_close, "1");
  ret |= add_filter(__NR_set_thread_area, "1");
  ret |= add_filter(__NR_mprotect, "1");
  ret |= add_filter(__NR_munmap, "1");
  ret |= add_filter(__NR_exit, "error_code == 1");
  ret |= apply_filters(true);
  if (ret) {
   printf("Failed to use a filter\n");
   return ret;
  }
  status = 0;
  pid = syscall(__NR_fork);
  if (pid == 0) {
    /* On exec applies _even_ if execv fails. Hrm. */
    _exit(execv(argv[0], argv));
  }
  wait(&status);
  if (WIFEXITED(status) && WEXITSTATUS(status) == 1)
    return 0;
  return 1;
}


int test_add_ftrace_on_exec_fail(void) {
  int status;
  pid_t pid;
  char * const argv[] = { "/proc/self/exe", "1", NULL };
  long ret = add_filter(__NR_brk, "1");
  ret |= add_filter(__NR_access, "1");
  ret |= add_filter(__NR_uname, "1");
  ret |= add_filter(__NR_open, "1");
  ret |= add_filter(__NR_read, "1");
  ret |= add_filter(__NR_fstat64, "1");
  ret |= add_filter(__NR_mmap2, "1");
  ret |= add_filter(__NR_close, "1");
  ret |= add_filter(__NR_set_thread_area, "1");
  ret |= add_filter(__NR_mprotect, "1");
  ret |= add_filter(__NR_munmap, "1");
  ret |= add_filter(__NR_exit, "error_code == 0");
  ret |= apply_filters(true);
  if (ret) {
   printf("Failed to use a filter\n");
   return ret;
  }
  status = 0;
  pid = syscall(__NR_fork);
  if (pid == 0) {
    /* On exec applies _even_ if execv fails. Hrm. */
    _exit(execv(argv[0], argv));
  }
  wait(&status);
  if (WIFSIGNALED(status) && WTERMSIG(status) == 9)
    return 0;
  return 1;
}

int test_add_drop_ftrace_on_exec(void) {
  int status;
  pid_t pid;
  char * const argv[] = { "/proc/self/exe", "4", NULL };
  long ret = add_filter(__NR_brk, "1");
  ret |= add_filter(__NR_access, "1");
  ret |= add_filter(__NR_uname, "1");
  ret |= add_filter(__NR_open, "1");
  ret |= add_filter(__NR_read, "1");
  ret |= add_filter(__NR_fstat64, "1");
  ret |= add_filter(__NR_mmap2, "1");
  ret |= add_filter(__NR_close, "1");
  ret |= add_filter(__NR_set_thread_area, "1");
  ret |= add_filter(__NR_mprotect, "1");
  ret |= add_filter(__NR_munmap, "1");
  ret |= add_filter(__NR_prctl, "1");
  ret |= add_filter(__NR_exit, "error_code == 1");
  ret |= apply_filters(true);
  if (ret) {
   printf("Failed to set all filters\n");
   return 1;
  }
  status = 0;
  pid = syscall(__NR_fork);
  if (pid == 0) {
    /* On exec applies _even_ if execv fails. Hrm. */
    execv(argv[0], argv);
    syscall(__NR_exit, 2);
  }
  wait(&status);
  if (WIFEXITED(status) && WEXITSTATUS(status) == 1)
    return 0;
  return 1;
}

int test_add_drop_ftrace_on_exec_fail(void) {
  int status;
  pid_t pid;
  char * const argv[] = { "/proc/self/exe", "5", NULL };
  long ret = add_filter(__NR_brk, "1");
  ret |= add_filter(__NR_access, "1");
  ret |= add_filter(__NR_uname, "1");
  ret |= add_filter(__NR_open, "1");
  ret |= add_filter(__NR_read, "1");
  ret |= add_filter(__NR_fstat64, "1");
  ret |= add_filter(__NR_mmap2, "1");
  ret |= add_filter(__NR_close, "1");
  ret |= add_filter(__NR_set_thread_area, "1");
  ret |= add_filter(__NR_mprotect, "1");
  ret |= add_filter(__NR_munmap, "1");
  ret |= add_filter(__NR_prctl, "1");
  ret |= add_filter(__NR_exit, "error_code == 1");
  ret |= apply_filters(true);
  if (ret) {
   printf("Failed to set all filters\n");
   return 1;
  }
  status = 0;
  pid = syscall(__NR_fork);
  if (pid == 0) {
    /* On exec applies _even_ if execv fails. Hrm. */
    execv(argv[0], argv);
    syscall(__NR_exit, 2);
  }
  wait(&status);
  if (WIFSIGNALED(status) && WTERMSIG(status) == 9)
    return 0;
  return 1;
}

int test_add_drop_null_ftrace_on_exec_fail(void) {
  int status;
  pid_t pid;
  char * const argv[] = { "/proc/self/exe", "6", NULL };
  long ret = add_filter(__NR_brk, "1");
  ret |= add_filter(__NR_access, "1");
  ret |= add_filter(__NR_uname, "1");
  ret |= add_filter(__NR_open, "1");
  ret |= add_filter(__NR_read, "1");
  ret |= add_filter(__NR_fstat64, "1");
  ret |= add_filter(__NR_mmap2, "1");
  ret |= add_filter(__NR_close, "1");
  ret |= add_filter(__NR_set_thread_area, "1");
  ret |= add_filter(__NR_mprotect, "1");
  ret |= add_filter(__NR_munmap, "1");
  ret |= add_filter(__NR_prctl, "1");
  ret |= add_filter(__NR_exit, "error_code == 1");
  ret |= apply_filters(true);
  if (ret) {
   printf("Failed to set all filters\n");
   return 1;
  }
  status = 0;
  pid = syscall(__NR_fork);
  if (pid == 0) {
    /* On exec applies _even_ if execv fails. Hrm. */
    execv(argv[0], argv);
    syscall(__NR_exit, 2);
  }
  wait(&status);
  if (WIFSIGNALED(status) && WTERMSIG(status) == 9)
    return 0;
  return 1;
}

int test_add_ftrace_apply_get(void) {
  char buf[256];
  long ret = allow(__NR_exit);
  ret |= allow(__NR_prctl);
  ret |= add_filter(__NR_write, "fd == 0 || fd == 1");
  ret |= apply_filters(false);
  if (ret) {
    printf("Failed to prepare filters: %ld\n", ret);
  }
  ret = prctl(PR_GET_SECCOMP_FILTER, PR_SECCOMP_FILTER_SYSCALL,
              __NR_write, buf, sizeof(buf) - 1);
  if (!ret)
    ret = strcmp("fd == 0 || fd == 1", buf);
  syscall(__NR_exit, ret);
  return -1;
}

int test_add_ftrace_apply_append_get(void) {
  char buf[256];
  long ret = allow(__NR_exit);
  ret |= allow(__NR_prctl);
  ret |= add_filter(__NR_write, "fd == 0 || fd == 1");
  ret |= apply_filters(false);
  if (ret) {
    printf("Failed to prepare filters: %ld\n", ret);
  }
  ret = prctl(PR_SET_SECCOMP_FILTER, PR_SECCOMP_FILTER_SYSCALL, __NR_write, "fd != 0");
  ret |= prctl(PR_GET_SECCOMP_FILTER, PR_SECCOMP_FILTER_SYSCALL, __NR_write, buf, sizeof(buf) - 1);
  if (!ret)
    ret = strcmp("(fd == 0 || fd == 1) && (fd != 0)", buf);
  syscall(__NR_exit, ret);
  return ret;
}

int test_add_drop_ftrace_proc(void) {
  int fd;
  char buf[1024];
  ssize_t bytes;
  long ret = add_filter(__NR_brk, "1");
  ret |= add_filter(__NR_access, "1");
  ret |= add_filter(__NR_uname, "1");
  ret |= add_filter(__NR_open, "1");
  ret |= add_filter(__NR_read, "1");
  ret |= add_filter(__NR_write, "fd == 1");
  ret |= add_filter(__NR_fstat64, "1");
  ret |= add_filter(__NR_mmap2, "1");
  ret |= add_filter(__NR_close, "1");
  ret |= add_filter(__NR_set_thread_area, "1");
  ret |= add_filter(__NR_mprotect, "1");
  ret |= add_filter(__NR_munmap, "1");
  ret |= add_filter(__NR_prctl, "option > 32 && option < 37");
  ret |= add_filter(__NR_exit, "error_code == 0 || error_code == 1");
  ret |= add_filter(__NR_exit, "error_code != 1");
  fd = open("/proc/self/seccomp_filter", O_RDONLY);
  ret |= apply_filters(true);
  bytes = read(fd, buf, sizeof(buf) - 1);
  if (write(1, "Read in:\n", 9) < 0 ||
      write(1, buf, bytes) < 0) {
    perror("write");
    return 1;
  }
  close(fd);
  syscall(__NR_exit, 0);
  return 0;
}



/***** TESTS END ******/

#define RUN_TEST(_n, _k) RUN_TEST_IMPL(_n, _k, true)
#define RUN_TEST_ROOT(_n, _k) RUN_TEST_IMPL(_n, _k, false)

#define RUN_TEST_IMPL(_name, _killed, _drop_root) \
  do { \
  int __ret = 1; \
  int status = 0; \
  pid_t __pid = syscall(__NR_fork); \
  \
  if (__pid < 0) \
    return -1; \
  if (__pid == 0) { \
    if (_drop_root) { \
      if (geteuid() == 0) { \
        if (setresuid(1000, 1000, 1000)) { \
          printf("setresuid call failed.\n"); \
          return -1; \
        } \
      } \
    } else { \
      if (geteuid() != 0) { \
        printf("Test expected root privileges.\n"); \
        return -1; \
      } \
    } \
    return test_##_name(); \
  } \
  wait(&status); \
  if (_killed && WIFSIGNALED(status) && WTERMSIG(status) == 9) \
    __ret = 0; \
  if (!_killed && WIFEXITED(status) && WEXITSTATUS(status) == 0) \
    __ret = 0; \
  printf("%s :: %s\n", (__ret ? "FAIL" : "PASS"), #_name); \
  if (__ret) { failed = 1; } \
} while(0);

void read_event_id(void)
{
  char buf[80];
  memset(buf, 0, sizeof(buf));
  FILE *idfp = fopen("/sys/kernel/debug/tracing/events/syscalls/sys_enter_exit/id", "r");
  if (!idfp || fread(buf, 1, sizeof(buf)-1, idfp)<1) {
    printf("WARNING: cannot read sys_enter_exit event id\n");
    if (idfp) fclose(idfp);
    return;
  }
  event_id = atoi(buf);
  fclose(idfp);
}

int main(int argc, char **argv) {
  int failed = 0;
  int rootonly = 0;
  if (argc > 1) {
    if (!strcmp(argv[1], "exec")) {
      char * const argvn[] = { "/proc/self/exe", "exit", NULL };
      deny(__NR_prctl);
      execv(argvn[0], argvn);
      syscall(__NR_exit, 0);
    } else if (!strcmp(argv[1], "exec2")) {
      char * const argvn[] = { "/proc/self/exe", "exit", NULL };
      execv(argvn[0], argvn);
    } else if (!strcmp(argv[1], "exit")) {
      syscall(__NR_exit, 0);
    } else if (!strcmp(argv[1], "rootonly")) {
      rootonly = 1;
    }
  }

  read_event_id();

  if (!rootonly) {
  RUN_TEST(mode_one_ok, false);
  RUN_TEST(mode_one_kill, true);
  RUN_TEST(add_filter_too_long, false);
  RUN_TEST(add_filter_too_short, false);
  RUN_TEST(add_filter_null, false);
  RUN_TEST(add_bool_apply, false);
  RUN_TEST(add_bool_apply_event, false);
  RUN_TEST(add_bool_apply_fail, true);
  RUN_TEST(add_bool_apply_get, false);
  RUN_TEST(add_bool_apply_add, false);
  RUN_TEST(add_bool_apply_drop, false);
  RUN_TEST(add_bool_apply_drop_die, true);
  RUN_TEST(add_ftrace_apply, false);
  RUN_TEST(add_ftrace_apply_fail, true);
  RUN_TEST(add_ftrace_apply_get, false);
  RUN_TEST(add_ftrace_apply_append_get, false);
  RUN_TEST(add_drop_ftrace_proc, false);
  }

  if (geteuid() == 0) {
    RUN_TEST_ROOT(keep_exec, true);
    RUN_TEST_ROOT(keep_exec_drop, true);
    RUN_TEST_ROOT(lose_exec, true);
  }

//  pause();
  return failed;
}

#elif defined(__ARMEL__) || defined(__PPC64__) || defined(__aarch64__) || defined(__s390x__)
int main(int argc, char **argv) {
  /* fail ARMEL and PPC64 automatically */
  return 1;
}
#else
# error "Not x86 or ARM"
#endif
