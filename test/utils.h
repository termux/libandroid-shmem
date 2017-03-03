#define _XOPEN_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef SYSV_ASHMEM_TEST_SYSTEM
# include <sys/shm.h>
#else
# include "shm.h"
#endif

void error_exit(char const* msg) {
	perror(msg);
	exit(1);
}

void failure_exit(char const* msg) {
	fprintf(stderr, "%s\n", msg);
	exit(1);
}
