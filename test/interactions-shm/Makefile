CFLAGS += -Wall -Wextra -Werror -std=c99 -I..

OS := $(shell uname -o 2> /dev/null)

ifeq ($(OS), Android)
CFLAGS += -I../.. -llog
EXTRA_CFILE = ../../shmem.c
cleanup-memory: test ;
else
CFLAGS += -DSYSV_ASHMEM_TEST_SYSTEM
EXTRA_CFILE =
cleanup-memory: test
	../cleanup-shared-memory.sh
endif

test: testcase-1 testcase-2 testcase-3 testcase-4

testcase-1: test-create-shm test-remove shm-available.sh testcase-1.sh
	bash ./testcase-1.sh

testcase-2: test-create-shm test-write test-read test-remove shm-available.sh testcase-2.sh
	bash ./testcase-2.sh

testcase-3: test-create-shm test-create-ipc test-remove shm-available.sh testcase-3.sh
	bash ./testcase-3.sh

testcase-4: test-create-shm test-write test-read test-endless-attachment test-status test-remove shm-available.sh check-attachments.sh
	bash ./testcase-4.sh

test-%: %.c $(EXTRA_CFILE)
	$(CC) $(CFLAGS) $+ -o $@

clean:
	rm -f test-*

.PHONY: clean \
	test

.PRECIOUS: test-%
