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

test: testcase-1 testcase-2 testcase-3

testcase-1: test-host test-remove host-available.sh
	./test-host &
	sleep 0.1

	./test-remove
	./host-available.sh no

testcase-2: test-host test-write test-read test-remove host-available.sh
	./test-host &
	sleep 0.1

	./test-host && exit 1 || true
	./host-available.sh yes

	./test-write
	./test-read

	./test-remove

testcase-3: test-host test-write test-read test-endless-attachment test-status test-remove host-available.sh check-attachments.sh
	./test-host &
	sleep 0.1

	./check-attachments.sh

	./test-endless-attachment &
	sleep 0.1

	./check-attachments.sh

	./test-endless-attachment &
	sleep 0.1

	./check-attachments.sh

	./test-remove
	./host-available.sh yes

	kill $$(pidof -s test-endless-attachment)
	./host-available.sh yes

	./test-write
	./test-read

	kill $$(pidof -s test-endless-attachment)
	./host-available.sh no

test-%: %.c $(EXTRA_CFILE)
	$(CC) $(CFLAGS) $+ -o $@

clean:
	rm -f test-*

.PHONY: clean \
	test

.PRECIOUS: test-%
