CFLAGS += -Wall -Wextra -Werror -std=c99

OS := $(shell uname -o 2> /dev/null)

ifeq ($(OS), Android)
CFLAGS += -I.. -llog
EXTRA_CFILES = ../shmem.c ../shmem_vanilla.c
cleanup-memory: test ;
else
CFLAGS += -DSYSV_ASHMEM_TEST_SYSTEM
EXTRA_CFILES =
cleanup-memory: test
	./cleanup-shared-memory.sh
endif

test: $(addprefix testcase-,$(patsubst %.c,%,$(wildcard *.c))) ;

testcase-% : test-%
	./$^

test-%: %.c $(EXTRA_CFILES)
	$(CC) $(CFLAGS) $+ -o $@

clean:
	rm -f test-*

.PHONY: clean \
	test \
	%-testcase

.PRECIOUS: test-%
