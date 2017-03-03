CFLAGS += -Wall -Wextra -Werror -std=c99

OS := $(shell uname -o 2> /dev/null)

ifeq ($(OS), Android)
CFLAGS += -I.. -llog
EXTRA_CFILE = ../shmem.c
cleanup-memory: test ;
else
CFLAGS += -DSYSV_ASHMEM_TEST_SYSTEM
EXTRA_CFILE =
cleanup-memory: test
	./cleanup-shared-memory.sh
endif

test: $(addprefix testcase-,$(patsubst %.c,%,$(wildcard *.c))) ;

testcase-% : test-%
	./$^

test-%: %.c $(EXTRA_CFILE)
	$(CC) $(CFLAGS) $+ -o $@

clean:
	rm -f test-*

.PHONY: clean \
	test \
	%-testcase

.PRECIOUS: test-%
