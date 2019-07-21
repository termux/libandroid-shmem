CFLAGS += -fpic -shared -std=c11 -Wall -Wextra
LDFLAGS += -Wl,--version-script=exports.txt

libandroid-shmem.a: shmem.o
	$(AR) rcu $@ shmem.o

libandroid-shmem.so: shmem.o
	$(CC) $(LDFLAGS) -shared shmem.o -o $@ -llog

shmem.o: shmem.c shm.h
	$(CC) $(CFLAGS) -c shmem.c -o $@

install: libandroid-shmem.a libandroid-shmem.so shm.h
	install -D libandroid-shmem.a $(PREFIX)/lib/libandroid-shmem.a
	install -D libandroid-shmem.so $(PREFIX)/lib/libandroid-shmem.so
	install -D shm.h $(PREFIX)/include/sys/shm.h

clean:
	rm -f libandroid-shmem.a libandroid-shmem.so

.PHONY: install
