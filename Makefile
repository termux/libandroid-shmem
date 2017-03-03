CFLAGS += -fpic -shared -std=c11 -Wall -Wextra -Wl,--version-script=exports.txt

libandroid-shmem.so: shmem.c shm.h
	$(CC) $(CFLAGS) $(LDFLAGS) shmem.c -llog -o $@

install: libandroid-shmem.so shm.h
	cp libandroid-shmem.so $(PREFIX)/lib/libandroid-shmem.so
	cp shm.h $(PREFIX)/include/sys/shm.h

clean:
	rm -f libandroid-shmem.so

.PHONY: install
