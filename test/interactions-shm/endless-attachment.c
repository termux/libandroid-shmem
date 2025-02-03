#include "utils.h"

int main() {
	key_t key;
	if ((key = ftok(".", 1)) == -1) error_exit("ftok");
	int shmid;
	if ((shmid = shmget(key, 30, 0666)) < 0) error_exit("shmget");
	if (shmat(shmid, NULL, 0) == (void*) -1) error_exit("shmat");
	printf("endless-attachment - ok\n");
	while (1)
		continue;
	return 0;
}
