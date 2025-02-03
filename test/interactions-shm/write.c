#include "utils.h"

int main() {
	key_t key;
	if ((key = ftok(".", 1)) == -1) error_exit("ftok");
	int shmid;
	if ((shmid = shmget(key, 30, 0666)) < 0) error_exit("shmget");
	char *shm;
	if ((shm = shmat(shmid, NULL, 0)) == (char*) -1) error_exit("shmat");
	memcpy(shm, TEST_TEXT, sizeof(TEST_TEXT));
	if (shmdt(shm) != 0) error_exit("shmdt");
	printf("write - ok\n");
	return 0;
}
