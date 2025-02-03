#include "utils.h"

int main() {
	key_t key;
	if ((key = ftok(".", 1)) == -1) error_exit("ftok");
	int shmid;
	if ((shmid = shmget(key, 30, 0666)) < 0) error_exit("shmget");
	char *shm;
	if ((shm = shmat(shmid, NULL, 0)) == (char*) -1) error_exit("shmat");
	printf("%s\n", shm);
	if (strcmp(TEST_TEXT, shm) != 0) error_exit("strcmp");
	if (shmdt(shm) != 0) error_exit("shmdt");
	printf("read - ok\n");
	return 0;
}
