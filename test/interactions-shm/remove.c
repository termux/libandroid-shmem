#include "utils.h"

int main() {
	key_t key;
	if ((key = ftok(".", 1)) == -1) error_exit("ftok");
	int shmid;
	if ((shmid = shmget(key, 30, 0666)) < 0) error_exit("shmget");
	if (shmctl(shmid, IPC_RMID, 0) == -1) error_exit("shmctl");
	printf("remove - ok\n");
	return 0;
}
