#include "utils.h"

int main() {
	key_t key;
	if ((key = ftok(".", 1)) == -1) error_exit("ftok");
	int shmid;
	if ((shmid = shmget(key, 30, 0666)) < 0) error_exit("shmget");
	struct shmid_ds buf;
	if (shmctl(shmid, IPC_STAT, &buf) == -1) error_exit("shmctl");
	printf("%lu\n", buf.shm_nattch);
	return 0;
}
