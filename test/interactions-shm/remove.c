#include "utils.h"

int main(int argc, char **argv) {
	int shmid;
	if (argc > 1) {
		if ((shmid = atoi(argv[1])) == 0) error_exit("atoi");
	} else {
		key_t key;
		if ((key = ftok(".", 1)) == -1) error_exit("ftok");
		if ((shmid = shmget(key, 30, 0666)) < 0) error_exit("shmget");
	}
	if (shmctl(shmid, IPC_RMID, 0) == -1) error_exit("shmctl");
	printf("remove - ok\n");
	return 0;
}
