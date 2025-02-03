#include "utils.h"

int main() {
	key_t key;
	if ((key = ftok(".", 1)) == -1) error_exit("ftok");
	if (shmget(key, 30, IPC_CREAT | IPC_EXCL | 0666) < 0) error_exit("shmget");
	while (shmget(key, 30, 0666) > 0)
		continue;
	printf("host - ok\n");
	return 0;
}
