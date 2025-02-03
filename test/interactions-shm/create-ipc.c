#include "utils.h"

int main() {
	int shmid;
	if ((shmid = shmget(IPC_PRIVATE, 30, 0666)) < 0) error_exit("shmget");
	printf("%d\n", shmid);
	return 0;
}
