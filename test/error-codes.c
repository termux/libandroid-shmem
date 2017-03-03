#include "utils.h"

int main() {
	// shmat(2) The shmat() system call will fail if: 
	// [EINVAL]           shmid is not a valid shared memory identifier.  shmaddr specifies an illegal address.
	char* shm;
	if ((shm = shmat(12345, NULL, 0)) != (char *) -1) failure_exit("shmat");
	if (errno != EINVAL) error_exit("shmat-wrong-errno");
	int shmid;
	if ((shmid = shmget(IPC_PRIVATE, 30, IPC_CREAT | 0666)) < 0) error_exit("shmget");
}
