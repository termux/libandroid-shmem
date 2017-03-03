#include "utils.h"

int main() {
	int pipe_fds[2], exit_pipes[2];
	if (pipe(pipe_fds) != 0) error_exit("pipe");
	if (pipe(exit_pipes) != 0) error_exit("pipe");

	int shmid;
	if ((shmid = shmget(IPC_PRIVATE, 30, IPC_CREAT | 0666)) < 0) error_exit("shmget");
	char* shm;
	if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) error_exit("shmat");

	char* s = shm;
	for (char c = 'a'; c <= 'z'; c++) *s++ = c;
	*s = 0;

	pid_t child_pid = fork();
	if (child_pid == -1) {
		error_exit("fork");
	} else if (child_pid == 0) {
		char* shm_child;
		if ((shm_child = shmat(shmid, NULL, 0)) == (char*) -1) error_exit("shmat-child");
		shm_child[0] = (shm_child[0] == 'a' && shm_child[1] == 'b') ? '*' : '!';
		if (shmdt(shm_child) != 0) error_exit("shmdt-child");
		if ((shm_child = shmat(shmid, NULL, 0)) == (char*) -1) error_exit("shmat-child");
		shm_child[1] = '#';
		if (shmdt(shm_child) != 0) error_exit("shmdt-child-2");

		// Create a new shared memory segment in the child to check that the
		// parent can access it.
		int shmid;
		if ((shmid = shmget(IPC_PRIVATE, 38, IPC_CREAT | 0666)) < 0) error_exit("shmget-child");
		char* shm;
		if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) error_exit("shmat-child-new");
		shm[0] = 'C';
		shm[1] = 'Q';
		if (write(pipe_fds[1], &shmid, sizeof(int)) != sizeof(int)) error_exit("write");

		// Await an ack from parent before exiting, to keep our listener thread alive.
		int dummy;
		if (read(exit_pipes[0], &dummy, sizeof(int)) != sizeof(int)) error_exit("read-pipe");

		return 0;
	} else {
		int shmid_from_child;
		if (read(pipe_fds[0], &shmid_from_child, sizeof(int)) != sizeof(int)) error_exit("read-pipe");
		char* shm_from_child;
		if ((shm_from_child = shmat(shmid_from_child, NULL, 0)) == (char*) -1) error_exit("shmat-parent-from-child");
		if (!(shm_from_child[0] == 'C' && shm_from_child[1] == 'Q')) failure_exit("wrong-memory-from-child");

		//  Tell child to exit.
		int dummy = 99;
		if (write(exit_pipes[1], &dummy, sizeof(int)) != sizeof(int)) error_exit("write-from-parent");

		int exit_status;
		if (wait(&exit_status) == -1) error_exit("wait");
		if (!(WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 0)) failure_exit("child-exit");

		if (!(shm[0] == '*' && shm[1] == '#')) failure_exit("wrong-parent-mem");
	}
}
