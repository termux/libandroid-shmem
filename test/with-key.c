#include "utils.h"

int main() {
	int pipe_fds[2];
	if (pipe(pipe_fds) != 0) error_exit("pipe");

	key_t SHMEM_KEY = ftok(".", 22);

	pid_t child_pid = fork();
	if (child_pid == -1) {
		error_exit("fork");
	} else if (child_pid == 0) {
		int shmid;
		if (read(pipe_fds[0], &shmid, sizeof(int)) != sizeof(int)) error_exit("child-read");

		int shmid_from_shmget;
		if ((shmid_from_shmget = shmget(SHMEM_KEY, 30, IPC_CREAT | 0666)) < 0) error_exit("shmget");
		if (shmid_from_shmget != shmid) failure_exit("shmid-mismatch");

		struct shmid_ds buf;
		if (shmctl(shmid, IPC_STAT, &buf) == -1) error_exit("shmctl");
		if (buf.shm_perm.
#ifdef __APPLE__
				_key
#elif defined(__ANDROID__)
				key
#else
				__key
#endif
				!= SHMEM_KEY) failure_exit("wrong-shmctl-key");

		char* shm_child;
		if ((shm_child = shmat(shmid, NULL, 0)) == (char*) -1) error_exit("shmat-child");
		shm_child[0] = (shm_child[0] == 'a' && shm_child[1] == 'b') ? '*' : '!';
		if (shmdt(shm_child) != 0) error_exit("shmdt-child");
		if ((shm_child = shmat(shmid, NULL, 0)) == (char*) -1) error_exit("shmat-child-2");
		shm_child[1] = '#';
		if (shmdt(shm_child) != 0) error_exit("shmdt-child-2");
		return 0;
	} else {
		int shmid;
		if ((shmid = shmget(SHMEM_KEY, 30, IPC_CREAT | 0666)) < 0) error_exit("shmget");
		char* shm;
		if ((shm = shmat(shmid, NULL, 0)) == (char *) -1) error_exit("shmat");
		char* s = shm;
		for (char c = 'a'; c <= 'z'; c++) *s++ = c;

		if (write(pipe_fds[1], &shmid, sizeof(int)) != sizeof(int)) error_exit("write");

		int exit_status;
		if (wait(&exit_status) == -1) error_exit("wait");
		if (!(WIFEXITED(exit_status) && WEXITSTATUS(exit_status) == 0)) failure_exit("child-exit");
		if (!(shm[0] == '*' && shm[1] == '#')) failure_exit("wrong-parent-mem");
	}
}
