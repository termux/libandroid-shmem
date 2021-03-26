#include "utils.h"

int main() {
    key_t SHMEM_KEY = ftok(".", 23);

    int shmid_from_shmget;
    if ((shmid_from_shmget = shmget(SHMEM_KEY, 30, IPC_CREAT | 0666)) < 0) error_exit("shmget");
    if ((shmid_from_shmget = shmget(SHMEM_KEY, 30, IPC_CREAT | 0666)) < 0) error_exit("shmget");

    return 0;
}
