#ifndef _SYS_SHM_H
#define _SYS_SHM_H

#include <linux/shm.h>
#include <stdint.h>
#include <sys/types.h>

__BEGIN_DECLS

#ifndef shmid_ds
# define shmid_ds shmid64_ds
#endif

/* Shared memory control operations. */
extern int shmctl(int shmid, int cmd, struct shmid_ds* buf);

/* Get shared memory area identifier. */
extern int shmget(key_t key, size_t size, int shmflg);

/* Attach shared memory segment. */
extern void *shmat(int shmid, void const* shmaddr, int shmflg);

/* Detach shared memory segment. */
extern int shmdt(void const* shmaddr);

__END_DECLS

#endif
