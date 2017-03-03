libandroid-shmem
================
System V shared memory (shmget, shmat, shmdt and shmctl) emulation
on Android using ashmem.

The shared memory segments it creates will be automatically destroyed
when the creating process destroys them or dies, which differs from
the System V shared memory behaviour.

Based on previous work in https://github.com/pelya/android-shmem.
