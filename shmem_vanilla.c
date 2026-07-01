/*
 * Copyright (C) 2016 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/** fork of https://android.googlesource.com/platform/bionic/+/02ce401d1e2b31586c94c8b6999364bbbce27388/libc/bionic/sys_shm.cpp */

#include <sys/syscall.h>
#include <unistd.h>

#include "shm_vanilla.h"

void* shmat_vanilla(int id, const void* address, int flags) {
  return (void*)(syscall(SYS_shmat, id, address, flags));
}

int shmctl_vanilla(int id, int cmd, struct shmid64_ds* buf) {
  // upstream bionic libc and also other libc implementations contain
  // this code that ORs cmd with IPC_64, but unfortunately, for some reason
  // in 32-bit termux-docker, an error always occurs during test-with-key
  // 'shmctl: Invalid argument' unless the ORing with IPC_64 is disabled.
  // when that is disabled, all tests pass. This result holds for both arm and i686
  // termux-docker running in both fully 32-bit kernels and the 32-bit mode of
  // 64-bit kernels.
#if 0
//#if !defined(__LP64__)
  // Annoyingly, the kernel requires this for 32-bit but rejects it for 64-bit.
  cmd |= IPC_64;
#endif
  return syscall(SYS_shmctl, id, cmd, buf);
}

int shmdt_vanilla(const void* address) {
  return syscall(SYS_shmdt, address);
}

int shmget_vanilla(key_t key, size_t size, int flags) {
  return syscall(SYS_shmget, key, size, flags);
}
