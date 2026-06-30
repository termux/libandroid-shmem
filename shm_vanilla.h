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

/** fork of https://android.googlesource.com/platform/bionic/+/02ce401d1e2b31586c94c8b6999364bbbce27388/libc/include/sys/shm.h */

#pragma once

#include <sys/cdefs.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/shm.h>

__BEGIN_DECLS

/** Not useful on normal Android; disallowed by SELinux. */
/** useful for partial Android userspace components running inside the unmodified kernel of a */
/** different operating system that doesn't have ashmem, ion, dma-buf or SELinux, */
/** for example using a container, or other method */

void* _Nonnull shmat_vanilla(int __shm_id, const void* _Nullable __addr, int __flags);
int shmctl_vanilla(int __shm_id, int __op, struct shmid64_ds* _Nullable __buf);
int shmdt_vanilla(const void* _Nonnull __addr);
int shmget_vanilla(key_t __key, size_t __size, int __flags);

__END_DECLS
