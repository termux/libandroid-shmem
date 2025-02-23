#include <android/log.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <paths.h>

#define __u32 uint32_t
#include <linux/ashmem.h>

#include "shm.h"

#define DBG(...) __android_log_print(ANDROID_LOG_INFO, "shmem", __VA_ARGS__)
#define ASHV_KEY_SYMLINK_PATH _PATH_TMP "ashv_key_%d"
#define ANDROID_SHMEM_SOCKNAME "/dev/shm/%08x"
#define ANDROID_SHMEM_GLOBAL_SOCKNAME "/dev/shm/global"
#define ANDROID_SHMEM_GLOBAL_PROCNAME "global-shmem"
#define ROUND_UP(N, S) ((((N) + (S) - 1) / (S)) * (S))

// Action numbers
#define ASHV_PUT 0
#define ASHV_GET 1
#define ASHV_UPD 2
#define ASHV_RM 3
#define ASHV_AT 4
#define ASHV_DT 5

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

typedef struct {
	// The shmid (shared memory id) contains the socket address (16 bits)
	// and a local id (15 bits).
	int id;
	void *addr;
	int descriptor;
	size_t size;
	bool markedForDeletion;
	key_t key;
	int countAttach;
	pid_t *attachedPids;
	bool global;
} shmem_t;

static shmem_t* shmem = NULL;
static size_t shmem_amount = 0;

// The lower 16 bits of (getpid() + i), where i is a sequence number.
// It is unique among processes as it's only set when bound.
static int ashv_local_socket_id = 0;
// To handle forks we store which pid the ashv_local_socket_id was
// created for.
static int ashv_pid_setup = 0;
static pthread_t ashv_listening_thread_id = 0;
static int global_sendsock;
static bool global_conf = false;

static int ancil_send_fd(int sock, int fd)
{
	char nothing = '!';
	struct iovec nothing_ptr = { .iov_base = &nothing, .iov_len = 1 };

	struct {
		struct cmsghdr align;
		int fd[1];
	} ancillary_data_buffer;

	struct msghdr message_header = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &nothing_ptr,
		.msg_iovlen = 1,
		.msg_flags = 0,
		.msg_control = &ancillary_data_buffer,
		.msg_controllen = sizeof(struct cmsghdr) + sizeof(int)
	};

	struct cmsghdr* cmsg = CMSG_FIRSTHDR(&message_header);
	cmsg->cmsg_len = message_header.msg_controllen; // sizeof(int);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	((int*) CMSG_DATA(cmsg))[0] = fd;

	return sendmsg(sock, &message_header, 0) >= 0 ? 0 : -1;
}

static int ancil_recv_fd(int sock)
{
	char nothing = '!';
	struct iovec nothing_ptr = { .iov_base = &nothing, .iov_len = 1 };

	struct {
		struct cmsghdr align;
		int fd[1];
	} ancillary_data_buffer;

	struct msghdr message_header = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &nothing_ptr,
		.msg_iovlen = 1,
		.msg_flags = 0,
		.msg_control = &ancillary_data_buffer,
		.msg_controllen = sizeof(struct cmsghdr) + sizeof(int)
	};

	struct cmsghdr* cmsg = CMSG_FIRSTHDR(&message_header);
	cmsg->cmsg_len = message_header.msg_controllen;
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	((int*) CMSG_DATA(cmsg))[0] = -1;

	if (recvmsg(sock, &message_header, 0) < 0) return -1;

	return ((int*) CMSG_DATA(cmsg))[0];
}

static int ashmem_get_size_region(int fd)
{
	//int ret = __ashmem_is_ashmem(fd, 1);
	//if (ret < 0) return ret;
	return TEMP_FAILURE_RETRY(ioctl(fd, ASHMEM_GET_SIZE, NULL));
}

/*
 * From https://android.googlesource.com/platform/system/core/+/master/libcutils/ashmem-dev.c
 *
 * ashmem_create_region - creates a new named ashmem region and returns the file
 * descriptor, or <0 on error.
 *
 * `name' is the label to give the region (visible in /proc/pid/maps)
 * `size' is the size of the region, in page-aligned bytes
 */
static int ashmem_create_region(char const* name, size_t size)
{
	int fd = open("/dev/ashmem", O_RDWR);
	if (fd < 0) return fd;

	char name_buffer[ASHMEM_NAME_LEN] = {0};
	strncpy(name_buffer, name, sizeof(name_buffer));
	name_buffer[sizeof(name_buffer)-1] = 0;

	int ret = ioctl(fd, ASHMEM_SET_NAME, name_buffer);
	if (ret < 0) goto error;

	ret = ioctl(fd, ASHMEM_SET_SIZE, size);
	if (ret < 0) goto error;

	return fd;
error:
	close(fd);
	return ret;
}

static void ashv_check_pid()
{
	pid_t mypid = getpid();
	if (ashv_pid_setup == 0) {
		ashv_pid_setup = mypid;
	} else if (ashv_pid_setup != mypid) {
		DBG("%s: Cleaning to new pid=%d from oldpid=%d", __PRETTY_FUNCTION__, mypid, ashv_pid_setup);
		// We inherited old state across a fork.
		ashv_pid_setup = mypid;
		ashv_local_socket_id = 0;
		ashv_listening_thread_id = 0;
		shmem_amount = 0;
		// Unlock if fork left us with held lock from parent thread.
		pthread_mutex_unlock(&mutex);
		if (shmem != NULL) free(shmem);
		shmem = NULL;
	}
}


// Store index in the lower 15 bits and the socket id in the
// higher 16 bits.
static int ashv_shmid_from_counter(unsigned int counter)
{
	return ashv_local_socket_id * 0x10000 + counter;
}

static int ashv_socket_id_from_shmid(int shmid)
{
	return shmid / 0x10000;
}

static int ashv_find_local_index(int shmid)
{
	for (size_t i = 0; i < shmem_amount; i++) {
		if (shmem[i].id == shmid) {
			return i;
		}
	}
	return -1;
}

static int ashv_write_pids(int sendsock, int idx)
{
	if (shmem[idx].countAttach > 0) {
		pid_t pids[shmem[idx].countAttach];
		for (int i=0; i<shmem[idx].countAttach; i++) {
			pids[i] = shmem[idx].attachedPids[i];
		}
		if (write(sendsock, &pids, sizeof(pid_t)*shmem[idx].countAttach) != sizeof(pid_t)*shmem[idx].countAttach) {
			DBG("%s: ERROR: write pids failed: %s", __PRETTY_FUNCTION__, strerror(errno));
			return -1;
		}
	}
	return 0;
}

static int ashv_read_pids(int recvsock, int idx)
{
	if (shmem[idx].countAttach > 0) {
		pid_t pids[shmem[idx].countAttach];
		if (read(recvsock, &pids, sizeof(pid_t)*shmem[idx].countAttach) != sizeof(pid_t)*shmem[idx].countAttach) {
			DBG("%s: ERROR: read pids failed: %s", __PRETTY_FUNCTION__, strerror(errno));
			return -1;
		}
		shmem[idx].attachedPids = NULL;
		shmem[idx].attachedPids = realloc(shmem[idx].attachedPids, sizeof(pid_t)*shmem[idx].countAttach);
		for (int i=0; i<shmem[idx].countAttach; i++) {
			shmem[idx].attachedPids[i] = pids[i];
		}
	} else {
		shmem[idx].attachedPids = NULL;
	}
	return 0;
}

static void android_shmem_attach_pid(int idx, pid_t pid)
{
	int idp = shmem[idx].countAttach;
	shmem[idx].countAttach++;
	shmem[idx].attachedPids = realloc(shmem[idx].attachedPids, shmem[idx].countAttach*sizeof(pid_t));
	shmem[idx].attachedPids[idp] = pid;
}

static void android_shmem_detach_pid(int idx, pid_t pid)
{
	for (int i=0; i<shmem[idx].countAttach; i++) {
		if (shmem[idx].attachedPids[i] == pid) {
			shmem[idx].countAttach--;
			memmove(&shmem[idx].attachedPids[i], &shmem[idx].attachedPids[i+1], (shmem[idx].countAttach-i)*sizeof(pid_t));
			break;
		}
	}
}

static void android_shmem_check_pids(int idx)
{
	for (int i=0; i<shmem[idx].countAttach; i++) {
		if (kill(shmem[idx].attachedPids[i], 0) != 0) {
			DBG ("%s: process %d not found, removed from list", __PRETTY_FUNCTION__, shmem[idx].attachedPids[i]);
			shmem[idx].countAttach--;
			memmove(&shmem[idx].attachedPids[i], &shmem[idx].attachedPids[i+1], (shmem[idx].countAttach-i)*sizeof(pid_t));
			i--;
		}
	}
}

static void android_shmem_delete(int idx)
{
	if (shmem[idx].descriptor) close(shmem[idx].descriptor);
	shmem_amount--;
	memmove(&shmem[idx], &shmem[idx+1], (shmem_amount - idx) * sizeof(shmem_t));
}

static void ashv_delete_segment(int idx)
{
	shmem[idx].markedForDeletion = true;
	if (shmem[idx].countAttach == 0) {
		android_shmem_delete(idx);
	}
}

static void* ashv_thread_function(void* arg)
{
	int sock = *(int*)arg;
	free(arg);
	struct sockaddr_un addr;
	socklen_t len = sizeof(addr);
	int sendsock;
	DBG("%s: thread started", __PRETTY_FUNCTION__);
	while ((sendsock = accept(sock, (struct sockaddr *)&addr, &len)) != -1) {
		int shmid;
		if (recv(sendsock, &shmid, sizeof(shmid), 0) != sizeof(shmid)) {
			DBG("%s: ERROR: recv() returned not %zu bytes", __PRETTY_FUNCTION__, sizeof(shmid));
			close(sendsock);
			continue;
		}
		if (!global_conf) {
			pthread_mutex_lock(&mutex);
		}
		int idx = ashv_find_local_index(shmid);
		if (idx != -1) {
			if (write(sendsock, &shmem[idx].key, sizeof(key_t)) != sizeof(key_t)) {
				DBG("%s: ERROR: write failed: %s", __PRETTY_FUNCTION__, strerror(errno));
			}
			if (ancil_send_fd(sendsock, shmem[idx].descriptor) != 0) {
				DBG("%s: ERROR: ancil_send_fd() failed: %s", __PRETTY_FUNCTION__, strerror(errno));
			}
		} else {
			DBG("%s: ERROR: cannot find shmid 0x%x", __PRETTY_FUNCTION__, shmid);
		}
		if (!global_conf) {
			pthread_mutex_unlock(&mutex);
		}
		close(sendsock);
		len = sizeof(addr);
	}
	DBG ("%s: ERROR: listen() failed, thread stopped", __PRETTY_FUNCTION__);
	return NULL;
}

static int ashv_put_remote_segment(int shmid)
{
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	sprintf(&addr.sun_path[1], ANDROID_SHMEM_SOCKNAME, ashv_socket_id_from_shmid(shmid));
	int addrlen = sizeof(addr.sun_family) + strlen(&addr.sun_path[1]) + 1;

	int recvsock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (recvsock == -1) {
		DBG ("%s: cannot create UNIX socket: %s", __PRETTY_FUNCTION__, strerror(errno));
		return -1;
	}
	if (connect(recvsock, (struct sockaddr*) &addr, addrlen) != 0) {
		DBG("%s: Cannot connect to UNIX socket %s: %s, len %d", __PRETTY_FUNCTION__, addr.sun_path + 1, strerror(errno), addrlen);
		goto error_close;
	}

	if (send(recvsock, &shmid, sizeof(shmid), 0) != sizeof(shmid)) {
		DBG ("%s: send() failed on socket %s: %s", __PRETTY_FUNCTION__, addr.sun_path + 1, strerror(errno));
		goto error_close;
	}

	key_t key;
	if (read(recvsock, &key, sizeof(key_t)) != sizeof(key_t)) {
		DBG("%s: ERROR: failed read", __PRETTY_FUNCTION__);
		goto error_close;
	}

	int descriptor = ancil_recv_fd(recvsock);
	if (descriptor < 0) {
		DBG("%s: ERROR: ancil_recv_fd() failed on socket %s: %s", __PRETTY_FUNCTION__, addr.sun_path + 1, strerror(errno));
		goto error_close;
	}
	close(recvsock);

	int size = ashmem_get_size_region(descriptor);
	if (size == 0 || size == -1) {
		DBG ("%s: ERROR: ashmem_get_size_region() returned %d on socket %s: %s", __PRETTY_FUNCTION__, size, addr.sun_path + 1, strerror(errno));
		return -1;
	}

	int idx = shmem_amount;
	shmem_amount ++;
	shmem = realloc(shmem, shmem_amount * sizeof(shmem_t));
	shmem[idx].id = shmid;
	shmem[idx].descriptor = descriptor;
	shmem[idx].size = size;
	shmem[idx].addr = NULL;
	shmem[idx].markedForDeletion = false;
	shmem[idx].key = key;
	shmem[idx].countAttach = 0;
        shmem[idx].global = false;
	return idx;
error_close:
	close(recvsock);
	return -1;
}

static void* ashv_thread_check_pids(void* arg) {
	(void) arg;
	while (true) {
		pthread_mutex_lock(&mutex);
		for (size_t i=0; i<shmem_amount; i++) {
			android_shmem_check_pids(i);
			if (shmem[i].markedForDeletion && shmem[i].countAttach == 0) {
				android_shmem_delete(i);
			}
		}
		if (shmem_amount == 0) {
			close(global_sendsock);
			exit(0);
		}
		pthread_mutex_unlock(&mutex);
	}
}

#define GSOCKET_ASHV_WRITE(type, var) \
	if (write(global_sendsock, &shmem[idx].var, sizeof(type)) != sizeof(type)) { \
		DBG("%s: ERROR: write %s failed: %s", __PRETTY_FUNCTION__, #var, strerror(errno)); \
		break; \
	}

#define GSOCKET_ASHV_READ(type, var) \
	if (read(global_sendsock, &var, sizeof(type)) != sizeof(type)) { \
		DBG("%s: ERROR: read %s failed: %s", __PRETTY_FUNCTION__, #var, strerror(errno)); \
		break; \
	}

static int ashv_fork_function()
{
	pid_t p = fork();
	if (p < 0) {
		DBG("%s: ERROR: fork() failed", __PRETTY_FUNCTION__);
		return -1;
	}

	if (p == 0) {
		signal(SIGINT, SIG_IGN);
		signal(SIGPIPE, SIG_IGN);
	} else {
		int ret = -1;
		int size = strlen(ANDROID_SHMEM_GLOBAL_PROCNAME);
		char path_comm[32];
		sprintf(path_comm, "/proc/%d/comm", p);
		while (kill(p, 0) == 0) {
			int cf = open(path_comm, O_RDONLY);
			if (cf == -1) {
				break;
			}
			char* comm = malloc(size*sizeof(char));
			if (read(cf, comm, size) != -1 && strcmp(comm, ANDROID_SHMEM_GLOBAL_PROCNAME) == 0) {
				ret = 0;
				break;
			}
			free(comm);
			close(cf);
		}
		if (ret == 0) {
			DBG("%s: fork() successfully started", __PRETTY_FUNCTION__);
		} else {
			DBG("%s: fork() failed to start global socket", __PRETTY_FUNCTION__);
		}
		return ret;
	}

	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (!sock) {
		DBG("%s: cannot create UNIX socket: %s", __PRETTY_FUNCTION__, strerror(errno));
		exit(1);
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	sprintf(&addr.sun_path[1], ANDROID_SHMEM_GLOBAL_SOCKNAME);

	if (bind(sock, (struct sockaddr *)&addr, sizeof(addr.sun_family)+strlen(&addr.sun_path[1])+1) != 0) {
		DBG("%s: cannot bind UNIX socket", __PRETTY_FUNCTION__);
		exit(1);
	}

	if (listen(sock, 4) != 0) {
		DBG("%s: listen failed", __PRETTY_FUNCTION__);
		exit(1);
	}

	pthread_mutex_unlock(&mutex);
	pthread_t ptid;
	pthread_create(&ptid, NULL, &ashv_thread_check_pids, NULL);
	pthread_setname_np(pthread_self(), ANDROID_SHMEM_GLOBAL_PROCNAME);

	struct sockaddr_un accept_addr;
	socklen_t len = sizeof(accept_addr);
	while ((global_sendsock=accept(sock, (struct sockaddr *)&accept_addr, &len)) != -1) {
		int action;
		if (recv(global_sendsock, &action, sizeof(action), 0) != sizeof(action)) {
			DBG("%s: ERROR: recv() returned not %zu action bytes", __PRETTY_FUNCTION__, sizeof(action));
			close(global_sendsock);
			continue;
		}
		int shmid;
		if (recv(global_sendsock, &shmid, sizeof(shmid), 0) != sizeof(shmid)) {
			DBG("%s: ERROR: recv() returned not %zu shmid bytes", __PRETTY_FUNCTION__, sizeof(shmid));
			close(global_sendsock);
			continue;
		}

		pthread_mutex_lock(&mutex);
		int status = -1;
		int idx = ashv_find_local_index(shmid);
		if (idx != -1 || action == ASHV_PUT) {
			pid_t pid;
			switch (action) {
			case ASHV_PUT:
				DBG("%s: action ASHV_PUT(%d) for %d", __PRETTY_FUNCTION__, action, shmid);
				if (idx == -1 && ashv_put_remote_segment(shmid) == -1) {
					DBG("%s: ERROR: failed to get remote shm %d", __PRETTY_FUNCTION__, shmid);
					break;
				}
				status = 0;
				break;
			case ASHV_GET:
				DBG("%s: action ASHV_GET(%d) for %d", __PRETTY_FUNCTION__, action, shmid);
				GSOCKET_ASHV_WRITE(key_t, key)
				GSOCKET_ASHV_WRITE(bool, markedForDeletion)
				GSOCKET_ASHV_WRITE(int, countAttach)
				if (ancil_send_fd(global_sendsock, shmem[idx].descriptor) != 0) {
					DBG("%s: ERROR: ancil_send_fd() failed: %s", __PRETTY_FUNCTION__, strerror(errno));
					break;
				}
				status = 0;
				break;
			case ASHV_UPD:
				DBG("%s: action ASHV_UPD(%d) for %d", __PRETTY_FUNCTION__, action, shmid);
				GSOCKET_ASHV_WRITE(bool, markedForDeletion)
				android_shmem_check_pids(idx);
				GSOCKET_ASHV_WRITE(int, countAttach)
				status = ashv_write_pids(global_sendsock, idx);
				break;
			case ASHV_RM:
				DBG("%s: action ASHV_RM(%d) for %d", __PRETTY_FUNCTION__, action, shmid);
				ashv_delete_segment(idx);
				status = 0;
				break;
			case ASHV_AT:
				DBG("%s: action ASHV_AT(%d) for %d", __PRETTY_FUNCTION__, action, shmid);
				GSOCKET_ASHV_READ(pid_t, pid)
				android_shmem_attach_pid(idx, pid);
				status = 0;
				break;
			case ASHV_DT:
				DBG("%s: action ASHV_DT(%d) for %d", __PRETTY_FUNCTION__, action, shmid);
				GSOCKET_ASHV_READ(pid_t, pid)
				android_shmem_detach_pid(idx, pid);
				status = 0;
				break;
			default:
				DBG("%s: ERROR: unknown action %d", __PRETTY_FUNCTION__, action);
				break;
			}
		} else {
			DBG("%s: ERROR: cannot find shmid 0x%x", __PRETTY_FUNCTION__, shmid);
		}
		if (write(global_sendsock, &status, sizeof(int)) != sizeof(int)) {
			DBG("%s: ERROR: write status failed: %s", __PRETTY_FUNCTION__, strerror(errno));
		}
		pthread_mutex_unlock(&mutex);

		close(global_sendsock);
		len = sizeof(accept_addr);
	}

	DBG ("%s: ERROR: listen() failed, fork stopped", __PRETTY_FUNCTION__);
	exit(1);
}

static int ashv_connect_gsocket(struct sockaddr_un *addr, int action, int shmid)
{
	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	sprintf(&addr->sun_path[1], ANDROID_SHMEM_GLOBAL_SOCKNAME);
	int addrlen = sizeof(addr->sun_family) + strlen(&addr->sun_path[1]) + 1;

	int gsock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (gsock == -1) {
		DBG ("%s: cannot create UNIX socket: %s", __PRETTY_FUNCTION__, strerror(errno));
		return -1;
	}
	if (connect(gsock, (struct sockaddr*)addr, addrlen) != 0) {
		DBG("%s: Cannot connect to UNIX socket %s: %s, len %d", __PRETTY_FUNCTION__, addr->sun_path + 1, strerror(errno), addrlen);
		goto close;
	}

	if (send(gsock, &action, sizeof(action), 0) != sizeof(action)) {
		DBG("%s: send acction failed on socket %s: %s", __PRETTY_FUNCTION__, addr->sun_path + 1, strerror(errno));
		goto close;
	}
	if (send(gsock, &shmid, sizeof(shmid), 0) != sizeof(shmid)) {
		DBG("%s: send shmid failed on socket %s: %s", __PRETTY_FUNCTION__, addr->sun_path + 1, strerror(errno));
		goto close;
	}

	global_conf = true;
	return gsock;
close:
	close(gsock);
	return -1;
}

static int ashv_status_gsocket(int gsock) {
	int status;
	if (read(gsock, &status, sizeof(int)) != sizeof(int)) {
		DBG("%s: ERROR: read status failed", __PRETTY_FUNCTION__);
		status = -1;
	}
	close(gsock);
	global_conf = false;
	return status;
}

static int ashv_one_action_gsocket(int action, int shmid)
{
	struct sockaddr_un addr;
	int gsock = ashv_connect_gsocket(&addr, action, shmid);
	if (gsock == -1) {
		return -1;
	}

	return ashv_status_gsocket(gsock);
}

static int ashv_send_pid_gsocket(int action, int shmid)
{
	struct sockaddr_un addr;
	int gsock = ashv_connect_gsocket(&addr, action, shmid);
	if (gsock == -1) {
		return -1;
	}

	if (write(gsock, &ashv_pid_setup, sizeof(pid_t)) != sizeof(pid_t)) {
		DBG("%s: ERROR: write pid failed", __PRETTY_FUNCTION__);
		close(gsock);
		return -1;
        }

	return ashv_status_gsocket(gsock);
}

#define ASHV_READ_GSOCK(type, var) \
	type var; \
	if (read(gsock, &var, sizeof(type)) != sizeof(type)) { \
		DBG("%s: ERROR: read %s failed", __PRETTY_FUNCTION__, #var); \
		goto error_close; \
	}

static int ashv_get_shm_gsocket(int shmid)
{
	struct sockaddr_un addr;
	int gsock = ashv_connect_gsocket(&addr, ASHV_GET, shmid);
	if (gsock == -1) {
		return -1;
	}

	ASHV_READ_GSOCK(key_t, key)
	ASHV_READ_GSOCK(bool, markedForDeletion)
	ASHV_READ_GSOCK(int, countAttach)

	if (markedForDeletion && countAttach == 0) {
		DBG("%s: shmid %d is marked for deletion so it is not passed", __PRETTY_FUNCTION__, shmid);
		goto error_close;
	}

	int descriptor = ancil_recv_fd(gsock);
	if (descriptor < 0) {
		DBG("%s: ERROR: ancil_recv_fd() failed on socket %s: %s", __PRETTY_FUNCTION__, addr.sun_path + 1, strerror(errno));
		goto error_close;
	}
	global_conf = false;
	close(gsock);

	int size = ashmem_get_size_region(descriptor);
	if (size == 0 || size == -1) {
		DBG ("%s: ERROR: ashmem_get_size_region() returned %d on socket %s: %s", __PRETTY_FUNCTION__, size, addr.sun_path + 1, strerror(errno));
		return -1;
	}

	int idx = shmem_amount;
	shmem_amount ++;
	shmem = realloc(shmem, shmem_amount * sizeof(shmem_t));
	shmem[idx].id = shmid;
	shmem[idx].descriptor = descriptor;
	shmem[idx].size = size;
	shmem[idx].addr = NULL;
	shmem[idx].markedForDeletion = markedForDeletion;
	shmem[idx].key = key;
	shmem[idx].countAttach = countAttach;
	shmem[idx].global = true;
	return idx;
error_close:
	global_conf = false;
	close(gsock);
	return -1;
}

static int ashv_update_shm_gsocket(int idx)
{
	int shmid = shmem[idx].id;
	struct sockaddr_un addr;
	int gsock = ashv_connect_gsocket(&addr, ASHV_UPD, shmid);
	if (gsock == -1) {
		goto removal;
	}

	if (read(gsock, &shmem[idx].markedForDeletion, sizeof(bool)) != sizeof(bool)) {
		close(gsock);
		goto removal;
	}

	if (read(gsock, &shmem[idx].countAttach, sizeof(int)) != sizeof(int)) {
		close(gsock);
		goto removal;
	}

	if (ashv_read_pids(gsock, idx) != 0) {
		close(gsock);
		goto removal;
	}

	return ashv_status_gsocket(gsock);
removal:
	DBG("%s: gsocket returned an error, shm %d will have a delete mark", __PRETTY_FUNCTION__, shmid);
	shmem[idx].countAttach = 0;
	shmem[idx].markedForDeletion = true;
	shmem[idx].global = false;
	shmem[idx].attachedPids = NULL;
	if (shmem[idx].addr != NULL) {
		android_shmem_attach_pid(idx, ashv_pid_setup);
	}
	return -1;
}

#define FIND_SHMEM \
	int idx = ashv_find_local_index(shmid); \
	if (idx == -1 && (idx = ashv_get_shm_gsocket(shmid)) == -1 && ashv_socket_id_from_shmid(shmid) != ashv_local_socket_id) { \
		idx = ashv_put_remote_segment(shmid); \
	}

/* Get shared memory area identifier. */
int shmget(key_t key, size_t size, int flags)
{
	ashv_check_pid();

	// Counter wrapping around at 15 bits.
	static size_t shmem_counter = 0;

	if (!ashv_listening_thread_id) {
		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		if (!sock) {
			DBG ("%s: cannot create UNIX socket: %s", __PRETTY_FUNCTION__, strerror(errno));
			errno = EINVAL;
			return -1;
		}
		int i;
		for (i = 0; i < 4096; i++) {
			struct sockaddr_un addr;
			int len;
			memset (&addr, 0, sizeof(addr));
			addr.sun_family = AF_UNIX;
			ashv_local_socket_id = (getpid() + i) & 0xffff;
			sprintf(&addr.sun_path[1], ANDROID_SHMEM_SOCKNAME, ashv_local_socket_id);
			len = sizeof(addr.sun_family) + strlen(&addr.sun_path[1]) + 1;
			if (bind(sock, (struct sockaddr *)&addr, len) != 0) continue;
			DBG("%s: bound UNIX socket %s in pid=%d", __PRETTY_FUNCTION__, addr.sun_path + 1, getpid());
			break;
		}
		if (i == 4096) {
			DBG("%s: cannot bind UNIX socket, bailing out", __PRETTY_FUNCTION__);
			ashv_local_socket_id = 0;
			errno = ENOMEM;
			return -1;
		}
		if (listen(sock, 4) != 0) {
			DBG("%s: listen failed", __PRETTY_FUNCTION__);
			errno = ENOMEM;
			return -1;
		}
		int* socket_arg = malloc(sizeof(int));
		*socket_arg = sock;
		pthread_create(&ashv_listening_thread_id, NULL, &ashv_thread_function, socket_arg);
	}

	int shmid = -1;

	pthread_mutex_lock(&mutex);
	char symlink_path[256];
	if (key != IPC_PRIVATE) {
		// (1) Check if symlink exists telling us where to connect.
		// (2) If so, try to connect and open.
		// (3) If connected and opened, done. If connection refused
		//     take ownership of the key and create the symlink.
		// (4) If no symlink, create it.
		sprintf(symlink_path, ASHV_KEY_SYMLINK_PATH, key);
		char path_buffer[256];
		char num_buffer[64];
		while (true) {
			int path_length = readlink(symlink_path, path_buffer, sizeof(path_buffer) - 1);
			if (path_length != -1) {
				path_buffer[path_length] = '\0';
				int shmid = atoi(path_buffer);
				if (shmid != 0) {
					FIND_SHMEM
					if (idx != -1 && shmem[idx].global) {
						ashv_update_shm_gsocket(idx);
						if (shmem[idx].markedForDeletion && shmem[idx].countAttach == 0) {
							android_shmem_delete(idx);
							idx = -1;
						}
					}

					if (idx != -1) {
						if (flags & IPC_CREAT && flags & IPC_EXCL) {
							DBG("%s: shm with key %d should be created but it already exists (IPC_CREAT+IPC_EXCL)", __PRETTY_FUNCTION__, key);
							errno = EEXIST;
							pthread_mutex_unlock(&mutex);
							return -1;
						}
						pthread_mutex_unlock(&mutex);
						return shmem[idx].id;
					}
				}
				// TODO: Not sure we should try to remove previous owner if e.g.
				// there was a tempporary failture to get a soket. Need to
				// distinguish between why ashv_read_remote_segment failed.
				unlink(symlink_path);
			}
			// Take ownership.
			// TODO: HAndle error (out of resouces, no infinite loop)
			if (shmid == -1) {
				shmem_counter = (shmem_counter + 1) & 0x7fff;
				shmid = ashv_shmid_from_counter(shmem_counter);
				sprintf(num_buffer, "%d", shmid);
			}
			if (symlink(num_buffer, symlink_path) == 0) break;
		}

		if (!(flags & IPC_CREAT)) {
			DBG("%s: shm with key %d was not found and no command was given to create it (no IPC_CREAT)", __PRETTY_FUNCTION__, key);
			errno = ENOENT;
			pthread_mutex_unlock(&mutex);
			return -1;
		}
	}


	int idx = shmem_amount;
	char buf[256];
	sprintf(buf, ANDROID_SHMEM_SOCKNAME "-%d", ashv_local_socket_id, idx);
	size = ROUND_UP(size, getpagesize());
	int descriptor = ashmem_create_region(buf, size);
	if (descriptor < 0) {
		DBG("%s: ashmem_create_region() failed for size %zu: %s", __PRETTY_FUNCTION__, size, strerror(errno));
		pthread_mutex_unlock(&mutex);
		return -1;
	}

	shmem_amount++;
	if (shmid == -1) {
		shmem_counter = (shmem_counter + 1) & 0x7fff;
		shmid = ashv_shmid_from_counter(shmem_counter);
	}

	shmem = realloc(shmem, shmem_amount * sizeof(shmem_t));
	shmem[idx].size = size;
	shmem[idx].descriptor = descriptor;
	shmem[idx].addr = NULL;
	shmem[idx].id = shmid;
	shmem[idx].markedForDeletion = false;
	shmem[idx].key = key;
	shmem[idx].countAttach = 0;
	shmem[idx].attachedPids = NULL;
	shmem[idx].global = false;
	if (ashv_one_action_gsocket(ASHV_PUT, shmid) == 0 || ashv_fork_function() == 0) {
		shmem[idx].global = true;
	}

	//DBG("%s: ID %d shmid %x FD %d size %zu", __PRETTY_FUNCTION__, idx, shmid, shmem[idx].descriptor, shmem[idx].size);
	/*
	status = ashmem_set_prot_region (shmem[idx].descriptor, 0666);
	if (status < 0) {
		DBG ("%s: ashmem_set_prot_region() failed for size %zu: %s %d", __PRETTY_FUNCTION__, size, strerror(status), status);
		shmem_amount --;
		shmem = realloc (shmem, shmem_amount * sizeof(shmem_t));
		pthread_mutex_unlock (&mutex);
		return -1;
	}
	*/
	/*
	status = ashmem_pin_region (shmem[idx].descriptor, 0, shmem[idx].size);
	if (status < 0) {
		DBG ("%s: ashmem_pin_region() failed for size %zu: %s %d", __PRETTY_FUNCTION__, size, strerror(status), status);
		shmem_amount --;
		shmem = realloc (shmem, shmem_amount * sizeof(shmem_t));
		pthread_mutex_unlock (&mutex);
		return -1;
	}
	*/
	pthread_mutex_unlock(&mutex);

	return shmid;
}

#define INIT_SHMEM(ret_err) \
	FIND_SHMEM \
	if (idx == -1) { \
		DBG ("%s: ERROR: shmid %x does not exist\n", __PRETTY_FUNCTION__, shmid); \
		pthread_mutex_unlock(&mutex); \
		errno = EINVAL; \
		return ret_err; \
	} \
	if (shmem[idx].global) { \
		ashv_update_shm_gsocket(idx); \
	} \
	if (shmem[idx].markedForDeletion && shmem[idx].countAttach == 0) { \
		DBG ("%s: shmid %d marked for deletion, it will be deleted\n", __PRETTY_FUNCTION__, shmid); \
		android_shmem_delete(idx); \
		pthread_mutex_unlock(&mutex); \
		errno = EINVAL; \
		return ret_err; \
	}

/* Attach shared memory segment. */
void* shmat(int shmid, void const* shmaddr, int shmflg)
{
	ashv_check_pid();

	void *addr;

	pthread_mutex_lock(&mutex);

	INIT_SHMEM((void*)-1)

	if (shmem[idx].addr == NULL) {
		if (shmem[idx].global) {
			ashv_send_pid_gsocket(ASHV_AT, shmid);
		}
		android_shmem_attach_pid(idx, ashv_pid_setup);
		shmem[idx].addr = mmap((void*) shmaddr, shmem[idx].size, PROT_READ | (shmflg == 0 ? PROT_WRITE : 0), MAP_SHARED, shmem[idx].descriptor, 0);
		if (shmem[idx].addr == MAP_FAILED) {
			DBG ("%s: mmap() failed for ID %x FD %d: %s", __PRETTY_FUNCTION__, idx, shmem[idx].descriptor, strerror(errno));
			shmem[idx].addr = NULL;
		}
	}
	addr = shmem[idx].addr;
	DBG ("%s: mapped addr %p for FD %d ID %d", __PRETTY_FUNCTION__, addr, shmem[idx].descriptor, idx);
	pthread_mutex_unlock (&mutex);

	return addr ? addr : (void *)-1;
}

/* Detach shared memory segment. */
int shmdt(void const* shmaddr)
{
	ashv_check_pid();

	pthread_mutex_lock(&mutex);
	for (size_t i = 0; i < shmem_amount; i++)
		if (shmem[i].addr == shmaddr) {
			if (munmap(shmem[i].addr, shmem[i].size) != 0) {
				DBG("%s: munmap %p failed", __PRETTY_FUNCTION__, shmaddr);
			}
			shmem[i].addr = NULL;
			DBG("%s: unmapped addr %p for FD %d ID %zu shmid %x", __PRETTY_FUNCTION__, shmaddr, shmem[i].descriptor, i, shmem[i].id);

			if (shmem[i].global) {
				ashv_update_shm_gsocket(i);
				ashv_send_pid_gsocket(ASHV_DT, shmem[i].id);
			}
			android_shmem_detach_pid(i, ashv_pid_setup);

			if (shmem[i].markedForDeletion && shmem[i].countAttach == 0) {
				DBG ("%s: deleting shmid %x", __PRETTY_FUNCTION__, shmem[i].id);
				if (shmem[i].global) {
					ashv_one_action_gsocket(ASHV_RM, shmem[i].id);
				}
				android_shmem_delete(i);
			}
			pthread_mutex_unlock(&mutex);
			return 0;
	}
	pthread_mutex_unlock(&mutex);

	DBG("%s: invalid address %p", __PRETTY_FUNCTION__, shmaddr);
	/* Could be a remove segment, do not report an error for that. */
	return 0;
}

/* Let PRoot attach shared memory segment to another process. */
int libandroid_shmat_fd(int shmid, size_t* out_size)
{
	ashv_check_pid();

	int fd;

	pthread_mutex_lock(&mutex);

	INIT_SHMEM(-1)

	if (shmem[idx].global) {
		ashv_send_pid_gsocket(ASHV_AT, shmid);
	}

	fd = shmem[idx].descriptor;
	*out_size = shmem[idx].size;
	DBG ("%s: mapped for FD %d ID %d", __PRETTY_FUNCTION__, shmem[idx].descriptor, idx);
	pthread_mutex_unlock (&mutex);

	return fd;
}

/* Let PRoot detach shared memory segment after last process detached. */
int libandroid_shmdt_fd(int fd)
{
	ashv_check_pid();

	pthread_mutex_lock(&mutex);
	for (size_t i = 0; i < shmem_amount; i++) {
		if (shmem[i].descriptor == fd) {
			DBG("%s: unmapped for FD %d ID %zu shmid %x", __PRETTY_FUNCTION__, shmem[i].descriptor, i, shmem[i].id);
			if (shmem[i].global) {
				ashv_update_shm_gsocket(i);
				ashv_send_pid_gsocket(ASHV_DT, shmem[i].id);
			}
			android_shmem_detach_pid(i, ashv_pid_setup);

			if (shmem[i].markedForDeletion && shmem[i].countAttach == 0) {
				DBG ("%s: deleting shmid %x", __PRETTY_FUNCTION__, shmem[i].id);
				if (shmem[i].global) {
					ashv_one_action_gsocket(ASHV_RM, shmem[i].id);
				}
				android_shmem_delete(i);
			}
			pthread_mutex_unlock(&mutex);
			return 0;
		}
	}
	pthread_mutex_unlock(&mutex);

	DBG("%s: invalid fd %d", __PRETTY_FUNCTION__, fd);
	/* Could be a remove segment, do not report an error for that. */
	return 0;
}

/* Shared memory control operation. */
int shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
	ashv_check_pid();

	pthread_mutex_lock(&mutex);

	INIT_SHMEM(-1)

	switch (cmd) {
	case IPC_RMID:
		DBG("%s: IPC_RMID for shmid=%x", __PRETTY_FUNCTION__, shmid);

		if (shmem[idx].global) {
			ashv_one_action_gsocket(ASHV_RM, shmid);
		}
		ashv_delete_segment(idx);

		goto ok;
	case SHM_STAT:
	case SHM_STAT_ANY:
	case IPC_STAT:
		if (!buf) {
			DBG ("%s: ERROR: buf == NULL for shmid %x", __PRETTY_FUNCTION__, shmid);
			goto error;
		}

		/* Report max permissive mode */
		memset(buf, 0, sizeof(struct shmid_ds));
		buf->shm_segsz = shmem[idx].size;
		buf->shm_nattch = shmem[idx].countAttach;
		buf->shm_perm.key = shmem[idx].key;
		buf->shm_perm.uid = geteuid();
		buf->shm_perm.gid = getegid();
		buf->shm_perm.cuid = geteuid();
		buf->shm_perm.cgid = getegid();
		buf->shm_perm.mode = 0666;
		buf->shm_perm.seq = 1;

		goto ok;
	default:
		DBG("%s: cmd %d not implemented yet!", __PRETTY_FUNCTION__, cmd);
		goto error;
	}
ok:
	pthread_mutex_unlock (&mutex);
	return 0;
error:
	pthread_mutex_unlock (&mutex);
	errno = EINVAL;
	return -1;
}

/* Make alias for use with e.g. dlopen() */
#undef shmctl
int shmctl(int shmid, int cmd, struct shmid_ds *buf) __attribute__((alias("libandroid_shmctl")));
#undef shmget
int shmget(key_t key, size_t size, int flags) __attribute__((alias("libandroid_shmget")));
#undef shmat
void* shmat(int shmid, void const* shmaddr, int shmflg) __attribute__((alias("libandroid_shmat")));
#undef shmdt
int shmdt(void const* shmaddr) __attribute__((alias("libandroid_shmdt")));
