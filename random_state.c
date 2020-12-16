//
// Created by schrodinger on 12/16/20.
//
#include "random_state.h"
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>

atomic_size_t COUNTER = 0;

#if defined(_WIN32)
/*
#pragma comment (lib,"bcrypt.lib")
#include <windows.h>
#include <bcrypt.h>
static bool os_random_buf(void* buf, size_t buf_len) {
  return (BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)buf_len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) >= 0);
}
*/
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#define RtlGenRandom  SystemFunction036
#ifdef __cplusplus
extern "C" {
#endif
  BOOLEAN NTAPI RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#ifdef __cplusplus
}
#endif
static bool os_random_buf(void* buf, size_t buf_len) {
  kk_assert_internal(buf_len >= sizeof(uintptr_t));
  memset(buf, 0, buf_len);
  RtlGenRandom(buf, (ULONG)buf_len);
  return (((uintptr_t*)buf)[0] != 0);  // sanity check (but RtlGenRandom should never fail)
}
#elif defined(ANDROID) || defined(XP_DARWIN) || defined(__APPLE__) || defined(__DragonFly__) || \
      defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
      defined(__wasi__)
#include <stdlib.h>
static bool os_random_buf(void* buf, size_t buf_len) {
  arc4random_buf(buf, buf_len);
  return true;
}
#elif defined(__linux__)
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
static bool os_random_buf(void* buf, size_t buf_len) {
    // Modern Linux provides `getrandom` but different distributions either use `sys/random.h` or `linux/random.h`
    // and for the latter the actual `getrandom` call is not always defined.
    // (see <https://stackoverflow.com/questions/45237324/why-doesnt-getrandom-compile>)
    // We therefore use a syscall directly and fall back dynamically to /dev/urandom when needed.
#ifdef SYS_getrandom
#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK (1)
#endif
    static volatile uintptr_t no_getrandom; // = 0
    if (no_getrandom == 0) {
        ssize_t ret = syscall(SYS_getrandom, buf, buf_len, GRND_NONBLOCK);
        if (ret >= 0) return (buf_len == (size_t)ret);
        if (ret != ENOSYS) return false;
        no_getrandom = 1; // don't call again, and fall back to /dev/urandom
    }
#endif
    int flags = O_RDONLY;
#if defined(O_CLOEXEC)
    flags |= O_CLOEXEC;
#endif
    int fd = open("/dev/urandom", flags, 0);
    if (fd < 0) return false;
    size_t count = 0;
    while(count < buf_len) {
        ssize_t ret = read(fd, (char*)buf + count, buf_len - count);
        if (ret<=0) {
            if (errno!=EAGAIN && errno!=EINTR) break;
        }
        else {
            count += ret;
        }
    }
    close(fd);
    return (count==buf_len);
}
#else
static bool os_random_buf(void* buf, size_t buf_len) {
  return false;
}
#endif

static uint64_t * default_seeds() {
    // just simple init
    static uint64_t SEEDS[8];
    static atomic_flag VISITED;
    if (!atomic_flag_test_and_set_explicit(&VISITED, memory_order_acq_rel)) {
        os_random_buf(SEEDS, 8 * sizeof (uint64_t));
    }
    return SEEDS;
}

random_state_t new_state() {

}

random_state_t new_state_from_keys(uint64_t *a, uint64_t *b) {

}