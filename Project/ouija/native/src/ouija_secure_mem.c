/*
 * OUIJA Native Security Core (C99 / POSIX)
 * Process hardening, memory locking (mlock), anti-dumping, and entropy harvesting.
 */

#define _GNU_SOURCE
#include "../include/ouija_core.h"
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

/**
 * Harden the current process against memory inspection, ptrace, and core dumps.
 * Returns 0 on success, or negative errno.
 */
int ouija_harden_process(void) {
    int ret = 0;

    /* Disable core dumps */
    struct rlimit rl = {0, 0};
    if (setrlimit(RLIMIT_CORE, &rl) != 0) {
        ret = -errno;
    }

    /* Disable process ptrace/dumpable flag on Linux */
#ifdef PR_SET_DUMPABLE
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0) {
        ret = -errno;
    }
#endif

    /* Prevent ptracing from child/unrelated processes if YAMA is enabled */
#ifdef PR_SET_PTRACER
    prctl(PR_SET_PTRACER, 0, 0, 0, 0);
#endif

    return ret;
}

/**
 * Lock virtual memory pages into physical RAM to prevent swapping to disk.
 */
int ouija_lock_memory(void *addr, size_t len) {
    if (!addr || len == 0) return 0;
    if (mlock(addr, len) != 0) {
        return -errno;
    }
    return 0;
}

/**
 * Unlock virtual memory pages.
 */
int ouija_unlock_memory(void *addr, size_t len) {
    if (!addr || len == 0) return 0;
    if (munlock(addr, len) != 0) {
        return -errno;
    }
    return 0;
}

/**
 * Allocate a secure locked memory page, zeroized and protected.
 */
void *ouija_secure_alloc(size_t len) {
    if (len == 0) return NULL;

    /* Use mmap with anonymous private memory */
    void *ptr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        return NULL;
    }

    /* Lock the memory in RAM (ignore mlock failure if unprivileged, but log) */
    mlock(ptr, len);

    /* Advise the kernel not to include this region in core dumps if possible */
#ifdef MADV_DONTDUMP
    madvise(ptr, len, MADV_DONTDUMP);
#endif

    /* Zero memory via assembly routine */
    ouija_secure_memzero_asm(ptr, len);

    return ptr;
}

/**
 * Securely zero and deallocate a locked memory page.
 */
void ouija_secure_free(void *ptr, size_t len) {
    if (!ptr || len == 0) return;

    /* Explicit zeroization via ASM memory barrier */
    ouija_secure_memzero_asm(ptr, len);

    /* Unlock memory */
    munlock(ptr, len);

    /* Unmap memory page */
    munmap(ptr, len);
}

/**
 * Harvest secure cryptographic entropy from Linux getrandom(2) syscall.
 */
int ouija_secure_random(uint8_t *buf, size_t len) {
    if (!buf || len == 0) return 0;

    size_t total = 0;
    while (total < len) {
        ssize_t r = getrandom(buf + total, len - total, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -errno;
        }
        total += (size_t)r;
    }

    return 0;
}
