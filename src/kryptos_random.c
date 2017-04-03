/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_random.h>
#include <kryptos_memory.h>
#include <kryptos_types.h>
#include <fcntl.h>
#include <unistd.h>

void *kryptos_get_random_block(const size_t size_in_bytes) {
    void *block = NULL;
#if defined(KRYPTOS_USER_MODE)
    int fd = -1;

    if (size_in_bytes == 0) {
        goto kryptos_get_random_block_epilogue;
    }

    fd = open("/dev/urandom", O_RDONLY);

    if (fd == -1) {
        fd = open("/dev/random", O_NONBLOCK | O_RDONLY);
    }

    if (fd == -1) {
        goto kryptos_get_random_block_epilogue;
    }

    block = kryptos_newseg(size_in_bytes);

    if (block == NULL) {
        goto kryptos_get_random_block_epilogue;
    }

    if (read(fd, block, size_in_bytes) == -1) {
        kryptos_freeseg(block);
        block = NULL;
    }

kryptos_get_random_block_epilogue:
    if (fd != -1) {
        close(fd);
    }

    return block;
#elif  defined(KRYPTOS_KERNEL_MODE)
    // TODO(Rafael): Use get_random_bytes(). [Do not read from /dev/urandom or /dev/random it would be nasty!!!]
#endif
    return NULL;
}
