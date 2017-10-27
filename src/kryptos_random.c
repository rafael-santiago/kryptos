/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_random.h>
#include <kryptos_memory.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <fcntl.h>
# include <unistd.h>
#endif

#if defined(KRYPTOS_KERNEL_MODE) && defined(__FreeBSD__)
static void get_random_bytes(kryptos_u8_t *buf, const size_t n);

static void get_random_bytes(kryptos_u8_t *buf, const size_t n) {
    kryptos_u8_t *b, *b_end;
    uint32_t r;
    size_t byte;

    if (buf == NULL || n == 0) {
        return;
    }

    b = buf;
    b_end = b + n;

    while (b != b_end) {
        r = arc4random();
        for (byte = 0; byte < sizeof(r) && b != b_end; byte++, b++) {
            *b = r & 0xFF;
            r = r >> 8;
        }
    }

    byte = 0;
    r = 0;
    b = NULL;
    b_end = NULL;
}
#endif

#if defined(__unix__)

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
#elif  defined(KRYPTOS_KERNEL_MODE)
    if (size_in_bytes > 0) {
        block = kryptos_newseg(size_in_bytes);

        if (block != NULL) {
            get_random_bytes(block, size_in_bytes);
        }
    }
#endif
    return block;
}

#elif defined(_WIN32)

void *kryptos_get_random_block(const size_t size_in_bytes) {
    void *block = NULL;
    HCRYPTPROV crypto_ctx = 0;

    if (size_in_bytes == 0) {
        goto kryptos_get_random_block_epilogue;
    }

    // TODO(Rafael): This seems to be slow as hell. Improve it to use a
    //               straightforward way of getting those bytes.

    if (!CryptAcquireContext(&crypto_ctx, NULL, NULL, PROV_RSA_FULL, 0)) {
        return NULL;
    }

    block = kryptos_newseg((DWORD)size_in_bytes);

    if (block == NULL) {
        goto kryptos_get_random_block_epilogue;
    }

    if (!CryptGenRandom(crypto_ctx, (DWORD) size_in_bytes, block)) {
        kryptos_freeseg(block);
        block = NULL;
        goto kryptos_get_random_block_epilogue;
    }

kryptos_get_random_block_epilogue:

    if (crypto_ctx) {
        CryptReleaseContext(crypto_ctx, 0);
    }

    return block;
}

#endif

#if defined(__unix__)

kryptos_u8_t kryptos_get_random_byte(void) {
    kryptos_u8_t b = 0;
#if defined(KRYPTOS_USER_MODE)
    int fd = -1;

    fd = open("/dev/urandom", O_RDONLY);

    if (fd == -1) {
        fd = open("/dev/random", O_NONBLOCK | O_RDONLY);
    }

    if (fd == -1) {
        goto kryptos_get_random_byte_epilogue;
    }

    read(fd, &b, 1);

kryptos_get_random_byte_epilogue:
    if (fd != -1) {
        close(fd);
    }
#elif  defined(KRYPTOS_KERNEL_MODE)
    get_random_bytes(&b, 1);
#endif
    return b;
}

#elif defined(_WIN32)
kryptos_u8_t kryptos_get_random_byte(void) {
    kryptos_u8_t b, *block;

    block = kryptos_get_random_block(1);
    b = *block;
    kryptos_freeseg(block);

    return b;
}
#endif
