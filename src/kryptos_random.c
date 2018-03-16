/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_random.h>
#include <kryptos_memory.h>
#include <kryptos_fortuna.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <fcntl.h>
# include <unistd.h>
# include <string.h>
#endif

static kryptos_csprng_t g_kryptos_csprng = kKryptosCSPRNGSys;

struct kryptos_fortuna_ctx *g_kryptos_fortuna_state = NULL;

static void kryptos_release_curr_csprng(void);

int kryptos_set_csprng(kryptos_csprng_t csprng) {
    int set_glvar = 0;
    kryptos_u8_t *seed;
    kryptos_u32_t seed_size;

    switch (csprng) {
        case kKryptosCSPRNGSys:
            kryptos_release_curr_csprng();
            set_glvar = 1;
            break;

        case kKryptosCSPRNGFortuna:
            seed = kryptos_get_random_block(4);

            if (seed == NULL) {
                goto kryptos_use_csprng_epilogue;
            }

            seed_size = *(kryptos_u32_t *)seed;
            seed_size = (seed_size + 1) % 32;
            kryptos_freeseg(seed);

            seed = kryptos_get_random_block((size_t)seed_size);

            if (seed == NULL) {
                goto kryptos_use_csprng_epilogue;
            }

            kryptos_release_curr_csprng();

            // INFO(Rafael): This way of using Fortuna does not worry about saving the random pool state. No arbitrary file
            //               is written even because it must be able to run in kernel mode too. By default it reseeds the
            //               generator using the previous chosen CSPRNG. If you need to manage the generator state among
            //               different threads, you must handle the generator returned by kryptos_fortuna_init(1) on your
            //               own; the kryptos_fortuna_init(0) convenience used here is not for you.

            g_kryptos_fortuna_state = kryptos_fortuna_init(0);
            set_glvar = kryptos_fortuna_reseed(g_kryptos_fortuna_state, seed, (size_t)seed_size);

            set_glvar = 1;
            break;

        default:
            break;
    }

kryptos_use_csprng_epilogue:

    if (seed != NULL) {
        memset(seed, 0, (size_t)seed_size);
        seed_size = 0;
        kryptos_freeseg(seed);
    }

    if (set_glvar) {
        g_kryptos_csprng = csprng;
    }

    return set_glvar;
}

static void kryptos_release_curr_csprng(void) {
    switch (g_kryptos_csprng) {
        case kKryptosCSPRNGFortuna:
            if (g_kryptos_csprng == kKryptosCSPRNGFortuna && g_kryptos_fortuna_state != NULL) {
                kryptos_fortuna_fini(g_kryptos_fortuna_state);
            }
            break;

        default:
            break;
    }
}

#if defined(KRYPTOS_KERNEL_MODE) && (defined(__FreeBSD__) || defined(__NetBSD__))
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
#if defined(__FreeBSD__)
        r = arc4random();
#elif defined(__NetBSD__)
        r = cprng_strong32();
#endif
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

    if (g_kryptos_csprng == kKryptosCSPRNGFortuna) {
        return kryptos_fortuna_get_random_block(g_kryptos_fortuna_state, size_in_bytes);
    }

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
    if (g_kryptos_csprgn == kKryptosCSPRNGFortuna) {
        return kryptos_fortuna_get_random_block(g_kryptos_fortuna_state, size_in_bytes);
    }
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

    if (g_kryptos_csprgn == kKryptosCSPRNGFortuna) {
        return kryptos_fortuna_get_random_block(g_kryptos_fortuna_state, size_in_bytes);
    }

    if (size_in_bytes == 0) {
        return NULL;
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

    if (g_kryptos_csprng == kKryptosCSPRNGFortuna) {
        return kryptos_fortuna_get_random_byte(g_kryptos_fortuna_state);
    }

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
    if (g_kryptos_csprng == kKryptosCSPRNGFortuna) {
        return kryptos_fortuna_get_random_byte(g_fortuna_state));
    }

    get_random_bytes(&b, 1);
#endif
    return b;
}

#elif defined(_WIN32)
kryptos_u8_t kryptos_get_random_byte(void) {
    kryptos_u8_t b, *block;

    if (g_kryptos_csprng == kKryptosCSPRNGFortuna) {
        return kryptos_fortuna_get_random_byte(g_fortuna_state));
    }

    block = kryptos_get_random_block(1);
    b = *block;
    kryptos_freeseg(block);

    return b;
}
#endif
