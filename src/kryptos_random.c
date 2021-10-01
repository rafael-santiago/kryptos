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
# if !defined(_MSC_VER)
#  include <unistd.h>
# endif
# include <string.h>
#endif

static kryptos_csprng_t g_kryptos_csprng = kKryptosCSPRNGSystem;

struct kryptos_fortuna_ctx *g_kryptos_fortuna_state = NULL;

void *kryptos_sys_get_random_block(const size_t size_in_bytes);

static void kryptos_release_curr_csprng(void);

kryptos_u8_t kryptos_unbiased_rand_mod_u8(const size_t n) {
    kryptos_u8_t r = 0;

    do {
        r = kryptos_get_random_byte();
    } while (r >= 0xFF - (0xFF % n));
    r = r % n;

    return r;
}

kryptos_u16_t kryptos_unbiased_rand_mod_u16(const size_t n) {
    kryptos_u16_t r = 0;

    do {
        r = (((kryptos_u16_t)kryptos_get_random_byte()) << 8) | kryptos_get_random_byte();
    } while (r >= 0xFFFF - (0xFFFF % n));

    r = r % n;

    return r;
}

kryptos_u32_t kryptos_unbiased_rand_mod_u32(const size_t n) {
    kryptos_u32_t r = 0;

    do {
        r = (((kryptos_u32_t)kryptos_get_random_byte()) << 24) |
            (((kryptos_u32_t)kryptos_get_random_byte()) << 16) |
            (((kryptos_u32_t)kryptos_get_random_byte()) <<  8) | kryptos_get_random_byte();
    } while (r >= 0xFFFFFFFF - (0xFFFFFFFF % n));
    r = r % n;

    return r;

}

kryptos_u64_t kryptos_unbiased_rand_mod_u64(const size_t n) {
    kryptos_u64_t r = 0;
#if defined(KRYPTOS_KERNEL_MODE) && defined(__linux__)
    kryptos_u32_t rem = 0;
    kryptos_u64_t lim = 0;
    div_u64_rem(0xFFFFFFFFFFFFFFFF, n, &rem);
    lim = 0xFFFFFFFFFFFFFFFF - rem;
    do {
        r = (((kryptos_u64_t)kryptos_get_random_byte()) << 56) |
            (((kryptos_u64_t)kryptos_get_random_byte()) << 48) |
            (((kryptos_u64_t)kryptos_get_random_byte()) << 40) |
            (((kryptos_u64_t)kryptos_get_random_byte()) << 32) |
            (((kryptos_u64_t)kryptos_get_random_byte()) << 24) |
            (((kryptos_u64_t)kryptos_get_random_byte()) << 16) |
            (((kryptos_u64_t)kryptos_get_random_byte()) <<  8) | kryptos_get_random_byte();
    } while (r >= lim);
    lim = r;
    div_u64_rem(lim, (u64)n, (u32 *)&r);
    rem = 0;
    lim = 0;
#else
    do {
        r = (((kryptos_u64_t)kryptos_get_random_byte()) << 56) |
            (((kryptos_u64_t)kryptos_get_random_byte()) << 48) |
            (((kryptos_u64_t)kryptos_get_random_byte()) << 40) |
            (((kryptos_u64_t)kryptos_get_random_byte()) << 32) |
            (((kryptos_u64_t)kryptos_get_random_byte()) << 24) |
            (((kryptos_u64_t)kryptos_get_random_byte()) << 16) |
            (((kryptos_u64_t)kryptos_get_random_byte()) <<  8) | kryptos_get_random_byte();
    } while (r >= 0xFFFFFFFFFFFFFFFF - (0xFFFFFFFFFFFFFFFF % n));
    r = r % n;
#endif
    return r;
}

int kryptos_set_csprng(kryptos_csprng_t csprng) {
    int set_glvar = 0;
    kryptos_u8_t *seed = NULL;
    kryptos_u32_t seed_size = 0;
    
    switch (csprng) {
        case kKryptosCSPRNGSystem:
            kryptos_release_curr_csprng();
            set_glvar = 1;
            break;

        case kKryptosCSPRNGFortuna:

            // CAUTION(Rafael): It is indispensable to use 'kryptos_sys_get_random_block' for avoiding a deadlock
            //                  and as a result a stack overflow failure.
            seed = kryptos_sys_get_random_block(4);

            if (seed == NULL) {
                goto kryptos_use_csprng_epilogue;
            }

            seed_size = *(kryptos_u32_t *)seed;
            seed_size = (seed_size % 31) + 1;
            kryptos_freeseg(seed, 4);

            seed = kryptos_sys_get_random_block((size_t)seed_size);

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
            break;

        default:
            break;
    }

kryptos_use_csprng_epilogue:

    if (seed != NULL) {
        kryptos_freeseg(seed, (size_t)seed_size);
        seed_size = 0;
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

void *kryptos_get_random_block(const size_t size_in_bytes) {
    if (g_kryptos_csprng == kKryptosCSPRNGFortuna) {
        return kryptos_fortuna_get_random_block(g_kryptos_fortuna_state, size_in_bytes);
    }

    return kryptos_sys_get_random_block(size_in_bytes);
}

#if defined(__unix__)

void *kryptos_sys_get_random_block(const size_t size_in_bytes) {
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
        kryptos_freeseg(block, size_in_bytes);
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

void *kryptos_sys_get_random_block(const size_t size_in_bytes) {
    void *block = NULL;
#if 0 // TODO(Rafael): Use 'bcrypt.h' in vista or newer.
    static HCRYPTPROV crypto_ctx = 0;

    if (size_in_bytes == 0) {
        return NULL;
    }

    // WARN(Rafael): crypto_ctx will 'leak' otherwise it will be slow as hell. 

    if (crypto_ctx == 0 && !CryptAcquireContext(&crypto_ctx, NULL, NULL, PROV_RSA_FULL, 0)) {
        return NULL;
    }

    block = kryptos_newseg((DWORD)size_in_bytes);

    if (block == NULL) {
        goto kryptos_get_random_block_epilogue;
    }

    if (!CryptGenRandom(crypto_ctx, (DWORD) size_in_bytes, block)) {
        kryptos_freeseg(block, size_in_bytes);
        block = NULL;
        goto kryptos_get_random_block_epilogue;
    }
#else
    if (size_in_bytes == 0) {
        return NULL;
    }
    block = kryptos_newseg(size_in_bytes);

    if (block == NULL) {
        goto kryptos_get_random_block_epilogue;
    }

    if (BCryptGenRandom(NULL, block, (ULONG)size_in_bytes,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) != STATUS_SUCCESS) {
        kryptos_freeseg(block, size_in_bytes);
        block = NULL;
    }
#endif

kryptos_get_random_block_epilogue:

    // WARN(Rafael): See? It is leaking. Go away! Boo!

    //if (crypto_ctx) {
    //    CryptReleaseContext(crypto_ctx, 0);
    //}

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
        return kryptos_fortuna_get_random_byte(g_kryptos_fortuna_state);
    }

    get_random_bytes(&b, 1);
#endif
    return b;
}

#elif defined(_WIN32)
kryptos_u8_t kryptos_get_random_byte(void) {
    kryptos_u8_t b, *block;

    if (g_kryptos_csprng == kKryptosCSPRNGFortuna) {
        return kryptos_fortuna_get_random_byte(g_kryptos_fortuna_state);
    }

    block = kryptos_get_random_block(1);
    b = *block;
    kryptos_freeseg(block, 1);

    return b;
}
#endif
