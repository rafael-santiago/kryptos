/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_fortuna.h>
#include <kryptos_memory.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define KRYPTOS_FORTUNA_OUTPUT_LIMIT 0x100000 // INFO(Rafael): 1 MB of random data

#define KRYPTOS_FORTUNA_MAX_CALLS_BEFORE_RESEED 0x40

static struct kryptos_fortuna_ctx g_fortuna;

static void *kryptos_fortuna_generate_blocks(struct kryptos_fortuna_ctx *fortuna, const size_t k);

struct kryptos_fortuna_ctx *kryptos_fortuna_init(const int allocate) {
    struct kryptos_fortuna_ctx *fortuna;

    if (allocate) {
        fortuna = (struct kryptos_fortuna_ctx *) kryptos_newseg(sizeof(struct kryptos_fortuna_ctx));
        if (fortuna == NULL) {
            return NULL;
        }
    } else {
        fortuna = &g_fortuna;
    }

    memset(fortuna->K, 0, 32);
    fortuna->K_size = 32;
    fortuna->C = 0;
    fortuna->call_nr = 0;
    memset(fortuna->seed, 0, 32);
    fortuna->seed_size = 0;

    return fortuna;
}

void kryptos_fortuna_fini(struct kryptos_fortuna_ctx *fortuna) {
    if (fortuna != NULL) {
        fortuna->call_nr = 0;
        memset(fortuna->seed, 0, fortuna->seed_size);
        fortuna->seed_size = 0;
        if (fortuna != &g_fortuna) {
            kryptos_freeseg(fortuna);
        }
    }
}

int kryptos_fortuna_reseed(struct kryptos_fortuna_ctx *fortuna, const kryptos_u8_t *seed, const size_t seed_size) {
    kryptos_task_ctx t, *ktask = &t;
    int done = 0;

    kryptos_task_init_as_null(ktask);

    if (fortuna != NULL) {
        ktask->in = (kryptos_u8_t *) kryptos_newseg(seed_size + fortuna->K_size);

        if (ktask->in == NULL) {
            goto kryptos_fortuna_reseed_epilogue;
        }

        memcpy(ktask->in, fortuna->K, fortuna->K_size);
        memcpy(ktask->in + fortuna->K_size, seed, seed_size);

        kryptos_sha256_hash(&ktask, 0);

        if (!kryptos_last_task_succeed(ktask)) {
            goto kryptos_fortuna_reseed_epilogue;
        }

        memcpy(fortuna->K, ktask->out, fortuna->K_size);
        fortuna->C += 1;

        // INFO(Rafael): Generating the next seed (the user must keep it stored in somewhere).

        memcpy(ktask->in, fortuna->K, fortuna->K_size >> 1);
        memcpy(ktask->in + fortuna->K_size, ktask->out, seed_size);

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

        kryptos_sha256_hash(&ktask, 0);

        if (!kryptos_last_task_succeed(ktask)) {
            goto kryptos_fortuna_reseed_epilogue;
        }

        memcpy(fortuna->seed, ktask->out, ktask->out_size);
        fortuna->seed_size = ktask->out_size;

        done = 1;
    }

kryptos_fortuna_reseed_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    return done;
}

void *kryptos_fortuna_get_random_block(struct kryptos_fortuna_ctx *fortuna, const size_t size_in_bytes) {
    kryptos_u8_t *t = NULL, *r = NULL;
    size_t t_size;

    if (size_in_bytes == 0 || size_in_bytes >= KRYPTOS_FORTUNA_OUTPUT_LIMIT) {
        return NULL;
    }

    t_size = size_in_bytes << 4;
    t = kryptos_fortuna_generate_blocks(fortuna, t_size);

    if (t == NULL) {
        goto kryptos_fortuna_get_random_block_epilogue;
    }

    r = (kryptos_u8_t *) kryptos_newseg(size_in_bytes);

    if (r == NULL) {
        goto kryptos_fortuna_get_random_block_epilogue;
    }

    memcpy(r, t, size_in_bytes);

    memset(t, 0, t_size);
    kryptos_freeseg(t);

    // INFO(Rafael): We are using AES-128 and we must fill up a key buffer of 32 bytes.

    t_size = 2;
    t = kryptos_fortuna_generate_blocks(fortuna, 2);

    if (t == NULL) {
        goto kryptos_fortuna_get_random_block_epilogue;
    }

    memcpy(fortuna->K, t, fortuna->K_size);

kryptos_fortuna_get_random_block_epilogue:

    if (t != NULL) {
        memset(t, 0, t_size);
        kryptos_freeseg(t);
    }

    t_size = 0;

    return r;
}

kryptos_u8_t kryptos_fortuna_get_random_byte(struct kryptos_fortuna_ctx *fortuna) {
    kryptos_u8_t *block = kryptos_fortuna_get_random_block(fortuna, 16);
    kryptos_u8_t byte = 0;

    if (block != NULL) {
        byte = *block;
        kryptos_freeseg(block);
    }

    return byte;
}

static void *kryptos_fortuna_generate_blocks(struct kryptos_fortuna_ctx *fortuna, const size_t k) {
    kryptos_u8_t *r, *rp, *seed = NULL;
    struct kryptos_fortuna_ctx *fp;
    kryptos_task_ctx t, *ktask = &t;
    size_t i, r_size, seed_size;

    fortuna->call_nr += 1;

    r_size = (k > 0) ? k << 4 : 16;
    r = (kryptos_u8_t *) kryptos_newseg(r_size);

    if (r == NULL) {
        return NULL;
    }

    rp = r;

    memset(rp, 0, r_size);

    fp = (fortuna == NULL) ? &g_fortuna : fortuna;

    if (fp->C == 0) {
        // INFO(Rafael): The generator was not seeded yet. It can happen when initializing it. Because the block cipher
        //               will try to pad with some random data by default. However, in this case, it is OK; we are not
        //               considering the padding part here. In this special case we will use the current active CSPRNG
        //               in order to avoid returning a zeroed by reseeding Fortuna.
        seed = kryptos_get_random_block(32);

        if (seed == NULL) {
            goto kryptos_fortuna_generate_blocks_epilogue;
        }

        seed_size = 32;

        if (!kryptos_fortuna_reseed(fortuna, seed, seed_size)) {
            goto kryptos_fortuna_generate_blocks_epilogue;
        }
    }

    if (fortuna->call_nr > KRYPTOS_FORTUNA_MAX_CALLS_BEFORE_RESEED) {
        if (!kryptos_fortuna_reseed(fortuna, fortuna->seed, fortuna->seed_size)) {
            goto kryptos_fortuna_generate_blocks_epilogue; // WARN(Rafael): In normal conditions, it should never happen.
        }
        fortuna->call_nr = 0;
    }

    kryptos_task_init_as_null(ktask);

    ktask->in = (kryptos_u8_t *) kryptos_newseg(4);
    ktask->in_size = 4;

    for (i = 0; i < k; i++) {
        kryptos_aes128_setup(ktask, fp->K, fp->K_size, kKryptosECB);
        kryptos_task_set_encrypt_action(ktask);

        ktask->in[0] = fp->C & 0xFF;
        ktask->in[1] = (fp->C & 0xFF00) >> 8;
        ktask->in[2] = (fp->C & 0xFF0000) >> 16;
        ktask->in[3] = fp->C >> 24;

        kryptos_aes128_cipher(&ktask);

        if (!kryptos_last_task_succeed(ktask)) {
            kryptos_freeseg(r);
            r = NULL;
            break;
        }

        memcpy(rp, ktask->out, ktask->out_size);
        rp += ktask->out_size;

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

        fp->C += 1;
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_IV | KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

kryptos_fortuna_generate_blocks_epilogue:

    if (seed != NULL) {
        memset(seed, 0, seed_size);
        kryptos_freeseg(seed);
        seed_size = 0;
    }

    return r;
}

#undef KRYPTOS_FORTUNA_OUTPUT_LIMIT

#undef KRYPTOS_FORTUNA_MAX_CALLS_BEFORE_RESEED
