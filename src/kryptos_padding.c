/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_padding.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#include <kryptos.h>
#ifdef KRYPTOS_USER_MODE
#include <string.h>
#endif

static void kryptos_oaep_i2osp(kryptos_u8_t *c, const kryptos_u32_t counter);

kryptos_u8_t *kryptos_ansi_x923_padding(const kryptos_u8_t *buffer, size_t *buffer_size,
                                        const size_t block_size_in_bytes, const int randomize) {
    kryptos_u8_t *bpad = NULL;
    size_t padded_size = 0;
    kryptos_u8_t byte;
    size_t p;

    if (buffer_size == NULL || block_size_in_bytes == 0 || *buffer_size == 0) {
        return NULL;
    }

    padded_size = *buffer_size;

    //  INFO(Rafael): We will always pad.
    if ((padded_size % block_size_in_bytes) == 0) {
        padded_size++;
    }

    while ((padded_size % block_size_in_bytes) != 0) {
        padded_size++;
    }

    bpad = (kryptos_u8_t *) kryptos_newseg(padded_size);

    memcpy(bpad, buffer, *buffer_size);
    if (randomize == 0) {
        memset(bpad + (*buffer_size), 0, padded_size - *buffer_size - 1);
    } else {
        for (p = (*buffer_size); p < padded_size - 1; p++) {
            byte = kryptos_get_random_byte();
            bpad[p] = byte;
        }
    }
    bpad[padded_size - 1] = (kryptos_u8_t)(padded_size - *buffer_size); // INFO(Rafael): duh!
    *buffer_size = padded_size;

    return bpad;
}

kryptos_u8_t *kryptos_oaep_mgf(const kryptos_u8_t *seed, const size_t seed_size,
                               const size_t len,
                               kryptos_hash_func hash_func,
                               size_t *out_size) {
    kryptos_u8_t *in = NULL, *out = NULL, *op = NULL;
    size_t in_size, o;
    kryptos_u32_t counter;
    kryptos_task_ctx t, *ktask = &t;

    if (seed == NULL || hash_func == NULL || out_size == NULL) {
        return NULL;
    }

    *out_size = 0;

    in_size = seed_size + sizeof(counter); // INFO(Rafael): PKCS#1 (v2.1 states 4 bytes).

    in = (kryptos_u8_t *) kryptos_newseg(in_size);

    if (in == NULL) {
        goto kryptos_oaep_mgf_epilogue;
    }

    if (memcpy(in, seed, seed_size) != in) {
        goto kryptos_oaep_mgf_epilogue;
    }

    out = (kryptos_u8_t *) kryptos_newseg(len);

    if (out == NULL) {
        goto kryptos_oaep_mgf_epilogue;
    }

    op = out;

    kryptos_task_init_as_null(ktask);

    ktask->in = in;
    ktask->in_size = in_size;

    counter = 0;

    while (*out_size < len) {
        kryptos_oaep_i2osp(ktask->in + seed_size, counter);

        hash_func(&ktask, 0);

        if (ktask->result != kKryptosSuccess) {
            kryptos_freeseg(out);
            out = NULL;
            *out_size = 0;
            goto kryptos_oaep_mgf_epilogue;
        }

        for (o = 0; o < ktask->out_size && *out_size < len; o++) {
            *op = ktask->out[o];
            *out_size += 1;
            op++;
        }

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

        counter++;
    }

kryptos_oaep_mgf_epilogue:

    if (in != NULL) {
        kryptos_freeseg(in);
    }

    op = NULL;

    in_size = 0;

    counter = 0;

    kryptos_task_init_as_null(ktask);

    return out;
}

static void kryptos_oaep_i2osp(kryptos_u8_t *c, const kryptos_u32_t counter) {
    // INFO(Rafael): This function takes in consideration that c is able to fit 4 bytes.
    if (c == NULL) {
        return;
    }
    *c = counter >> 24;
    *(c + 1) = ((counter >> 16) & 0xFF);
    *(c + 2) = ((counter >>  8) & 0xFF);
    *(c + 3) = counter & 0xFF;
}
