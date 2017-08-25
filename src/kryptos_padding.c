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

kryptos_u8_t *kryptos_oaep_padding(const kryptos_u8_t *buffer, size_t *buffer_size,
                                   const size_t k, const kryptos_u8_t *label, const size_t label_size,
                                   kryptos_hash_func hash_func,
                                   kryptos_hash_size_func hash_size_func) {
    kryptos_hash_func hash = kryptos_sha1_hash;
    kryptos_hash_size_func hash_size = kryptos_sha1_hash_size;
    kryptos_u8_t *em = NULL, *ps = "", *l = "", *db = NULL, *seed = NULL, *dbmask = NULL, *seedmask = NULL;
    size_t em_size, ps_size, h_size, l_size = 0, db_size = 0, dbmask_size = 0, x, seedmask_size = 0;
    kryptos_task_ctx t, *ktask = &t;

    if (buffer == NULL || buffer_size == NULL || *buffer_size == 0 || *buffer_size > k) {
        return NULL;
    }

    if (hash_func != NULL && hash_size_func != NULL) {
        hash = hash_func;
        hash_size = hash_size_func;
    }

    if ((h_size = hash_size()) > k) { // INFO(Rafael): In practice it should never happen but let's assure it.
        return NULL;
    }

    if (label != NULL && label_size > 0) {
        l = (kryptos_u8_t *)label;
        l_size = label_size;
    }

    // INFO(Rafael).1: Generate a string PS of length k - |M| - 2|H| - 2 of zeroed bytes (PS length can be zero).

    ps_size = k - *buffer_size - (2 * h_size) - 2; // CLUE(Rafael): The usage of parentheses is saying: 'is exactly it'.
                                                   //               Please do not mess.

    if (ps_size > 0) {
        ps = (kryptos_u8_t *) kryptos_newseg(ps_size);

        if (ps == NULL) {
            goto  kryptos_oaep_padding_epilogue;
        }

        memset(ps, 0, ps_size);
    }

    // INFO(Rafael).2: Let DB be the concatenation of Hash(L), PS, 0x01 and M.

    db_size = h_size + ps_size + *buffer_size + 1;

    if ((db = (kryptos_u8_t *) kryptos_newseg(db_size)) == NULL) {
        goto kryptos_oaep_padding_epilogue;
    }

    kryptos_task_init_as_null(ktask);

    ktask->in = l;
    ktask->in_size = l_size;

    hash(&ktask, 0);

    if (ktask->result != kKryptosSuccess || ktask->out == NULL) {
        goto kryptos_oaep_padding_epilogue;
    }

    if (memcpy(db, ktask->out, ktask->out_size) != db) {
        goto kryptos_oaep_padding_epilogue;
    }

    if (ps_size > 0 && (memcpy(db + h_size, ps, ps_size) != (db + h_size))) {
        goto kryptos_oaep_padding_epilogue;
    }

    *(db + h_size + ps_size) = 0x01;

    if (memcpy(db + h_size + ps_size + 1, buffer, *buffer_size) != (db + h_size + ps_size + 1)) {
        goto kryptos_oaep_padding_epilogue;
    }

    // INFO(Rafael).3: Generate a random seed of |H| length.

    if ((seed = kryptos_get_random_block(h_size)) == NULL) {
        goto kryptos_oaep_padding_epilogue;
    }

    // INFO(Rafael).4: Let dbMask be MGF(seed, k - |H| - 1).

    dbmask = kryptos_oaep_mgf(seed, h_size, k - h_size - 1, hash, &dbmask_size);

    if (dbmask == NULL) {
        goto kryptos_oaep_padding_epilogue;
    }

    // INFO(Rafael).5: maskedDB = DB ^ dbMask.

    for (x = 0; x < dbmask_size; x++) {
        db[x] = db[x] ^ dbmask[x];
    }

    // INFO(Rafael).6: Let seedMask be MGF(maskedDB, |H|).

    seedmask = kryptos_oaep_mgf(db, db_size, h_size, hash, &seedmask_size);

    if (seedmask == NULL) {
        goto kryptos_oaep_padding_epilogue;
    }

    // INFO(Rafael).7: maskedSeed = seed ^ seedMask;

    for (x = 0; x < h_size; x++) {
        seed[x] = seed[x] ^ seedmask[x];
    }

    // INFO(Rafael).8: Concatenate 0x00, maskedSeed, maskedDB and call it EM.

    em_size = *buffer_size + db_size + h_size + 1;

    em = (kryptos_u8_t *) kryptos_newseg(em_size);

    if (em == NULL) {
        goto kryptos_oaep_padding_epilogue;
    }

    *em = 0x00;

    if (memcpy(em + 1, seed, h_size) != (em + 1)) {
        kryptos_freeseg(em);
        em = NULL;
        goto kryptos_oaep_padding_epilogue;
    }

    if (memcpy(em + h_size + 1, db, db_size) != (em + h_size + 1)) {
        kryptos_freeseg(em);
        em = NULL;
        goto kryptos_oaep_padding_epilogue;
    }

    *buffer_size = em_size;

kryptos_oaep_padding_epilogue:

    if (ps != NULL) {
        kryptos_freeseg(ps);
    }

    if (db != NULL) {
        kryptos_freeseg(db);
    }

    if (seed != NULL) {
        kryptos_freeseg(seed);
    }

    if (dbmask != NULL) {
        kryptos_freeseg(dbmask);
    }

    if (seedmask != NULL) {
        kryptos_freeseg(seedmask);
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(ktask);

    em_size = ps_size = h_size = l_size = db_size = dbmask_size = seedmask_size = 0;
    hash = NULL;
    hash_size = NULL;
    ps = l = NULL;

    return em;
}
