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

kryptos_u8_t *kryptos_padding_mgf(const kryptos_u8_t *seed, const size_t seed_size,
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
        goto kryptos_padding_mgf_epilogue;
    }

    if (memcpy(in, seed, seed_size) != in) {
        goto kryptos_padding_mgf_epilogue;
    }

    out = (kryptos_u8_t *) kryptos_newseg(len);

    if (out == NULL) {
        goto kryptos_padding_mgf_epilogue;
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
            goto kryptos_padding_mgf_epilogue;
        }

        for (o = 0; o < ktask->out_size && *out_size < len; o++) {
            *op = ktask->out[o];
            *out_size += 1;
            op++;
        }

        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

        counter++;
    }

kryptos_padding_mgf_epilogue:

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
/*
void print_buffer(const kryptos_u8_t *buf, const size_t buf_size) {
    const kryptos_u8_t *bp = buf;
    const kryptos_u8_t *bp_end = bp + buf_size;
    while (bp != bp_end) {
        printf("%.2X", *bp);
        bp++;
    }
    printf("\n");
}
*/
kryptos_u8_t *kryptos_apply_oaep_padding(const kryptos_u8_t *buffer, size_t *buffer_size,
                                         const size_t k, const kryptos_u8_t *label, const size_t label_size,
                                         kryptos_hash_func hash_func,
                                         kryptos_hash_size_func hash_size_func) {
    kryptos_hash_func hash = kryptos_sha1_hash;
    kryptos_hash_size_func hash_size = kryptos_sha1_hash_size;
    kryptos_u8_t *em = NULL, *ps = (kryptos_u8_t *)"", *l = (kryptos_u8_t *)"", *db = NULL, *seed = NULL,
                 *dbmask = NULL, *seedmask = NULL;
    size_t em_size, ps_size, h_size, l_size = 0, db_size = 0, dbmask_size = 0, x, seedmask_size = 0;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *dest = NULL;

    kryptos_task_init_as_null(ktask);

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
#if !defined(__FreeBSD__)
        l = (kryptos_u8_t *)label;
#else
        l = (kryptos_u8_t *)(uintptr_t)label;
#endif
        l_size = label_size;
    }

    // INFO(Rafael).1: Generate a string PS of length k - |M| - 2|H| - 2 of zeroed bytes (PS length can be zero).

    ps_size = k - *buffer_size - (2 * h_size) - 2; // CLUE(Rafael): The usage of parentheses is saying: 'is exactly it'.
                                                   //               Please do not mess.

    if ((long)ps_size >= 0) {
        ps = (kryptos_u8_t *) kryptos_newseg(ps_size);

        if (ps == NULL) {
            goto  kryptos_apply_oaep_padding_epilogue;
        }

        memset(ps, 0, ps_size);
    } else {
        // WARN(Rafael): Too long buffer it will be larger than the modulus byte size.
        ps_size = 0;
        goto kryptos_apply_oaep_padding_epilogue;
    }

    // INFO(Rafael).2: Let DB be the concatenation of Hash(L), PS, 0x01 and M.

    db_size = h_size + ps_size + *buffer_size + 1;

    if ((db = (kryptos_u8_t *) kryptos_newseg(db_size)) == NULL) {
        goto kryptos_apply_oaep_padding_epilogue;
    }

    ktask->in = l;
    ktask->in_size = l_size;

    hash(&ktask, 0);

    if (ktask->result != kKryptosSuccess || ktask->out == NULL) {
        goto kryptos_apply_oaep_padding_epilogue;
    }

    if (memcpy(db, ktask->out, ktask->out_size) != db) {
        goto kryptos_apply_oaep_padding_epilogue;
    }

    dest = db + h_size;

    if (ps_size > 0 && (memcpy(dest, ps, ps_size) != dest)) {
        goto kryptos_apply_oaep_padding_epilogue;
    }

    *(db + h_size + ps_size) = 0x01;

    dest = db + h_size + ps_size + 1;

    if (memcpy(dest, buffer, *buffer_size) != dest) {
        goto kryptos_apply_oaep_padding_epilogue;
    }

    // INFO(Rafael).3: Generate a random seed of |H| length.

    if ((seed = kryptos_get_random_block(h_size)) == NULL) {
        goto kryptos_apply_oaep_padding_epilogue;
    }

    // INFO(Rafael).4: Let dbMask be MGF(seed, k - |H| - 1).

    dbmask = kryptos_padding_mgf(seed, h_size, k - h_size - 1, hash, &dbmask_size);

    if (dbmask == NULL) {
        goto kryptos_apply_oaep_padding_epilogue;
    }

    // INFO(Rafael).5: maskedDB = DB ^ dbMask.

    for (x = 0; x < dbmask_size; x++) {
        db[x] = db[x] ^ dbmask[x];
    }

    // INFO(Rafael).6: Let seedMask be MGF(maskedDB, |H|).

    seedmask = kryptos_padding_mgf(db, db_size, h_size, hash, &seedmask_size);

    if (seedmask == NULL) {
        goto kryptos_apply_oaep_padding_epilogue;
    }

    // INFO(Rafael).7: maskedSeed = seed ^ seedMask;

    for (x = 0; x < h_size; x++) {
        seed[x] = seed[x] ^ seedmask[x];
    }

    // INFO(Rafael).8: Concatenate 0x00, maskedSeed, maskedDB and call it EM.

    em_size = db_size + h_size + 1;

    em = (kryptos_u8_t *) kryptos_newseg(em_size);

    if (em == NULL) {
        goto kryptos_apply_oaep_padding_epilogue;
    }

    *em = 0x00;

    dest = em + 1;

    if (memcpy(dest, seed, h_size) != dest) {
        kryptos_freeseg(em);
        em = NULL;
        goto kryptos_apply_oaep_padding_epilogue;
    }

    dest = em + h_size + 1;

    if (memcpy(dest, db, db_size) != dest) {
        kryptos_freeseg(em);
        em = NULL;
        goto kryptos_apply_oaep_padding_epilogue;
    }

    *buffer_size = em_size;

kryptos_apply_oaep_padding_epilogue:

    if (ps_size > 0 && ps != NULL) {
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
    ps = l = dest = NULL;

    return em;
}

kryptos_u8_t *kryptos_drop_oaep_padding(const kryptos_u8_t *buffer, size_t *buffer_size,
                                        const size_t k, const kryptos_u8_t *label, const size_t label_size,
                                        kryptos_hash_func hash_func,
                                        kryptos_hash_size_func hash_size_func) {
    kryptos_u8_t *buffer_copy = NULL;
    size_t buffer_copy_size = 0;
    kryptos_u8_t *m = NULL;
    kryptos_hash_func hash = kryptos_sha1_hash;
    kryptos_hash_size_func hash_size = kryptos_sha1_hash_size;
    kryptos_u8_t *seedmask = NULL, *dbmask = NULL, *l = (kryptos_u8_t *)"";
    kryptos_u8_t *dest = NULL, *dest_end = NULL, *dest_p = NULL;
    size_t seedmask_size = 0, h_size = 0, x, dbmask_size = 0, l_size = 0, ps_size = 0, exp_ps_size = 0, m_size = 0;
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    if (buffer == NULL || buffer_size == NULL || *buffer_size == 0) {
        return NULL;
    }

    if (*buffer != 0x00) {
        // INFO(Rafael): No way, it is invalid.
        return NULL;
    }

    buffer_copy = (kryptos_u8_t *) kryptos_newseg(*buffer_size);

    if (buffer_copy == NULL) {
        goto kryptos_drop_oaep_padding_epilogue;
    }

    buffer_copy_size = *buffer_size;

    if (memcpy(buffer_copy, buffer, buffer_copy_size) != buffer_copy) {
        goto kryptos_drop_oaep_padding_epilogue;
    }

    if (hash_func != NULL && hash_size_func != NULL) {
        hash = hash_func;
        hash_size = hash_size_func;
    }

    if (label != NULL && label_size > 0) {
#if !defined(__FreeBSD__)
        l = (kryptos_u8_t *)label;
#else
        l = (kryptos_u8_t *)(uintptr_t)label;
#endif
        l_size = label_size;
    }

    h_size = hash_size();

    seedmask = kryptos_padding_mgf(buffer_copy + h_size + 1, k - h_size - 1, h_size, hash, &seedmask_size);

    if (seedmask == NULL) {
        goto kryptos_drop_oaep_padding_epilogue;
    }

    dest = buffer_copy + 1;

    for (x = 0; x < h_size; x++) {
        seedmask[x] = seedmask[x] ^ dest[x];
    }

    // INFO(Rafael): Now we got into seedmask the original random seed. Having this piece of information we can get dbmask.

    // WARN(Rafael): We also could use (k - h_size - 1) instead of (buffer_copy_size - h_size - 1) but I think it is
    //               trust so much in input.
    dbmask = kryptos_padding_mgf(seedmask, h_size, buffer_copy_size - h_size - 1, hash, &dbmask_size);

    if (dbmask == NULL) {
        goto kryptos_drop_oaep_padding_epilogue;
    }

    dest = buffer_copy + h_size + 1;

    for (x = 0; x < dbmask_size; x++) {
        dest[x] = dest[x] ^ dbmask[x];
    }

    // INFO(Rafael): Now dest is pointing to the plain padded structure (DB). Let's check it.

    ktask->in = l;
    ktask->in_size = l_size;

    hash(&ktask, 0);

    if (ktask->result != kKryptosSuccess || ktask->out == NULL || ktask->out_size != h_size) {
        goto kryptos_drop_oaep_padding_epilogue;
    }

    // INFO(Rafael): Verifying Hash(L) data.

    if (memcmp(dest, ktask->out, h_size) != 0) {
        // INFO(Rafael): No way, it is invalid.
        goto kryptos_drop_oaep_padding_epilogue;
    }

    // INFO(Rafael): Verifying the PS section data.

    dest_p = dest + h_size;
    dest_end = buffer_copy + buffer_copy_size;

    ps_size = 0;

    while (dest_p < dest_end && *dest_p == 0x00) {
        ps_size++;
        dest_p++;
    }

    if (*dest_p != 0x01) {
        // INFO(Rafael): No way, it is invalid.
        goto kryptos_drop_oaep_padding_epilogue;
    }

    m_size = dest_end - dest_p - 1;

    exp_ps_size = k - m_size - (2 * h_size) - 2;

    if (ps_size != exp_ps_size) {
        // INFO(Rafael): No way, it is invalid.
        goto kryptos_drop_oaep_padding_epilogue;
    }

    m = (kryptos_u8_t *) kryptos_newseg(m_size + 1);
    memset(m, 0, m_size + 1);

    if (m == NULL) {
        goto kryptos_drop_oaep_padding_epilogue;
    }

    if (memcpy(m, dest_p + 1, m_size) != m) {
        kryptos_freeseg(m);
        m = NULL;
        goto kryptos_drop_oaep_padding_epilogue;
    }

    *buffer_size = m_size;

kryptos_drop_oaep_padding_epilogue:

    if (buffer_copy != NULL) {
        kryptos_freeseg(buffer_copy);
    }

    if (seedmask != NULL) {
        kryptos_freeseg(seedmask);
    }

    if (dbmask != NULL) {
        kryptos_freeseg(dbmask);
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(ktask);

    l = dest = dest_end = dest_p = NULL;

    seedmask_size = dbmask_size = l_size = ps_size = exp_ps_size = buffer_copy_size = m_size = 0;

    return m;
}

kryptos_u8_t *kryptos_pss_encode(const kryptos_u8_t *buffer, size_t *buffer_size,
                                 const size_t k, const size_t salt_size,
                                 kryptos_hash_func hash_func, kryptos_hash_size_func hash_size_func) {

    kryptos_u8_t *em = NULL, *mp = NULL, *dest = NULL, *salt = NULL, *ps = NULL, *db = NULL, *dbmask = NULL,
                 *p = NULL, *p_end = NULL;
    size_t h_size = 0, mp_size = 0, ps_size = 0, db_size = 0, dbmask_size = 0;
    kryptos_hash_func hash = kryptos_sha1_hash;
    kryptos_hash_size_func hash_size = kryptos_sha1_hash_size;
    kryptos_task_ctx ht, *ktask = &ht;

    if (buffer == NULL || buffer_size == NULL) {
        return NULL;
    }

    if (hash_func != NULL) {
        hash = hash_func;
    }

    if (hash_size_func != NULL) {
        hash_size = hash_size_func;
    }

    h_size = hash_size();

    kryptos_task_init_as_null(ktask);

    // WARN(Rafael): Since any hash function limitation tends to be quite huge, I will let this verification out.

    if (*buffer_size < (h_size + salt_size + 2)) {
        // INFO(Rafael): 'Encoding error'.
        goto kryptos_pss_encode_epilogue;
    }

    // INFO(Rafael): Computing 'mHash'.

#if !defined(__FreeBSD__)
    ktask->in = (kryptos_u8_t *)buffer;
#else
    ktask->in = (kryptos_u8_t *)(uintptr_t)buffer;
#endif

    ktask->in_size = *buffer_size;

    hash(&ktask, 0);

    if (ktask->out == NULL || ktask->out_size != h_size) {
        goto kryptos_pss_encode_epilogue;
    }

    // INFO(Rafael): Now mHash is known as ktask->out. Let's build up M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt.

    mp_size = 8 + h_size + salt_size;

    mp = (kryptos_u8_t *) kryptos_newseg(mp_size);

    if (mp == NULL) {
        goto kryptos_pss_encode_epilogue;
    }

    if (memset(mp, 0, mp_size) != mp) {
        goto kryptos_pss_encode_epilogue;
    }

    dest = mp + 8;

    if (memcpy(dest, ktask->out, h_size) != dest) {
        goto kryptos_pss_encode_epilogue;
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    if (salt_size > 0) {
        if ((salt = kryptos_get_random_block(salt_size)) != NULL) {
            dest += h_size;

            if (memcpy(dest, salt, salt_size) != dest) {
                goto kryptos_pss_encode_epilogue;
            }
        }
    }

    // INFO(Rafael): Now H = Hash(M') of hLen bytes.

    ktask->in = mp;
    ktask->in_size = mp_size;

    hash(&ktask, 0);

    if (ktask->out == NULL || ktask->out_size != h_size) {
        goto kryptos_pss_encode_epilogue;
    }

    // INFO(Rafael): H is now known as ktask->out and hLen ktask->out_size.
    //               Let's generate PS with *buffer_size - salt_size - h_size - 2 zeroed bytes.

    ps_size = *buffer_size - salt_size - h_size - 2;

    if (ps_size > 0) {
        ps = (kryptos_u8_t *) kryptos_newseg(ps_size);

        if (ps == NULL) {
            goto kryptos_pss_encode_epilogue;
        }

        if (memset(ps, 0, ps_size) != ps) {
            goto kryptos_pss_encode_epilogue;
        }
    }

    db_size = ps_size + salt_size + 1;
    db = (kryptos_u8_t *) kryptos_newseg(db_size);

    if (db == NULL) {
        goto kryptos_pss_encode_epilogue;
    }

    dest = db;

    if (ps_size > 0) {
        if (memcpy(dest, ps, ps_size) != dest) {
            goto kryptos_pss_encode_epilogue;
        }

        dest += ps_size;
    }

    *dest = 0x01;

    if (salt_size > 0) {
        dest += 1;

        if (memcpy(dest, salt, salt_size) != dest) {
            goto kryptos_pss_encode_epilogue;
        }

        kryptos_freeseg(salt);
        salt = NULL;
    }

    dbmask = kryptos_padding_mgf(ktask->out, ktask->out_size, *buffer_size - h_size - 1, hash, &dbmask_size);

    if (dbmask == NULL) {
        goto kryptos_pss_encode_epilogue;
    }

    // INFO(Rafael): maskedDB = DB ^ dbmask

    dest = db;

    p = dbmask;
    p_end = dbmask + dbmask_size;

    while (p != p_end) {
        (*p) = (*p) ^ (*dest);
        p++;
        dest++;
    }

    // INFO(Rafael): 'Set the leftmost 8 * emLen - emBits bits to zero', i.e. the first byte of dbmask is always zero.

    if (ps_size > 0) {
        *dbmask = 0x00;
    }

    // INFO(Rafael): 'EM = maskeddb || H || 0xbc.'.

    *buffer_size = dbmask_size + h_size + 1;
    em = (kryptos_u8_t *) kryptos_newseg(*buffer_size);

    if (em == NULL) {
        goto kryptos_pss_encode_epilogue;
    }

    dest = em;

    if (memcpy(dest, dbmask, dbmask_size) != dest) {
        kryptos_freeseg(em);
        em = NULL;
        goto kryptos_pss_encode_epilogue;
    }

    dest += dbmask_size;

    if (memcpy(dest, ktask->out, h_size) != dest) {
        kryptos_freeseg(em);
        em = NULL;
        goto kryptos_pss_encode_epilogue;
    }

    dest += h_size;

    *dest = 0xBC;

    // done!

kryptos_pss_encode_epilogue:

    if (dbmask != NULL) {
        kryptos_freeseg(dbmask);
    }

    if (db != NULL) {
        kryptos_freeseg(db);
    }

    if (ps != NULL) {
        kryptos_freeseg(ps);
    }

    if (mp != NULL) {
        kryptos_freeseg(mp);
    }

    if (salt != NULL) {
        kryptos_freeseg(salt);
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(ktask);

    hash = NULL;
    hash_size = NULL;

    h_size = 0;

    kryptos_task_init_as_null(ktask);

    dest = p = p_end = NULL;

    if (em == NULL) {
        *buffer_size = 0;
    }

    return em;
}

const kryptos_u8_t *kryptos_pss_verify(const kryptos_u8_t *m, const size_t m_size,
                                       const kryptos_u8_t *em, const size_t em_size,
                                       const size_t k, const size_t salt_size,
                                       kryptos_hash_func hash_func, kryptos_hash_size_func hash_size_func) {
    // WARN(Rafael): Since hash function limitation is quite long I will not check if m is greater than it.

    kryptos_task_ctx ht, *ktask = &ht;
    kryptos_hash_func hash = kryptos_sha1_hash;
    kryptos_hash_size_func hash_size = kryptos_sha1_hash_size;
    kryptos_u8_t *mp = NULL, *dbmask = NULL, *h = NULL, *dest = NULL, *db = NULL, *p = NULL, *p_end = NULL, *salt = NULL;
    size_t h_size = 0, dbmask_size = 0, db_size = 0, mp_size = 0, ps_size = 0;
    int inconsistent = 1;

    if (m == NULL || m_size == 0 || em == NULL || em_size == 0 || k == 0) {
        return NULL;
    }

    if (hash_func != NULL) {
        hash = hash_func;
    }

    if (hash_size_func != NULL) {
        hash_size = hash_size_func;
    }

    h_size = hash_size();

    kryptos_task_init_as_null(ktask);

    // INFO(Rafael): 'If emLen < hLen + sLen + 2' -> 'inconsistent'.

    if (em_size < (h_size + salt_size + 2)) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'If the rightmost octet of EM does not have 0xbc' -> 'inconsistent'.

    if (*(em + em_size - 1) != 0xBC) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'Let mHash = Hasm(M)'.

#if !defined(__FreeBSD__)
    ktask->in = (kryptos_u8_t *)m;
#else
    ktask->in = (kryptos_u8_t *)(uintptr_t)m;
#endif
    ktask->in_size = m_size;

    hash(&ktask, 0);

    if (ktask->out == NULL || ktask->out_size != h_size) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): Now mHash is known as ktask->out.

    // INFO(Rafael): 'Let maskedDB be the leftmost emLen - hLen - 1 octets of EM, and let H be the next hLen octets'

    dbmask_size = em_size - h_size - 1;
    dbmask = (kryptos_u8_t *) kryptos_newseg(dbmask_size);

    if (dbmask == NULL) {
        goto kryptos_pss_verify_epilogue;
    }

    dest = dbmask;

    if (memcpy(dest, em, dbmask_size) != dest) {
        goto kryptos_pss_verify_epilogue;
    }

    h = (kryptos_u8_t *) kryptos_newseg(h_size);

    if (h == NULL) {
        goto kryptos_pss_verify_epilogue;
    }

    dest = h;

    if (memcpy(dest, em + dbmask_size, h_size) != dest) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'If the 8 * emLen - emBits of the leftmost octet in maskedDB are not all == 0' -> 'inconsistent'.
    //               Considering (8 * emLen - emBits) always 0.

    // WARN(Rafael): PS should have size zero and this fact, implicitly, must be taken in consideration during further
    //               verifications.
    ps_size = em_size - salt_size - h_size - 2;

    if (ps_size > 0 && *dbmask != 0x00) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'Let dbMask = MGF(H, emLen - hLen - 1)'.

    db = kryptos_padding_mgf(h, h_size, em_size - h_size - 1, hash, &db_size);

    if (db == NULL) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'Let DB = maskedDB ^ dbMask'.

    p = db;
    p_end = db + db_size;
    dest = dbmask;

    while (p != p_end) {
        *p = (*p) ^ (*dest);
        p++;
        dest++;
    }

    // INFO(Rafael): 'Set the letfmost 8 * emLen - emBits of the leftmost octet in DB to zero'. I.e. -> db[0].

    if (ps_size > 0) {
        *db = 0x00;
    }

    // INFO(Rafael): 'If the octect at position emLen - hLen - sLen - 1 does not have 0x01' -> 'inconsistent'.
    if (*(db + em_size - h_size - salt_size - 2) != 0x01) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): 'If the emLen - hLen - sLen - 2 leftmost octets of DB are not zero' -> 'inconsistent'.

    p = db;
    p_end = db + (em_size - h_size - salt_size - 2);

    while (p != p_end) {
        if (*p != 0x00) {
            goto kryptos_pss_verify_epilogue;
        }
        p++;
    }

    // INFO(Rafael): 'Let salt be the last sLen octets of DB'.

    if (salt_size > 0) {
        salt = (kryptos_u8_t *) kryptos_newseg(salt_size);

        if (salt == NULL) {
            goto kryptos_pss_verify_epilogue;
        }

        p = db + (db_size - salt_size);

        dest = salt;

        if (memcpy(dest, p, salt_size) != dest) {
            goto kryptos_pss_verify_epilogue;
        }
    }

    // INFO(Rafael): 'Let M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt.
    //               Again, mHasm is still in ktask->out.

    mp_size = 8 + ktask->out_size + salt_size;
    mp = (kryptos_u8_t *) kryptos_newseg(mp_size);

    if (mp == NULL) {
        goto kryptos_pss_verify_epilogue;
    }

    dest = mp;

    if (memset(dest, 0, mp_size) != dest) {
        goto kryptos_pss_verify_epilogue;
    }

    dest += 8;

    if (memcpy(dest, ktask->out, ktask->out_size) != dest) {
        goto kryptos_pss_verify_epilogue;
    }

    dest += ktask->out_size;

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    if (salt != NULL) {
        if (memcpy(dest, salt, salt_size) != dest) {
            goto kryptos_pss_verify_epilogue;
        }
    }

    // INFO(Rafael): 'Let H' = Hash(M'), an octet of length hLen'.

    ktask->in = mp;
    ktask->in_size = mp_size;

    hash(&ktask, 0);

    if (ktask->out == NULL || ktask->out_size != h_size) {
        goto kryptos_pss_verify_epilogue;
    }

    // INFO(Rafael): Now ktask->out is also known as H'. 'If H = H' ' -> 'consistent'. 'Otherwise' -> 'inconsistent'.

    inconsistent = (memcmp(h, ktask->out, h_size) != 0);

kryptos_pss_verify_epilogue:

    if (mp != NULL) {
        kryptos_freeseg(mp);
    }

    if (salt != NULL) {
        kryptos_freeseg(salt);
    }

    if (dbmask != NULL) {
        kryptos_freeseg(dbmask);
    }

    if (h != NULL) {
        kryptos_freeseg(h);
    }

    if (db != NULL) {
        kryptos_freeseg(db);
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_task_init_as_null(ktask);

    dest = p = p_end = NULL;

    hash = NULL;

    hash_size = NULL;

    h_size = dbmask_size = db_size = mp_size = ps_size = 0;

    return (!inconsistent) ? m : NULL;
}