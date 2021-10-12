/*
 *                                Copyright (C) 2019 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#if !(defined(__NetBSD__) && defined(KRYPTOS_KERNEL_MODE))
// WARN(Rafael): During my tests I got double faults with NetBSD I find it is related to the entire stack size consumption.
//               Under Linux and FreeBSD this code works well in kernel space. It seems to be a limitation imposed by NetBSD.
//               Due to it I am deactivating it in NetBSD for security issues.

#include <kryptos_argon2.h>
#include <kryptos_memory.h>
#include <kryptos_blake2.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#elif defined(KRYPTOS_KERNEL_MODE) && defined(_WIN32)
# pragma warning(push)
# pragma warning(disable: 4296)
#endif

// WARN(Rafael): Until now (2019) Argon2 algorithm counts with a specification that has some really bad and cruel
//               inconsistences. Additionally it has a bunch of unclearer points. The way of getting the prime indexes i' and j'
//               is textual and rather abstract. My main intention here was produce a more sane and self-contained code.
//               Excluding Blake2, all stuff related to Argon2 can be found here in this single implementation file.
//               You do not need to enter in a crazy 'trebuchet mode' when reading my code to really understand what
//               the algorithm specification was trying to say. In fact it would be a useless additional difficulty...
//
//               Maybe Argon2 spec should be more technical and less academic. It would be really great and would save hours
//               for the next practical person in the implementation role.
//
//               My second intention was to produce a code with a less intensive memory usage. It still could be improved more,
//               but by now for me it is OK.
//
//               Only the PHC winner version is implemented here but it is possible to give support for prior versions just
//               by passing the version constant as argument. Not relevant for my issues. I prefer keeping with the PHC
//               recommendations.
//
//               If you are a crypto student trying to make Argon2 start making sense, get 'argon2pure.py' by Bas Westerbaan.
//               Use it as a supplementary material. This code helped me a lot! In my opinion it is better than the entire
//               current algorithm specification.
//
//               MT support here?! Nevermind! This is a crypto library. I think it would bring extra native complications
//               really out of scope when considering the main purpose of this piece of software.

#define KRYPTOS_ARGON2_PASSWORD_MAX_SIZE        (0xFFFFFFFF >> 3)
#define KRYPTOS_ARGON2_SALT_MAX_SIZE            (0xFFFFFFFF >> 3)
#define KRYPTOS_ARGON2_PARALLELISM_MAX_SIZE     (0x00FFFFFF     )
#define KRYPTOS_ARGON2_TAG_MAX_SIZE             (0xFFFFFFFF >> 3)
#define KRYPTOS_ARGON2_MEMORY_SIZE_KB_MAX_SIZE  (0xFFFFFFFF >> 3)
#define KRYPTOS_ARGON2_ITERATIONS_MAX_SIZE      (0xFFFFFFFF >> 3)
#define KRYPTOS_ARGON2_KEY_MAX_SIZE             (0xFFFFFFFF >> 3)
#define KRYPTOS_ARGON2_ASSOCIATED_DATA_MAX_SIZE (0xFFFFFFFF >> 3)

#define kryptos_argon2_check_size_bounds(var, floor, ceil) ( (var) == 0 || ((var) >= (floor) && (var) <= (ceil)) )

#define kryptos_argon2_put_u32(buf, v) ( (buf)[3] = ((v)  >> 24),        \
                                         (buf)[2] = (((v) >> 16) & 0xFF),\
                                         (buf)[1] = (((v) >>  8) & 0xFF),\
                                         (buf)[0] = ((v)         & 0xFF),\
                                         buf += 4 )

#define KRYPTOS_ARGON2_DATA_SIZE                (1 << 10)

struct kryptos_argon2_array_ctx {
    size_t data_size;
    kryptos_u8_t *data;
};

struct kryptos_argon2_params_ctx {
    size_t i;
    size_t col_count;
    size_t segment, segment_length;
    size_t iteration, iterations;
    size_t mm;
    size_t pr_buf_size;
    kryptos_argon2_hash_type_t htype;
    kryptos_u32_t version;
    kryptos_u32_t parallelism;
    kryptos_u8_t *pr_buf, *next_pr_chunk;
};

static kryptos_u8_t *kryptos_argon2_H(kryptos_u8_t *h, const size_t h_size,
                                      const kryptos_u32_t digest_size, size_t *a_size);

static void kryptos_argon2_G(struct kryptos_argon2_array_ctx **B, struct kryptos_argon2_params_ctx *params);

static void kryptos_argon2_GB(kryptos_u8_t **z, size_t *z_size,
                              const kryptos_u8_t *x, const size_t x_size, const kryptos_u8_t *y, const size_t y_size,
                              struct kryptos_argon2_params_ctx *params);

static void kryptos_argon2_P(kryptos_u8_t *s0, kryptos_u8_t *s1, kryptos_u8_t *s2, kryptos_u8_t *s3,
                             kryptos_u8_t *s4, kryptos_u8_t *s5, kryptos_u8_t *s6, kryptos_u8_t *s7);

static void kryptos_argon2_get_indexes(struct kryptos_argon2_array_ctx **B,
                                       kryptos_u8_t *pr_buf, struct kryptos_argon2_params_ctx *params, const size_t j,
                                       const size_t index,
                                       size_t *ii, size_t *jj);

kryptos_u8_t *kryptos_do_argon2(kryptos_u8_t *password, const kryptos_u32_t password_size,
                                kryptos_u8_t *salt, const kryptos_u32_t salt_size,
                                const kryptos_u32_t parallelism,
                                const kryptos_u32_t tag_size,
                                const kryptos_u32_t memory_size_kb, const kryptos_u32_t iterations,
                                kryptos_u8_t *key, const kryptos_u32_t key_size,
                                kryptos_u8_t *associated_data, const kryptos_u32_t associated_data_size,
                                const kryptos_argon2_hash_type_t htype) {

    kryptos_u8_t *tag = NULL, *buffer = NULL, *bp, *tp, *tp_end, *tt, *tt_end, *cp, *cp_end, C[KRYPTOS_ARGON2_DATA_SIZE];
    size_t buffer_size = 0;
    kryptos_u32_t hash_type = htype;
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *H0 = NULL;
    size_t H0_size = 0;
    struct kryptos_argon2_array_ctx **B = NULL;
    struct kryptos_argon2_params_ctx params;
    kryptos_u32_t i, j;
    const kryptos_u32_t version = 0x13;

    kryptos_task_init_as_null(ktask);
    memset(&params, 0, sizeof(params));

    if (!kryptos_argon2_check_size_bounds(password_size, 0, KRYPTOS_ARGON2_PASSWORD_MAX_SIZE)                             ||
        !kryptos_argon2_check_size_bounds(salt_size, 0, KRYPTOS_ARGON2_SALT_MAX_SIZE)                                     ||
        !kryptos_argon2_check_size_bounds(parallelism, 1, KRYPTOS_ARGON2_PARALLELISM_MAX_SIZE)                            ||
        !kryptos_argon2_check_size_bounds(tag_size, 1, KRYPTOS_ARGON2_TAG_MAX_SIZE)                                       ||
        !kryptos_argon2_check_size_bounds(memory_size_kb, (parallelism << 3), KRYPTOS_ARGON2_MEMORY_SIZE_KB_MAX_SIZE)     ||
        !kryptos_argon2_check_size_bounds(iterations, 1, KRYPTOS_ARGON2_ITERATIONS_MAX_SIZE)                              ||
        !kryptos_argon2_check_size_bounds(key_size, 0, KRYPTOS_ARGON2_KEY_MAX_SIZE)                                       ||
        !kryptos_argon2_check_size_bounds(associated_data_size, 0, KRYPTOS_ARGON2_ASSOCIATED_DATA_MAX_SIZE)) {

        goto kryptos_do_argon2_epilogue;

    }

    buffer_size = password_size + salt_size + key_size + associated_data_size +
                  sizeof(password_size) + sizeof(salt_size) + sizeof(key_size) + sizeof(associated_data_size) +
                  sizeof(parallelism) + sizeof(tag_size) + sizeof(memory_size_kb) +
                  sizeof(iterations) + sizeof(hash_type) + sizeof(kryptos_u32_t);

    if ((buffer = (kryptos_u8_t *)kryptos_newseg(buffer_size)) == NULL) {
        goto kryptos_do_argon2_epilogue;
    }

    bp = buffer;
    kryptos_argon2_put_u32(bp, parallelism);
    kryptos_argon2_put_u32(bp, tag_size);
    // INFO(Rafael): This value must be the integer value not the value multiplied by 1024.
    kryptos_argon2_put_u32(bp, memory_size_kb);
    kryptos_argon2_put_u32(bp, iterations);
    // INFO(Rafael): In case of further algorithm updates this version should be passed as an argument. This is not
    //               the case by now (2019).
    kryptos_argon2_put_u32(bp, version);
    kryptos_argon2_put_u32(bp, hash_type);

    kryptos_argon2_put_u32(bp, password_size);
    if (password != NULL) {
        memcpy(bp, password, password_size);
        bp += password_size;
    }

    kryptos_argon2_put_u32(bp, salt_size);
    if (salt != NULL) {
        memcpy(bp, salt, salt_size);
        bp += salt_size;
    }

    kryptos_argon2_put_u32(bp, key_size);
    if (key != NULL) {
        memcpy(bp, key, key_size);
        bp += key_size;
    }

    kryptos_argon2_put_u32(bp, associated_data_size);
    if (associated_data != NULL) {
        memcpy(bp, associated_data, associated_data_size);
    }

    bp = buffer;

    kryptos_hash(blake2b512, ktask, buffer, buffer_size, 0);

    if (!kryptos_last_task_succeed(ktask)) {
        ktask->in = NULL;
        ktask->in_size = 0;
        goto kryptos_do_argon2_epilogue;
    }

    H0 = ktask->out;
    H0_size = ktask->out_size;
    ktask->out = NULL;
    ktask->out_size = 0;

    kryptos_freeseg(buffer, buffer_size);
    buffer = NULL;
    buffer_size = 0;

    params.mm = ((memory_size_kb) / (parallelism << 2)) * (parallelism << 2);
    params.col_count = params.mm / parallelism;

    params.segment_length = params.col_count >> 2;

    B = (struct kryptos_argon2_array_ctx **)kryptos_newseg(parallelism * sizeof(struct kryptos_argon2_array_ctx *));

    if (B == NULL) {
        goto kryptos_do_argon2_epilogue;
    }

    for (i = 0; i < parallelism; i++) {
        B[i] = (struct kryptos_argon2_array_ctx *)kryptos_newseg(params.col_count * sizeof(struct kryptos_argon2_array_ctx));
        if (B[i] == NULL) {
            B = NULL; // WARN(Rafael): 'Live and let it leak guy...'
            goto kryptos_do_argon2_epilogue;
        }
        memset(B[i], 0, params.col_count * sizeof(struct kryptos_argon2_array_ctx));
    }

    // INFO(Rafael): Computing the first and the second block.

    buffer_size = H0_size + sizeof(kryptos_u32_t) + sizeof(kryptos_u32_t);

    if ((buffer = (kryptos_u8_t *)kryptos_newseg(buffer_size)) == NULL) {
        goto kryptos_do_argon2_epilogue;
    }

    bp = buffer;
    memcpy(bp, H0, H0_size);

    for (i = 0; i < parallelism; i++) {
        bp = buffer + H0_size;
        j = 0;
        kryptos_argon2_put_u32(bp, j);
        kryptos_argon2_put_u32(bp, i);

        B[i][0].data = kryptos_argon2_H(buffer, buffer_size, KRYPTOS_ARGON2_DATA_SIZE, &B[i][0].data_size);

        bp = buffer + H0_size;
        j = 1;
        kryptos_argon2_put_u32(bp, j);
        kryptos_argon2_put_u32(bp, i);

        B[i][1].data = kryptos_argon2_H(buffer, buffer_size, KRYPTOS_ARGON2_DATA_SIZE, &B[i][1].data_size);
    }

    kryptos_freeseg(buffer, buffer_size);
    buffer = NULL;
    buffer_size = 0;

    // INFO(Rafael): Compressing and filling up the four [i][j .. j_end] segments but skipping B[i][0] and B[i][1].
    //               Here the memory is divided into four parts:
    //
    //               +------------------------------------------------+
    //               |                  Segment length                | <-- [ Always a multiple of four ]
    //               +-----------+------------+-----------+-----------+
    //               | Segment 0 |  Segment 1 | Segment 2 | Segment 3 |
    //               +-----------+------------+-----------+-----------+
    //   [ i=0 ] --> | j = 0, ...| ..., ...,  | ..., ..., | ...,  j_q |
    //     ...       ... --------+------------+-----------+-------- ...
    //   [ i=n ] --> | j = 0, ...| ..., ...,  | ..., ..., | ...,  j_q |
    //               +------------------------------------------------+
    //
    //               We first process the whole cells in segment 0, after 1, 2 and finally segment 3.

    params.version = version;
    params.parallelism = parallelism;
    params.htype = htype;
    params.iterations = iterations;
    params.pr_buf = NULL;
    params.pr_buf_size = 0;

    for (params.iteration = 0; params.iteration < iterations; params.iteration++) {
        for (params.segment = 0; params.segment < 4; params.segment++) {
            for (params.i = 0; params.i < parallelism; params.i++) {
                kryptos_argon2_G(B, &params);
           }
        }
    }

    // INFO(Rafael): XORing the last column.

    if (parallelism > 1) {
        tp_end = B[0][params.col_count - 1].data + B[0][params.col_count - 1].data_size;
        for (i = 1; i < parallelism; i++) {
            tp = B[0][params.col_count - 1].data;
            bp = B[i][params.col_count - 1].data;
            while (tp != tp_end) {
                *tp ^= *bp;
                bp++;
                tp++;
            }
        }
    }

    // INFO(Rafael): Reversing the byte order and getting the final hash.

    cp = &C[0];
    cp_end = cp + sizeof(C);
    tp = B[0][params.col_count - 1].data;
    tp_end = tp + B[0][params.col_count - 1].data_size;

    while (tp != tp_end && cp != cp_end) {
        tt = tp + 7;
        tt_end = tp - 1;
        while (tt != tt_end && cp != cp_end) {
            *cp = *tt;
            cp++;
            tt--;
        }
        tp += 8;
    }

    tag = kryptos_argon2_H(C, sizeof(C), tag_size, NULL);

kryptos_do_argon2_epilogue:

    // INFO(Rafael): Just housekeeping.

    if (buffer != NULL) {
        kryptos_freeseg(buffer, buffer_size);
    }

    buffer_size = 0;

    if (params.pr_buf != NULL) {
        kryptos_freeseg(params.pr_buf, params.pr_buf_size);
        params.pr_buf_size = 0;
    }

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    if (H0 != NULL) {
        kryptos_freeseg(H0, H0_size);
    }

    if (B != NULL) {
        for (i = 0; i < parallelism; i++) {
            for (j = 0; j < params.col_count; j++) {
                if (B[i][j].data != NULL) {
                    kryptos_freeseg(B[i][j].data, B[i][j].data_size);
                }
            }
        }

        for (i = 0; i < parallelism; i++) {
            kryptos_freeseg(B[i], params.col_count * sizeof(struct kryptos_argon2_array_ctx));
        }

        kryptos_freeseg(B, parallelism * sizeof(struct kryptos_argon2_array_ctx *));
    }

    memset(&params, 0, sizeof(params));

    H0 = buffer = bp = tp = tp_end = NULL;
    buffer_size = H0_size = 0;
    i = j = 0;
    B = NULL;

    kryptos_task_init_as_null(ktask);

    return tag;
}

static kryptos_u8_t *kryptos_argon2_H(kryptos_u8_t *h, const size_t h_size,
                                      const kryptos_u32_t digest_size, size_t *a_size) {
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *in, *a = NULL, *in_p, *a_p, *a_p_end, *o, *o_end, *oo, *oo_end;
    size_t in_size, r_sz;

    kryptos_task_init_as_null(ktask);

    in_size = h_size + sizeof(kryptos_u32_t);
    if ((in = (kryptos_u8_t *)kryptos_newseg(in_size)) == NULL) {
        goto kryptos_argon2_H_epilogue;
    }

    in_p = in;

    kryptos_argon2_put_u32(in_p, digest_size);
    memcpy(in_p, h, h_size);

    if (digest_size > 64) {
        kryptos_hash(blake2b512, ktask, in, in_size, 0);
    } else {
        ktask->out_size = digest_size;
        kryptos_hash(blake2bN, ktask, in, in_size, 0);
    }

    if (!kryptos_last_task_succeed(ktask)) {
        goto kryptos_argon2_H_epilogue;
    }

    if (digest_size <= 64) {
        a = ktask->out;
        ktask->out = NULL;
        goto kryptos_argon2_H_epilogue;
    }

    if ((a = (kryptos_u8_t *)kryptos_newseg(digest_size)) == NULL) {
        goto kryptos_argon2_H_epilogue;
    }

    r_sz = digest_size;

    a_p = a;
    a_p_end = a + digest_size;

    while (a_p != a_p_end) {
        o = ktask->out;
        if (r_sz > 64) {
            // INFO(Rafael): Only the first half of the block is picked.
            o_end = o + (ktask->out_size >> 1);
        } else {
            // INFO(Rafael): For the last block we pick the whole (every call for this function asks 1024 byte).
            o_end = o + ktask->out_size;
        }
        while (o != o_end && a_p != a_p_end) {
            // INFO(Rafael): The bytes must be stored in little endian. Let's doing it on our own.
            oo = o + 7;
            oo_end = o - 1;
            while (oo != oo_end && a_p != a_p_end) {
                *a_p = *oo;
                a_p++;
                oo--;
            }
            o += 8;
        }

        r_sz -= 32;

        if (a_p == a_p_end) {
            continue;
        }

        in = ktask->out;
        in_size = ktask->out_size;
        kryptos_task_free(ktask, KRYPTOS_TASK_IN);

        if (r_sz > 64) {
            kryptos_hash(blake2b512, ktask, in, in_size, 0);
        } else {
            ktask->out_size = r_sz;
            kryptos_hash(blake2bN, ktask, in, in_size, 0);
        }

        if (!kryptos_last_task_succeed(ktask)) {
            kryptos_freeseg(a, digest_size);
            a = NULL;
            goto kryptos_argon2_H_epilogue;
        }
    }

kryptos_argon2_H_epilogue:

    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    if (in != NULL) {
        kryptos_freeseg(in, in_size);
    }

    if (a != NULL && a_size != NULL) {
        *a_size = digest_size;
    }

    return a;
}

static void kryptos_argon2_get_indexes(struct kryptos_argon2_array_ctx **B,
                                       kryptos_u8_t *pr_buf, struct kryptos_argon2_params_ctx *params, const size_t j,
                                       const size_t index,
                                       size_t *ii, size_t *jj) {
    kryptos_u32_t J_1, J_2;
    size_t ref_area_size;
    kryptos_u64_t rel_pos, start_pos;

    // INFO(Rafael): This function was based on 'argon2pure.py' by Bas Westerbaan. It gave me the clues,
    //               differing from that pretty messy and textual specification.

    if (pr_buf != NULL) {
        J_2 = ((kryptos_u32_t) pr_buf[0] << 24) |
              ((kryptos_u32_t) pr_buf[1] << 16) |
              ((kryptos_u32_t) pr_buf[2] <<  8) |
              ((kryptos_u32_t) pr_buf[3]      );
        J_1 = ((kryptos_u32_t) pr_buf[4] << 24) |
              ((kryptos_u32_t) pr_buf[5] << 16) |
              ((kryptos_u32_t) pr_buf[6] <<  8) |
              ((kryptos_u32_t) pr_buf[7]      );
    } else {
        J_2 = ((kryptos_u32_t) B[params->i][(j - 1) % params->col_count].data[0] << 24) |
              ((kryptos_u32_t) B[params->i][(j - 1) % params->col_count].data[1] << 16) |
              ((kryptos_u32_t) B[params->i][(j - 1) % params->col_count].data[2] <<  8) |
              ((kryptos_u32_t) B[params->i][(j - 1) % params->col_count].data[3]      );
        J_1 = ((kryptos_u32_t) B[params->i][(j - 1) % params->col_count].data[4] << 24) |
              ((kryptos_u32_t) B[params->i][(j - 1) % params->col_count].data[5] << 16) |
              ((kryptos_u32_t) B[params->i][(j - 1) % params->col_count].data[6] <<  8) |
              ((kryptos_u32_t) B[params->i][(j - 1) % params->col_count].data[7]      );
    }

    *ii = ((params->iteration == 0) && (params->segment == 0)) ? params->i : J_2 % params->parallelism;

    if (params->iteration == 0) {
        if (params->segment == 0 || params->i == *ii) {
            ref_area_size = j - 1;
        } else if (index == 0) {
            ref_area_size = params->segment * params->segment_length - 1;
        } else {
            ref_area_size = params->segment * params->segment_length;
        }
    } else if (params->i == *ii) {
        ref_area_size = params->col_count - params->segment_length + index - 1;
    } else if (index == 0) {
        ref_area_size = params->col_count - params->segment_length - 1;
    } else {
        ref_area_size = params->col_count - params->segment_length;
    }

    rel_pos = ((kryptos_u64_t)J_1 * (kryptos_u64_t)J_1) >> 32;
    rel_pos = ref_area_size - 1 - ((ref_area_size * rel_pos) >> 32);
    start_pos = 0;

    if (params->iteration != 0 && params->segment != 3) {
        start_pos = (params->segment + 1) * params->segment_length;
    }

#if defined(KRYPTOS_KERNEL_MODE) && defined(__linux__)
    start_pos += rel_pos;
    *jj = do_div(start_pos, params->col_count);
#else
    *jj = (start_pos + rel_pos) % params->col_count;
#endif

    J_1 = J_2 = 0;
    rel_pos = start_pos = ref_area_size = 0;
}

static void kryptos_argon2_G(struct kryptos_argon2_array_ctx **B, struct kryptos_argon2_params_ctx *params) {
    size_t ii, jj, lj, pr_buf_size;
    kryptos_u8_t pr_buf[KRYPTOS_ARGON2_DATA_SIZE], *pr_p, *pr_p_end;
    static kryptos_u8_t zero_buf[KRYPTOS_ARGON2_DATA_SIZE];
    int is_di;
    size_t index, j;
    kryptos_u32_t ctr;

    is_di = (params->htype == kArgon2i || (params->htype == kArgon2id && params->iteration == 0 && params->segment <= 1));

#define kryptos_argon2_put_u64(d, s) {\
        (d)[7] = (((kryptos_u64_t)(s))      ) & 0xFF;\
        (d)[6] = (((kryptos_u64_t)(s)) >>  8) & 0xFF;\
        (d)[5] = (((kryptos_u64_t)(s)) >> 16) & 0xFF;\
        (d)[4] = (((kryptos_u64_t)(s)) >> 24) & 0xFF;\
        (d)[3] = (((kryptos_u64_t)(s)) >> 32) & 0xFF;\
        (d)[2] = (((kryptos_u64_t)(s)) >> 40) & 0xFF;\
        (d)[1] = (((kryptos_u64_t)(s)) >> 48) & 0xFF;\
        (d)[0] = (((kryptos_u64_t)(s)) >> 56) & 0xFF;\
        (d) += 8;\
}

#define kryptos_argon2_GB2(x, x_size, y, y_size) {\
        kryptos_argon2_GB(&x, &x_size, x, x_size, y, y_size, NULL);\
        kryptos_argon2_GB(&x, &x_size, x, x_size, y, y_size, NULL);\
}

    if (is_di) {
        // INFO(Rafael): It will avoid stressing up the memory manager with a bunch of allocations and deallocations for
        //               each kryptos_argon2_G() call.
        if (params->pr_buf == NULL) {
            params->pr_buf_size = params->segment_length << 3; // INFO(Rafael): Because we need J_1 and J_2.
            if ((params->pr_buf = (kryptos_u8_t *)kryptos_newseg(params->pr_buf_size)) == NULL) {
                return;
            }
        }

        // WARN(Rafael): In general, during the iteration 0 it will compute two not used pseudo rands. Maybe it should be
        //               improved.

        ctr = 1;
        index = 0;

        while (index < params->pr_buf_size) {
            if (params->iteration == 0) {
                memset(zero_buf, 0, sizeof(zero_buf));
            }

            // INFO(Rafael): Filling up the buffer following this data layout: 'r || l || s || m' || t || x || i || 968 zeros'.
            //               Each variable has 8 bytes...

            pr_p = &pr_buf[0];
            kryptos_argon2_put_u64(pr_p, params->iteration);
            kryptos_argon2_put_u64(pr_p, params->i);
            kryptos_argon2_put_u64(pr_p, params->segment);
            kryptos_argon2_put_u64(pr_p, params->mm);
            kryptos_argon2_put_u64(pr_p, params->iterations);
            kryptos_argon2_put_u64(pr_p, params->htype);
            kryptos_argon2_put_u64(pr_p, ctr++);
            memset(pr_p, 0, KRYPTOS_ARGON2_DATA_SIZE - 56);

            pr_p = &pr_buf[0];
            pr_buf_size = sizeof(pr_buf);
            pr_p_end = pr_p + pr_buf_size;
            kryptos_argon2_GB2(pr_p, pr_buf_size, zero_buf, sizeof(zero_buf));

            while (index < params->pr_buf_size && pr_p != pr_p_end) {
                params->pr_buf[index] = *pr_p;
                pr_p++;
                index++;
            }
        }

        memset(pr_buf, 0, sizeof(pr_buf));
        params->next_pr_chunk = &params->pr_buf[0];
    }

#undef kryptos_argon2_GB2

#undef kryptos_argon2_put_u64

    for (index = 0; index < params->segment_length; index++) {
        j = params->segment * params->segment_length + index;

        if (params->iteration == 0 && j < 2) {
            // INFO(Rafael): Blocks B[i][0] and B[i][1] are already computed.
            continue;
        }

        kryptos_argon2_get_indexes(B, (is_di) ? params->next_pr_chunk : NULL, params, j, index, &ii, &jj);

        lj = (params->iteration == 0 || j != 0) ? j - 1 : params->col_count - 1;

        // INFO(Rafael): Sizes here are always 1024 bytes anyway let's pass it indirectly.
        kryptos_argon2_GB(&B[params->i][j].data, &B[params->i][j].data_size,
                          B[params->i][lj].data, B[params->i][lj].data_size, B[ii][jj].data, B[ii][jj].data_size, params);

        if (is_di) {
            params->next_pr_chunk += 8;
        }
    }

    ii = jj = lj = 0;
}

static void kryptos_argon2_GB(kryptos_u8_t **z, size_t *z_size,
                              const kryptos_u8_t *x, const size_t x_size, const kryptos_u8_t *y, const size_t y_size,
                              struct kryptos_argon2_params_ctx *params) {
    // INFO(Rafael): Understand "B" here as the actually G function's body.
    kryptos_u8_t *zp, *zp_end, temp_z[KRYPTOS_ARGON2_DATA_SIZE], *tpz_p, *tpz_p_end;
    const kryptos_u8_t *yp, *yp_end, *xp, *xp_end;
    struct R_ctx {
        kryptos_u8_t data[16];
    } R[64];
    size_t r, d;
    int do_xor = 0;

    if ((*z) == NULL) {
        // INFO(Rafael): Due to cost issues let's allocate memory once during the whole processing.
        if (((*z) = (kryptos_u8_t *)kryptos_newseg(KRYPTOS_ARGON2_DATA_SIZE)) != NULL) {
            *z_size = KRYPTOS_ARGON2_DATA_SIZE;
        } else {
            *z_size = 0;
        }
    } else if ((do_xor = (params != NULL && params->version == 0x13 && params->iteration != 0)) != 0) {
        // INFO(Rafael): params->iteration != 0 is useless here because every block at iteration zero will be NULL,
        //               anyway, let's follow the original algorithm condition.
        memcpy(temp_z, *z, *z_size);
    }

    if ((*z) != NULL) {
        // INFO(Rafael): XOR.

        zp = *z;
        zp_end = zp + *z_size;

        xp = x;
        xp_end = xp + x_size;

        yp = y;
        yp_end = yp + y_size; // INFO(Rafael): Always expected 1024 bytes.

        while (xp != xp_end) {
            *zp = *xp ^ *yp;
            xp++;
            yp++;
            zp++;
        }

        zp = *z;

        for (r = 0; r < 64; r++) {
            for (d = 0; d < 16; d++) {
                R[r].data[d] = *zp;
                zp++;
            }
        }

        // INFO(Rafael): Applying P rowwise.

        kryptos_argon2_P(R[ 0].data, R[ 1].data, R[ 2].data, R[ 3].data, R[ 4].data, R[ 5].data, R[ 6].data, R[ 7].data);
        kryptos_argon2_P(R[ 8].data, R[ 9].data, R[10].data, R[11].data, R[12].data, R[13].data, R[14].data, R[15].data);
        kryptos_argon2_P(R[16].data, R[17].data, R[18].data, R[19].data, R[20].data, R[21].data, R[22].data, R[23].data);
        kryptos_argon2_P(R[24].data, R[25].data, R[26].data, R[27].data, R[28].data, R[29].data, R[30].data, R[31].data);
        kryptos_argon2_P(R[32].data, R[33].data, R[34].data, R[35].data, R[36].data, R[37].data, R[38].data, R[39].data);
        kryptos_argon2_P(R[40].data, R[41].data, R[42].data, R[43].data, R[44].data, R[45].data, R[46].data, R[47].data);
        kryptos_argon2_P(R[48].data, R[49].data, R[50].data, R[51].data, R[52].data, R[53].data, R[54].data, R[55].data);
        kryptos_argon2_P(R[56].data, R[57].data, R[58].data, R[59].data, R[60].data, R[61].data, R[62].data, R[63].data);

        // INFO(Rafael): Applying P columnwise.

        kryptos_argon2_P(R[ 0].data, R[ 8].data, R[16].data, R[24].data, R[32].data, R[40].data, R[48].data, R[56].data);
        kryptos_argon2_P(R[ 1].data, R[ 9].data, R[17].data, R[25].data, R[33].data, R[41].data, R[49].data, R[57].data);
        kryptos_argon2_P(R[ 2].data, R[10].data, R[18].data, R[26].data, R[34].data, R[42].data, R[50].data, R[58].data);
        kryptos_argon2_P(R[ 3].data, R[11].data, R[19].data, R[27].data, R[35].data, R[43].data, R[51].data, R[59].data);
        kryptos_argon2_P(R[ 4].data, R[12].data, R[20].data, R[28].data, R[36].data, R[44].data, R[52].data, R[60].data);
        kryptos_argon2_P(R[ 5].data, R[13].data, R[21].data, R[29].data, R[37].data, R[45].data, R[53].data, R[61].data);
        kryptos_argon2_P(R[ 6].data, R[14].data, R[22].data, R[30].data, R[38].data, R[46].data, R[54].data, R[62].data);
        kryptos_argon2_P(R[ 7].data, R[15].data, R[23].data, R[31].data, R[39].data, R[47].data, R[55].data, R[63].data);

        zp = *z;
        for (r = 0; r < 64; r++) {
            for (d = 0; d < 16; d++) {
                *zp ^= R[r].data[d];
                zp++;
            }
        }

        if (do_xor) {
            // INFO(Rafael): Argon2 version 19 (0x13) includes this final xoring for iterations greater than zero.
            //               The specification does not make it clearer. You need to grasp into the reference implemention...
            zp = *z;
            tpz_p = &temp_z[0];
            tpz_p_end = tpz_p + sizeof(temp_z);

            while (tpz_p != tpz_p_end) {
                *zp ^= *tpz_p;
                *tpz_p = 0x0;
                zp++;
                tpz_p++;
            }
        }

        memset(R, 0, sizeof(R));
    }

    zp = zp_end = NULL;
    xp = xp_end = yp = yp_end = NULL;
}

static void kryptos_argon2_P(kryptos_u8_t *s0, kryptos_u8_t *s1, kryptos_u8_t *s2, kryptos_u8_t *s3,
                             kryptos_u8_t *s4, kryptos_u8_t *s5, kryptos_u8_t *s6, kryptos_u8_t *s7) {

    // INFO(Rafael): Each argument is a 16-byte array.

    kryptos_u64_t v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15;

    // INFO(Rafael): The relationship between S and V is given by: s_i = (v_2_{i+1}||v_2_i).

#define kryptos_argon2_S2V(sn, vh, vl) {\
    vl = ((kryptos_u64_t) sn[ 0] << 56) |\
         ((kryptos_u64_t) sn[ 1] << 48) |\
         ((kryptos_u64_t) sn[ 2] << 40) |\
         ((kryptos_u64_t) sn[ 3] << 32) |\
         ((kryptos_u64_t) sn[ 4] << 24) |\
         ((kryptos_u64_t) sn[ 5] << 16) |\
         ((kryptos_u64_t) sn[ 6] <<  8) |\
         ((kryptos_u64_t) sn[ 7]      );\
    vh = ((kryptos_u64_t) sn[ 8] << 56) |\
         ((kryptos_u64_t) sn[ 9] << 48) |\
         ((kryptos_u64_t) sn[10] << 40) |\
         ((kryptos_u64_t) sn[11] << 32) |\
         ((kryptos_u64_t) sn[12] << 24) |\
         ((kryptos_u64_t) sn[13] << 16) |\
         ((kryptos_u64_t) sn[14] <<  8) |\
         ((kryptos_u64_t) sn[15]      );\
}

    kryptos_argon2_S2V(s0,  v1,  v0); // INFO(Rafael): S0 = ( v1 ||  v0).
    kryptos_argon2_S2V(s1,  v3,  v2); // INFO(Rafael): S1 = ( v3 ||  v2).
    kryptos_argon2_S2V(s2,  v5,  v4); // INFO(Rafael): S2 = ( v5 ||  v4).
    kryptos_argon2_S2V(s3,  v7,  v6); // INFO(Rafael): S3 = ( v7 ||  v6).
    kryptos_argon2_S2V(s4,  v9,  v8); // INFO(Rafael): S4 = ( v9 ||  v8).
    kryptos_argon2_S2V(s5, v11, v10); // INFO(Rafael): S5 = (v11 || v10).
    kryptos_argon2_S2V(s6, v13, v12); // INFO(Rafael): S6 = (v13 || v12).
    kryptos_argon2_S2V(s7, v15, v14); // INFO(Rafael): S7 = (v15 || v14).

#undef kryptos_argon2_S2V

    // INFO(Rafael): The P function based on Blake2.

#define kryptos_argon2_rr(x, n) ( ( (x) >> (n) ) | ( (x) << (64 - (n)) ) )

#define kryptos_argon2_xl(x) ( (x) & 0xFFFFFFFF )

#define kryptos_argon2_p(a, b, c, d) {\
    (a) = (a) + (b) + ((kryptos_argon2_xl(a) * kryptos_argon2_xl(b)) << 1);\
    (d) = kryptos_argon2_rr((d) ^ (a), 32);\
    (c) = (c) + (d) + ((kryptos_argon2_xl(c) * kryptos_argon2_xl(d)) << 1);\
    (b) = kryptos_argon2_rr((b) ^ (c), 24);\
    (a) = (a) + (b) + ((kryptos_argon2_xl(a) * kryptos_argon2_xl(b)) << 1);\
    (d) = kryptos_argon2_rr((d) ^ (a), 16);\
    (c) = (c) + (d) + ((kryptos_argon2_xl(c) * kryptos_argon2_xl(d)) << 1);\
    (b) = kryptos_argon2_rr((b) ^ (c), 63);\
}

    kryptos_argon2_p(v0, v4,  v8, v12);
    kryptos_argon2_p(v1, v5,  v9, v13);
    kryptos_argon2_p(v2, v6, v10, v14);
    kryptos_argon2_p(v3, v7, v11, v15);
    kryptos_argon2_p(v0, v5, v10, v15);
    kryptos_argon2_p(v1, v6, v11, v12);
    kryptos_argon2_p(v2, v7,  v8, v13);
    kryptos_argon2_p(v3, v4,  v9, v14);

#undef kryptos_argon2_p

#undef kryptos_argon2_xl

#undef kryptos_argon2_rr

#define kryptos_argon2_V2S(vh, vl, sn) {\
    sn[ 0] = (vl >> 56) & 0xFF;\
    sn[ 1] = (vl >> 48) & 0xFF;\
    sn[ 2] = (vl >> 40) & 0xFF;\
    sn[ 3] = (vl >> 32) & 0xFF;\
    sn[ 4] = (vl >> 24) & 0xFF;\
    sn[ 5] = (vl >> 16) & 0xFF;\
    sn[ 6] = (vl >>  8) & 0xFF;\
    sn[ 7] =  vl        & 0xFF;\
    sn[ 8] = (vh >> 56) & 0xFF;\
    sn[ 9] = (vh >> 48) & 0xFF;\
    sn[10] = (vh >> 40) & 0xFF;\
    sn[11] = (vh >> 32) & 0xFF;\
    sn[12] = (vh >> 24) & 0xFF;\
    sn[13] = (vh >> 16) & 0xFF;\
    sn[14] = (vh >>  8) & 0xFF;\
    sn[15] =  vh        & 0xFF;\
}

    kryptos_argon2_V2S( v1,  v0, s0); // INFO(Rafael): S0 = ( v1 ||  v0).
    kryptos_argon2_V2S( v3,  v2, s1); // INFO(Rafael): S1 = ( v3 ||  v2).
    kryptos_argon2_V2S( v5,  v4, s2); // INFO(Rafael): S2 = ( v5 ||  v4).
    kryptos_argon2_V2S( v7,  v6, s3); // INFO(Rafael): S3 = ( v7 ||  v6).
    kryptos_argon2_V2S( v9,  v8, s4); // INFO(Rafael): S4 = ( v9 ||  v8).
    kryptos_argon2_V2S(v11, v10, s5); // INFO(Rafael): S5 = (v11 || v10).
    kryptos_argon2_V2S(v13, v12, s6); // INFO(Rafael): S6 = (v13 || v12).
    kryptos_argon2_V2S(v15, v14, s7); // INFO(Rafael): S7 = (v15 || v14).


#undef kryptos_argon2_V2S

    v0 = v1 =  v2 =  v3 =  v4 =  v5 =  v6 =  v7 =
    v8 = v9 = v10 = v11 = v12 = v13 = v14 = v15 = 0;
}

#undef KRYPTOS_ARGON2_PASSWORD_MAX_SIZE
#undef KRYPTOS_ARGON2_SALT_MAX_SIZE
#undef KRYPTOS_ARGON2_PARALLELISM_MAX_SIZE
#undef KRYPTOS_ARGON2_TAG_MAX_SIZE
#undef KRYPTOS_ARGON2_MEMORY_SIZE_KB_MAX_SIZE
#undef KRYPTOS_ARGON2_ITERATIONS_MAX_SIZE
#undef KRYPTOS_ARGON2_KEY_MAX_SIZE
#undef KRYPTOS_ARGON2_ASSOCIATED_DATA_MAX_SIZE

#undef kryptos_argon2_check_size_bounds

#undef kryptos_argon2_put_u32

#undef KRYPTOS_ARGON2_DATA_SIZE

#if defined(KRYPTOS_KERNEL_MODE) && defined(_WIN32)
# pragma warning(pop)
#endif

#endif
