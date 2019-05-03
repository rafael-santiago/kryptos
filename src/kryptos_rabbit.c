/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_rabbit.h>
#include <kryptos_memory.h>
#include <kryptos_endianness_utils.h>
#include <kryptos.h>

// WARN(Rafael): This implementation is intended for little-endian machines.

// INFO(Rafael): Rabbit's internal constants.

#define KRYPTOS_RABBIT_A0 0x4D34D34D
#define KRYPTOS_RABBIT_A1 0xD34D34D3
#define KRYPTOS_RABBIT_A2 0x34D34D34
#define KRYPTOS_RABBIT_A3 0x4D34D34D
#define KRYPTOS_RABBIT_A4 0xD34D34D3
#define KRYPTOS_RABBIT_A5 0x34D34D34
#define KRYPTOS_RABBIT_A6 0x4D34D34D
#define KRYPTOS_RABBIT_A7 0xD34D34D3

#define KRYPTOS_RABBIT_WORDSIZE 0x100000000

#define kryptos_rabbit_rol(x, s) ( ((x) << (s)) | ((x) >> (32 - (s))) )

#define kryptos_rabbit_lsw(w) ( (w) & 0xFFFFFFFF )

#define kryptos_rabbit_msw(w) ( (w) >> 32 )

// TODO(Rafael): Maybe it should be improved.
#define kryptos_rabbit_square(u, v) ( (((u) + (v)) % KRYPTOS_RABBIT_WORDSIZE) * (((u) + (v)) % KRYPTOS_RABBIT_WORDSIZE) )

#define kryptos_rabbit_g(u, v) (  kryptos_rabbit_lsw(kryptos_rabbit_square(u, v)) ^\
                                  kryptos_rabbit_msw(kryptos_rabbit_square(u, v)) )

#define kryptos_rabbit_iter(sks) {\
    kryptos_rabbit_ctr_system(sks);\
    kryptos_rabbit_nxt_state_func(sks);\
}

#define kryptos_rabbit_extract(S, sks) {\
    kryptos_rabbit_iter(sks);\
    S[1] = ((kryptos_u64_t)((sks->X[0] & 0xFFFF) ^ ((sks->X[5] >> 16) & 0xFFFF)) <<  0) |\
           ((kryptos_u64_t)(((sks->X[0] >> 16) & 0xFFFF) ^ (sks->X[3] & 0xFFFF)) << 16) |\
           ((kryptos_u64_t)((sks->X[2] & 0xFFFF) ^ ((sks->X[7] >> 16) & 0xFFFF)) << 32) |\
           ((kryptos_u64_t)(((sks->X[2] >> 16) & 0xFFFF) ^ (sks->X[5] & 0xFFFF)) << 48);\
    S[0] = ((kryptos_u64_t)((sks->X[4] & 0xFFFF) ^ ((sks->X[1] >> 16) & 0xFFFF)) <<  0) |\
           ((kryptos_u64_t)(((sks->X[4] >> 16) & 0xFFFF) ^ (sks->X[7] & 0xFFFF)) << 16) |\
           ((kryptos_u64_t)((sks->X[6] & 0xFFFF) ^ ((sks->X[3] >> 16) & 0xFFFF)) << 32) |\
           ((kryptos_u64_t)((((sks->X[6] >> 16) & 0xFFFF) ^ (sks->X[1] & 0xFFFF))) << 48);\
}

#define kryptos_rabbit_rev64(w) ( ((w) >> 56)                      |\
                                  (((w) >> 40) & 0xFF00)           |\
                                  (((w) >> 24) & 0xFF0000)         |\
                                  (((w) >>  8) & 0xFF000000)       |\
                                  (((w) <<  8) & 0xFF00000000)     |\
                                  (((w) << 24) & 0xFF0000000000)   |\
                                  (((w) << 40) & 0xFF000000000000) |\
                                  ((w) << 56) )

struct kryptos_rabbit_keystream {
    kryptos_u32_t X[8];
    kryptos_u32_t C[8];
    kryptos_u8_t b:1;
};

static void kryptos_rabbit_key_setup(const kryptos_u8_t *key, const size_t key_size, const kryptos_u8_t *iv64,
                                     struct kryptos_rabbit_keystream *sks);

static void kryptos_rabbit_ld_user_key(kryptos_u16_t *K, const kryptos_u8_t *key, const size_t key_size);

static void kryptos_rabbit_ctr_system(struct kryptos_rabbit_keystream *sks);

static void kryptos_rabbit_nxt_state_func(struct kryptos_rabbit_keystream *sks);

static void kryptos_rabbit_xor(kryptos_u8_t *block, struct kryptos_rabbit_keystream *sks);

/*
static void print_rabbit_state(struct kryptos_rabbit_keystream *sks) {
    size_t i;

    printf("b = %d\n\n", sks->b);
    for (i = 0; i < 8; i++) {
        printf("X%d = 0x%.8X\n", i, sks->X[i]);
    }
    printf("\n");
    for (i = 0; i < 8; i++) {
        printf("C%d = 0x%.8X\n", i, sks->C[i]);
    }
//    exit(1);
}
*/

void kryptos_rabbit_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size, kryptos_u8_t *iv64) {
    if (ktask == NULL) {
        return;
    }

    ktask->key = key;
    ktask->key_size = key_size;
    ktask->cipher = kKryptosCipherRABBIT;
    ktask->iv = iv64;
    // INFO(Rafael): Actually it is never used but we are signaling for 'the finder party' how much bytes
    //               there are into the iv buffer or at least would be expected.
    ktask->iv_size = KRYPTOS_RABBIT_BLOCKSIZE >> 1;
}

void kryptos_rabbit_cipher(kryptos_task_ctx **ktask) {
    struct kryptos_rabbit_keystream sks;
    size_t o;
    kryptos_u8_t outblock[KRYPTOS_RABBIT_BLOCKSIZE], *in_p, *in_p_end, *out_p;

    if (ktask == NULL) {
        return;
    }

    (*ktask)->out_size = (*ktask)->in_size;
    (*ktask)->out = (kryptos_u8_t *) kryptos_newseg((*ktask)->out_size);

    if ((*ktask)->out == NULL) {
        (*ktask)->result = kKryptosProcessError;
        (*ktask)->result_verbose = "No memory to get a valid output.";
        return;
    }

    (*ktask)->result = kKryptosSuccess;

    kryptos_rabbit_key_setup((*ktask)->key, (*ktask)->key_size, (*ktask)->iv, &sks);

    in_p = (*ktask)->in;
    in_p_end = in_p + (*ktask)->in_size;
    out_p = (*ktask)->out;
    o = 0;
    while (in_p != in_p_end) {
        outblock[o++] = *in_p;
        in_p++;
        if (o == KRYPTOS_RABBIT_BLOCKSIZE || in_p == in_p_end) {
            kryptos_rabbit_xor(outblock, &sks);
            memcpy(out_p, outblock, o);
            out_p += KRYPTOS_RABBIT_BLOCKSIZE;
            o = 0;
        }
    }

    outblock[ 0] = outblock[ 1] = outblock[ 2] = outblock[ 3] =
    outblock[ 4] = outblock[ 5] = outblock[ 6] = outblock[ 7] =
    outblock[ 8] = outblock[ 9] = outblock[10] = outblock[11] =
    outblock[12] = outblock[13] = outblock[14] = outblock[15] = 0;

    sks.b = 0;
    memset(sks.X, 0, sizeof(kryptos_u32_t) << 3);
    memset(sks.C, 0, sizeof(kryptos_u32_t) << 3);
    in_p = in_p_end = out_p = NULL;
    o = 0;
}

static void kryptos_rabbit_ld_user_key(kryptos_u16_t *K, const kryptos_u8_t *key, const size_t key_size) {
    const kryptos_u8_t *kp, *kp_end;
    kryptos_u16_t KK[8];
#if defined(__GNUC__)
    // WARN(Rafael): The longjmp generated by the goto escape statement in the kryptos_ld_user_key_prologue, may
    //               deceive GCC making he warns about 'b' and 'w' be uninitialized. Those useless assignments
    //               are just for silenting the warning.
    size_t w = 0, b = 0;
#else
    size_t w, b;
#endif
    ssize_t k;
    kryptos_u8_t *ktemp;

    ktemp = (kryptos_u8_t *)kryptos_newseg(key_size);

    if (ktemp == NULL) {
#if defined(__FreeBSD__) && defined(KRYPTOS_KERNEL_MODE)
        ktemp = (kryptos_u8_t *)(intptr_t)key;
#else
        ktemp = (kryptos_u8_t *)key;
#endif
    } else {
        for (k = key_size - 1; k >= 0; k--) {
            ktemp[key_size - k - 1] = key[k];
        }
    }

    kryptos_ld_user_key_prologue(KK, 8, ktemp, key_size, kp, kp_end, w, b, goto kryptos_rabbit_ld_user_key_epilogue);

    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(KK, w, b, kp, kp_end, kryptos_rabbit_ld_user_key_epilogue);

    kryptos_ld_user_key_epilogue(kryptos_rabbit_ld_user_key_epilogue, KK, w, b, kp, kp_end);

    if (ktemp != NULL && ktemp != key) {
        kryptos_freeseg(ktemp, key_size);
    }

    // INFO(Rafael): This algorithm follows the I2OSP convention from PKCS#1.
    K[0] = KK[7];
    K[1] = KK[6];
    K[2] = KK[5];
    K[3] = KK[4];
    K[4] = KK[3];
    K[5] = KK[2];
    K[6] = KK[1];
    K[7] = KK[0];

    memset(KK, 0, sizeof(kryptos_u16_t) << 3);
}


static void kryptos_rabbit_key_setup(const kryptos_u8_t *key, const size_t key_size, const kryptos_u8_t *iv64,
                                     struct kryptos_rabbit_keystream *sks) {
    kryptos_u16_t K[8];
    kryptos_u64_t iv;
    kryptos_u32_t IV[4];

    kryptos_rabbit_ld_user_key(K, key, key_size);

    sks->b = 0;

#define kryptos_rabbit_init_state_round(sks, K, j) {\
    if (((j) & 0x1) == 0) {\
        (sks)->X[(j)] = ((kryptos_u32_t)(K)[((j) + 1) & 0x7] << 16) | (K)[(j)];\
        (sks)->C[(j)] = ((kryptos_u32_t)(K)[((j) + 4) & 0x7] << 16) | (K)[((j) + 5) & 0x7];\
    } else {\
        (sks)->X[(j)] = ((kryptos_u32_t)(K)[((j) + 5) & 0x7] << 16) | (K)[((j) + 4) & 0x7];\
        (sks)->C[(j)] = ((kryptos_u32_t)(K)[(j)] << 16) | (K)[((j) + 1) & 0x7];\
    }\
}

    kryptos_rabbit_init_state_round(sks, K, 0);
    kryptos_rabbit_init_state_round(sks, K, 1);
    kryptos_rabbit_init_state_round(sks, K, 2);
    kryptos_rabbit_init_state_round(sks, K, 3);
    kryptos_rabbit_init_state_round(sks, K, 4);
    kryptos_rabbit_init_state_round(sks, K, 5);
    kryptos_rabbit_init_state_round(sks, K, 6);
    kryptos_rabbit_init_state_round(sks, K, 7);

    memset(K, 0, sizeof(kryptos_u16_t) << 3);

    // INFO(Rafael: 'The system is then iterated four times, each iteration consisting of
    //               counter update (Section 2.5) and next-state function (Section 2.6).'

    kryptos_rabbit_iter(sks);
    kryptos_rabbit_iter(sks);
    kryptos_rabbit_iter(sks);
    kryptos_rabbit_iter(sks);

#define kryptos_rabbit_reinit_ctr_regs(sks, j) {\
    (sks)->C[(j)] ^= (sks)->X[((j) + 4) & 0x7];\
}

    kryptos_rabbit_reinit_ctr_regs(sks, 0);
    kryptos_rabbit_reinit_ctr_regs(sks, 1);
    kryptos_rabbit_reinit_ctr_regs(sks, 2);
    kryptos_rabbit_reinit_ctr_regs(sks, 3);
    kryptos_rabbit_reinit_ctr_regs(sks, 4);
    kryptos_rabbit_reinit_ctr_regs(sks, 5);
    kryptos_rabbit_reinit_ctr_regs(sks, 6);
    kryptos_rabbit_reinit_ctr_regs(sks, 7);

    if (iv64 != NULL) {
        // INFO(Rafael): IV setup.
        iv = ((kryptos_u64_t)iv64[7] << 56) |
             ((kryptos_u64_t)iv64[6] << 48) |
             ((kryptos_u64_t)iv64[5] << 40) |
             ((kryptos_u64_t)iv64[4] << 32) |
             ((kryptos_u64_t)iv64[3] << 24) |
             ((kryptos_u64_t)iv64[2] << 16) |
             ((kryptos_u64_t)iv64[1] <<  8) |
             (kryptos_u64_t)iv64[0];

        IV[0] = iv & 0x00000000FFFFFFFF;
        IV[1] = ((iv >> 48) << 16) | ((iv >> 16) & 0xFFFF);
        IV[2] = iv >> 32;
        IV[3] = (((iv >> 32) & 0xFFFF) << 16) | (iv & 0xFFFF);

        sks->C[0] ^= IV[0];
        sks->C[1] ^= IV[1];
        sks->C[2] ^= IV[2];
        sks->C[3] ^= IV[3];
        sks->C[4] ^= IV[0];
        sks->C[5] ^= IV[1];
        sks->C[6] ^= IV[2];
        sks->C[7] ^= IV[3];

        IV[0] = IV[1] = IV[2] = IV[3] = 0;
        iv = 0;

        // INFO(Rafael): 'The system is then iterated another 4 times, each iteration
        //                consisting of counter update (Section 2.5) and next-state function
        //                (Section 2.6).'

        kryptos_rabbit_iter(sks);
        kryptos_rabbit_iter(sks);
        kryptos_rabbit_iter(sks);
        kryptos_rabbit_iter(sks);
    }

#undef kryptos_rabbit_reinit_ctr_regs

#undef kryptos_rabbit_init_state_round
}

static void kryptos_rabbit_ctr_system(struct kryptos_rabbit_keystream *sks) {
    kryptos_u32_t A[8] = {
        KRYPTOS_RABBIT_A0, KRYPTOS_RABBIT_A1, KRYPTOS_RABBIT_A2, KRYPTOS_RABBIT_A3,
        KRYPTOS_RABBIT_A4, KRYPTOS_RABBIT_A5, KRYPTOS_RABBIT_A6, KRYPTOS_RABBIT_A7
    };
    kryptos_u32_t temp;

#define kryptos_rabbit_ctr_system_update_round(sks, A, j, temp) {\
    (temp) = (sks)->C[(j)] + (A)[(j)] + (sks)->b;\
    (sks)->b = (temp) < (sks)->C[(j)];\
    (sks)->C[(j)] = (temp);\
}

    kryptos_rabbit_ctr_system_update_round(sks, A, 0, temp);
    kryptos_rabbit_ctr_system_update_round(sks, A, 1, temp);
    kryptos_rabbit_ctr_system_update_round(sks, A, 2, temp);
    kryptos_rabbit_ctr_system_update_round(sks, A, 3, temp);
    kryptos_rabbit_ctr_system_update_round(sks, A, 4, temp);
    kryptos_rabbit_ctr_system_update_round(sks, A, 5, temp);
    kryptos_rabbit_ctr_system_update_round(sks, A, 6, temp);
    kryptos_rabbit_ctr_system_update_round(sks, A, 7, temp);

    temp = 0;
    memset(A, 0, sizeof(kryptos_u32_t) << 3);

#undef kryptos_rabbit_ctr_system_update_round
}

static void kryptos_rabbit_nxt_state_func(struct kryptos_rabbit_keystream *sks) {
    kryptos_u32_t G[8];

    G[0] = kryptos_rabbit_g(sks->X[0], sks->C[0]);
    G[1] = kryptos_rabbit_g(sks->X[1], sks->C[1]);
    G[2] = kryptos_rabbit_g(sks->X[2], sks->C[2]);
    G[3] = kryptos_rabbit_g(sks->X[3], sks->C[3]);
    G[4] = kryptos_rabbit_g(sks->X[4], sks->C[4]);
    G[5] = kryptos_rabbit_g(sks->X[5], sks->C[5]);
    G[6] = kryptos_rabbit_g(sks->X[6], sks->C[6]);
    G[7] = kryptos_rabbit_g(sks->X[7], sks->C[7]);

    sks->X[0] = G[0] + kryptos_rabbit_rol(G[7], 16) + kryptos_rabbit_rol(G[6], 16);
    sks->X[1] = G[1] + kryptos_rabbit_rol(G[0],  8) + G[7];
    sks->X[2] = G[2] + kryptos_rabbit_rol(G[1], 16) + kryptos_rabbit_rol(G[0], 16);
    sks->X[3] = G[3] + kryptos_rabbit_rol(G[2],  8) + G[1];
    sks->X[4] = G[4] + kryptos_rabbit_rol(G[3], 16) + kryptos_rabbit_rol(G[2], 16);
    sks->X[5] = G[5] + kryptos_rabbit_rol(G[4],  8) + G[3];
    sks->X[6] = G[6] + kryptos_rabbit_rol(G[5], 16) + kryptos_rabbit_rol(G[4], 16);
    sks->X[7] = G[7] + kryptos_rabbit_rol(G[6],  8) + G[5];

    memset(G, 0, sizeof(kryptos_u32_t) << 3);
}

static void kryptos_rabbit_xor(kryptos_u8_t *block, struct kryptos_rabbit_keystream *sks) {
    kryptos_u64_t B[2], S[2];

    B[0] = kryptos_rabbit_rev64(kryptos_get_u64_as_big_endian(block + 8, 8));
    B[1] = kryptos_rabbit_rev64(kryptos_get_u64_as_big_endian(block, 8));

    kryptos_rabbit_extract(S, sks);

    B[0] ^= S[0];
    B[1] ^= S[1];

    kryptos_cpy_u64_as_big_endian(block, 16, kryptos_rabbit_rev64(B[1]));
    kryptos_cpy_u64_as_big_endian(block + 8, 8, kryptos_rabbit_rev64(B[0]));

    S[0] = S[1] = B[0] = B[1] = 0;
}

#undef KRYPTOS_RABBIT_WORDSIZE

#undef KRYPTOS_RABBIT_A0
#undef KRYPTOS_RABBIT_A1
#undef KRYPTOS_RABBIT_A2
#undef KRYPTOS_RABBIT_A3
#undef KRYPTOS_RABBIT_A4
#undef KRYPTOS_RABBIT_A5
#undef KRYPTOS_RABBIT_A6
#undef KRYPTOS_RABBIT_A7

#undef kryptos_rabbit_rol

#undef kryptos_rabbit_lsw

#undef kryptos_rabbit_msw

#undef kryptos_rabbit_square

#undef kryptos_rabbit_g

#undef kryptos_rabbit_iter

#undef kryptos_rabbit_extract

#undef kryptos_rabbit_rev64
