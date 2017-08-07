/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_feal.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define KRYPTOS_FEAL_MAX 801

#define kryptos_feal_rotl2(x) (kryptos_u8_t) (x) << 2 | (kryptos_u8_t) (x) >> ((sizeof(x) << 3) - 2)

#define kryptos_feal_get_byte_from_u32(w, n) ( ( (w) >> (24 - ((n) << 3)) ) & 0xff )

#define kryptos_feal_get_byte_from_u16(w, n) ( ( (w) >> (8 - ((n) << 3)) ) & 0xff )

struct kryptos_feal_subkeys {
 kryptos_u16_t K[KRYPTOS_FEAL_MAX];
 int rounds;
};

typedef void (*kryptos_feal_block_processor)(kryptos_u8_t *block, const struct kryptos_feal_subkeys *sks);

static kryptos_u8_t kryptos_feal_Sd(kryptos_u8_t T, kryptos_u8_t U, int d);

static kryptos_u32_t kryptos_feal_fK(kryptos_u32_t V, kryptos_u32_t W);

static void kryptos_feal_ld_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_feal_expand_key(const kryptos_u8_t *key, const size_t key_size, struct kryptos_feal_subkeys *sks);

static void kryptos_feal_block_encrypt(kryptos_u8_t *block, const struct kryptos_feal_subkeys *sks);

static void kryptos_feal_block_decrypt(kryptos_u8_t *block, const struct kryptos_feal_subkeys *sks);

static kryptos_u32_t kryptos_feal_f(kryptos_u32_t V, kryptos_u16_t W);

KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(feal, ktask, kKryptosCipherFEAL, KRYPTOS_FEAL_BLOCKSIZE, int *rounds,
                                       {
                                            if (rounds != NULL) {
                                                ktask->arg[0] = rounds;
                                            } else {
                                                ktask->arg[0] = NULL;
                                            }
                                       })

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(feal,
                                    ktask,
                                    kryptos_feal_subkeys,
                                    sks,
                                    kryptos_feal_block_processor,
                                    feal_block_processor,
                                    {
                                        if ((*ktask)->arg[0] == NULL) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "FEAL round parameter is missing.";
                                            goto kryptos_feal_cipher_epilogue;
                                        }
                                        sks.rounds = *(int *)(*ktask)->arg[0];
                                        // INFO(Rafael): The FEAL algorithm also expects a number of rounds
                                        //               configurable by the user. Let's check if the passed
                                        //               number makes sense.
                                        if (sks.rounds >= KRYPTOS_FEAL_MAX - 8) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "FEAL round overflow.";
                                            goto kryptos_feal_cipher_epilogue;
                                        } else if (sks.rounds < 1) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "FEAL round underflow.";
                                            goto kryptos_feal_cipher_epilogue;
                                        }
                                        // INFO(Rafael): All ok, let's expand this user key and use it!
                                        kryptos_feal_expand_key((*ktask)->key, (*ktask)->key_size, &sks);
                                    },
                                    kryptos_feal_block_encrypt, /*No additional steps before encrypting*/,
                                    kryptos_feal_block_decrypt, /*No additional steps before decrypting*/,
                                    KRYPTOS_FEAL_BLOCKSIZE,
                                    feal_cipher_epilogue,
                                    outblock,
                                    feal_block_processor(outblock, &sks))

static kryptos_u8_t kryptos_feal_Sd(kryptos_u8_t T, kryptos_u8_t U, int d) {
    T = (T + U + d) % 256;
    return kryptos_feal_rotl2(T);
}

static kryptos_u32_t kryptos_feal_fK(kryptos_u32_t V, kryptos_u32_t W) {
    kryptos_u8_t t1, t2, U[4];

    t1 = kryptos_feal_get_byte_from_u32(V, 0) ^ kryptos_feal_get_byte_from_u32(V, 1);
    t2 = kryptos_feal_get_byte_from_u32(V, 2) ^ kryptos_feal_get_byte_from_u32(V, 3);

    U[1] = kryptos_feal_Sd(t1, t2 ^ kryptos_feal_get_byte_from_u32(W, 0), 1);
    U[2] = kryptos_feal_Sd(t2, U[1] ^ kryptos_feal_get_byte_from_u32(W, 1), 0);
    U[0] = kryptos_feal_Sd(kryptos_feal_get_byte_from_u32(V, 0), U[1] ^ kryptos_feal_get_byte_from_u32(W, 2), 0);
    U[3] = kryptos_feal_Sd(kryptos_feal_get_byte_from_u32(V, 3), U[2] ^ kryptos_feal_get_byte_from_u32(W, 3), 1);

    t1=0;
    t2=0;

    return ((kryptos_u32_t) U[0] << 24 | (kryptos_u32_t) U[1] << 16 | (kryptos_u32_t) U[2] << 8 | (kryptos_u32_t) U[3]);
}

static void kryptos_feal_ld_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t b, w;

    kryptos_ld_user_key_prologue(key, 2, user_key, user_key_size, kp, kp_end, w, b, return);

    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_feal_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_feal_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_feal_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_feal_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_feal_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_feal_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_feal_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_feal_ld_user_key_epilogue);

    kryptos_ld_user_key_epilogue(kryptos_feal_ld_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_feal_expand_key(const kryptos_u8_t *key, const size_t key_size, struct kryptos_feal_subkeys *sks) {
    size_t r, r_nr;
#ifdef KRYPTOS_KERNEL_MODE
    static kryptos_u32_t D[KRYPTOS_FEAL_MAX], A[KRYPTOS_FEAL_MAX], B[KRYPTOS_FEAL_MAX];
#else
    kryptos_u32_t D[KRYPTOS_FEAL_MAX], A[KRYPTOS_FEAL_MAX], B[KRYPTOS_FEAL_MAX];
#endif
    kryptos_u32_t user_key[2];

    kryptos_feal_ld_user_key(user_key, key, key_size);

    memset(sks->K, 0, sizeof(sks->K));

    D[0] = 0L;
    A[0] = user_key[0];
    B[0] = user_key[1];

    r_nr = ((sks->rounds + 8) / 2) + (sks->rounds + 8) % 2;

    for(r = 1; r <= r_nr; r++) {
        D[r] = A[r - 1];
        A[r] = B[r - 1];
        B[r] = kryptos_feal_fK(A[r - 1], B[r - 1] ^ D[r - 1]);

        sks->K[(r-1) << 1] = (kryptos_u16_t) kryptos_feal_get_byte_from_u32(B[r], 0) << 8  |
                             (kryptos_u16_t) kryptos_feal_get_byte_from_u32(B[r], 1);
        sks->K[((r-1) << 1) + 1] = (kryptos_u16_t) kryptos_feal_get_byte_from_u32(B[r], 2) << 8 |
                                   (kryptos_u16_t) kryptos_feal_get_byte_from_u32(B[r], 3);
    }

    r_nr = 0;
    memset(A, 0, sizeof(A));
    memset(B, 0, sizeof(B));
    memset(D, 0, sizeof(D));
    memset(user_key, 0, sizeof(user_key));
}

static void kryptos_feal_block_encrypt(kryptos_u8_t *block, const struct kryptos_feal_subkeys *sks) {
#ifdef KRYPTOS_KERNEL_MODE
    static kryptos_u32_t L[KRYPTOS_FEAL_MAX], R[KRYPTOS_FEAL_MAX];
#else
    kryptos_u32_t L[KRYPTOS_FEAL_MAX], R[KRYPTOS_FEAL_MAX];
#endif
    size_t r;

    L[0] = kryptos_get_u32_as_big_endian(block, 4);
    R[0] = kryptos_get_u32_as_big_endian(block + 4, 4);

    L[0] = L[0] ^ ((kryptos_u32_t) sks->K[sks->rounds] << 16 |
                   (kryptos_u32_t) sks->K[sks->rounds + 1]);

    R[0] = R[0] ^ ((kryptos_u32_t) sks->K[sks->rounds + 2] << 16 |
                   (kryptos_u32_t) sks->K[sks->rounds + 3]);

    R[0] = R[0] ^ L[0];

    for(r = 1; r <= sks->rounds; r++) {
        R[r] = L[r - 1] ^ kryptos_feal_f(R[r - 1], sks->K[r - 1]);
        L[r] = R[r - 1];
    }

    L[r - 1] = L[r - 1] ^ R[r - 1];

    R[r - 1] = R[r - 1] ^ ((kryptos_u32_t) sks->K[sks->rounds + 4] << 16 | (kryptos_u32_t) sks->K[sks->rounds + 5]);
    L[r - 1] = L[r - 1] ^ ((kryptos_u32_t) sks->K[sks->rounds + 6] << 16 | (kryptos_u32_t) sks->K[sks->rounds + 7]);

    kryptos_cpy_u32_as_big_endian(block, 8, R[r - 1]);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, L[r - 1]);

    memset(L, 0, sizeof(L));
    memset(R, 0, sizeof(R));
}

static void kryptos_feal_block_decrypt(kryptos_u8_t *block, const struct kryptos_feal_subkeys *sks) {
#ifdef KRYPTOS_KERNEL_MODE
    static kryptos_u32_t L[KRYPTOS_FEAL_MAX], R[KRYPTOS_FEAL_MAX];
#else
    kryptos_u32_t L[KRYPTOS_FEAL_MAX], R[KRYPTOS_FEAL_MAX];
#endif
    size_t r;

    L[sks->rounds] = kryptos_get_u32_as_big_endian(block + 4, 4);
    R[sks->rounds] = kryptos_get_u32_as_big_endian(block, 4);

    L[sks->rounds] = L[sks->rounds] ^ ((kryptos_u32_t) sks->K[sks->rounds + 6] << 16 | (kryptos_u32_t) sks->K[sks->rounds + 7]);
    R[sks->rounds] = R[sks->rounds] ^ ((kryptos_u32_t) sks->K[sks->rounds + 4] << 16 | (kryptos_u32_t) sks->K[sks->rounds + 5]);

    L[sks->rounds] = L[sks->rounds] ^ R[sks->rounds];

    for (r = sks->rounds; r >= 1; r--) {
        L[r - 1] = R[r] ^ kryptos_feal_f(L[r], sks->K[r - 1]);
        R[r - 1] = L[r];
    }

    R[r] = R[r] ^ L[r];

    L[r] = L[r] ^ ((kryptos_u32_t) sks->K[sks->rounds] << 16 |
                   (kryptos_u32_t) sks->K[sks->rounds + 1]);

    R[r] = R[r] ^ ((kryptos_u32_t) sks->K[sks->rounds + 2] << 16 |
                   (kryptos_u32_t) sks->K[sks->rounds + 3]);

    kryptos_cpy_u32_as_big_endian(block, 8, L[r]);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, R[r]);

    memset(L, 0, sizeof(L));
    memset(R, 0, sizeof(R));
}

static kryptos_u32_t kryptos_feal_f(kryptos_u32_t V, kryptos_u16_t W) {
    kryptos_u8_t t1, t2, U[4];

    t1 = (kryptos_feal_get_byte_from_u32(V, 0) ^ kryptos_feal_get_byte_from_u32(V, 1)) ^ kryptos_feal_get_byte_from_u16(W, 0);
    t2 = (kryptos_feal_get_byte_from_u32(V, 2) ^ kryptos_feal_get_byte_from_u32(V, 3)) ^ kryptos_feal_get_byte_from_u16(W, 1);

    U[1] = kryptos_feal_Sd(t1, t2, 1);
    U[2] = kryptos_feal_Sd(t2, U[1], 0);
    U[0] = kryptos_feal_Sd(kryptos_feal_get_byte_from_u32(V, 0), U[1], 0);
    U[3] = kryptos_feal_Sd(kryptos_feal_get_byte_from_u32(V, 3), U[2], 1);

    t1=0;
    t2=0;

  return ((kryptos_u32_t) U[0] << 24 | (kryptos_u32_t) U[1] << 16 | (kryptos_u32_t) U[2] << 8 | (kryptos_u32_t) U[3]);
}

#undef KRYPTOS_FEAL_MAX

#undef kryptos_feal_rotl2

#undef kryptos_feal_get_byte_from_u32

#undef kryptos_feal_get_byte_from_u16
