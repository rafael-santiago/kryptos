/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_gost.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

// WARN(Rafael): GOST 28147-89 is pretty old, I am just including it here for historical issues.
//               Maybe it should be useful for crypto classes, homeworks and so on.

// INFO(Rafael): This implementation uses the DES s-boxes.
static kryptos_u8_t kryptos_gost_s8[16] = {
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7
};

static kryptos_u8_t kryptos_gost_s7[16] = {
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10
};

static kryptos_u8_t kryptos_gost_s6[16] = {
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8
};

static kryptos_u8_t kryptos_gost_s5[16] = {
     7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15
};

static kryptos_u8_t kryptos_gost_s4[16] = {
     2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9
};

static kryptos_u8_t kryptos_gost_s3[16] = {
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11
};

static kryptos_u8_t kryptos_gost_s2[16] = {
     4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1
};

static kryptos_u8_t kryptos_gost_s1[16] = {
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7
};

static size_t kryptos_gost_rounds_k_lt[32] = {
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
    0, 1, 2, 3, 4, 5, 6, 7,
    7, 6, 5, 4, 3, 2, 1, 0
};

#define kryptos_gost_kr(K, r) ( (K)[kryptos_gost_rounds_k_lt[(r)]] )

#define kryptos_gost_lsh(b) ( ((b) << 11) | ((b) >> 21) )

// INFO(Rafael): I am replacing one nibble at once because it is easier when using custom s-boxes defined at
//               run-time.
#define kryptos_gost_sub(b, sks) {\
    (b) = (sks)->s8[((b) >> 28) & 0xF] << 28 |\
          (sks)->s7[((b) >> 24) & 0xF] << 24 |\
          (sks)->s6[((b) >> 20) & 0xF] << 20 |\
          (sks)->s5[((b) >> 16) & 0xF] << 16 |\
          (sks)->s4[((b) >> 12) & 0xF] << 12 |\
          (sks)->s3[((b) >>  8) & 0xF] <<  8 |\
          (sks)->s2[((b) >>  4) & 0xF] <<  4 |\
          (sks)->s1[((b) & 0xF)      ];\
}

#define kryptos_gost_f(R, K, L, sks) {\
    (R) += (K);\
    kryptos_gost_sub(R, sks);\
    (R) = kryptos_gost_lsh(R);\
    (R) ^= (L);\
}

#define kryptos_gost_round(L, R, sks, temp, r) {\
    (temp) = (R);\
    kryptos_gost_f(R, kryptos_gost_kr((sks)->K, r), L, sks);\
    (L) = (temp);\
}

struct kryptos_gost_subkeys {
    kryptos_u32_t K[8];
    kryptos_u8_t *s1, *s2, *s3, *s4, *s5, *s6, *s7, *s8;
};

typedef void (*kryptos_gost_block_processor)(kryptos_u8_t *block, const struct kryptos_gost_subkeys *sks);

static void kryptos_gost_load_user_key(const kryptos_u8_t *key, const size_t key_size, struct kryptos_gost_subkeys *sks);

static void kryptos_gost_block_encrypt(kryptos_u8_t *block, const struct kryptos_gost_subkeys *sks);

static void kryptos_gost_block_decrypt(kryptos_u8_t *block, const struct kryptos_gost_subkeys *sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(gost_ds, kKryptosCipherGOSTDS, KRYPTOS_GOST_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(gost_ds,
                                    ktask,
                                    kryptos_gost_subkeys,
                                    sks,
                                    kryptos_gost_block_processor,
                                    gost_block_processor,
                                    {
                                        kryptos_gost_load_user_key((*ktask)->key, (*ktask)->key_size, &sks);
                                        sks.s1 = &kryptos_gost_s1[0];
                                        sks.s2 = &kryptos_gost_s2[0];
                                        sks.s3 = &kryptos_gost_s3[0];
                                        sks.s4 = &kryptos_gost_s4[0];
                                        sks.s5 = &kryptos_gost_s5[0];
                                        sks.s6 = &kryptos_gost_s6[0];
                                        sks.s7 = &kryptos_gost_s7[0];
                                        sks.s8 = &kryptos_gost_s8[0];
                                    },
                                    kryptos_gost_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_gost_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_GOST_BLOCKSIZE,
                                    gost_cipher_epilogue,
                                    outblock,
                                    gost_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg (No GCM) */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E_NO_SUPPORT(gost_ds)

void kryptos_gost_setup(kryptos_task_ctx *ktask,
                                  kryptos_u8_t *key,
                                  const size_t key_size,
                                  const kryptos_cipher_mode_t mode,
                                  kryptos_u8_t *s1, kryptos_u8_t *s2, kryptos_u8_t *s3, kryptos_u8_t *s4,
                                  kryptos_u8_t *s5, kryptos_u8_t *s6, kryptos_u8_t *s7, kryptos_u8_t *s8) {
    if (ktask == NULL) {
        return;
    }

    if (s1 != NULL) {
        ktask->arg[0] = (void *)s1;
    } else {
        ktask->arg[0] = NULL;
    }

    if (s2 != NULL) {
        ktask->arg[1] = (void *)s2;
    } else {
        ktask->arg[1] = NULL;
    }

    if (s3 != NULL) {
        ktask->arg[2] = (void *)s3;
    } else {
        ktask->arg[2] = NULL;
    }

    if (s4 != NULL) {
        ktask->arg[3] = (void *)s4;
    } else {
        ktask->arg[3] = NULL;
    }

    if (s5 != NULL) {
        ktask->arg[4] = (void *)s5;
    } else {
        ktask->arg[4] = NULL;
    }

    if (s6 != NULL) {
        ktask->arg[5] = (void *)s6;
    } else {
        ktask->arg[5] = NULL;
    }

    if (s7 != NULL) {
        ktask->arg[6] = (void *)s7;
    } else {
        ktask->arg[6] = NULL;
    }

    if (s8 != NULL) {
        ktask->arg[7] = (void *)s8;
    } else {
        ktask->arg[7] = NULL;
    }

    ktask->key = key;
    ktask->key_size = key_size;
    ktask->mode = mode;
    ktask->cipher = kKryptosCipherGOST;

    if ((ktask->mode == kKryptosCBC || ktask->mode == kKryptosOFB || ktask->mode == kKryptosCTR) && ktask->iv == NULL) {
        ktask->iv = kryptos_get_random_block(KRYPTOS_GOST_BLOCKSIZE);
        ktask->iv_size = KRYPTOS_GOST_BLOCKSIZE;
    }

    if (ktask->mode == kKryptosCTR && ktask->ctr != NULL) {
        ktask->iv[KRYPTOS_GOST_BLOCKSIZE - 4] = (*ktask->ctr) >> 24;
        ktask->iv[KRYPTOS_GOST_BLOCKSIZE - 3] = ((*ktask->ctr) & 0xFF0000) >> 16;
        ktask->iv[KRYPTOS_GOST_BLOCKSIZE - 2] = ((*ktask->ctr) & 0xFF00) >> 8;
        ktask->iv[KRYPTOS_GOST_BLOCKSIZE - 1] = (*ktask->ctr) & 0xFF;
    }
}

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(gost,
                                    ktask,
                                    kryptos_gost_subkeys,
                                    sks,
                                    kryptos_gost_block_processor,
                                    gost_block_processor,
                                    {
                                        if ((*ktask)->arg[0] == NULL || (*ktask)->arg[1] == NULL ||
                                            (*ktask)->arg[2] == NULL || (*ktask)->arg[3] == NULL ||
                                            (*ktask)->arg[4] == NULL || (*ktask)->arg[5] == NULL ||
                                            (*ktask)->arg[6] == NULL || (*ktask)->arg[7] == NULL) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "GOST s-boxes are incomplete.";
                                            goto kryptos_gost_cipher_epilogue;
                                        }
                                        kryptos_gost_load_user_key((*ktask)->key, (*ktask)->key_size, &sks);
                                        sks.s1 = (kryptos_u8_t *)(*ktask)->arg[0];
                                        sks.s2 = (kryptos_u8_t *)(*ktask)->arg[1];
                                        sks.s3 = (kryptos_u8_t *)(*ktask)->arg[2];
                                        sks.s4 = (kryptos_u8_t *)(*ktask)->arg[3];
                                        sks.s5 = (kryptos_u8_t *)(*ktask)->arg[4];
                                        sks.s6 = (kryptos_u8_t *)(*ktask)->arg[5];
                                        sks.s7 = (kryptos_u8_t *)(*ktask)->arg[6];
                                        sks.s8 = (kryptos_u8_t *)(*ktask)->arg[7];
                                    },
                                    kryptos_gost_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_gost_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_GOST_BLOCKSIZE,
                                    gost_cipher_epilogue,
                                    outblock,
                                    gost_block_processor(outblock, &sks),
                                    NULL /* GCM E functio arg (No GCM) */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E_NO_SUPPORT(gost)

static void kryptos_gost_load_user_key(const kryptos_u8_t *key, const size_t key_size, struct kryptos_gost_subkeys *sks) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;
    kryptos_ld_user_key_prologue(sks->K, 8, key, key_size, kp, kp_end, w, b, return);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
        kryptos_ld_user_key_byte(sks->K, w, b, kp, kp_end, kryptos_gost_load_user_key_epilogue);
    kryptos_ld_user_key_epilogue(kryptos_gost_load_user_key_epilogue, sks->K, w, b, kp, kp_end);
}

static void kryptos_gost_block_encrypt(kryptos_u8_t *block, const struct kryptos_gost_subkeys *sks) {
    kryptos_u32_t L, R, temp;

    L = kryptos_get_u32_as_big_endian(block + 4, 4);
    R = kryptos_get_u32_as_big_endian(block, 4);

    kryptos_gost_round(L, R, sks, temp,  0);
    kryptos_gost_round(L, R, sks, temp,  1);
    kryptos_gost_round(L, R, sks, temp,  2);
    kryptos_gost_round(L, R, sks, temp,  3);
    kryptos_gost_round(L, R, sks, temp,  4);
    kryptos_gost_round(L, R, sks, temp,  5);
    kryptos_gost_round(L, R, sks, temp,  6);
    kryptos_gost_round(L, R, sks, temp,  7);
    kryptos_gost_round(L, R, sks, temp,  8);
    kryptos_gost_round(L, R, sks, temp,  9);
    kryptos_gost_round(L, R, sks, temp, 10);
    kryptos_gost_round(L, R, sks, temp, 11);
    kryptos_gost_round(L, R, sks, temp, 12);
    kryptos_gost_round(L, R, sks, temp, 13);
    kryptos_gost_round(L, R, sks, temp, 14);
    kryptos_gost_round(L, R, sks, temp, 15);
    kryptos_gost_round(L, R, sks, temp, 16);
    kryptos_gost_round(L, R, sks, temp, 17);
    kryptos_gost_round(L, R, sks, temp, 18);
    kryptos_gost_round(L, R, sks, temp, 19);
    kryptos_gost_round(L, R, sks, temp, 20);
    kryptos_gost_round(L, R, sks, temp, 21);
    kryptos_gost_round(L, R, sks, temp, 22);
    kryptos_gost_round(L, R, sks, temp, 23);
    kryptos_gost_round(L, R, sks, temp, 24);
    kryptos_gost_round(L, R, sks, temp, 25);
    kryptos_gost_round(L, R, sks, temp, 26);
    kryptos_gost_round(L, R, sks, temp, 27);
    kryptos_gost_round(L, R, sks, temp, 28);
    kryptos_gost_round(L, R, sks, temp, 29);
    kryptos_gost_round(L, R, sks, temp, 30);
    kryptos_gost_round(L, R, sks, temp, 31);

    kryptos_cpy_u32_as_big_endian(block, 4, L);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, R);

    L = R = temp = 0;
}

static void kryptos_gost_block_decrypt(kryptos_u8_t *block, const struct kryptos_gost_subkeys *sks) {
    kryptos_u32_t L, R, temp;

    L = kryptos_get_u32_as_big_endian(block + 4, 4);
    R = kryptos_get_u32_as_big_endian(block, 4);

    kryptos_gost_round(L, R, sks, temp, 31);
    kryptos_gost_round(L, R, sks, temp, 30);
    kryptos_gost_round(L, R, sks, temp, 29);
    kryptos_gost_round(L, R, sks, temp, 28);
    kryptos_gost_round(L, R, sks, temp, 27);
    kryptos_gost_round(L, R, sks, temp, 26);
    kryptos_gost_round(L, R, sks, temp, 25);
    kryptos_gost_round(L, R, sks, temp, 24);
    kryptos_gost_round(L, R, sks, temp, 23);
    kryptos_gost_round(L, R, sks, temp, 22);
    kryptos_gost_round(L, R, sks, temp, 21);
    kryptos_gost_round(L, R, sks, temp, 20);
    kryptos_gost_round(L, R, sks, temp, 19);
    kryptos_gost_round(L, R, sks, temp, 18);
    kryptos_gost_round(L, R, sks, temp, 17);
    kryptos_gost_round(L, R, sks, temp, 16);
    kryptos_gost_round(L, R, sks, temp, 15);
    kryptos_gost_round(L, R, sks, temp, 14);
    kryptos_gost_round(L, R, sks, temp, 13);
    kryptos_gost_round(L, R, sks, temp, 12);
    kryptos_gost_round(L, R, sks, temp, 11);
    kryptos_gost_round(L, R, sks, temp, 10);
    kryptos_gost_round(L, R, sks, temp,  9);
    kryptos_gost_round(L, R, sks, temp,  8);
    kryptos_gost_round(L, R, sks, temp,  7);
    kryptos_gost_round(L, R, sks, temp,  6);
    kryptos_gost_round(L, R, sks, temp,  5);
    kryptos_gost_round(L, R, sks, temp,  4);
    kryptos_gost_round(L, R, sks, temp,  3);
    kryptos_gost_round(L, R, sks, temp,  2);
    kryptos_gost_round(L, R, sks, temp,  1);
    kryptos_gost_round(L, R, sks, temp,  0);

    kryptos_cpy_u32_as_big_endian(block, 8, L);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, R);

    L = R = temp = 0;
}

#undef kryptos_gost_kr

#undef kryptos_gost_lsh

#undef kryptos_gost_sub

#undef kryptos_gost_f

#undef kryptos_gost_round
