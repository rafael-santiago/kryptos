/*
 *                          Copyright (C) 2006, 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_rc6.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define kryptos_rc6_W 32

#define kryptos_rc6_U 4

#define kryptos_rc6_PW 0xB7E15163

#define kryptos_rc6_QW 0x9E3779B9

#define kryptos_rc6_K_NR 800

#define kryptos_rc6_LG_W 5

#define kryptos_rc6_rotl(w, s) ( ( (w) << (s) ) | ( (w) >> (32 - (s)) ) )

#define kryptos_rc6_rotr(w, s) ( ( (w) >> (s) ) | ( (w) << (32 - (s)) ) )

#define kryptos_rc6_rev32(w) ( ((w)              << 24) |\
                               (((w) & 0xFF00)   <<  8) |\
                               (((w) & 0xFF0000) >>  8) |\
                               ((w)              >> 24) )


typedef enum {
    kKryptosRC6128 = 16,
    kKryptosRC6192 = 24,
    kKryptosRC6256 = 32
}kryptos_rc6_ksize_t;

struct kryptos_rc6_subkeys {
    kryptos_u32_t K[kryptos_rc6_K_NR];
    int rounds;
    kryptos_rc6_ksize_t ksize;
};

typedef void (*kryptos_rc6_block_processor)(kryptos_u8_t *block, const struct kryptos_rc6_subkeys *sks);

static void kryptos_rc6_ksched(const kryptos_u8_t *user_key, const size_t user_key_size, struct kryptos_rc6_subkeys *sks);

static void kryptos_rc6_ld_user_key(kryptos_u32_t *l, const kryptos_u8_t *key, const size_t key_size);

static void kryptos_rc6_block_encrypt(kryptos_u8_t *block, const struct kryptos_rc6_subkeys *sks);

static void kryptos_rc6_block_decrypt(kryptos_u8_t *block, const struct kryptos_rc6_subkeys *sks);

KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(rc6_128, ktask, kKryptosCipherRC6, KRYPTOS_RC6_BLOCKSIZE, int *rounds,
                                       {
                                            if (rounds != NULL) {
                                                ktask->arg[0] = rounds;
                                            } else {
                                                ktask->arg[0] = NULL;
                                            }
                                        })

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(rc6_128,
                                    ktask,
                                    kryptos_rc6_subkeys,
                                    sks,
                                    kryptos_rc6_block_processor,
                                    rc6_block_processor,
                                    {
                                        if ((*ktask)->key_size > 16) {
                                            (*ktask)->result = kKryptosKeyError;
                                            (*ktask)->result_verbose = "RC6 key size greater than 16 bytes.";
                                            goto kryptos_rc6_128_cipher_epilogue;
                                        }
                                        if ((*ktask)->arg[0] == NULL) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC6 round parameter is missing.";
                                            goto kryptos_rc6_128_cipher_epilogue;
                                        }
                                        sks.rounds = *(int *)(*ktask)->arg[0];
                                        if (sks.rounds < 1) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC6 rounds underflow.";
                                            goto kryptos_rc6_128_cipher_epilogue;
                                        } else if (((sks.rounds + 2) << 1) > kryptos_rc6_K_NR) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC6 rounds overflow.";
                                            goto kryptos_rc6_128_cipher_epilogue;
                                        }
                                        sks.ksize = kKryptosRC6128;
                                        kryptos_rc6_ksched((*ktask)->key, (*ktask)->key_size, &sks);
                                    },
                                    kryptos_rc6_block_encrypt, /* No additional steps for encrypting */,
                                    kryptos_rc6_block_decrypt, /* No additional steps for decrypting */,
                                    KRYPTOS_RC6_BLOCKSIZE,
                                    rc6_128_cipher_epilogue,
                                    outblock,
                                    rc6_block_processor(outblock, &sks))

KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(rc6_192, ktask, kKryptosCipherRC6, KRYPTOS_RC6_BLOCKSIZE, int *rounds,
                                       {
                                            if (rounds != NULL) {
                                                ktask->arg[0] = rounds;
                                            } else {
                                                ktask->arg[0] = NULL;
                                            }
                                        })

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(rc6_192,
                                    ktask,
                                    kryptos_rc6_subkeys,
                                    sks,
                                    kryptos_rc6_block_processor,
                                    rc6_block_processor,
                                    {
                                        if ((*ktask)->key_size > 24) {
                                            (*ktask)->result = kKryptosKeyError;
                                            (*ktask)->result_verbose = "RC6 key size greater than 24 bytes.";
                                            goto kryptos_rc6_192_cipher_epilogue;
                                        }
                                        if ((*ktask)->arg[0] == NULL) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC6 round parameter is missing.";
                                            goto kryptos_rc6_192_cipher_epilogue;
                                        }
                                        sks.rounds = *(int *)(*ktask)->arg[0];
                                        if (sks.rounds < 1) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC6 rounds underflow.";
                                            goto kryptos_rc6_192_cipher_epilogue;
                                        } else if (((sks.rounds + 2) << 1) > kryptos_rc6_K_NR) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC6 rounds overflow.";
                                            goto kryptos_rc6_192_cipher_epilogue;
                                        }
                                        sks.ksize = kKryptosRC6192;
                                        kryptos_rc6_ksched((*ktask)->key, (*ktask)->key_size, &sks);
                                    },
                                    kryptos_rc6_block_encrypt, /* No additional steps for encrypting */,
                                    kryptos_rc6_block_decrypt, /* No additional steps for decrypting */,
                                    KRYPTOS_RC6_BLOCKSIZE,
                                    rc6_192_cipher_epilogue,
                                    outblock,
                                    rc6_block_processor(outblock, &sks))

KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(rc6_256, ktask, kKryptosCipherRC6, KRYPTOS_RC6_BLOCKSIZE, int *rounds,
                                       {
                                            if (rounds != NULL) {
                                                ktask->arg[0] = rounds;
                                            } else {
                                                ktask->arg[0] = NULL;
                                            }
                                        })

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(rc6_256,
                                    ktask,
                                    kryptos_rc6_subkeys,
                                    sks,
                                    kryptos_rc6_block_processor,
                                    rc6_block_processor,
                                    {
                                        if ((*ktask)->key_size > 32) {
                                            (*ktask)->result = kKryptosKeyError;
                                            (*ktask)->result_verbose = "RC6 key size greater than 32 bytes.";
                                            goto kryptos_rc6_256_cipher_epilogue;
                                        }
                                        if ((*ktask)->arg[0] == NULL) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC6 round parameter is missing.";
                                            goto kryptos_rc6_256_cipher_epilogue;
                                        }
                                        sks.rounds = *(int *)(*ktask)->arg[0];
                                        if (sks.rounds < 1) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC6 rounds underflow.";
                                            goto kryptos_rc6_256_cipher_epilogue;
                                        } else if (((sks.rounds + 2) << 1) > kryptos_rc6_K_NR) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC6 rounds overflow.";
                                            goto kryptos_rc6_256_cipher_epilogue;
                                        }
                                        sks.ksize = kKryptosRC6256;
                                        kryptos_rc6_ksched((*ktask)->key, (*ktask)->key_size, &sks);
                                    },
                                    kryptos_rc6_block_encrypt, /* No additional steps for encrypting */,
                                    kryptos_rc6_block_decrypt, /* No additional steps for decrypting */,
                                    KRYPTOS_RC6_BLOCKSIZE,
                                    rc6_256_cipher_epilogue,
                                    outblock,
                                    rc6_block_processor(outblock, &sks))

void kryptos_rc6_ld_user_key(kryptos_u32_t *l, const kryptos_u8_t *key, const size_t key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;
    kryptos_ld_user_key_prologue(l, kryptos_rc6_K_NR, key, key_size, kp, kp_end, w, b, return);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc6_ld_user_key_epilogue);
    kryptos_ld_user_key_epilogue(kryptos_rc6_ld_user_key_epilogue, l, w, b, kp, kp_end);
}

void kryptos_rc6_ksched(const kryptos_u8_t *user_key, const size_t user_key_size, struct kryptos_rc6_subkeys *sks) {
    kryptos_u8_t cp_uk[32];
#ifdef KRYPTOS_KERNEL_MODE
    static kryptos_u32_t L[kryptos_rc6_K_NR];
#else
    kryptos_u32_t L[kryptos_rc6_K_NR];
#endif
    kryptos_u32_t A, B;
    size_t c, i, s, t, v, j;

    memset(cp_uk, 0, sizeof(cp_uk));
    memcpy(cp_uk, user_key, user_key_size);

    kryptos_rc6_ld_user_key(L, cp_uk, sks->ksize);

    c = sks->ksize >> 2;

    for (i = 0; i < c; i++) {
        L[i] = kryptos_rc6_rev32(L[i]);
    }

    t = (sks->rounds << 1) + 3;

    sks->K[0] = kryptos_rc6_PW;

    for (i = 1; i <= t; i++) {
        sks->K[i] = sks->K[i - 1] + kryptos_rc6_QW;
    }

    i = j = 0;

    A = B = 0;

    v = 3 * ((sks->rounds << 1) + 4);

    for (s = 0; s < v; s++) {
        A = sks->K[i] = kryptos_rc6_rotl((sks->K[i] + A + B), 3);
        B = L[j] = kryptos_rc6_rotl((L[j] + A + B), (A + B) % kryptos_rc6_W);
        i = (i + 1) % (4 + (sks->rounds << 1));
        j = (j + 1) % (c);
    }

    memset(L, 0, sizeof(L[0]) * kryptos_rc6_K_NR);
    memset(cp_uk, 0, sks->ksize);
    A = B = 0;
}

void kryptos_rc6_block_encrypt(kryptos_u8_t *block, const struct kryptos_rc6_subkeys *sks) {
    kryptos_u32_t A, B, C, D, t, u;
    size_t r;

    A = (((kryptos_u32_t)block[3]) << 24) |
        (((kryptos_u32_t)block[2]) << 16) |
        (((kryptos_u32_t)block[1]) <<  8) |
        block[0];

    B = (((kryptos_u32_t)block[7]) << 24) |
        (((kryptos_u32_t)block[6]) << 16) |
        (((kryptos_u32_t)block[5]) <<  8) |
        block[4];

    C = (((kryptos_u32_t)block[11]) << 24) |
        (((kryptos_u32_t)block[10]) << 16) |
        (((kryptos_u32_t)block[ 9]) <<  8) |
        block[8];

    D = (((kryptos_u32_t)block[15]) << 24) |
        (((kryptos_u32_t)block[14]) << 16) |
        (((kryptos_u32_t)block[13]) <<  8) |
        block[12];

    B += sks->K[0];
    D += sks->K[1];

    for (r = 1; r <= sks->rounds; r++) {
        t = kryptos_rc6_rotl(B * ((B<<1) + 1), kryptos_rc6_LG_W);
        u = kryptos_rc6_rotl(D * ((D<<1) + 1), kryptos_rc6_LG_W);
        A = kryptos_rc6_rotl(A ^ t, u % kryptos_rc6_W) + sks->K[r<<1];
        C = kryptos_rc6_rotl(C ^ u, t % kryptos_rc6_W) + sks->K[(r<<1)+1];
        t = A;
        A = B;
        B = C;
        C = D;
        D = t;
    }

    A += sks->K[(sks->rounds << 1) + 2];
    C += sks->K[(sks->rounds << 1) + 3];

    kryptos_cpy_u32_as_big_endian(block, 16, kryptos_rc6_rev32(A));
    kryptos_cpy_u32_as_big_endian(block + 4, 12, kryptos_rc6_rev32(B));
    kryptos_cpy_u32_as_big_endian(block + 8, 8, kryptos_rc6_rev32(C));
    kryptos_cpy_u32_as_big_endian(block + 12, 4, kryptos_rc6_rev32(D));

    A =
    B =
    C =
    D =
    t =
    u = 0;
}

void kryptos_rc6_block_decrypt(kryptos_u8_t *block, const struct kryptos_rc6_subkeys *sks) {
    kryptos_u32_t A, B, C, D, t, u;
    size_t r;

    A = (((kryptos_u32_t)block[3]) << 24) |
        (((kryptos_u32_t)block[2]) << 16) |
        (((kryptos_u32_t)block[1]) <<  8) |
        block[0];

    B = (((kryptos_u32_t)block[7]) << 24) |
        (((kryptos_u32_t)block[6]) << 16) |
        (((kryptos_u32_t)block[5]) <<  8) |
        block[4];

    C = (((kryptos_u32_t)block[11]) << 24) |
        (((kryptos_u32_t)block[10]) << 16) |
        (((kryptos_u32_t)block[ 9]) <<  8) |
        block[8];

    D = (((kryptos_u32_t)block[15]) << 24) |
        (((kryptos_u32_t)block[14]) << 16) |
        (((kryptos_u32_t)block[13]) <<  8) |
        block[12];

    C -= sks->K[(sks->rounds << 1) + 3];
    A -= sks->K[(sks->rounds << 1) + 2];

    for (r = sks->rounds; r >= 1; r--) {
        t = A;
        A = D;
        u = B;
        B = t;
        t = C;
        C = u;
        D = t;
        u = kryptos_rc6_rotl(D * ((D<<1) + 1), kryptos_rc6_LG_W);
        t = kryptos_rc6_rotl(B * ((B<<1) + 1), kryptos_rc6_LG_W);
        C = kryptos_rc6_rotr(C - sks->K[(r<<1) + 1], t % kryptos_rc6_W) ^ u;
        A = kryptos_rc6_rotr(A - sks->K[r<<1], u % kryptos_rc6_W) ^ t;
    }

    D -= sks->K[1];
    B -= sks->K[0];

    kryptos_cpy_u32_as_big_endian(block, 16, kryptos_rc6_rev32(A));
    kryptos_cpy_u32_as_big_endian(block + 4, 12, kryptos_rc6_rev32(B));
    kryptos_cpy_u32_as_big_endian(block + 8, 8, kryptos_rc6_rev32(C));
    kryptos_cpy_u32_as_big_endian(block + 12, 4, kryptos_rc6_rev32(D));

    A =
    B =
    C =
    D =
    t =
    u = 0;
}

#undef kryptos_rc6_W

#undef kryptos_rc6_U

#undef kryptos_rc6_PW

#undef kryptos_rc6_QW

#undef kryptos_rc6_K_NR

#undef kryptos_rc6_LG_W

#undef kryptos_rc6_rotl

#undef kryptos_rc6_rotr
