/*
 *                          Copyright (C) 2006, 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_rc5.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

// WARN(Rafael): This implementation only considers little-endian machines, if you want to
//               make it also big-endian, watch out some obvious points during key scheduling,
//               encryption and decryption.

#define kryptos_rc5_W 32

#define kryptos_rc5_U 4 // INFO(Rafael): This is about rc5-32, your real cpu size does not matter here.

#define kryptos_rc5_PW 0xB7E15163

#define kryptos_rc5_QW 0x9E3779B9

#define kryptos_rc5_K_NR 800

#define kryptos_rc5_rotl(w, s) ( ( (w) << (s) ) | ( (w) >> ( 32 - (s) ) ) )

#define kryptos_rc5_rotr(w, s) ( ( (w) >> (s) ) | ( (w) << ( 32 - (s) ) ) )

#define kryptos_rc5_rev32(w) ( ((w)              << 24) |\
                               (((w) & 0xFF00)   <<  8) |\
                               (((w) & 0xFF0000) >>  8) |\
                               ((w)              >> 24) )

struct kryptos_rc5_subkeys {
    kryptos_u32_t K[kryptos_rc5_K_NR];
    int rounds;
};

typedef void (*kryptos_rc5_block_processor)(kryptos_u8_t *block, const struct kryptos_rc5_subkeys *sks);

static void kryptos_rc5_ld_user_key(kryptos_u32_t *l, const kryptos_u8_t *key, const size_t key_size);

static void kryptos_rc5_ksched(const kryptos_u8_t *user_key, const size_t user_key_size, struct kryptos_rc5_subkeys *sks);

static void kryptos_rc5_block_encrypt(kryptos_u8_t *block, const struct kryptos_rc5_subkeys *sks);

static void kryptos_rc5_block_decrypt(kryptos_u8_t *block, const struct kryptos_rc5_subkeys *sks);

KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(rc5, ktask, kKryptosCipherRC5, KRYPTOS_RC5_BLOCKSIZE, int *rounds,
                                       {
                                            if (rounds != NULL) {
                                                ktask->arg[0] = rounds;
                                            } else {
                                                ktask->arg[0] = NULL;
                                            }
                                        })

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(rc5,
                                    ktask,
                                    kryptos_rc5_subkeys,
                                    sks,
                                    kryptos_rc5_block_processor,
                                    rc5_block_processor,
                                    {
                                        if ((*ktask)->key_size > 64) {
                                            (*ktask)->result = kKryptosKeyError;
                                            (*ktask)->result_verbose = "RC5 key size greater than 64 bytes.";
                                            goto kryptos_rc5_cipher_epilogue;
                                        }
                                        if ((*ktask)->arg[0] == NULL) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC5 round parameter is missing.";
                                            goto kryptos_rc5_cipher_epilogue;
                                        }
                                        sks.rounds = *(int *)(*ktask)->arg[0];
                                        // INFO(Rafael): Some checking related to K array boundary is necessary.
                                        if (sks.rounds < 1) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC5 round underflow.";
                                            goto kryptos_rc5_cipher_epilogue;
                                        } else if (((sks.rounds + 2) << 1) > kryptos_rc5_K_NR) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "RC5 round overflow.";
                                            goto kryptos_rc5_cipher_epilogue;
                                        }
                                        // INFO(Rafael): All clean, this current user key is able to be expanded.
                                        kryptos_rc5_ksched((*ktask)->key, (*ktask)->key_size, &sks);
                                    },
                                    kryptos_rc5_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_rc5_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_RC5_BLOCKSIZE,
                                    rc5_cipher_epilogue,
                                    outblock,
                                    rc5_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg (No GCM) */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E_NO_SUPPORT(rc5)

static void kryptos_rc5_ld_user_key(kryptos_u32_t *l, const kryptos_u8_t *key, const size_t key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;

    // INFO(Rafael): Maximum user key size = 64 bytes (512-bits).

    kryptos_ld_user_key_prologue(l, kryptos_rc5_K_NR, key, key_size, kp, kp_end, w, b, return);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
        kryptos_ld_user_key_byte(l, w, b, kp, kp_end, kryptos_rc5_ld_user_key_epilogue);
    kryptos_ld_user_key_epilogue(kryptos_rc5_ld_user_key_epilogue, l, w, b, kp, kp_end);
}

static void kryptos_rc5_ksched(const kryptos_u8_t *user_key, const size_t user_key_size,  struct kryptos_rc5_subkeys *sks) {
#ifndef KRYPTOS_KERNEL_MODE
    kryptos_u32_t S[kryptos_rc5_K_NR], L[kryptos_rc5_K_NR];
#else
    static kryptos_u32_t S[kryptos_rc5_K_NR], L[kryptos_rc5_K_NR];
#endif
    kryptos_u32_t A, B;
    size_t c, i, j, s, t = (sks->rounds << 1) + 2, ttt;

    kryptos_rc5_ld_user_key(L, user_key, user_key_size);

    i = user_key_size;
    while (i % 4) {
        i++;
    }

    c = i >> 2; // WARN(Rafael): kryptos_rc5_U == 4 because this module implements rc5/32.

    for (i = 0; i < c; i++) {
        L[i] = kryptos_rc5_rev32(L[i]);
    }

    sks->K[0] = kryptos_rc5_PW;

    for(i = 1; i < t; i++) {
        sks->K[i] = sks->K[i-1] + kryptos_rc5_QW;
    }

    A = B = i = j = 0;

    t = (t < c) ? c : t;

    ttt = 3 * t;

    for (s = 0; s < ttt; s++) {
        A = sks->K[i] = kryptos_rc5_rotl((sks->K[i] + (A + B)), 3);
        B = L[j] = kryptos_rc5_rotl((L[j] + (A + B)),(A + B) % kryptos_rc5_W);
        i = (i+1) % (t);
        j = (j+1) % (c);
    }

    memset(S, 0, sizeof(S[0]) * kryptos_rc5_K_NR);
    memset(L, 0, sizeof(L[0]) * kryptos_rc5_K_NR);
    A = B = 0;
}

static void kryptos_rc5_block_encrypt(kryptos_u8_t *block, const struct kryptos_rc5_subkeys *sks) {
    kryptos_u32_t A, B;
    size_t r;

    A = (((kryptos_u32_t)block[3]) << 24) |
        (((kryptos_u32_t)block[2]) << 16) |
        (((kryptos_u32_t)block[1]) <<  8) |
        block[0];

    B = (((kryptos_u32_t)block[7]) << 24) |
        (((kryptos_u32_t)block[6]) << 16) |
        (((kryptos_u32_t)block[5]) <<  8) |
        block[4];

    A = A + sks->K[0];
    B = B + sks->K[1];

    for (r = 1; r <= sks->rounds; r++) {
        A = kryptos_rc5_rotl(A ^ B, B % kryptos_rc5_W) + sks->K[r << 1];
        B = kryptos_rc5_rotl(B ^ A, A % kryptos_rc5_W) + sks->K[(r << 1) + 1];
    }

    block[0] = A & 0xFF;
    block[1] = (A >> 8) & 0xFF;
    block[2] = (A >> 16) & 0xFF;
    block[3] = A >> 24;
    block[4] = B & 0xFF;
    block[5] = (B >> 8) & 0xFF;
    block[6] = (B >> 16) & 0xFF;
    block[7] = B >> 24;

    r = 0;

    A = B = 0;
}

static void kryptos_rc5_block_decrypt(kryptos_u8_t *block, const struct kryptos_rc5_subkeys *sks) {
    kryptos_u32_t A, B;
    size_t r;

    A = (((kryptos_u32_t)block[3]) << 24) |
        (((kryptos_u32_t)block[2]) << 16) |
        (((kryptos_u32_t)block[1]) <<  8) |
        block[0];

    B = (((kryptos_u32_t)block[7]) << 24) |
        (((kryptos_u32_t)block[6]) << 16) |
        (((kryptos_u32_t)block[5]) <<  8) |
        block[4];


    for (r = sks->rounds; r >= 1; r--) {
        B = kryptos_rc5_rotr(B - sks->K[(r << 1) + 1], A % kryptos_rc5_W) ^ A;
        A = kryptos_rc5_rotr(A - sks->K[r << 1], B % kryptos_rc5_W) ^ B;
    }

    A -= sks->K[0];
    B -= sks->K[1];

    block[0] = A & 0xFF;
    block[1] = (A >> 8) & 0xFF;
    block[2] = (A >> 16) & 0xFF;
    block[3] = A >> 24;
    block[4] = B & 0xFF;
    block[5] = (B >> 8) & 0xFF;
    block[6] = (B >> 16) & 0xFF;
    block[7] = B >> 24;

    A = B = 0;
}

#undef kryptos_rc5_W

#undef kryptos_rc5_U

#undef kryptos_rc5_PW

#undef kryptos_rc5_QW

#undef kryptos_rc5_K_NR

#undef kryptos_rc5_rotl

#undef kryptos_rc5_rotr

#undef kryptos_rc5_rev32
