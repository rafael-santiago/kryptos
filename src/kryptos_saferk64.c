/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_saferk64.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define KRYPTOS_SAFERK64_MAX_ROUND 800

#define kryptos_saferk64_shl(x, s) ( (x) << (s) | (x) >> ( ( sizeof(x) << 3 ) - (s) ) )

#define kryptos_saferk64_get_u8_from_u32(x, n) ( ( (x) >> (24 - ((n) << 3)) ) & 0xff )

// TODO(Rafael): It should be improved a little.
#define kryptos_saferk64_HT2(a1, a2, b1, b2) {\
 b1 = ( 2 * a1 + a2 ) % 256;\
 b2 = (   a1 +  a2  ) % 256;\
}

// TODO(Rafael): It should be improved a little.
#define kryptos_saferk64_IHT2(a1, a2, b1, b2) {\
 b1 = (  a1 - a2 ) % 256;\
 b2 = ( -a1 + 2*a2 ) % 256;\
}

// INFO(Rafael): The lookup tables that I am using for this implementation.

// INFO(Rafael): The following lookup table contains the results of (45^x mod 257).

static kryptos_u8_t kryptos_saferk64_e_lt[256] = { 0x01, 0x2d, 0xe2, 0x93, 0xbe, 0x45, 0x15, 0xae,
                                                   0x78, 0x03, 0x87, 0xa4, 0xb8, 0x38, 0xcf, 0x3f,
                                                   0x08, 0x67, 0x09, 0x94, 0xeb, 0x26, 0xa8, 0x6b,
                                                   0xbd, 0x18, 0x34, 0x1b, 0xbb, 0xbf, 0x72, 0xf7,
                                                   0x40, 0x35, 0x48, 0x9c, 0x51, 0x2f, 0x3b, 0x55,
                                                   0xe3, 0xc0, 0x9f, 0xd8, 0xd3, 0xf3, 0x8d, 0xb1,
                                                   0xff, 0xa7, 0x3e, 0xdc, 0x86, 0x77, 0xd7, 0xa6,
                                                   0x11, 0xfb, 0xf4, 0xba, 0x92, 0x91, 0x64, 0x83,
                                                   0xf1, 0x33, 0xef, 0xda, 0x2c, 0xb5, 0xb2, 0x2b,
                                                   0x88, 0xd1, 0x99, 0xcb, 0x8c, 0x84, 0x1d, 0x14,
                                                   0x81, 0x97, 0x71, 0xca, 0x5f, 0xa3, 0x8b, 0x57,
                                                   0x3c, 0x82, 0xc4, 0x52, 0x5c, 0x1c, 0xe8, 0xa0,
                                                   0x04, 0xb4, 0x85, 0x4a, 0xf6, 0x13, 0x54, 0xb6,
                                                   0xdf, 0x0c, 0x1a, 0x8e, 0xde, 0xe0, 0x39, 0xfc,
                                                   0x20, 0x9b, 0x24, 0x4e, 0xa9, 0x98, 0x9e, 0xab,
                                                   0xf2, 0x60, 0xd0, 0x6c, 0xea, 0xfa, 0xc7, 0xd9,
                                                   0x00, 0xd4, 0x1f, 0x6e, 0x43, 0xbc, 0xec, 0x53,
                                                   0x89, 0xfe, 0x7a, 0x5d, 0x49, 0xc9, 0x32, 0xc2,
                                                   0xf9, 0x9a, 0xf8, 0x6d, 0x16, 0xdb, 0x59, 0x96,
                                                   0x44, 0xe9, 0xcd, 0xe6, 0x46, 0x42, 0x8f, 0x0a,
                                                   0xc1, 0xcc, 0xb9, 0x65, 0xb0, 0xd2, 0xc6, 0xac,
                                                   0x1e, 0x41, 0x62, 0x29, 0x2e, 0x0e, 0x74, 0x50,
                                                   0x02, 0x5a, 0xc3, 0x25, 0x7b, 0x8a, 0x2a, 0x5b,
                                                   0xf0, 0x06, 0x0d, 0x47, 0x6f, 0x70, 0x9d, 0x7e,
                                                   0x10, 0xce, 0x12, 0x27, 0xd5, 0x4c, 0x4f, 0xd6,
                                                   0x79, 0x30, 0x68, 0x36, 0x75, 0x7d, 0xe4, 0xed,
                                                   0x80, 0x6a, 0x90, 0x37, 0xa2, 0x5e, 0x76, 0xaa,
                                                   0xc5, 0x7f, 0x3d, 0xaf, 0xa5, 0xe5, 0x19, 0x61,
                                                   0xfd, 0x4d, 0x7c, 0xb7, 0x0b, 0xee, 0xad, 0x4b,
                                                   0x22, 0xf5, 0xe7, 0x73, 0x23, 0x21, 0xc8, 0x05,
                                                   0xe1, 0x66, 0xdd, 0xb3, 0x58, 0x69, 0x63, 0x56,
                                                   0x0f, 0xa1, 0x31, 0x95, 0x17, 0x07, 0x3a, 0x28 };

// INFO(Rafael): The log table. A.k.a the e^-1. This table contains the inverse of (45^x mod 257)
//               in this case the results of log45(45^x mod 257).

static kryptos_u8_t kryptos_saferk64_l_lt[256] = { 0x80, 0x00, 0xb0, 0x09, 0x60, 0xef, 0xb9, 0xfd,
                                                   0x10, 0x12, 0x9f, 0xe4, 0x69, 0xba, 0xad, 0xf8,
                                                   0xc0, 0x38, 0xc2, 0x65, 0x4f, 0x06, 0x94, 0xfc,
                                                   0x19, 0xde, 0x6a, 0x1b, 0x5d, 0x4e, 0xa8, 0x82,
                                                   0x70, 0xed, 0xe8, 0xec, 0x72, 0xb3, 0x15, 0xc3,
                                                   0xff, 0xab, 0xb6, 0x47, 0x44, 0x01, 0xac, 0x25,
                                                   0xc9, 0xfa, 0x8e, 0x41, 0x1a, 0x21, 0xcb, 0xd3,
                                                   0x0d, 0x6e, 0xfe, 0x26, 0x58, 0xda, 0x32, 0x0f,
                                                   0x20, 0xa9, 0x9d, 0x84, 0x98, 0x05, 0x9c, 0xbb,
                                                   0x22, 0x8c, 0x63, 0xe7, 0xc5, 0xe1, 0x73, 0xc6,
                                                   0xaf, 0x24, 0x5b, 0x87, 0x66, 0x27, 0xf7, 0x57,
                                                   0xf4, 0x96, 0xb1, 0xb7, 0x5c, 0x8b, 0xd5, 0x54,
                                                   0x79, 0xdf, 0xaa, 0xf6, 0x3e, 0xa3, 0xf1, 0x11,
                                                   0xca, 0xf5, 0xd1, 0x17, 0x7b, 0x93, 0x83, 0xbc,
                                                   0xbd, 0x52, 0x1e, 0xeb, 0xae, 0xcc, 0xd6, 0x35,
                                                   0x08, 0xc8, 0x8a, 0xb4, 0xe2, 0xcd, 0xbf, 0xd9,
                                                   0xd0, 0x50, 0x59, 0x3f, 0x4d, 0x62, 0x34, 0x0a,
                                                   0x48, 0x88, 0xb5, 0x56, 0x4c, 0x2e, 0x6b, 0x9e,
                                                   0xd2, 0x3d, 0x3c, 0x03, 0x13, 0xfb, 0x97, 0x51,
                                                   0x75, 0x4a, 0x91, 0x71, 0x23, 0xbe, 0x76, 0x2a,
                                                   0x5f, 0xf9, 0xd4, 0x55, 0x0b, 0xdc, 0x37, 0x31,
                                                   0x16, 0x74, 0xd7, 0x77, 0xa7, 0xe6, 0x07, 0xdb,
                                                   0xa4, 0x2f, 0x46, 0xf3, 0x61, 0x45, 0x67, 0xe3,
                                                   0x0c, 0xa2, 0x3b, 0x1c, 0x85, 0x18, 0x04, 0x1d,
                                                   0x29, 0xa0, 0x8f, 0xb2, 0x5a, 0xd8, 0xa6, 0x7e,
                                                   0xee, 0x8d, 0x53, 0x4b, 0xa1, 0x9a, 0xc1, 0x0e,
                                                   0x7a, 0x49, 0xa5, 0x2c, 0x81, 0xc4, 0xc7, 0x36,
                                                   0x2b, 0x7f, 0x43, 0x95, 0x33, 0xf2, 0x6c, 0x68,
                                                   0x6d, 0xf0, 0x02, 0x28, 0xce, 0xdd, 0x9b, 0xea,
                                                   0x5e, 0x99, 0x7c, 0x14, 0x86, 0xcf, 0xe5, 0x42,
                                                   0xb8, 0x40, 0x78, 0x2d, 0x3a, 0xe9, 0x64, 0x1f,
                                                   0x92, 0x90, 0x7d, 0x39, 0x6f, 0xe0, 0x89, 0x30 };

struct kryptos_saferk64_32bit_pair {
    kryptos_u32_t side[2];
};

struct kryptos_saferk64_subkeys {
    struct kryptos_saferk64_32bit_pair K[KRYPTOS_SAFERK64_MAX_ROUND << 1];
    int rounds;
};

typedef void (*kryptos_saferk64_block_processor)(kryptos_u8_t *block, const struct kryptos_saferk64_subkeys *sks);

static void kryptos_saferk64_ld_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_saferk64_make_key(const kryptos_u8_t *key, const size_t key_size, struct kryptos_saferk64_subkeys *sks);

static void kryptos_saferk64_block_encrypt(kryptos_u8_t *block, const struct kryptos_saferk64_subkeys *sks);

static void kryptos_saferk64_block_decrypt(kryptos_u8_t *block, const struct kryptos_saferk64_subkeys *sks);

KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(saferk64, ktask, kKryptosCipherSAFERK64, KRYPTOS_SAFERK64_BLOCKSIZE, int *rounds,
                                       {
                                            if (rounds != NULL) {
                                                ktask->arg[0] = rounds;
                                            } else {
                                                ktask->arg[0] = NULL;
                                            }
                                        })

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(saferk64,
                                    ktask,
                                    kryptos_saferk64_subkeys,
                                    sks,
                                    kryptos_saferk64_block_processor,
                                    saferk64_block_processor,
                                    {
                                        // INFO(Rafael): Loading the rounds parameter if possible.
                                        if ((*ktask)->arg[0] == NULL) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "SAFER K-64 round parameter is missing.";
                                            goto kryptos_saferk64_cipher_epilogue;
                                        }
                                        sks.rounds = *(int *)(*ktask)->arg[0];
                                        // INFO(Rafael): The rounds parameter requires some checking.
                                        if (sks.rounds < 1) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "SAFER K-64 round underflow.";
                                            goto kryptos_saferk64_cipher_epilogue;
                                        } else if (sks.rounds > KRYPTOS_SAFERK64_MAX_ROUND) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "SAFER K-64 round overflow.";
                                            goto kryptos_saferk64_cipher_epilogue;
                                        }
                                        // INFO(Rafael): The rounds parameter is ok, let's make the key.
                                        kryptos_saferk64_make_key((*ktask)->key, (*ktask)->key_size, &sks);
                                    },
                                    kryptos_saferk64_block_encrypt, /* There is no additional steps before encryption */,
                                    kryptos_saferk64_block_decrypt, /* There is no additional steps before decryption */,
                                    KRYPTOS_SAFERK64_BLOCKSIZE,
                                    saferk64_cipher_epilogue,
                                    outblock,
                                    saferk64_block_processor(outblock, &sks),
                                    NULL /* GCM E function arg (No GCM) */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E_NO_SUPPORT(saferk64)

static void kryptos_saferk64_ld_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t b, w;

    kryptos_ld_user_key_prologue(key, 2, user_key, user_key_size, kp, kp_end, w, b, return);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_saferk64_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_saferk64_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_saferk64_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_saferk64_ld_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_saferk64_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_saferk64_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_saferk64_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_saferk64_ld_user_key_epilogue);

    kryptos_ld_user_key_epilogue(kryptos_saferk64_ld_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_saferk64_make_key(const kryptos_u8_t *key, const size_t key_size, struct kryptos_saferk64_subkeys *sks) {
    size_t i, i_nr;
#ifdef KRYPTOS_KERNEL_MODE
    static struct kryptos_saferk64_32bit_pair c[KRYPTOS_SAFERK64_MAX_ROUND << 1];
#else
    struct kryptos_saferk64_32bit_pair c[KRYPTOS_SAFERK64_MAX_ROUND << 1];
#endif
    kryptos_u32_t K1[2];
    kryptos_u8_t b0, b1, b2, b3, b4, b5, b6, b7;
    kryptos_u8_t e0, e1, e2, e3, e4, e5, e6, e7;

    kryptos_saferk64_ld_user_key(sks->K[0].side, key, key_size);

    i_nr = sks->rounds << 1;

    for (i = 0; i < i_nr; i++) {
        c[i].side[0] =                     kryptos_saferk64_e_lt[kryptos_saferk64_e_lt[(9 * (i + 2) + 1) % 257]];
        c[i].side[0] = c[i].side[0] << 8 | kryptos_saferk64_e_lt[kryptos_saferk64_e_lt[(9 * (i + 2) + 2) % 257]];
        c[i].side[0] = c[i].side[0] << 8 | kryptos_saferk64_e_lt[kryptos_saferk64_e_lt[(9 * (i + 2) + 3) % 257]];
        c[i].side[0] = c[i].side[0] << 8 | kryptos_saferk64_e_lt[kryptos_saferk64_e_lt[(9 * (i + 2) + 4) % 257]];
        c[i].side[1] = 		           kryptos_saferk64_e_lt[kryptos_saferk64_e_lt[(9 * (i + 2) + 5) % 257]];
        c[i].side[1] = c[i].side[1] << 8 | kryptos_saferk64_e_lt[kryptos_saferk64_e_lt[(9 * (i + 2) + 6) % 257]];
        c[i].side[1] = c[i].side[1] << 8 | kryptos_saferk64_e_lt[kryptos_saferk64_e_lt[(9 * (i + 2) + 7) % 257]];
        c[i].side[1] = c[i].side[1] << 8 | kryptos_saferk64_e_lt[kryptos_saferk64_e_lt[(9 * (i + 2) + 8) % 257]];
    }

    K1[0] = sks->K[0].side[0];
    K1[1] = sks->K[0].side[1];

    // INFO(Rafael): Generating the remaining (2 * r) sub-keys.
    for (i = 1; i <= i_nr; i++) {
        b0 = kryptos_saferk64_get_u8_from_u32(K1[0], 0);
        b1 = kryptos_saferk64_get_u8_from_u32(K1[0], 1);
        b2 = kryptos_saferk64_get_u8_from_u32(K1[0], 2);
        b3 = kryptos_saferk64_get_u8_from_u32(K1[0], 3);
        b4 = kryptos_saferk64_get_u8_from_u32(K1[1], 0);
        b5 = kryptos_saferk64_get_u8_from_u32(K1[1], 1);
        b6 = kryptos_saferk64_get_u8_from_u32(K1[1], 2);
        b7 = kryptos_saferk64_get_u8_from_u32(K1[1], 3);

        b0 = kryptos_saferk64_shl(b0, 3);
        b1 = kryptos_saferk64_shl(b1, 3);
        b2 = kryptos_saferk64_shl(b2, 3);
        b3 = kryptos_saferk64_shl(b3, 3);
        b4 = kryptos_saferk64_shl(b4, 3);
        b5 = kryptos_saferk64_shl(b5, 3);
        b6 = kryptos_saferk64_shl(b6, 3);
        b7 = kryptos_saferk64_shl(b7, 3);

        K1[0] = (kryptos_u32_t) b0 << 24 | (kryptos_u32_t) b1 << 16 | (kryptos_u32_t) b2 << 8 | (kryptos_u32_t) b3;
        K1[1] = (kryptos_u32_t) b4 << 24 | (kryptos_u32_t) b5 << 16 | (kryptos_u32_t) b6 << 8 | (kryptos_u32_t) b7;

        e0 = kryptos_saferk64_get_u8_from_u32(c[i - 1].side[0], 0);
        e1 = kryptos_saferk64_get_u8_from_u32(c[i - 1].side[0], 1);
        e2 = kryptos_saferk64_get_u8_from_u32(c[i - 1].side[0], 2);
        e3 = kryptos_saferk64_get_u8_from_u32(c[i - 1].side[0], 3);
        e4 = kryptos_saferk64_get_u8_from_u32(c[i - 1].side[1], 0);
        e5 = kryptos_saferk64_get_u8_from_u32(c[i - 1].side[1], 1);
        e6 = kryptos_saferk64_get_u8_from_u32(c[i - 1].side[1], 2);
        e7 = kryptos_saferk64_get_u8_from_u32(c[i - 1].side[1], 3);

        e0 = e0 + b0;
        e1 = e1 + b1;
        e2 = e2 + b2;
        e3 = e3 + b3;
        e4 = e4 + b4;
        e5 = e5 + b5;
        e6 = e6 + b6;
        e7 = e7 + b7;

        sks->K[i].side[0] = (kryptos_u32_t) e0 << 24 | (kryptos_u32_t) e1 << 16 | (kryptos_u32_t) e2 << 8 | (kryptos_u32_t) e3;
        sks->K[i].side[1] = (kryptos_u32_t) e4 << 24 | (kryptos_u32_t) e5 << 16 | (kryptos_u32_t) e6 << 8 | (kryptos_u32_t) e7;
    }

    i = i_nr = 0;
    b0 = e0 = b1 = e1 = b2 = e2 = b3 = e3 = b4 = e4 = b5 = e5 = b6 = e6 = b7 = e7 = 0;
    memset(c, 0, sizeof(c));
    memset(K1, 0, sizeof(K1));
}

static void kryptos_saferk64_block_encrypt(kryptos_u8_t *block, const struct kryptos_saferk64_subkeys *sks) {
    size_t r;
    kryptos_u8_t c0, c1, c2, c3, c4, c5, c6, c7;
    kryptos_u8_t b0, b1, b2, b3, b4, b5, b6, b7;

    c0 =       *block; c1 = *(block + 1); c2 = *(block + 2); c3 = *(block + 3);
    c4 = *(block + 4); c5 = *(block + 5); c6 = *(block + 6); c7 = *(block + 7);

    for (r = 0; r < sks->rounds; r++) {

        // INFO(Rafael): First step.
        c0 ^= kryptos_saferk64_get_u8_from_u32(sks->K[r << 1].side[0], 0);
        c1 += kryptos_saferk64_get_u8_from_u32(sks->K[r << 1].side[0], 1);
        c2 += kryptos_saferk64_get_u8_from_u32(sks->K[r << 1].side[0], 2);
        c3 ^= kryptos_saferk64_get_u8_from_u32(sks->K[r << 1].side[0], 3);
        c4 ^= kryptos_saferk64_get_u8_from_u32(sks->K[r << 1].side[1], 0);
        c5 += kryptos_saferk64_get_u8_from_u32(sks->K[r << 1].side[1], 1);
        c6 += kryptos_saferk64_get_u8_from_u32(sks->K[r << 1].side[1], 2);
        c7 ^= kryptos_saferk64_get_u8_from_u32(sks->K[r << 1].side[1], 3);

        // INFO(Rafael): Second step.
        c0 = kryptos_saferk64_e_lt[c0];
        c1 = kryptos_saferk64_l_lt[c1];
        c2 = kryptos_saferk64_l_lt[c2];
        c3 = kryptos_saferk64_e_lt[c3];
        c4 = kryptos_saferk64_e_lt[c4];
        c5 = kryptos_saferk64_l_lt[c5];
        c6 = kryptos_saferk64_l_lt[c6];
        c7 = kryptos_saferk64_e_lt[c7];

        // INFO(Rafael): Third step.
        c0 += kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) + 1].side[0], 0);
        c1 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) + 1].side[0], 1);
        c2 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) + 1].side[0], 2);
        c3 += kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) + 1].side[0], 3);
        c4 += kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) + 1].side[1], 0);
        c5 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) + 1].side[1], 1);
        c6 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) + 1].side[1], 2);
        c7 += kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) + 1].side[1], 3);

        // INFO(Rafael): Fourth step.
        kryptos_saferk64_HT2(c0, c1, b0, b1);
        kryptos_saferk64_HT2(c2, c3, b2, b3);
        kryptos_saferk64_HT2(c4, c5, b4, b5);
        kryptos_saferk64_HT2(c6, c7, b6, b7);

        kryptos_saferk64_HT2(b0, b2, c0, c1);
        kryptos_saferk64_HT2(b4, b6, c2, c3);
        kryptos_saferk64_HT2(b1, b3, c4, c5);
        kryptos_saferk64_HT2(b5, b7, c6, c7);

        kryptos_saferk64_HT2(c0, c2, b0, b1);
        kryptos_saferk64_HT2(c4, c6, b2, b3);
        kryptos_saferk64_HT2(c1, c3, b4, b5);
        kryptos_saferk64_HT2(c5, c7, b6, b7);

        c0 = b0;
        c1 = b1;
        c2 = b2;
        c3 = b3;
        c4 = b4;
        c5 = b5;
        c6 = b6;
        c7 = b7;
    }

    // INFO(Rafael): Final T transform.
    c0 ^= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[0], 0);
    c1 += kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[0], 1);
    c2 += kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[0], 2);
    c3 ^= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[0], 3);
    c4 ^= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[1], 0);
    c5 += kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[1], 1);
    c6 += kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[1], 2);
    c7 ^= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[1], 3);

          *block = c0; *(block + 1) = c1; *(block + 2) = c2; *(block + 3) = c3;
    *(block + 4) = c4; *(block + 5) = c5; *(block + 6) = c6; *(block + 7) = c7;

    r = 0;

    c0 =
    c1 =
    c2 =
    c3 =
    c4 =
    c5 =
    c6 =
    c7 = 0;
}

static void kryptos_saferk64_block_decrypt(kryptos_u8_t *block, const struct kryptos_saferk64_subkeys *sks) {
    size_t r;
    kryptos_u8_t c0, c1, c2, c3, c4, c5, c6, c7;
    kryptos_u8_t b0, b1, b2, b3, b4, b5, b6, b7;

    c0 =       *block; c1 = *(block + 1); c2 = *(block + 2); c3 = *(block + 3);
    c4 = *(block + 4); c5 = *(block + 5); c6 = *(block + 6); c7 = *(block + 7);

    // INFO(Rafael): Initial T transform.
    c0 ^= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[0], 0);
    c1 -= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[0], 1);
    c2 -= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[0], 2);
    c3 ^= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[0], 3);
    c4 ^= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[1], 0);
    c5 -= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[1], 1);
    c6 -= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[1], 2);
    c7 ^= kryptos_saferk64_get_u8_from_u32(sks->K[sks->rounds << 1].side[1], 3);

    for (r = sks->rounds; r >= 1; r--) {

        // INFO(Rafael): First step.
        kryptos_saferk64_IHT2(c0, c1, b0, b1);
        kryptos_saferk64_IHT2(c2, c3, b2, b3);
        kryptos_saferk64_IHT2(c4, c5, b4, b5);
        kryptos_saferk64_IHT2(c6, c7, b6, b7);

        kryptos_saferk64_IHT2(b0, b4, c0, c1);
        kryptos_saferk64_IHT2(b1, b5, c2, c3);
        kryptos_saferk64_IHT2(b2, b6, c4, c5);
        kryptos_saferk64_IHT2(b3, b7, c6, c7);

        kryptos_saferk64_IHT2(c0, c4, b0, b1);
        kryptos_saferk64_IHT2(c1, c5, b2, b3);
        kryptos_saferk64_IHT2(c2, c6, b4, b5);
        kryptos_saferk64_IHT2(c3, c7, b6, b7);

        c0 = b0;
        c1 = b1;
        c2 = b2;
        c3 = b3;
        c4 = b4;
        c5 = b5;
        c6 = b6;
        c7 = b7;

        // INFO(Rafael): Second step.
        c0 -= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 1].side[0], 0);
        c1 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 1].side[0], 1);
        c2 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 1].side[0], 2);
        c3 -= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 1].side[0], 3);
        c4 -= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 1].side[1], 0);
        c5 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 1].side[1], 1);
        c6 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 1].side[1], 2);
        c7 -= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 1].side[1], 3);

        // INFO(Rafael): Third step.
        c0 = kryptos_saferk64_l_lt[c0];
        c1 = kryptos_saferk64_e_lt[c1];
        c2 = kryptos_saferk64_e_lt[c2];
        c3 = kryptos_saferk64_l_lt[c3];
        c4 = kryptos_saferk64_l_lt[c4];
        c5 = kryptos_saferk64_e_lt[c5];
        c6 = kryptos_saferk64_e_lt[c6];
        c7 = kryptos_saferk64_l_lt[c7];

        // INFO(Rafael): Fourth step.
        c0 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 2].side[0], 0);
        c1 -= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 2].side[0], 1);
        c2 -= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 2].side[0], 2);
        c3 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 2].side[0], 3);
        c4 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 2].side[1], 0);
        c5 -= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 2].side[1], 1);
        c6 -= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 2].side[1], 2);
        c7 ^= kryptos_saferk64_get_u8_from_u32(sks->K[(r << 1) - 2].side[1], 3);
    }

          *block = c0; *(block + 1) = c1; *(block + 2) = c2; *(block + 3) = c3;
    *(block + 4) = c4; *(block + 5) = c5; *(block + 6) = c6; *(block + 7) = c7;

    r = 0;

    c0 =
    c1 =
    c2 =
    c3 =
    c4 =
    c5 =
    c6 =
    c7 = 0;
}

#undef KRYPTOS_SAFERK64_MAX_ROUND

#undef kryptos_saferk64_shl

#undef kryptos_saferk64_get_u8_from_u32

#undef kryptos_saferk64_HT2

#undef kryptos_saferk64_IHT2
