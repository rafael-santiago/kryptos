/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_des.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#include <string.h>

#define kryptos_des_SHL(x, s)  (x) << (s) | (x) >> ( ( sizeof( (x) ) << 3) - (s) ) // WARN(Rafael): The lack of ( ... ) was planned, do not mess.

#define KRYPTOS_DES_MASTER_SIZE 70

// WARN(Rafael): The shifts are done on 28-bit values but here I am using 32-bit values, due to it the
//               shift levels were increased by 4.
static int kryptos_des_SH[] = { 0, 5, 5, 6, 6, 6, 6, 6, 6, 5, 6, 6, 6, 6, 6, 6, 5 };

// INFO(Rafael): PC-1 table.
static int kryptos_des_PC_1[] = {
    56, 48, 40, 32, 24, 16,  8,
     0, 57, 49, 41, 33, 25, 17,
     9,  1, 58, 50, 42, 34, 26,
    18, 10,  2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,
     6, 61, 53, 45, 37, 29, 21,
    13,  5, 60, 52, 44, 36, 28,
    20, 12,  4, 27, 19, 11,  3
};

// INFO(Rafael): PC-2 table.
static int kryptos_des_PC_2[] = {
    13, 16, 10, 23,  0,  4,
     2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7,
    15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54,
    29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52,
    45, 41, 49, 35, 28, 31
};

// INFO(Rafael): S-BOXES.

static int kryptos_des_S1[4][16] = {
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
};

static int kryptos_des_S2[4][16] = {
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
};

static int kryptos_des_S3[4][16] = {
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
};

static int kryptos_des_S4[4][16] = {
     7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
};

static int kryptos_des_S5[4][16] = {
     2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
};

static int kryptos_des_S6[4][16] = {
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
};

static int kryptos_des_S7[4][16] = {
     4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
};

static int kryptos_des_S8[4][16] = {
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12, 7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9, 2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5, 8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
};

// INFO(Rafael): IP table.
static int kryptos_des_IP[] = {
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
    56, 48, 40, 32, 24, 16,  8, 0,
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6
};

// INFO(Rafael): Selection table E.
static int kryptos_des_E[] = {
    31,  0,  1,  2,  3,  4,
     3,  4,  5,  6,  7,  8,
     7,  8,  9, 10, 11, 12,
    11, 12, 13, 14, 15, 16,
    15, 16, 17, 18, 19, 20,
    19, 20, 21, 22, 23, 24,
    23, 24, 25, 26, 27, 28,
    27, 28, 29, 30, 31,  0
};

//INFO(Rafael): P table.
static int kryptos_des_P []  = {
    15,  6, 19, 20,
    28, 11, 27, 16,
     0, 14, 22, 25,
     4, 17, 30,  9,
     1,  7, 23, 13,
    31, 26,  2,  8,
    18, 12, 29,  5,
    21, 10,  3, 24
};

//INFO(Rafael): Inverse IP table.
static int kryptos_des_IP_1 [] = {
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
    32, 0, 40,  8, 48, 16, 56, 24
};

struct kryptos_des_key {
    kryptos_u32_t L;
    kryptos_u32_t R;
};

struct kryptos_des_subkeys {
 struct kryptos_des_key K[18];
};

typedef void (*kryptos_des_block_processor)(kryptos_u8_t *block, struct kryptos_des_subkeys sks);

#define kryptos_des_getbit_from_u32(w, n) (kryptos_u8_t)( ( ( (w) << (n) ) >> 31 ) + 48 )

static kryptos_u32_t kryptos_des_bitseq_to_u32(kryptos_u8_t bitseq[KRYPTOS_DES_MASTER_SIZE]);

static kryptos_u32_t kryptos_des_f(kryptos_u32_t R, kryptos_u32_t KL, kryptos_u32_t KR);

static void kryptos_des_expand_user_key(struct kryptos_des_subkeys *sks, const kryptos_u8_t *key, const size_t key_size);

static void kryptos_des_ld_user_key(kryptos_u32_t key[2], const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_des_block_encrypt(kryptos_u8_t *block, struct kryptos_des_subkeys sks);

static void kryptos_des_block_decrypt(kryptos_u8_t *block, struct kryptos_des_subkeys sks);

static kryptos_u32_t kryptos_des_bitseq_to_u32(kryptos_u8_t bitseq[KRYPTOS_DES_MASTER_SIZE]) {
    kryptos_u32_t value = 0L;
    size_t i;

    for (i = 0; bitseq[i] != 0; i++) {
        value = (value << 1) | (kryptos_u32_t) (bitseq[i] - 48);
    }

    return value;
}

static kryptos_u32_t kryptos_des_f(kryptos_u32_t R, kryptos_u32_t KL, kryptos_u32_t KR) {
    size_t i;
    kryptos_u8_t bits[KRYPTOS_DES_MASTER_SIZE], REx[KRYPTOS_DES_MASTER_SIZE];
    kryptos_u32_t RL, RR;
    kryptos_u32_t b, l, c;

    memset(bits,'\0',sizeof(bits));
    for (i = 0; i < 32; i++) {
        bits[i] = kryptos_des_getbit_from_u32(R, i);
    }

    // INFO(Rafael): E expansion.
    memset(REx,'\0',sizeof(REx));
    for (i = 0; i < 48; i++) {
        REx[i] = bits[kryptos_des_E[i]];
    }

    memset(bits,'\0',sizeof(bits));
    for (i = 0; i < 24; i++) {
        bits[i] = REx[i];
    }

    RL = kryptos_des_bitseq_to_u32(bits);

    for (; i < 48; i++) {
        bits[i-24] = REx[i];
    }

    RR = kryptos_des_bitseq_to_u32(bits);
    RL = RL ^ KL;
    RR = RR ^ KR;

    RL = RL << 8;
    RR = RR << 8;

    R=0;

    b = RL >> 26; // b1
    l = ((b & 0x20) >> 4) | (b & 0x1); // row -> [0]1001[0]
    c = (b & 0x1e) >> 1; // column -> 0[1001]0
    R = kryptos_des_S1[l][c];

    b = RL >> 20; // b2
    l = ((b & 0x20) >> 4) | (b & 0x1); // row -> [0]1001[0]
    c = (b & 0x1e) >> 1; // column -> 0[1001]0
    R = (R << 4) | kryptos_des_S2[l][c];

    b = RL >> 14; // b3 0 7
    l = ((b & 0x20) >> 4) | (b & 0x1);// row -> [0]1001[0]
    c = (b & 0x1e) >> 1; // column -> 0[1001]0
    R = (R << 4) | kryptos_des_S3[l][c];

    b = RL >> 8; // b4 2 13
    l = ((b & 0x20) >> 4) | (b & 0x1); // row -> [0]1001[0]
    c = (b & 0x1e) >> 1; // column -> 0[1001]0
    R = (R << 4) | kryptos_des_S4[l][c];

    b = RR >> 26; // b5
    l = ((b & 0x20) >> 4) | (b & 0x1); // row -> [0]1001[0]
    c = (b & 0x1e) >> 1; // column -> 0[1001]0
    R = (R << 4) | kryptos_des_S5[l][c];

    b = RR >> 20; // b6
    l = ((b & 0x20) >> 4) | (b & 0x1); // row -> [0]1001[0]
    c = (b & 0x1e) >> 1; // column -> 0[1001]0
    R = (R << 4) | kryptos_des_S6[l][c];

    b = RR >> 14; // b7
    l = ((b & 0x20) >> 4) | (b & 0x1); // row -> [0]1001[0]
    c = (b & 0x1e) >> 1; // column -> 0[1001]0
    R = (R << 4) | kryptos_des_S7[l][c];

    b = RR >> 8; // b8
    l = ((b & 0x20) >> 4) | (b & 0x1); // row -> [0]1001[0]
    c = (b & 0x1e) >> 1; // column -> 0[1001]0
    R = (R << 4) | kryptos_des_S8[l][c];

    memset(bits, 0, sizeof(bits));
    for (i = 0; i < 32; i++) {
        bits[i] = kryptos_des_getbit_from_u32(R, i);
    }

    memset(REx, 0, sizeof(REx));
    for (i = 0; i < 32; i++) {
        REx[i] = bits[kryptos_des_P[i]];
    }

    R = kryptos_des_bitseq_to_u32(REx);

    RR = 0;
    RL = 0;
    b  = 0;
    l  = 0;
    c  = 0;
    memset(bits, 0, sizeof(bits));
    memset(REx, 0, sizeof(REx));

    return R;
}

static void kryptos_des_block_encrypt(kryptos_u8_t *block, struct kryptos_des_subkeys sks) {
    kryptos_u8_t bits[KRYPTOS_DES_MASTER_SIZE], block_perm[KRYPTOS_DES_MASTER_SIZE];
    kryptos_u32_t L[18], R[18];
    size_t i;
    kryptos_u32_t plaintext[2];

    plaintext[0] = kryptos_get_u32_as_big_endian(block, 4);
    plaintext[1] = kryptos_get_u32_as_big_endian(block + 4, 4);

    // INFO(Rafael): IP permutation.
    memset(bits, 0, sizeof(bits));
    for(i = 0; i < 64; i++) {
        if (i < 32) {
            bits[i] = kryptos_des_getbit_from_u32(plaintext[0], i);
        } else {
            bits[i] = kryptos_des_getbit_from_u32(plaintext[1], i - 32);
        }
    }

    memset(block_perm, 0, sizeof(block_perm));
    for (i = 0; i < 64; i++) {
        block_perm[i] = bits[kryptos_des_IP[i]];
    }

    memset(bits, 0, sizeof(bits));
    for (i = 0; i < 32; i++) {
        bits[i] = block_perm[i];
    }

    L[0] = kryptos_des_bitseq_to_u32(bits);

    for (; i < 64; i++) {
        bits[i - 32] = block_perm[i];
    }

    R[0] = kryptos_des_bitseq_to_u32(bits);

    // INFO(Rafael): Starting the 16 DES rounds.

    for (i = 1; i < 17; i++) {
        L[i] = R[i - 1];
        R[i] = L[i - 1] ^ kryptos_des_f(R[i - 1], sks.K[i - 1].L, sks.K[i - 1].R);
    }

    // INFO(Rafael): Blocks reversion.
    memset(bits, 0, sizeof(bits));
    for (i = 0; i < 64; i++) {
        if (i < 32) {
            bits[i] = kryptos_des_getbit_from_u32(R[16], i);
        } else {
            bits[i] = kryptos_des_getbit_from_u32(L[16], i - 32);
        }
    }

    // INFO(Rafael): Inverse IP permutation.
    memset(block_perm, 0, sizeof(block_perm));
    for (i = 0; i < 64; i++) {
        block_perm[i] = bits[kryptos_des_IP_1[i]];
    }

    memset(bits, 0, sizeof(bits));
    for (i = 0; i < 32; i++) {
        bits[i] = block_perm[i];
    }
    plaintext[0] = kryptos_des_bitseq_to_u32(bits);

    for (; i < 64; i++) {
        bits[i-32] = block_perm[i];
    }
    plaintext[1] = kryptos_des_bitseq_to_u32(bits);

    kryptos_cpy_u32_as_big_endian(block, 8, plaintext[0]);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, plaintext[1]);

    memset(plaintext, 0, sizeof(plaintext));
    memset(bits, 0, sizeof(bits));
    memset(block_perm, 0, sizeof(block_perm));
    memset(L, 0, sizeof(L));
    memset(R, 0, sizeof(R));
}

static void kryptos_des_block_decrypt(kryptos_u8_t *block, struct kryptos_des_subkeys sks) {
    kryptos_u8_t bits[KRYPTOS_DES_MASTER_SIZE], block_perm[KRYPTOS_DES_MASTER_SIZE];
    kryptos_u32_t L[18], R[18];
    size_t i;
    kryptos_u32_t ciphertext[2];

    ciphertext[0] = kryptos_get_u32_as_big_endian(block, 4);
    ciphertext[1] = kryptos_get_u32_as_big_endian(block + 4, 4);

    // INFO(Rafael): IP permutation.
    memset(bits, 0, sizeof(bits));
    for (i = 0; i < 64; i++) {
        if (i < 32) {
            bits[i] = kryptos_des_getbit_from_u32(ciphertext[0], i);
        } else {
            bits[i] = kryptos_des_getbit_from_u32(ciphertext[1], i - 32);
        }
    }

    memset(block_perm, 0, sizeof(block_perm));
    for (i = 0; i < 64; i++) {
        block_perm[i] = bits[kryptos_des_IP[i]];
    }

    memset(bits, 0, sizeof(bits));
    for (i = 0; i < 32; i++) {
        bits[i] = block_perm[i];
    }

    L[0] = kryptos_des_bitseq_to_u32(bits);
    for (; i < 64; i++) {
        bits[i - 32] = block_perm[i];
    }

    R[0] = kryptos_des_bitseq_to_u32(bits);

    // INFO(Rafael): Start of the 16 DES rounds.
    for (i = 1; i < 17; i++) {
        L[i] = R[i - 1];
        R[i] = L[i - 1] ^ kryptos_des_f(R[i - 1], sks.K[(19 - i) - 3].L, sks.K[(19 - i) - 3].R);
    }

    // INFO(Rafael): Applying the blocks reversion.
    memset(bits, 0, sizeof(bits));
    for(i = 0; i < 64; i++) {
        if (i < 32) {
            bits[i] = kryptos_des_getbit_from_u32(R[16], i);
        } else {
            bits[i] = kryptos_des_getbit_from_u32(L[16], i - 32);
        }
    }

    // INFO(Rafael): IP permutation (inverse).
    memset(block_perm, 0, sizeof(block_perm));
    for (i = 0; i < 64; i++) {
        block_perm[i] = bits[kryptos_des_IP_1[i]];
    }

    memset(bits,'\0',sizeof(bits));
    for (i = 0; i < 32; i++) {
        bits[i] = block_perm[i];
    }
    ciphertext[0] = kryptos_des_bitseq_to_u32(bits);

    for (; i < 64; i++) {
        bits[i - 32] = block_perm[i];
    }
    ciphertext[1] = kryptos_des_bitseq_to_u32(bits);

    kryptos_cpy_u32_as_big_endian(block, 8, ciphertext[0]);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, ciphertext[1]);

    memset(ciphertext, 0, sizeof(ciphertext));
    memset(bits, 0, sizeof(bits));
    memset(block_perm, 0, sizeof(block_perm));
    memset(L, 0, sizeof(L));
    memset(R, 0, sizeof(R));
}

static void kryptos_des_ld_user_key(kryptos_u32_t key[2], const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t b;
    size_t w;

    memset(key, 0, sizeof(kryptos_u32_t) << 1);

    if (user_key == NULL || user_key_size == 0) {
        return;
    }

    kp = user_key;
    kp_end = kp + user_key_size;
    b = 0;
    w = 0;

#define kryptos_des_ld_user_key_byte(state, kp, kp_end, label) {\
    if (kp == kp_end) goto kryptos_des_ld_user_key_ ## label;\
    state = (state << 8) | (kryptos_u32_t)*kp;\
    kp++;\
    b = (b + 1) % sizeof(kryptos_u32_t);\
    if (b == 0) {\
        w = 1;\
    }\
}

    kryptos_des_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_des_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_des_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_des_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_des_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_des_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_des_ld_user_key_byte(key[w], kp, kp_end, epilogue);
    kryptos_des_ld_user_key_byte(key[w], kp, kp_end, epilogue);

#undef kryptos_des_ld_user_key_byte

kryptos_des_ld_user_key_epilogue:

    if (b > 0) {
        key[w] = key[w] << (sizeof(kryptos_u32_t) - b);
    }

    b = w = 0;
    kp = NULL;
    kp_end = NULL;
}

static void kryptos_des_expand_user_key(struct kryptos_des_subkeys *sks, const kryptos_u8_t *key, const size_t key_size) {
    kryptos_u8_t bits[KRYPTOS_DES_MASTER_SIZE], key_perm[KRYPTOS_DES_MASTER_SIZE];
    kryptos_u32_t C[18];
    kryptos_u32_t D[18];
    kryptos_u32_t user_key[2];
    size_t i, j;

    kryptos_des_ld_user_key(user_key, key, key_size);

    memset(bits, 0, sizeof(bits));

    // INFO(Rafael): Stripping the parity bits.
    for (i = 0; i < 64; i++) {
        if (i < 32) {
            bits[i] = kryptos_des_getbit_from_u32(user_key[0], i);
        } else {
            bits[i] = kryptos_des_getbit_from_u32(user_key[1], i - 32);
        }
    }

    memset(key_perm, 0, sizeof(key_perm));

    for (i = 0; i < 56; i++) {
        key_perm[i] = bits[kryptos_des_PC_1[i]];
    }

    memset(bits, 0, sizeof(bits));

    for (i = 0; i < 28; i++) {
        bits[i] = key_perm[i];
    }

    C[0] = kryptos_des_bitseq_to_u32(bits);

    for (; i < 56; i++) {
        bits[i - 28] = key_perm[i];
    }

    D[0] = kryptos_des_bitseq_to_u32(bits);

    // INFO(Rafael): Shift stuff.
    for (i = 1; i < 17; i++) {
        C[i] = (kryptos_des_SHL(C[i-1], kryptos_des_SH[i]) << 4) >> 4;
        D[i] = (kryptos_des_SHL(D[i-1], kryptos_des_SH[i]) << 4) >> 4;
    }

    // INFO(Rafael): Final permutation.
    for(i = 1; i < 17; i++) {
        memset(bits, 0, sizeof(bits));

        for (j = 0; j < 56; j++) {
            if(j < 28) {
                bits[j] = kryptos_des_getbit_from_u32(C[i], j + 4);
            } else {
                bits[j] = kryptos_des_getbit_from_u32(D[i], (j - 28) + 4);
            }
        }

        memset(key_perm, 0, sizeof(key_perm));

        for(j = 0; j < 48; j++) {
            key_perm[j] = bits[kryptos_des_PC_2[j]];
        }

        memset(bits, 0, sizeof(bits));

        // INFO(Rafael): Adding the current halve of the expanded key to the related struct.
        for (j = 0; j < 24; j++) {
            bits[j] = key_perm[j];
        }

        sks->K[i - 1].L = kryptos_des_bitseq_to_u32(bits);

        for (; j < 48; j++) {
            bits[j - 24] = key_perm[j];
        }

        sks->K[i - 1].R = kryptos_des_bitseq_to_u32(bits);
    }

    memset(C, 0L, sizeof(C));
    memset(D, 0L, sizeof(D));
    memset(key_perm, 0, sizeof(key_perm));
    memset(bits, 0, sizeof(bits));
    memset(user_key, 0, sizeof(user_key));
    i = j = 0;
}

void kryptos_des_setup(kryptos_task_ctx *ktask, kryptos_u8_t *key, const size_t key_size, const kryptos_cipher_mode_t mode) {
    if (ktask == NULL) {
        return;
    }

    ktask->cipher = kKryptosCipherDES;
    ktask->mode = mode;
    ktask->key = key;
    ktask->key_size = key_size;

    if (ktask->mode == kKryptosCBC && ktask->iv == NULL) {
        ktask->iv = kryptos_get_random_block(KRYPTOS_DES_BLOCKSIZE);
        ktask->iv_size = KRYPTOS_DES_BLOCKSIZE;
    }
}

void kryptos_des_cipher(kryptos_task_ctx **ktask) {
    struct kryptos_des_subkeys sks;
    kryptos_des_block_processor des_block_processor;
    kryptos_u8_t *in_p, *in_end, *out_p;
    kryptos_u8_t *outblock, *outblock_p, *inblock, *inblock_p;
    size_t in_size;

    if (kryptos_task_check(ktask) == 0) {
        return;
    }

    kryptos_des_expand_user_key(&sks, (*ktask)->key, (*ktask)->key_size);

    if ((*ktask)->action == kKryptosEncrypt) {
        des_block_processor = kryptos_des_block_encrypt;
    } else {
        des_block_processor = kryptos_des_block_decrypt;
    }

    kryptos_meta_block_processing_prologue(KRYPTOS_DES_BLOCKSIZE,
                                           inblock, inblock_p,
                                           outblock, outblock_p,
                                           in_size, (*ktask)->in_size);

    kryptos_meta_block_processing(KRYPTOS_DES_BLOCKSIZE,
                                  (*ktask)->action,
                                  (*ktask)->mode,
                                  (*ktask)->iv,
                                  (*ktask)->in,
                                  in_p, in_end,
                                  &in_size,
                                  (*ktask)->out, out_p,
                                  &(*ktask)->out_size,
                                  inblock_p,
                                  outblock_p,
                                  des_cipher_epilogue, des_block_processor(outblock, sks));

    kryptos_meta_block_processing_epilogue(des_cipher_epilogue,
                                           inblock, inblock_p, in_p, in_end,
                                           outblock, outblock_p, out_p,
                                           in_size,
                                           sks, ktask);

    des_block_processor = NULL;
}
