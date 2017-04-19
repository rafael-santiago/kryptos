/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_aes.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>
#include <string.h>

#define kryptos_aes_rotl(x, s) ( (x) << (s) | (x) >> ((sizeof(x) << 3) - (s)) )

#define kryptos_aes_get_u8_from_u32(x, n) ( ( (x) >> (24 - ((n) << 3)) ) & 0xff )

// INFO(Rafael): Mix Columns constants.
#define KRYPTOS_AES_DX1 0x02030101 // Returns the byte(0) (MSB) of the multiplication
#define KRYPTOS_AES_DX2 0x01020301 // Returns the byte(1) (DX1 >>> 8)
#define KRYPTOS_AES_DX3 0x01010203 // Returns the byte(2) (DX2 >>> 8)
#define KRYPTOS_AES_DX4 0x03010102 // Returns the byte(3) (DX3 >>> 8)

// INFO(Rafael): Mix Columns inverse contants.
#define KRYPTOS_AES_INVDX1 0x0E0B0D09 // Returns the byte(0) (MSB) of the inverse multiplication
#define KRYPTOS_AES_INVDX2 0x090E0B0D // Returns the byte(1) (INVDX1 >>> 8)
#define KRYPTOS_AES_INVDX3 0x0D090E0B // Returns the byte(2) (INVDX2 >>> 8)
#define KRYPTOS_AES_INVDX4 0x0B0D090E // Returns the byte(3) (INVDX3 >>> 8)

struct kryptos_128bit_u8_matrix {
    kryptos_u8_t data[4][4];
};

struct kryptos_aes_subkeys {
    struct kryptos_128bit_u8_matrix round[11];
};

// INFO(Rafael): The AES pre-sets.

static kryptos_u32_t kryptos_aes_rcon[10] = {
    0x01000000,
    0x02000000,
    0x04000000,
    0x08000000,
    0x10000000,
    0x20000000,
    0x40000000,
    0x80000000,
    0x1b000000,
    0x36000000
};

// INFO(Rafael): The s-box and its inverse.

static kryptos_u8_t kryptos_aes_sbox[16][16] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static kryptos_u8_t kryptos_aes_sbox_1[16][16] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// INFO(Rafael): Look-up tables for the Mix columns transform.

static kryptos_u8_t kryptos_aes_ptable[256] = {
      1,   3,   5,  15,  17,  51,  85, 255,  26,  46, 114, 150, 161, 248,  19,  53,  95, 225,  56,  72, 216, 115, 149,
    164, 247,   2,   6,  10,  30,  34, 102, 170, 229,  52,  92, 228,  55,  89, 235,  38, 106, 190, 217, 112, 144,
    171, 230,  49,  83, 245,   4,  12,  20,  60,  68, 204,  79, 209, 104, 184, 211, 110, 178, 205,  76, 212, 103,
    169, 224,  59,  77, 215,  98, 166, 241,   8,  24,  40, 120, 136, 131, 158, 185, 208, 107, 189, 220, 127,
    129, 152, 179, 206,  73, 219, 118, 154, 181, 196,  87, 249,  16,  48,  80, 240,  11,  29,  39, 105, 187,
    214,  97, 163, 254,  25,  43, 125, 135, 146, 173, 236,  47, 113, 147, 174, 233,  32,  96, 160, 251,  22,
     58,  78, 210, 109, 183, 194,  93, 231,  50,  86, 250,  21,  63,  65, 195,  94, 226,  61,  71, 201,  64, 192,
     91, 237,  44, 116, 156, 191, 218, 117, 159, 186, 213, 100, 172, 239,  42, 126, 130, 157, 188, 223,
    122, 142, 137, 128, 155, 182, 193, 88,  232,  35, 101, 175, 234,  37, 111, 177, 200,  67, 197,  84,
    252,  31,  33,  99, 165, 244,   7,  9,   27,  45, 119, 153, 176, 203,  70, 202,  69, 207,  74, 222, 121, 139,
    134, 145, 168, 227,  62,  66, 198,  81, 243,  14,  18,  54,  90, 238,  41, 123, 141, 140, 143, 138, 133,
    148, 167, 242,  13,  23,  57,  75, 221, 124, 132, 151, 162, 253,  28,  36, 108, 180, 199,  82, 246,   1
};

static kryptos_u8_t kryptos_aes_ltable[256] = {
      0, 255,  25,   1,  50,   2,  26, 198,  75, 199,  27, 104,  51, 238, 223,   3, 100,   4, 224,  14,  52, 141, 129, 239,
     76, 113,   8, 200, 248, 105,  28, 193, 125, 194,  29, 181, 249, 185,  39, 106,  77, 228, 166, 114, 154,
    201,   9, 120, 101,  47, 138,   5,  33,  15, 225,  36,  18, 240, 130,  69,  53, 147, 218, 142, 150, 143, 219,
    189,  54, 208, 206, 148,  19,  92, 210, 241,  64,  70, 131,  56, 102, 221, 253,  48, 191,   6, 139,  98, 179,
     37, 226, 152,  34, 136, 145,  16, 126, 110,  72, 195, 163, 182,  30,  66,  58, 107,  40,  84, 250, 133,  61,
    186,  43, 121,  10,  21, 155, 159,  94, 202,  78, 212, 172, 229, 243, 115, 167,  87, 175,  88, 168,  80,
    244, 234, 214, 116,  79, 174, 233, 213, 231, 230, 173, 232,  44, 215, 117, 122, 235,  22,  11, 245,
     89, 203,  95, 176, 156, 169,  81, 160, 127,  12, 246, 111,  23, 196,  73, 236, 216,  67,  31,  45, 164,
    118, 123, 183, 204, 187,  62,  90, 251,  96, 177, 134,  59,  82, 161, 108, 170,  85,  41, 157, 151, 178,
    135, 144,  97, 190, 220, 252, 188, 149, 207, 205,  55,  63,  91, 209,  83,  57, 132,  60,  65, 162, 109,
     71,  20,  42, 158,  93,  86, 242, 211, 171,  68,  17, 146, 217,  35,  32,  46, 137, 180, 124, 184, 38,119,
    153, 227, 165, 103,  74, 237, 222, 197,  49, 254,  24,  13,  99, 140, 128, 192, 247, 112,   7
};

typedef void (*kryptos_aes_block_processor)(kryptos_u8_t *block, struct kryptos_aes_subkeys sks);

static void kryptos_aes_sto_u32_into_byte_matrix(const kryptos_u32_t word[4], struct kryptos_128bit_u8_matrix *u8m);

static kryptos_u8_t kryptos_aes_subbytes(const kryptos_u32_t value, const size_t byte, const kryptos_u8_t sbox[16][16]);

static void kryptos_aes_ld_user_key(kryptos_u32_t key[4], const kryptos_u8_t *user_key, const size_t user_key_size);

static void kryptos_aes_eval_skeys(const kryptos_u8_t *key, const size_t key_size, struct kryptos_aes_subkeys *sks);

static kryptos_u8_t kryptos_aes_mul_xy(const kryptos_u8_t x, const kryptos_u8_t y);

static kryptos_u32_t kryptos_aes_mix_col(const kryptos_u32_t value);

static kryptos_u32_t kryptos_aes_inv_mix_col(const kryptos_u32_t value);

static void kryptos_aes_block_encrypt(kryptos_u8_t *block, struct kryptos_aes_subkeys sks);

static void kryptos_aes_block_decrypt(kryptos_u8_t *block, struct kryptos_aes_subkeys sks);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(aes, kKryptosCipherAES, KRYPTOS_AES_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(aes,
                                    ktask,
                                    kryptos_aes_subkeys,
                                    sks,
                                    kryptos_aes_block_processor,
                                    aes_block_processor,
                                    kryptos_aes_eval_skeys((*ktask)->key, (*ktask)->key_size, &sks),
                                    kryptos_aes_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_aes_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_AES_BLOCKSIZE,
                                    aes_cipher_epilogue,
                                    outblock,
                                    aes_block_processor(outblock, sks))

static void kryptos_aes_sto_u32_into_byte_matrix(const kryptos_u32_t word[4], struct kryptos_128bit_u8_matrix *u8m) {
    size_t i, j, k, c;

    for (i = 0, k = 0; i < 4; i++) {
        for (j = 0; j < 4; j++, k++) {
            u8m->data[k & 3][i] = kryptos_aes_get_u8_from_u32(word[i], j);
        }
    }

    i = j = k = c = 0;
}

static kryptos_u8_t kryptos_aes_subbytes(const kryptos_u32_t value, const size_t byte, const kryptos_u8_t sbox[16][16]) {
    kryptos_u8_t r, c;
    kryptos_u8_t eval;
    r = c = kryptos_aes_get_u8_from_u32(value, byte);
    r = r >> 4;
    c = c & 0xff;
    eval = sbox[r][c];
    r = c = 0;
    return eval;
}

static void kryptos_aes_ld_user_key(kryptos_u32_t key[4], const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;
    kryptos_ld_user_key_prologue(key, 4, user_key, user_key_size, kp, kp_end, w, b, return);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_byte(key[w], kp, kp_end, kryptos_aes_ld_user_key_epilogue);
    kryptos_ld_user_key_epilogue(kryptos_aes_ld_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_aes_eval_skeys(const kryptos_u8_t *key, const size_t key_size, struct kryptos_aes_subkeys *sks) {
    kryptos_u32_t wkey[4], roundkey[4];
    size_t i, curr, next, j;

    kryptos_aes_ld_user_key(wkey, key, key_size);

    // INFO(Rafael): Storing the 128-bits of the user key.
    kryptos_aes_sto_u32_into_byte_matrix(wkey, &sks->round[0]);
    for (curr = 0, next = 1; curr < 10; curr++, next++) {
        // INFO(Rafael): Handling the last matrix column
        wkey[0] = 0;
        for (i = 0; i < 4; i++) {
            wkey[0] = wkey[0] << 8 | sks->round[curr].data[i][3];
        }

        // INFO(Rafael): Rotating (level=1-byte) the entire column
        wkey[0] = kryptos_aes_rotl(wkey[0], 8);

        // INFO(Rafael): Replacing the byte basing on the s-box.
        wkey[1] = 0;
        for (i = 0; i < 4; i++) {
            wkey[1] = wkey[1] << 8 | kryptos_aes_subbytes(wkey[0], i, kryptos_aes_sbox);
        }
        wkey[0] = wkey[1] ^ kryptos_aes_rcon[curr];

        // INFO(Rafael): Handling the N-column.
        for (j = 0; j < 4; j++) {
            wkey[1] = 0;
            for(i=0;i < 4; i++) {
                wkey[1] = wkey[1] << 8 | sks->round[curr].data[i][j];
            }
            wkey[0] = roundkey[j] = wkey[0] ^ wkey[1];
        }
        // INFO(Rafael): Storing the evaluated roundkey of the current step.
        kryptos_aes_sto_u32_into_byte_matrix(roundkey, &sks->round[next]);
    }

    memset(roundkey, 0, sizeof(roundkey));
    memset(wkey, 0, sizeof(wkey));
    i = curr = next = j = 0;
}

static kryptos_u8_t kryptos_aes_mul_xy(const kryptos_u8_t x, const kryptos_u8_t y) {
    if (x != 0 && y != 0) {
        return kryptos_aes_ptable[(kryptos_aes_ltable[x] + kryptos_aes_ltable[y]) % 255];
    }

    return 0;
}

static kryptos_u32_t kryptos_aes_mix_col(const kryptos_u32_t value) {
    kryptos_u8_t wb[4], db[4];
    kryptos_u32_t temp;

    wb[0] = kryptos_aes_get_u8_from_u32(value, 0);
    wb[1] = kryptos_aes_get_u8_from_u32(value, 1);
    wb[2] = kryptos_aes_get_u8_from_u32(value, 2);
    wb[3] = kryptos_aes_get_u8_from_u32(value, 3);

    db[0] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX1, 0);
    db[1] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX1, 1);
    db[2] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX1, 2);
    db[3] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX1, 3);

    temp = kryptos_aes_mul_xy(wb[0], db[0]) ^
           kryptos_aes_mul_xy(wb[1], db[1]) ^
           kryptos_aes_mul_xy(wb[2], db[2]) ^
           kryptos_aes_mul_xy(wb[3], db[3]);

    db[0] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX2, 0);
    db[1] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX2, 1);
    db[2] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX2, 2);
    db[3] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX2, 3);

    temp = temp << 8 | kryptos_aes_mul_xy(wb[0], db[0]) ^
                       kryptos_aes_mul_xy(wb[1], db[1]) ^
                       kryptos_aes_mul_xy(wb[2], db[2]) ^
                       kryptos_aes_mul_xy(wb[3], db[3]);

    db[0] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX3, 0);
    db[1] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX3, 1);
    db[2] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX3, 2);
    db[3] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX3, 3);

    temp = temp << 8 | kryptos_aes_mul_xy(wb[0], db[0]) ^
                       kryptos_aes_mul_xy(wb[1], db[1]) ^
                       kryptos_aes_mul_xy(wb[2], db[2]) ^
                       kryptos_aes_mul_xy(wb[3], db[3]);

    db[0] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX4, 0);
    db[1] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX4, 1);
    db[2] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX4, 2);
    db[3] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_DX4, 3);

    temp = temp << 8 | kryptos_aes_mul_xy(wb[0], db[0]) ^
                       kryptos_aes_mul_xy(wb[1], db[1]) ^
                       kryptos_aes_mul_xy(wb[2], db[2]) ^
                       kryptos_aes_mul_xy(wb[3], db[3]);

    memset(wb, 0, sizeof(wb));
    memset(db, 0, sizeof(db));

    return temp;
}

static kryptos_u32_t kryptos_aes_inv_mix_col(const kryptos_u32_t value) {
    kryptos_u8_t wb[4], db[4];
    kryptos_u32_t temp;

    wb[0] = kryptos_aes_get_u8_from_u32(value, 0);
    wb[1] = kryptos_aes_get_u8_from_u32(value, 1);
    wb[2] = kryptos_aes_get_u8_from_u32(value, 2);
    wb[3] = kryptos_aes_get_u8_from_u32(value, 3);

    db[0] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX1, 0);
    db[1] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX1, 1);
    db[2] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX1, 2);
    db[3] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX1, 3);

    temp = kryptos_aes_mul_xy(wb[0], db[0]) ^
           kryptos_aes_mul_xy(wb[1], db[1]) ^
           kryptos_aes_mul_xy(wb[2], db[2]) ^
           kryptos_aes_mul_xy(wb[3], db[3]);

    db[0] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX2, 0);
    db[1] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX2, 1);
    db[2] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX2, 2);
    db[3] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX2, 3);

    temp = temp << 8 | kryptos_aes_mul_xy(wb[0], db[0]) ^
                       kryptos_aes_mul_xy(wb[1], db[1]) ^
                       kryptos_aes_mul_xy(wb[2], db[2]) ^
                       kryptos_aes_mul_xy(wb[3], db[3]);

    db[0] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX3, 0);
    db[1] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX3, 1);
    db[2] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX3, 2);
    db[3] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX3, 3);

    temp = temp << 8 | kryptos_aes_mul_xy(wb[0], db[0]) ^
                       kryptos_aes_mul_xy(wb[1], db[1]) ^
                       kryptos_aes_mul_xy(wb[2], db[2]) ^
                       kryptos_aes_mul_xy(wb[3], db[3]);

    db[0] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX4, 0);
    db[1] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX4, 1);
    db[2] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX4, 2);
    db[3] = kryptos_aes_get_u8_from_u32(KRYPTOS_AES_INVDX4, 3);

    temp = temp << 8 | kryptos_aes_mul_xy(wb[0], db[0]) ^
                       kryptos_aes_mul_xy(wb[1], db[1]) ^
                       kryptos_aes_mul_xy(wb[2], db[2]) ^
                       kryptos_aes_mul_xy(wb[3], db[3]);

    memset(wb, 0, sizeof(wb));
    memset(db, 0, sizeof(db));

    return temp;
}

static void kryptos_aes_block_encrypt(kryptos_u8_t *block, struct kryptos_aes_subkeys sks) {
    struct kryptos_128bit_u8_matrix state;
    size_t i, j, r, k;
    kryptos_u8_t b;
    kryptos_u32_t wblock[4];

    state.data[0][0] = *block;
    state.data[0][1] = *(block +  1);
    state.data[0][2] = *(block +  2);
    state.data[0][3] = *(block +  3);
    state.data[1][0] = *(block +  4);
    state.data[1][1] = *(block +  5);
    state.data[1][2] = *(block +  6);
    state.data[1][3] = *(block +  7);
    state.data[2][0] = *(block +  8);
    state.data[2][1] = *(block +  9);
    state.data[2][2] = *(block + 10);
    state.data[2][3] = *(block + 11);
    state.data[3][0] = *(block + 12);
    state.data[3][1] = *(block + 13);
    state.data[3][2] = *(block + 14);
    state.data[3][3] = *(block + 15);

    // INFO(Rafael): AddRoundKey.
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state.data[i][j] = sks.round[0].data[i][j] ^ state.data[i][j];
        }
    }

    for (r = 1; r < 11; r++) {
        // INFO(Rafael): SubBytes.
        for (i = 0; i < 4; i++) {
            for (j = 0;j < 4; j++) {
                wblock[i] = wblock[i] << 8 | state.data[j][i];
            }
        }

        for (i = 0; i < 4; i++) {
            for(j = 0; j < 4; j++) {
                state.data[j][i] = kryptos_aes_subbytes(wblock[i], j, kryptos_aes_sbox);
            }
        }

        // INFO(Rafael): ShiftRows.
        for (i = 1; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                wblock[i] = wblock[i] << 8 | state.data[i][j];
            }
        }

        wblock[1] = kryptos_aes_rotl(wblock[1], 8);
        wblock[2] = kryptos_aes_rotl(wblock[2], 16);
        wblock[3] = kryptos_aes_rotl(wblock[3], 24);

        for (i = 1; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                state.data[i][j] = kryptos_aes_get_u8_from_u32(wblock[i], j);
            }
        }

        if (r < 10) {
            for (i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    wblock[i] = wblock[i] << 8 | state.data[j][i];
                }
            }
            // INFO(Rafael): MixColumns.
            for (j = 0; j < 4; j++) {
                wblock[j] = kryptos_aes_mix_col(wblock[j]);
            }
            // INFO(Rafael): AddRoundKey.
            for (i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    state.data[j][i] = kryptos_aes_get_u8_from_u32(wblock[i],j) ^ sks.round[r].data[j][i];
                }
            }
        } else {
            // INFO(Rafael): AddRoundKey.
            for (i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    state.data[i][j] = state.data[i][j] ^ sks.round[r].data[i][j];
                }
            }
        }
    }

           *block = state.data[0][0];
    *(block +  1) = state.data[0][1];
    *(block +  2) = state.data[0][2];
    *(block +  3) = state.data[0][3];
    *(block +  4) = state.data[1][0];
    *(block +  5) = state.data[1][1];
    *(block +  6) = state.data[1][2];
    *(block +  7) = state.data[1][3];
    *(block +  8) = state.data[2][0];
    *(block +  9) = state.data[2][1];
    *(block + 10) = state.data[2][2];
    *(block + 11) = state.data[2][3];
    *(block + 12) = state.data[3][0];
    *(block + 13) = state.data[3][1];
    *(block + 14) = state.data[3][2];
    *(block + 15) = state.data[3][3];

    memset(state.data, 0, sizeof(state.data));
    memset(wblock, 0, sizeof(wblock));
    i = j = r = k = b = 0;
}

static void kryptos_aes_block_decrypt(kryptos_u8_t *block, struct kryptos_aes_subkeys sks) {
    struct kryptos_128bit_u8_matrix state;
    size_t i, j, r, k;
    kryptos_u8_t b;
    kryptos_u32_t wblock[4];

    state.data[0][0] = *block;
    state.data[0][1] = *(block +  1);
    state.data[0][2] = *(block +  2);
    state.data[0][3] = *(block +  3);
    state.data[1][0] = *(block +  4);
    state.data[1][1] = *(block +  5);
    state.data[1][2] = *(block +  6);
    state.data[1][3] = *(block +  7);
    state.data[2][0] = *(block +  8);
    state.data[2][1] = *(block +  9);
    state.data[2][2] = *(block + 10);
    state.data[2][3] = *(block + 11);
    state.data[3][0] = *(block + 12);
    state.data[3][1] = *(block + 13);
    state.data[3][2] = *(block + 14);
    state.data[3][3] = *(block + 15);

    for (r = 10; r > 0; r--) {
        if (r < 10) {
            // INFO(Rafael): AddRoundKey.
            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    state.data[i][j] = state.data[i][j] ^ sks.round[r].data[i][j];
                }
            }

            for (i = 0; i < 4; i++) {
                for (j = 0; j < 4; j++) {
                    wblock[i] = wblock[i] << 8 | state.data[j][i];
                }
            }

            // INFO(Rafael): MixColumns.
            for(j = 0; j < 4; j++) {
                wblock[j] = kryptos_aes_inv_mix_col(wblock[j]);
            }

            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    state.data[j][i] = kryptos_aes_get_u8_from_u32(wblock[i], j);
                }
            }
        } else {
            // INFO(Rafael): AddRoundKey.
            for(i = 0; i < 4; i++) {
                for(j = 0; j < 4; j++) {
                    state.data[i][j] = state.data[i][j] ^ sks.round[r].data[i][j];
                }
            }
        }

        // INFO(Rafael): ShiftRows.
        for (i = 1; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                wblock[i] = wblock[i] << 8 | state.data[i][j];
            }
        }

        wblock[1] = kryptos_aes_rotl(wblock[1], 24);
        wblock[2] = kryptos_aes_rotl(wblock[2], 16);
        wblock[3] = kryptos_aes_rotl(wblock[3], 8);
        for(i = 1; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                state.data[i][j] = kryptos_aes_get_u8_from_u32(wblock[i], j);
            }
        }

        // INFO(Rafael): SubBytes.
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                wblock[i] = wblock[i] << 8 | state.data[j][i];
            }
        }
        for (i = 0; i < 4; i++) {
            for (j = 0; j < 4; j++) {
                state.data[j][i] = kryptos_aes_subbytes(wblock[i], j, kryptos_aes_sbox_1);
            }
        }
    }

    // INFO(Rafael): AddRoundKey.
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state.data[i][j] = sks.round[0].data[i][j] ^ state.data[i][j];
        }
    }

           *block = state.data[0][0];
    *(block +  1) = state.data[0][1];
    *(block +  2) = state.data[0][2];
    *(block +  3) = state.data[0][3];
    *(block +  4) = state.data[1][0];
    *(block +  5) = state.data[1][1];
    *(block +  6) = state.data[1][2];
    *(block +  7) = state.data[1][3];
    *(block +  8) = state.data[2][0];
    *(block +  9) = state.data[2][1];
    *(block + 10) = state.data[2][2];
    *(block + 11) = state.data[2][3];
    *(block + 12) = state.data[3][0];
    *(block + 13) = state.data[3][1];
    *(block + 14) = state.data[3][2];
    *(block + 15) = state.data[3][3];

    memset(state.data, 0, sizeof(state.data));
    memset(wblock, 0, sizeof(wblock));
    i = j = r = k = b = 0;
}
