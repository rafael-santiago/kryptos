/*
 *                          Copyright (C) 2006, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_camellia.h>
#include <kryptos_endianess_utils.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos_task_check.h>
#include <kryptos.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
#endif

#define kryptos_camellia_rotl(x, s) ( (x) << (s) | (x) >> ( 32 - (s) ) )

#define KRYPTOS_CAMELLIA_SIGMA1L 0xa09e667f
#define KRYPTOS_CAMELLIA_SIGMA1R 0x3bcc908b
#define KRYPTOS_CAMELLIA_SIGMA2L 0xb67ae858
#define KRYPTOS_CAMELLIA_SIGMA2R 0x4caa73b2
#define KRYPTOS_CAMELLIA_SIGMA3L 0xc6ef372f
#define KRYPTOS_CAMELLIA_SIGMA3R 0xe94f82be
#define KRYPTOS_CAMELLIA_SIGMA4L 0x54ff53a5
#define KRYPTOS_CAMELLIA_SIGMA4R 0xf1d36f1c
#define KRYPTOS_CAMELLIA_SIGMA5L 0x10e527fa
#define KRYPTOS_CAMELLIA_SIGMA5R 0xde682d1d
#define KRYPTOS_CAMELLIA_SIGMA6L 0xb05688c2
#define KRYPTOS_CAMELLIA_SIGMA6R 0xb3e6c1fd

#define kryptos_camellia_get_u8_from_u32(x, b) ( ( (x) >> ( 24 - ((b) << 3) ) ) & 0xff )

#define kryptos_camellia_assignment(x, y) ( (y)[0] = (x)[0], (y)[1] = (x)[1], (y)[2] = (x)[2], (y)[3] = (x)[3] )

//INFO(Rafael): s-boxes

static kryptos_u8_t kryptos_camellia_s1[] = { 112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
                                               35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
                                              134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
                                              166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
                                              139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
                                              223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209, 23,    4, 215,
                                               20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83, 24,  242,  34,
                                              254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
                                              170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
                                               16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
                                              135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
                                               82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
                                              233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
                                              120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
                                              114,  7, 185,   85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
                                               64, 40, 211,  123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158 };

static kryptos_u8_t kryptos_camellia_s2[] = { 224,   5,  88, 217, 103,  78, 129, 203, 201,  11, 174, 106, 213,  24,  93, 130,
                                               70, 223, 214,  39, 138,  50,  75,  66, 219,  28, 158, 156,  58, 202,  37, 123,
                                               13, 113,  95,  31, 248, 215,  62, 157, 124,  96, 185, 190, 188, 139,  22,  52,
                                               77, 195, 114, 149, 171, 142, 186, 122, 179,   2, 180, 173, 162, 172, 216, 154,
                                               23,  26,  53, 204, 247, 153,  97,  90, 232,  36,  86,  64, 225,  99,   9,  51,
                                              191, 152, 151, 133, 104, 252, 236,  10, 218, 111,  83,  98, 163,  46,   8, 175,
                                               40, 176, 116, 194, 189,  54,  34,  56, 100,  30,  57,  44, 166,  48, 229,  68,
                                              253, 136, 159, 101, 135, 107, 244,  35,  72,  16, 209,  81, 192, 249, 210, 160,
                                               85, 161,  65, 250,  67,  19, 196,  47, 168, 182,  60,  43, 193, 255, 200, 165,
                                               32, 137,   0, 144,  71, 239, 234, 183,  21,   6, 205, 181,  18, 126, 187,  41,
                                               15, 184,   7,   4, 155, 148,  33, 102, 230, 206, 237, 231,  59, 254, 127, 197,
                                              164,  55, 177,  76, 145, 110, 141, 118,   3,  45, 222, 150,  38, 125, 198,  92,
                                              211, 242,  79,  25,  63, 220, 121,  29,  82, 235, 243, 109,  94, 251, 105, 178,
                                              240,  49,  12, 212, 207, 140, 226, 117, 169,  74,  87, 132,  17,  69,  27, 245,
                                              228,  14, 115, 170, 241, 221,  89,  20, 108, 146,  84, 208, 120, 112, 227,  73,
                                              128,  80, 167, 246, 119, 147, 134, 131,  42, 199,  91, 233, 238, 143,   1,  61 };

static kryptos_u8_t kryptos_camellia_s3[] = { 56,  65,  22, 118, 217, 147,  96, 242, 114, 194, 171, 154, 117,   6,  87, 160,
                                             145, 247, 181, 201, 162, 140, 210, 144, 246,   7, 167,  39, 142, 178,  73, 222,
                                              67,  92, 215, 199,  62, 245, 143, 103,  31,  24, 110, 175,  47, 226, 133,  13,
                                              83, 240, 156, 101, 234, 163, 174, 158, 236, 128,  45, 107, 168,  43,  54, 166,
                                             197, 134,  77,  51, 253, 102,  88, 150,  58,   9, 149,  16, 120, 216,  66, 204,
                                             239,  38, 229,  97,  26,  63,  59, 130, 182, 219, 212, 152, 232, 139,   2, 235,
                                              10,  44,  29, 176, 111, 141, 136,  14,  25, 135,  78,  11, 169,  12, 121,  17,
                                             127,  34, 231,  89, 225, 218,  61, 200,  18,   4, 116,  84,  48, 126, 180,  40,
                                              85, 104,  80, 190, 208, 196,  49, 203,  42, 173,  15, 202, 112, 255,  50, 105,
                                               8,  98,   0,  36, 209, 251, 186, 237,  69, 129, 115, 109, 132, 159, 238,  74,
                                             195,  46, 193,   1, 230,  37,  72, 153, 185, 179, 123, 249, 206, 191, 223, 113,
                                              41, 205, 108,  19, 100, 155,  99, 157, 192,  75, 183, 165, 137,  95, 177,  23,
                                             244, 188, 211,  70, 207,  55,  94,  71, 148, 250, 252,  91, 151, 254,  90, 172,
                                              60,  76,   3,  53, 243,  35, 184,  93, 106, 146, 213,  33,  68,  81, 198, 125,
                                              57, 131, 220, 170, 124, 119,  86,   5,  27, 164,  21,  52,  30,  28, 248,  82,
                                              32,  20, 233, 189, 221, 228, 161, 224, 138, 241, 214, 122, 187, 227,  64,  79 };

static kryptos_u8_t kryptos_camellia_s4[] = { 112,  44, 179, 192, 228,  87, 234, 174,  35, 107,  69, 165, 237,  79,  29, 146,
                                              134, 175, 124,  31,  62, 220,  94,  11, 166,  57, 213,  93, 217,  90,  81, 108,
                                              139, 154, 251, 176, 116,  43, 240, 132, 223, 203,  52, 118, 109, 169, 209,   4,
                                               20,  58, 222,  17,  50, 156,  83, 242, 254, 207, 195, 122,  36, 232,  96, 105,
                                              170, 160, 161,  98,  84,  30, 224, 100,  16,   0, 163, 117, 138, 230,   9, 221,
                                              135, 131, 205, 144, 115, 246, 157, 191,  82, 216, 200, 198, 129, 111,  19,  99,
                                              233, 167, 159, 188,  41, 249,  47, 180, 120,   6, 231, 113, 212, 171, 136, 141,
                                              114, 185, 248, 172,  54,  42,  60, 241,  64, 211, 187,  67,  21, 173, 119, 128,
                                              130, 236,  39, 229, 133,  53,  12,  65, 239, 147,  25,  33,  14,  78, 101, 189,
                                              184, 143, 235, 206,  48,  95, 197,  26, 225, 202,  71,  61,   1, 214,  86,  77,
                                               13, 102, 204,  45,  18,  32, 177, 153,  76, 194, 126,   5, 183,  49,  23, 215,
                                               88,  97,  27,  28,  15,  22,  24,  34,  68, 178, 181, 145,   8, 168, 252,  80,
                                              208, 125, 137, 151,  91, 149, 255, 210, 196,  72, 247, 219,   3, 218,  63, 148,
                                               92,   2,  74,  51, 103, 243, 127, 226, 155,  38,  55,  59, 150,  75, 190,  46,
                                              121, 140, 110, 142, 245, 182, 253,  89, 152, 106,  70, 186,  37,  66, 162, 250,
                                                7,  85, 238,  10,  73, 104,  56, 164,  40, 123, 201, 193, 227, 244, 199, 158 };
struct kryptos_camellia_subkeys {
    kryptos_u32_t kw[ 14][12]; // INFO(Rafael): kw1..kw4
    kryptos_u32_t  k[124][12]; // INFO(Rafael): k1..k18
    kryptos_u32_t ke[ 16][12]; // INFO(Rafael): ke1..ke4
    kryptos_camellia_keysize_t keysize;
};

typedef void (*kryptos_camellia_block_processor)(kryptos_u8_t *block, const struct kryptos_camellia_subkeys *sks);

static void kryptos_camellia_roll128b(kryptos_u32_t *x, int s);

static void kryptos_camellia_keyexp_128(const kryptos_u8_t *key, const size_t key_size, struct kryptos_camellia_subkeys *sks);

static void kryptos_camellia_keyexp_192_256(const kryptos_u8_t *key, const size_t key_size,
                                            struct kryptos_camellia_subkeys *sks);

static void kryptos_camellia_F(kryptos_u32_t *data, kryptos_u32_t kl, kryptos_u32_t kr, kryptos_u32_t *out);

static void kryptos_camellia_block_encrypt_128(kryptos_u8_t *block, const struct kryptos_camellia_subkeys *sks);

static void kryptos_camellia_block_decrypt_128(kryptos_u8_t *block, const struct kryptos_camellia_subkeys *sks);

static void kryptos_camellia_block_encrypt_192_256(kryptos_u8_t *block, const struct kryptos_camellia_subkeys *sks);

static void kryptos_camellia_block_decrypt_192_256(kryptos_u8_t *block, const struct kryptos_camellia_subkeys *sks);

static void kryptos_camellia_FL(kryptos_u32_t *data, const kryptos_u32_t kl, const kryptos_u32_t kr);

static void kryptos_camellia_FL_1(kryptos_u32_t *data, const kryptos_u32_t kl, const kryptos_u32_t kr);

KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(camellia, ktask, kKryptosCipherCAMELLIA, KRYPTOS_CAMELLIA_BLOCKSIZE,
                                       kryptos_camellia_keysize_t *keysize,
                                       {
                                            if (keysize != NULL) {
                                                ktask->arg[0] = keysize;
                                            } else {
                                                ktask->arg[0] = NULL;
                                            }
                                       })

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(camellia,
                                    ktask,
                                    kryptos_camellia_subkeys,
                                    sks,
                                    kryptos_camellia_block_processor,
                                    camellia_block_processor,
                                    {
                                        if ((*ktask)->arg[0] == NULL) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "CAMELLIA key size is missing.";
                                            goto kryptos_camellia_cipher_epilogue;
                                        }
                                        sks.keysize = *(kryptos_camellia_keysize_t *)(*ktask)->arg[0];
                                        // INFO(Rafael): Until now these are the supported key sizes.
                                        if (sks.keysize != kKryptosCAMELLIA128 &&
                                            sks.keysize != kKryptosCAMELLIA192 &&
                                            sks.keysize != kKryptosCAMELLIA256) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "CAMELLIA unknown key size.";
                                            goto kryptos_camellia_cipher_epilogue;
                                        }
                                        // INFO(Rafael): Depending on the key size, we must redirect the
                                        //               processing flow to the desired key expansion algorithm.
                                        if (sks.keysize == kKryptosCAMELLIA128) {
                                            kryptos_camellia_keyexp_128((*ktask)->key, (*ktask)->key_size, &sks);
                                        } else if (sks.keysize == kKryptosCAMELLIA192 ||
                                                   sks.keysize == kKryptosCAMELLIA256) {
                                            kryptos_camellia_keyexp_192_256((*ktask)->key, (*ktask)->key_size, &sks);
                                        }
                                    },
                                    kryptos_camellia_block_encrypt_128,
                                    {
                                        // INFO(Rafael): Dirty trick for using the correct encryption based on
                                        //               the chosen key size. Tip: "sks.keysize != kKryptosCAMELLIA128"
                                        //               would be naive because could inject a bug when added new key sizes.
                                        if (sks.keysize == kKryptosCAMELLIA192 ||
                                            sks.keysize == kKryptosCAMELLIA256) {
                                            camellia_block_processor = kryptos_camellia_block_encrypt_192_256;
                                        }
                                    },
                                    kryptos_camellia_block_decrypt_128,
                                    {
                                        // INFO(Rafael): Dirty trick for using the correct decryption based on
                                        //               the chosen key size. Tip: "sks.keysize != kKryptosCAMELLIA128"
                                        //               would be naive because could inject a bug when added new key sizes.
                                        if (sks.keysize == kKryptosCAMELLIA192 ||
                                            sks.keysize == kKryptosCAMELLIA256) {
                                            camellia_block_processor = kryptos_camellia_block_decrypt_192_256;
                                        }
                                    },
                                    KRYPTOS_CAMELLIA_BLOCKSIZE,
                                    camellia_cipher_epilogue,
                                    outblock,
                                    camellia_block_processor(outblock, &sks))

static void kryptos_camellia_roll128b(kryptos_u32_t *x, int s) {
    kryptos_u32_t t0, t1, t2, t3;
    kryptos_u32_t tt0, tt1, tt2, tt3;
    if (s > 0) {
        t0 = kryptos_camellia_rotl(x[0], 1);
        t1 = kryptos_camellia_rotl(x[1], 1);
        t2 = kryptos_camellia_rotl(x[2], 1);
        t3 = kryptos_camellia_rotl(x[3], 1);

        tt0 = t0 << 31;
        tt0 = kryptos_camellia_rotl(tt0, 1);
        tt1 = t1 << 31;
        tt1 = kryptos_camellia_rotl(tt1, 1);
        tt2 = t2 << 31;
        tt2 = kryptos_camellia_rotl(tt2, 1);
        tt3 = t3 << 31;
        tt3 = kryptos_camellia_rotl(tt3, 1);

        x[3] = x[3] << 1 | tt0;
        x[2] = x[2] << 1 | tt3;
        x[1] = x[1] << 1 | tt2;
        x[0] = x[0] << 1 | tt1;
        kryptos_camellia_roll128b(x, --s);
        t0 = t1 = t2 = t3 = tt0 = tt1 = tt2 = tt3 = 0;
    }
}

static void kryptos_camellia_ld_128_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;
    kryptos_ld_user_key_prologue(key, 4, user_key, user_key_size, kp, kp_end, w, b, return);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_128_user_key_epilogue);

    kryptos_ld_user_key_epilogue(kryptos_camellia_ld_128_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_camellia_ld_192_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;
    kryptos_ld_user_key_prologue(key, 6, user_key, user_key_size, kp, kp_end, w, b, return);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_192_user_key_epilogue);

    kryptos_ld_user_key_epilogue(kryptos_camellia_ld_192_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_camellia_ld_256_user_key(kryptos_u32_t *key, const kryptos_u8_t *user_key, const size_t user_key_size) {
    const kryptos_u8_t *kp, *kp_end;
    size_t w, b;
    kryptos_ld_user_key_prologue(key, 8, user_key, user_key_size, kp, kp_end, w, b, return);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);

    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);
    kryptos_ld_user_key_byte(key, w, b, kp, kp_end, kryptos_camellia_ld_256_user_key_epilogue);

    kryptos_ld_user_key_epilogue(kryptos_camellia_ld_256_user_key_epilogue, key, w, b, kp, kp_end);
}

static void kryptos_camellia_keyexp_128(const kryptos_u8_t *key, const size_t key_size, struct kryptos_camellia_subkeys *sks) {
    kryptos_u32_t KL[4], KR[4] = {0x00, 0x00, 0x00, 0x00};
    kryptos_u32_t D1[2], D2[2];
    kryptos_u32_t T[4], fout[2];
    kryptos_u32_t KA[4];

    kryptos_camellia_ld_128_user_key(KL, key, key_size);

    T[0] = KL[0] ^ KR[0];
    T[1] = KL[1] ^ KR[1];
    T[2] = KL[2] ^ KR[2];
    T[3] = KL[3] ^ KR[3];
    D1[0] = T[0];
    D1[1] = T[1];
    D2[0] = T[2];
    D2[1] = T[3];
    kryptos_camellia_F(D1, KRYPTOS_CAMELLIA_SIGMA1L, KRYPTOS_CAMELLIA_SIGMA1R, fout);
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, KRYPTOS_CAMELLIA_SIGMA2L, KRYPTOS_CAMELLIA_SIGMA2R, fout);
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    D1[0] = D1[0] ^ KL[0];
    D1[1] = D1[1] ^ KL[1];
    D2[0] = D2[0] ^ KL[2];
    D2[1] = D2[1] ^ KL[3];
    kryptos_camellia_F(D1, KRYPTOS_CAMELLIA_SIGMA3L, KRYPTOS_CAMELLIA_SIGMA3R, fout);
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, KRYPTOS_CAMELLIA_SIGMA4L, KRYPTOS_CAMELLIA_SIGMA4R, fout);
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];

    KA[0] = D1[0];
    KA[1] = D1[1];
    KA[2] = D2[0];
    KA[3] = D2[1];

    D1[0] = KA[0] ^ KR[0];
    D1[1] = KA[1] ^ KR[1];
    D2[0] = KA[2] ^ KR[2];
    D2[1] = KA[3] ^ KR[3];

    // INFO(Rafael): Generating the 128-bit sub-keys
    sks->kw[0][0] = KL[0]; // kw1
    sks->kw[0][1] = KL[1];
    sks->kw[1][0] = KL[2]; // kw2
    sks->kw[1][1] = KL[3];
    sks->k[0][0] = KA[0]; // k1
    sks->k[0][1] = KA[1];
    sks->k[1][0] = KA[2]; // k2
    sks->k[1][1] = KA[3];
    kryptos_camellia_assignment(KL, T);
    kryptos_camellia_roll128b(T, 15);
    sks->k[2][0] = T[0]; // k3
    sks->k[2][1] = T[1];
    sks->k[3][0] = T[2]; // k4
    sks->k[3][1] = T[3];
    kryptos_camellia_assignment(KA, T);
    kryptos_camellia_roll128b(T, 15);
    sks->k[4][0] = T[0]; // k5
    sks->k[4][1] = T[1];
    sks->k[5][0] = T[2]; // k6
    sks->k[5][1] = T[3];
    kryptos_camellia_assignment(KA, T);
    kryptos_camellia_roll128b(T, 30);
    sks->ke[0][0] = T[0]; // ke1
    sks->ke[0][1] = T[1];
    sks->ke[1][0] = T[2]; // ke2
    sks->ke[1][1] = T[3];
    kryptos_camellia_assignment(KL, T);
    kryptos_camellia_roll128b(T, 45);
    sks->k[6][0] = T[0]; // k7
    sks->k[6][1] = T[1];
    sks->k[7][0] = T[2]; // k8
    sks->k[7][1] = T[3];
    kryptos_camellia_assignment(KA, T);
    kryptos_camellia_roll128b(T, 45);
    sks->k[8][0] = T[0]; // k9
    sks->k[8][1] = T[1];
    kryptos_camellia_assignment(KL, T);
    kryptos_camellia_roll128b(T, 60);
    sks->k[ 9][0] = T[2]; // k10
    sks->k[ 9][1] = T[3];
    kryptos_camellia_assignment(KA, T);
    kryptos_camellia_roll128b(T, 60);
    sks->k[10][0] = T[0]; // k11
    sks->k[10][1] = T[1];
    sks->k[11][0] = T[2]; // k12
    sks->k[11][1] = T[3];
    kryptos_camellia_assignment(KL, T);
    kryptos_camellia_roll128b(T, 77);
    sks->ke[2][0] = T[0]; // ke3
    sks->ke[2][1] = T[1];
    sks->ke[3][0] = T[2]; // ke4
    sks->ke[3][1] = T[3];
    kryptos_camellia_assignment(KL, T);
    kryptos_camellia_roll128b(T, 94);
    sks->k[12][0] = T[0]; // k13
    sks->k[12][1] = T[1];
    sks->k[13][0] = T[2]; // k14
    sks->k[13][1] = T[3];
    kryptos_camellia_assignment(KA, T);
    kryptos_camellia_roll128b(T, 94);
    sks->k[14][0] = T[0]; // k15
    sks->k[14][1] = T[1];
    sks->k[15][0] = T[2]; // k16
    sks->k[15][1] = T[3];
    kryptos_camellia_assignment(KL, T);
    kryptos_camellia_roll128b(T, 111);
    sks->k[16][0] = T[0]; // k17
    sks->k[16][1] = T[1];
    sks->k[17][0] = T[2]; // k18
    sks->k[17][1] = T[3];
    kryptos_camellia_assignment(KA, T);
    kryptos_camellia_roll128b(T, 111);
    sks->kw[2][0] = T[0]; // kw3
    sks->kw[2][1] = T[1];
    sks->kw[3][0] = T[2]; // kw4
    sks->kw[3][1] = T[3];
    D1[0]   = D1[1]   = D2[0] = D2[1] =  T[0] = T[1]  =
     T[2]   =  T[3]   = KL[0] = KL[1] = KL[2] = KL[3] =
    KR[0]   = KR[1]   = KR[2] = KR[3] = KA[0] = KA[1] =
    KA[2]   = KA[3]   = fout[0] = fout[1] = 0;
}

static void kryptos_camellia_keyexp_192_256(const kryptos_u8_t *key, const size_t key_size,
                                            struct kryptos_camellia_subkeys *sks) {
    kryptos_u32_t KL[4], KR[4];
    kryptos_u32_t D1[2], D2[2];
    kryptos_u32_t T[4], fout[2];
    kryptos_u32_t KA[4], KB[4], K256[8], K192[6];

    if (sks->keysize == kKryptosCAMELLIA192) {
        kryptos_camellia_ld_192_user_key(K192, key, key_size);
        KL[0] = K192[0];
        KL[1] = K192[1];
        KL[2] = K192[2];
        KL[3] = K192[3];
        KR[0] = K192[4];
        KR[1] = K192[5];
        KR[2] = ~KR[0];
        KR[3] = ~KR[1];
        K192[0] = K192[1] = K192[2] = K192[3] = K192[4] = K192[5] = 0;
    } else if (sks->keysize == kKryptosCAMELLIA256) {
        kryptos_camellia_ld_256_user_key(K256, key, key_size);
        KL[0] = K256[0];
        KL[1] = K256[1];
        KL[2] = K256[2];
        KL[3] = K256[3];
        KR[0] = K256[4];
        KR[1] = K256[5];
        KR[2] = K256[6];
        KR[3] = K256[7];
        K256[0] = K256[1] = K256[2] = K256[3] = K256[4] = K256[5] = 
        K256[6] = K256[7] = 0;
    } else {
        return;
    }

    T[0] = KL[0] ^ KR[0];
    T[1] = KL[1] ^ KR[1];
    T[2] = KL[2] ^ KR[2];
    T[3] = KL[3] ^ KR[3];
    D1[0] = T[0];
    D1[1] = T[1];
    D2[0] = T[2];
    D2[1] = T[3];
    kryptos_camellia_F(D1, KRYPTOS_CAMELLIA_SIGMA1L, KRYPTOS_CAMELLIA_SIGMA1R, fout);
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, KRYPTOS_CAMELLIA_SIGMA2L, KRYPTOS_CAMELLIA_SIGMA2R, fout);
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    D1[0] = D1[0] ^ KL[0];
    D1[1] = D1[1] ^ KL[1];
    D2[0] = D2[0] ^ KL[2];
    D2[1] = D2[1] ^ KL[3];
    kryptos_camellia_F(D1, KRYPTOS_CAMELLIA_SIGMA3L, KRYPTOS_CAMELLIA_SIGMA3R, fout);
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, KRYPTOS_CAMELLIA_SIGMA4L, KRYPTOS_CAMELLIA_SIGMA4R, fout);
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];

    KA[0] = D1[0];
    KA[1] = D1[1];
    KA[2] = D2[0];
    KA[3] = D2[1];

    D1[0] = KA[0] ^ KR[0];
    D1[1] = KA[1] ^ KR[1];
    D2[0] = KA[2] ^ KR[2];
    D2[1] = KA[3] ^ KR[3];

    kryptos_camellia_F(D1, KRYPTOS_CAMELLIA_SIGMA5L, KRYPTOS_CAMELLIA_SIGMA5R, fout);
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, KRYPTOS_CAMELLIA_SIGMA6L, KRYPTOS_CAMELLIA_SIGMA6R, fout);
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    KB[0] = D1[0];
    KB[1] = D1[1];
    KB[2] = D2[0];
    KB[3] = D2[1];

    // INFO(Rafael): Generating the 192/256-bit sub-keys.
    sks->kw[0][0] = KL[0]; // kw1
    sks->kw[0][1] = KL[1];
    sks->kw[1][0] = KL[2]; // kw2
    sks->kw[1][1] = KL[3];
    sks->k[0][0] = KB[0]; // k1
    sks->k[0][1] = KB[1];
    sks->k[1][0] = KB[2]; // k2
    sks->k[1][1] = KB[3];
    kryptos_camellia_assignment(KR, T);
    kryptos_camellia_roll128b(T, 15);
    sks->k[2][0] = T[0]; // k3
    sks->k[2][1] = T[1];
    sks->k[3][0] = T[2]; // k4
    sks->k[3][1] = T[3];
    kryptos_camellia_assignment(KA, T);
    kryptos_camellia_roll128b(T, 15);
    sks->k[4][0] = T[0]; // k5
    sks->k[4][1] = T[1];
    sks->k[5][0] = T[2]; // k6
    sks->k[5][1] = T[3];
    kryptos_camellia_assignment(KR, T);
    kryptos_camellia_roll128b(T, 30);
    sks->ke[0][0] = T[0]; // ke1
    sks->ke[0][1] = T[1];
    sks->ke[1][0] = T[2]; // ke2
    sks->ke[1][1] = T[3];
    kryptos_camellia_assignment(KB, T);
    kryptos_camellia_roll128b(T, 30);
    sks->k[6][0] = T[0]; // k7
    sks->k[6][1] = T[1];
    sks->k[7][0] = T[2]; // k8
    sks->k[7][1] = T[3];
    kryptos_camellia_assignment(KL, T);
    kryptos_camellia_roll128b(T, 45);
    sks->k[8][0] = T[0]; // k9
    sks->k[8][1] = T[1];
    sks->k[9][0] = T[2]; // k10
    sks->k[9][1] = T[3];
    kryptos_camellia_assignment(KA, T);
    kryptos_camellia_roll128b(T, 45);
    sks->k[10][0] = T[0]; // k11
    sks->k[10][1] = T[1];
    sks->k[11][0] = T[2]; // k12
    sks->k[11][1] = T[3];
    kryptos_camellia_assignment(KL, T);
    kryptos_camellia_roll128b(T, 60);
    sks->ke[2][0] = T[0]; // ke3
    sks->ke[2][1] = T[1];
    sks->ke[3][0] = T[2]; // ke4
    sks->ke[3][1] = T[3];
    kryptos_camellia_assignment(KR, T);
    kryptos_camellia_roll128b(T, 60);
    sks->k[12][0] = T[0]; // k13
    sks->k[12][1] = T[1];
    sks->k[13][0] = T[2]; // k14
    sks->k[13][1] = T[3];
    kryptos_camellia_assignment(KB, T);
    kryptos_camellia_roll128b(T, 60);
    sks->k[14][0] = T[0]; // k15
    sks->k[14][1] = T[1];
    sks->k[15][0] = T[2]; // k16
    sks->k[15][1] = T[3];
    kryptos_camellia_assignment(KL, T);
    kryptos_camellia_roll128b(T, 77);
    sks->k[16][0] = T[0]; // k17
    sks->k[16][1] = T[1];
    sks->k[17][0] = T[2]; // k18
    sks->k[17][1] = T[3];
    kryptos_camellia_assignment(KA, T);
    kryptos_camellia_roll128b(T, 77);
    sks->ke[4][0] = T[0]; // ke5
    sks->ke[4][1] = T[1];
    sks->ke[5][0] = T[2]; // ke6
    sks->ke[5][1] = T[3];
    kryptos_camellia_assignment(KR, T);
    kryptos_camellia_roll128b(T, 94);
    sks->k[18][0] = T[0]; // k19
    sks->k[18][1] = T[1];
    sks->k[19][0] = T[2]; // k20
    sks->k[19][1] = T[3];
    kryptos_camellia_assignment(KA, T);
    kryptos_camellia_roll128b(T, 94);
    sks->k[20][0] = T[0]; // k21
    sks->k[20][1] = T[1];
    sks->k[21][0] = T[2]; // k22
    sks->k[21][1] = T[3];
    kryptos_camellia_assignment(KL, T);
    kryptos_camellia_roll128b(T, 111);
    sks->k[22][0] = T[0]; // k23
    sks->k[22][1] = T[1];
    sks->k[23][0] = T[2]; // k24
    sks->k[23][1] = T[3];
    kryptos_camellia_assignment(KB, T);
    kryptos_camellia_roll128b(T, 111);
    sks->kw[2][0] = T[0]; // kw3
    sks->kw[2][1] = T[1];
    sks->kw[3][0] = T[2]; // kw4
    sks->kw[3][1] = T[3];

    D1[0]   = D1[1]   = D2[0] = D2[1] =  T[0] = T[1]  =
     T[2]   =  T[3]   = KL[0] = KL[1] = KL[2] = KL[3] =
    KR[0]   = KR[1]   = KR[2] = KR[3] = KA[0] = KA[1] =
    KA[2]   = KA[3]   = KB[0] = KB[1] = KB[2] = KB[3] =
    fout[0] = fout[1] = 0L;
}

static void kryptos_camellia_F(kryptos_u32_t *data, kryptos_u32_t kl, kryptos_u32_t kr, kryptos_u32_t *out) {
    kryptos_u32_t x[2];
    kryptos_u8_t t1, t2, t3, t4, t5, t6, t7, t8;
    kryptos_u8_t y1, y2, y3, y4, y5, y6, y7, y8;
    x[0] = data[0] ^ kl;
    x[1] = data[1] ^ kr;
    t1 = kryptos_camellia_get_u8_from_u32(x[0], 0);
    t2 = kryptos_camellia_get_u8_from_u32(x[0], 1);
    t3 = kryptos_camellia_get_u8_from_u32(x[0], 2);
    t4 = kryptos_camellia_get_u8_from_u32(x[0], 3);
    t5 = kryptos_camellia_get_u8_from_u32(x[1], 0);
    t6 = kryptos_camellia_get_u8_from_u32(x[1], 1);
    t7 = kryptos_camellia_get_u8_from_u32(x[1], 2);
    t8 = kryptos_camellia_get_u8_from_u32(x[1], 3);
    t1 = kryptos_camellia_s1[t1];
    t2 = kryptos_camellia_s2[t2];
    t3 = kryptos_camellia_s3[t3];
    t4 = kryptos_camellia_s4[t4];
    t5 = kryptos_camellia_s2[t5];
    t6 = kryptos_camellia_s3[t6];
    t7 = kryptos_camellia_s4[t7];
    t8 = kryptos_camellia_s1[t8];
    y1 = t1 ^ t3 ^ t4 ^ t6 ^ t7 ^ t8;
    y2 = t1 ^ t2 ^ t4 ^ t5 ^ t7 ^ t8;
    y3 = t1 ^ t2 ^ t3 ^ t5 ^ t6 ^ t8;
    y4 = t2 ^ t3 ^ t4 ^ t5 ^ t6 ^ t7;
    y5 = t1 ^ t2 ^ t6 ^ t7 ^ t8;
    y6 = t2 ^ t3 ^ t5 ^ t7 ^ t8;
    y7 = t3 ^ t4 ^ t5 ^ t6 ^ t8;
    y8 = t1 ^ t4 ^ t5 ^ t6 ^ t7;
    out[0] = (kryptos_u32_t) y1 << 24 | (kryptos_u32_t) y2 << 16 | (kryptos_u32_t) y3 << 8 | (kryptos_u32_t) y4;
    out[1] = (kryptos_u32_t) y5 << 24 | (kryptos_u32_t) y6 << 16 | (kryptos_u32_t) y7 << 8 | (kryptos_u32_t) y8;
    t1 = t2 = t3 = t4 = t5 = t6 = t7 = t8 = y1 = y2 = y3 = y4 = y5 = y6 = y7 = y8 = x[0] = x[1] = 0;
}

static void kryptos_camellia_block_encrypt_128(kryptos_u8_t *block, const struct kryptos_camellia_subkeys *sks) {
    kryptos_u32_t D1[2], D2[2];
    kryptos_u32_t fout[2];

    D1[0] = kryptos_get_u32_as_big_endian(block, 4);
    D1[1] = kryptos_get_u32_as_big_endian(block + 4, 4);
    D2[0] = kryptos_get_u32_as_big_endian(block + 8, 4);
    D2[1] = kryptos_get_u32_as_big_endian(block + 12, 4);

    D1[0] = D1[0] ^ sks->kw[0][0]; // prewhitening
    D1[1] = D1[1] ^ sks->kw[0][1];
    D2[0] = D2[0] ^ sks->kw[1][0];
    D2[1] = D2[1] ^ sks->kw[1][1];
    kryptos_camellia_F(D1, sks->k[0][0], sks->k[0][1], fout); // round 1
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[1][0], sks->k[1][1], fout); // round 2
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[2][0], sks->k[2][1], fout); // round 3
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[3][0], sks->k[3][1], fout); // round 4
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[4][0], sks->k[4][1], fout); // round 5
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[5][0], sks->k[5][1], fout); // round 6
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_FL(D1, sks->ke[0][0], sks->ke[0][1]); // FL
    kryptos_camellia_FL_1(D2, sks->ke[1][0], sks->ke[1][1]); // FLINV
    kryptos_camellia_F(D1, sks->k[6][0], sks->k[6][1], fout); // round 7
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[7][0], sks->k[7][1], fout); // round 8
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[8][0], sks->k[8][1], fout); // round 9
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[9][0], sks->k[9][1], fout); // round 10
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[10][0], sks->k[10][1], fout); // round 11
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[11][0], sks->k[11][1], fout); // round 12
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_FL(D1, sks->ke[2][0], sks->ke[2][1]); // FL
    kryptos_camellia_FL_1(D2, sks->ke[3][0], sks->ke[3][1]); // FLINV
    kryptos_camellia_F(D1, sks->k[12][0], sks->k[12][1], fout); // round 13
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[13][0], sks->k[13][1], fout); // round 14
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[14][0], sks->k[14][1], fout); // round 15
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[15][0], sks->k[15][1], fout); // round 16
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[16][0], sks->k[16][1], fout); // round 17
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[17][0], sks->k[17][1], fout); // round 18
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    D1[0] = D1[0] ^ sks->kw[3][0]; // postwithening
    D1[1] = D1[1] ^ sks->kw[3][1];
    D2[0] = D2[0] ^ sks->kw[2][0];
    D2[1] = D2[1] ^ sks->kw[2][1];

    kryptos_cpy_u32_as_big_endian(block, 16, D2[0]);
    kryptos_cpy_u32_as_big_endian(block + 4, 12, D2[1]);
    kryptos_cpy_u32_as_big_endian(block + 8, 8, D1[0]);
    kryptos_cpy_u32_as_big_endian(block + 12, 4, D1[1]);

    D2[0] = D2[1] = D1[0] = D1[1] = fout[0] = fout[1] = 0x00;
}

static void kryptos_camellia_block_decrypt_128(kryptos_u8_t *block, const struct kryptos_camellia_subkeys *sks) {
    kryptos_u32_t D1[2], D2[2];
    kryptos_u32_t fout[2];

    D1[0] = kryptos_get_u32_as_big_endian(block, 4);
    D1[1] = kryptos_get_u32_as_big_endian(block + 4, 4);
    D2[0] = kryptos_get_u32_as_big_endian(block + 8, 4);
    D2[1] = kryptos_get_u32_as_big_endian(block + 12, 4);

    D1[0] = D1[0] ^ sks->kw[2][0]; // postwhitening
    D1[1] = D1[1] ^ sks->kw[2][1];
    D2[0] = D2[0] ^ sks->kw[3][0];
    D2[1] = D2[1] ^ sks->kw[3][1];
    kryptos_camellia_F(D1, sks->k[17][0], sks->k[17][1], fout); // round 1
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[16][0], sks->k[16][1], fout); // round 2
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[15][0], sks->k[15][1], fout); // round 3
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[14][0], sks->k[14][1], fout); // round 4
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[13][0], sks->k[13][1], fout); // round 5
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[12][0], sks->k[12][1], fout); // round 6
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_FL(D1, sks->ke[3][0], sks->ke[3][1]); // FL
    kryptos_camellia_FL_1(D2, sks->ke[2][0], sks->ke[2][1]); // FLINV
    kryptos_camellia_F(D1, sks->k[11][0], sks->k[11][1], fout); // round 7
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[10][0], sks->k[10][1], fout); // round 8
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[9][0], sks->k[9][1], fout); // round 9
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[8][0], sks->k[8][1], fout); // round 10
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[7][0], sks->k[7][1], fout); // round 11
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[6][0], sks->k[6][1], fout); // round 12
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_FL(D1, sks->ke[1][0], sks->ke[1][1]); // FL
    kryptos_camellia_FL_1(D2, sks->ke[0][0], sks->ke[0][1]); // FLINV
    kryptos_camellia_F(D1, sks->k[5][0], sks->k[5][1], fout); // round 13
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[4][0], sks->k[4][1], fout); // round 14
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[3][0], sks->k[3][1], fout); // round 15
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[2][0], sks->k[2][1], fout); // round 16
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[1][0], sks->k[1][1], fout); // round 17
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[0][0], sks->k[0][1], fout); // round 18
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    D1[0] = D1[0] ^ sks->kw[1][0]; // prewithening
    D1[1] = D1[1] ^ sks->kw[1][1];
    D2[0] = D2[0] ^ sks->kw[0][0];
    D2[1] = D2[1] ^ sks->kw[0][1];

    kryptos_cpy_u32_as_big_endian(block, 16, D2[0]);
    kryptos_cpy_u32_as_big_endian(block + 4, 12, D2[1]);
    kryptos_cpy_u32_as_big_endian(block + 8, 8, D1[0]);
    kryptos_cpy_u32_as_big_endian(block + 12, 4, D1[1]);

    D2[0] = D2[1] = D1[0] = D1[1] = fout[0] = fout[1] = 0x00;
}

static void kryptos_camellia_block_encrypt_192_256(kryptos_u8_t *block, const struct kryptos_camellia_subkeys *sks) {
    kryptos_u32_t D1[2], D2[2];
    kryptos_u32_t fout[2];

    D1[0] = kryptos_get_u32_as_big_endian(block, 4);
    D1[1] = kryptos_get_u32_as_big_endian(block + 4, 4);
    D2[0] = kryptos_get_u32_as_big_endian(block + 8, 4);
    D2[1] = kryptos_get_u32_as_big_endian(block + 12, 4);

    D1[0] = D1[0] ^ sks->kw[0][0]; // prewhitening
    D1[1] = D1[1] ^ sks->kw[0][1];
    D2[0] = D2[0] ^ sks->kw[1][0];
    D2[1] = D2[1] ^ sks->kw[1][1];
    kryptos_camellia_F(D1, sks->k[0][0], sks->k[0][1], fout); // round 1
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[1][0], sks->k[1][1], fout); // round 2
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[2][0], sks->k[2][1], fout); // round 3
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[3][0], sks->k[3][1], fout); // round 4
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[4][0], sks->k[4][1], fout); // round 5
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[5][0], sks->k[5][1], fout); // round 6
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_FL(D1, sks->ke[0][0], sks->ke[0][1]); // FL
    kryptos_camellia_FL_1(D2, sks->ke[1][0], sks->ke[1][1]); // FLINV
    kryptos_camellia_F(D1, sks->k[6][0], sks->k[6][1], fout); // round 7
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[7][0], sks->k[7][1], fout); // round 8
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[8][0], sks->k[8][1], fout); // round 9
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[9][0], sks->k[9][1], fout); // round 10
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[10][0], sks->k[10][1], fout); // round 11
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[11][0], sks->k[11][1], fout); // round 12
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_FL(D1, sks->ke[2][0], sks->ke[2][1]); // FL
    kryptos_camellia_FL_1(D2, sks->ke[3][0], sks->ke[3][1]); // FLINV
    kryptos_camellia_F(D1, sks->k[12][0], sks->k[12][1], fout); // round 13
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[13][0], sks->k[13][1], fout); // round 14
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[14][0], sks->k[14][1], fout); // round 15
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[15][0], sks->k[15][1], fout); // round 16
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[16][0], sks->k[16][1], fout); // round 17
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[17][0], sks->k[17][1], fout); // round 18
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_FL(D1, sks->ke[4][0], sks->ke[4][1]); // FL
    kryptos_camellia_FL_1(D2, sks->ke[5][0], sks->ke[5][1]); // FLINV
    kryptos_camellia_F(D1, sks->k[18][0], sks->k[18][1], fout); // round 19
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[19][0], sks->k[19][1], fout); // round 20
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[20][0], sks->k[20][1], fout); // round 21
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[21][0], sks->k[21][1], fout); // round 22
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[22][0], sks->k[22][1], fout); // round 23
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[23][0], sks->k[23][1], fout); // round 24
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    D1[0] = D1[0] ^ sks->kw[3][0]; // postwithening
    D1[1] = D1[1] ^ sks->kw[3][1];
    D2[0] = D2[0] ^ sks->kw[2][0];
    D2[1] = D2[1] ^ sks->kw[2][1];

    kryptos_cpy_u32_as_big_endian(block, 16, D2[0]);
    kryptos_cpy_u32_as_big_endian(block + 4, 12, D2[1]);
    kryptos_cpy_u32_as_big_endian(block + 8, 8, D1[0]);
    kryptos_cpy_u32_as_big_endian(block + 12, 4, D1[1]);

    D2[0] = D2[1] = D1[0] = D1[1] = fout[0] = fout[1] = 0x00;
}

static void kryptos_camellia_block_decrypt_192_256(kryptos_u8_t *block, const struct kryptos_camellia_subkeys *sks) {
    kryptos_u32_t D1[2], D2[2];
    kryptos_u32_t fout[2];

    D1[0] = kryptos_get_u32_as_big_endian(block, 4);
    D1[1] = kryptos_get_u32_as_big_endian(block + 4, 4);
    D2[0] = kryptos_get_u32_as_big_endian(block + 8, 4);
    D2[1] = kryptos_get_u32_as_big_endian(block + 12, 4);

    D1[0] = D1[0] ^ sks->kw[2][0]; // postwhitening
    D1[1] = D1[1] ^ sks->kw[2][1];
    D2[0] = D2[0] ^ sks->kw[3][0];
    D2[1] = D2[1] ^ sks->kw[3][1];
    kryptos_camellia_F(D1, sks->k[23][0], sks->k[23][1], fout); // round 1
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[22][0], sks->k[22][1], fout); // round 2
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[21][0], sks->k[21][1], fout); // round 3
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[20][0], sks->k[20][1], fout); // round 4
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[19][0], sks->k[19][1], fout); // round 5
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[18][0], sks->k[18][1], fout); // round 6
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_FL(D1, sks->ke[5][0], sks->ke[5][1]); // FL
    kryptos_camellia_FL_1(D2, sks->ke[4][0], sks->ke[4][1]); // FLINV
    kryptos_camellia_F(D1, sks->k[17][0], sks->k[17][1], fout); // round 7
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[16][0], sks->k[16][1], fout); // round 8
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[15][0], sks->k[15][1], fout); // round 9
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[14][0], sks->k[14][1], fout); // round 10
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[13][0], sks->k[13][1], fout); // round 11
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[12][0], sks->k[12][1], fout); // round 12
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_FL(D1, sks->ke[3][0], sks->ke[3][1]); // FL
    kryptos_camellia_FL_1(D2, sks->ke[2][0], sks->ke[2][1]); // FLINV
    kryptos_camellia_F(D1, sks->k[11][0], sks->k[11][1], fout); // round 13
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[10][0], sks->k[10][1], fout); // round 14
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[9][0], sks->k[9][1], fout); // round 15
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[8][0], sks->k[8][1], fout); // round 16
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[7][0], sks->k[7][1], fout); // round 17
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[6][0], sks->k[6][1], fout); // round 18
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_FL(D1, sks->ke[1][0], sks->ke[1][1]); // FL
    kryptos_camellia_FL_1(D2, sks->ke[0][0], sks->ke[0][1]); // FLINV
    kryptos_camellia_F(D1, sks->k[5][0], sks->k[5][1], fout); // round 19
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[4][0], sks->k[4][1], fout); // round 20
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[3][0], sks->k[3][1], fout); // round 21
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[2][0], sks->k[2][1], fout); // round 22
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    kryptos_camellia_F(D1, sks->k[1][0], sks->k[1][1], fout); // round 23
    D2[0] = D2[0] ^ fout[0];
    D2[1] = D2[1] ^ fout[1];
    kryptos_camellia_F(D2, sks->k[0][0], sks->k[0][1], fout); // round 24
    D1[0] = D1[0] ^ fout[0];
    D1[1] = D1[1] ^ fout[1];
    D1[0] = D1[0] ^ sks->kw[1][0]; // prewithening
    D1[1] = D1[1] ^ sks->kw[1][1];
    D2[0] = D2[0] ^ sks->kw[0][0];
    D2[1] = D2[1] ^ sks->kw[0][1];

    kryptos_cpy_u32_as_big_endian(block, 16, D2[0]);
    kryptos_cpy_u32_as_big_endian(block + 4, 12, D2[1]);
    kryptos_cpy_u32_as_big_endian(block + 8, 8, D1[0]);
    kryptos_cpy_u32_as_big_endian(block + 12, 4, D1[1]);

    D2[0] = D2[1] = D1[0] = D1[1] = fout[0] = fout[1] = 0x00;
}

static void kryptos_camellia_FL(kryptos_u32_t *data, const kryptos_u32_t kl, const kryptos_u32_t kr) {
    data[1] = data[1] ^ kryptos_camellia_rotl((data[0] & kl), 1);
    data[0] = data[0] ^ (data[1] | kr);
}

static void kryptos_camellia_FL_1(kryptos_u32_t *data, const kryptos_u32_t kl, const kryptos_u32_t kr) {
    data[0] = data[0] ^ (data[1] | kr);
    data[1] = data[1] ^ kryptos_camellia_rotl((data[0] & kl), 1);
}

#undef kryptos_camellia_rotl

#undef KRYPTOS_CAMELLIA_SIGMA1L
#undef KRYPTOS_CAMELLIA_SIGMA1R
#undef KRYPTOS_CAMELLIA_SIGMA2L
#undef KRYPTOS_CAMELLIA_SIGMA2R
#undef KRYPTOS_CAMELLIA_SIGMA3L
#undef KRYPTOS_CAMELLIA_SIGMA3R
#undef KRYPTOS_CAMELLIA_SIGMA4L
#undef KRYPTOS_CAMELLIA_SIGMA4R
#undef KRYPTOS_CAMELLIA_SIGMA5L
#undef KRYPTOS_CAMELLIA_SIGMA5R
#undef KRYPTOS_CAMELLIA_SIGMA6L
#undef KRYPTOS_CAMELLIA_SIGMA6R

#undef kryptos_camellia_get_u8_from_u32

#undef kryptos_camellia_assignment
