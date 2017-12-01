/*
 *                          Copyright (C) 2005, 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_tea.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_task_check.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos.h>

#define KRYPTOS_TEA_DELTA 0x9E3779B9

struct kryptos_tea_into_the_void { };

typedef void (*kryptos_tea_block_processor)(kryptos_u8_t *block, kryptos_u8_t *key);

static void kryptos_tea_block_encryption(kryptos_u8_t *block, kryptos_u8_t *key);

static void kryptos_tea_block_decryption(kryptos_u8_t *block, kryptos_u8_t *key);

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_SETUP(tea, kKryptosCipherTEA, KRYPTOS_TEA_BLOCKSIZE)

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(tea,
                                    ktask,
                                    kryptos_tea_into_the_void,
                                    sks,
                                    kryptos_tea_block_processor,
                                    tea_block_processor,
                                    {
                                        // CLUE(Rafael): I think that implement some 'key schedule' in TEA capable of
                                        //               expanding or padding the user key to 128-bit could introduce
                                        //               a flaw by reducing the key search space, since users tend to choose
                                        //               short keys. Due to it, this implementation aborts when not passed
                                        //               a key buffer with exact 16 bytes.
                                        if ((*ktask)->key_size != 16) {
                                            (*ktask)->result = kKryptosKeyError;
                                            (*ktask)->result_verbose = "TEA algorithm needs a 128-bit key.";
                                            goto kryptos_tea_cipher_epilogue;
                                        }
                                    },
                                    kryptos_tea_block_encryption, /* No additional steps before encrypting */,
                                    kryptos_tea_block_decryption, /* No additional steps before decrypting */,
                                    KRYPTOS_TEA_BLOCKSIZE,
                                    tea_cipher_epilogue,
                                    outblock,
                                    tea_block_processor(outblock, (*ktask)->key))

static void kryptos_tea_block_encryption(kryptos_u8_t *block, kryptos_u8_t *key) {
    kryptos_u32_t y, z, k[4];
    size_t sum = 0, r;

    k[0] = kryptos_get_u32_as_big_endian(key, 4);
    k[1] = kryptos_get_u32_as_big_endian(key + 4, 4);
    k[2] = kryptos_get_u32_as_big_endian(key + 8, 4);
    k[3] = kryptos_get_u32_as_big_endian(key + 12, 4);

    y = kryptos_get_u32_as_big_endian(block, 4);
    z = kryptos_get_u32_as_big_endian(block + 4, 4);

    for (r = 0; r < 32; r++) {
        sum += KRYPTOS_TEA_DELTA;
        y += ((z << 4) + k[0]) ^ (z + sum) ^ ((z >> 5) + k[1]);
        z += ((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3]);
    }

    kryptos_cpy_u32_as_big_endian(block, 8, y);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, z);

    memset(k, 0, sizeof(k));
    y = z = 0;
    sum = r = 0;
}

static void kryptos_tea_block_decryption(kryptos_u8_t *block, kryptos_u8_t *key) {
    kryptos_u32_t y, z, k[4];
    size_t sum = KRYPTOS_TEA_DELTA << 5, r;

    k[0] = kryptos_get_u32_as_big_endian(key, 4);
    k[1] = kryptos_get_u32_as_big_endian(key + 4, 4);
    k[2] = kryptos_get_u32_as_big_endian(key + 8, 4);
    k[3] = kryptos_get_u32_as_big_endian(key + 12, 4);

    y = kryptos_get_u32_as_big_endian(block, 4);
    z = kryptos_get_u32_as_big_endian(block + 4, 4);

    for (r = 0; r < 32; r++) {
        z -= ((y << 4) + k[2]) ^ (y + sum) ^ ((y >> 5) + k[3]);
        y -= ((z << 4) + k[0]) ^ (z + sum) ^ ((z >> 5) + k[1]);
        sum -= KRYPTOS_TEA_DELTA;
    }

    kryptos_cpy_u32_as_big_endian(block, 8, y);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, z);

    memset(k, 0, sizeof(k));
    y = z = 0;
    sum = r = 0;
}

#undef KRYPTOS_TEA_DELTA
