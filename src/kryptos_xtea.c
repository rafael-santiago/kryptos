/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <kryptos_xtea.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_random.h>
#include <kryptos_padding.h>
#include <kryptos_task_check.h>
#include <kryptos.h>

struct kryptos_xtea_nullkeys { };

#define KRYPTOS_XTEA_DELTA 0x9E3779B9

typedef void (*kryptos_xtea_block_processor)(kryptos_u8_t *block, kryptos_u8_t *key, const int rounds);

static void kryptos_xtea_block_encrypt(kryptos_u8_t *block, kryptos_u8_t *key, const int rounds);

static void kryptos_xtea_block_decrypt(kryptos_u8_t *block, kryptos_u8_t *key, const int rounds);

KRYPTOS_IMPL_CUSTOM_BLOCK_CIPHER_SETUP(xtea, ktask, kKryptosCipherXTEA, KRYPTOS_XTEA_BLOCKSIZE, int *rounds,
                                       {
                                            if (rounds != NULL) {
                                                ktask->arg[0] = rounds;
                                            } else {
                                                ktask->arg[0] = NULL;
                                            }
                                        })

KRYPTOS_IMPL_BLOCK_CIPHER_PROCESSOR(xtea,
                                    ktask,
                                    kryptos_xtea_nullkeys,
                                    sks,
                                    kryptos_xtea_block_processor,
                                    xtea_block_processor,
                                    {
                                        if ((*ktask)->key_size != 16) {
                                            (*ktask)->result = kKryptosKeyError;
                                            (*ktask)->result_verbose= "XTEA algorithm needs a 128-bit key.";
                                            goto kryptos_xtea_cipher_epilogue;
                                        }

                                        if ((*ktask)->arg[0] == NULL) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "XTEA round parameter is missing.";
                                            goto kryptos_xtea_cipher_epilogue;
                                        }

                                        if (*(int *)(*ktask)->arg[0] <= 0) {
                                            (*ktask)->result = kKryptosInvalidParams;
                                            (*ktask)->result_verbose = "XTEA the round parameter must be greater than zero.";
                                            goto kryptos_xtea_cipher_epilogue;
                                        }
                                    },
                                    kryptos_xtea_block_encrypt, /* No additional steps before encrypting */,
                                    kryptos_xtea_block_decrypt, /* No additional steps before decrypting */,
                                    KRYPTOS_XTEA_BLOCKSIZE,
                                    xtea_cipher_epilogue,
                                    outblock,
                                    xtea_block_processor(outblock, (*ktask)->key, *(int *)(*ktask)->arg[0]),
                                    NULL /* GCM E function arg (No GCM) */)

KRYPTOS_IMPL_STANDARD_BLOCK_CIPHER_GCM_E_NO_SUPPORT(xtea)

static void kryptos_xtea_block_encrypt(kryptos_u8_t *block, kryptos_u8_t *key, const int rounds) {
    int r;
    kryptos_u32_t v[2], k[4], sum = 0;

    v[0] = kryptos_get_u32_as_big_endian(block, 4);
    v[1] = kryptos_get_u32_as_big_endian(block + 4, 4);

    k[0] = kryptos_get_u32_as_big_endian(key, 4);
    k[1] = kryptos_get_u32_as_big_endian(key + 4, 4);
    k[2] = kryptos_get_u32_as_big_endian(key + 8, 4);
    k[3] = kryptos_get_u32_as_big_endian(key + 12, 4);

    for (r = 0; r < rounds; r++) {
        v[0] += (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + k[sum & 3]);
        sum += KRYPTOS_XTEA_DELTA;
        v[1] += (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + k[(sum >> 11) & 3]);
    }

    kryptos_cpy_u32_as_big_endian(block, 8, v[0]);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, v[1]);

    memset(v, 0, sizeof(v));
    memset(k, 0, sizeof(k));

    sum = 0;
    r = 0;
}

static void kryptos_xtea_block_decrypt(kryptos_u8_t *block, kryptos_u8_t *key, const int rounds) {
    int r;
    kryptos_u32_t v[2], k[4], sum = KRYPTOS_XTEA_DELTA * rounds;

    v[0] = kryptos_get_u32_as_big_endian(block, 4);
    v[1] = kryptos_get_u32_as_big_endian(block + 4, 4);

    k[0] = kryptos_get_u32_as_big_endian(key, 4);
    k[1] = kryptos_get_u32_as_big_endian(key + 4, 4);
    k[2] = kryptos_get_u32_as_big_endian(key + 8, 4);
    k[3] = kryptos_get_u32_as_big_endian(key + 12, 4);

    for (r = 0; r < rounds; r++) {
        v[1] -= (((v[0] << 4) ^ (v[0] >> 5)) + v[0]) ^ (sum + k[(sum >> 11) & 3]);
        sum -= KRYPTOS_XTEA_DELTA;
        v[0] -= (((v[1] << 4) ^ (v[1] >> 5)) + v[1]) ^ (sum + k[sum & 3]);
    }

    kryptos_cpy_u32_as_big_endian(block, 8, v[0]);
    kryptos_cpy_u32_as_big_endian(block + 4, 4, v[1]);

    memset(v, 0, sizeof(v));
    memset(k, 0, sizeof(k));

    sum = 0;
    r = 0;
}

#undef KRYPTOS_XTEA_DELTA
