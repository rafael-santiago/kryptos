/*
 *                                Copyright (C) 2018 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "bad_buf_tests.h"
#include "test_vectors.h"
#include <kryptos.h>

CUTE_TEST_CASE(kryptos_bad_decryption_tests)
    kryptos_task_ctx t, *ktask = &t;
    size_t feal_rounds = 19;
    int rc2_t1 = 128;
    int saferk64_n = 6;
    kryptos_u8_t *tdes_k2 = "abc", *tdes_k3 = "def";
    size_t tdes_k2_size = 3, tdes_k3_size = 3;
    int xtea_rounds = 72;
    int rc5_rounds = 48;
    int rc6_rounds = 90;
    kryptos_u8_t *rabbit_iv = "abcdefghijklmnopqrstuvwxyz"
                              "abcdefghijklmnopqrstuvwxyz"
                              "abcdefghijkl";
    kryptos_u8_t gost_s1[16] = {
         4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3
    };
    kryptos_u8_t gost_s2[16] = {
        14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9
    };
    kryptos_u8_t gost_s3[16] = {
        5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11
    };
    kryptos_u8_t gost_s4[16] = {
        7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3
    };
    kryptos_u8_t gost_s5[16] = {
        6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2
    };
    kryptos_u8_t gost_s6[16] = {
        4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14
    };
    kryptos_u8_t gost_s7[16] = {
        13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12
    };
    kryptos_u8_t gost_s8[16] = {
         1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12
    };
    kryptos_seal_version_t seal_v = kKryptosSEAL30;
    size_t seal_n = 0xDEADBEEF, seal_l = 4096;

    kryptos_bad_buf_run_block_cipher(des, ktask);
    kryptos_bad_buf_run_block_cipher(idea, ktask);
    kryptos_bad_buf_run_block_cipher(blowfish, ktask);
    kryptos_bad_buf_run_block_cipher(camellia128, ktask);
    kryptos_bad_buf_run_block_cipher(camellia192, ktask);
    kryptos_bad_buf_run_block_cipher(camellia256, ktask);
    kryptos_bad_buf_run_block_cipher(cast5, ktask);
    kryptos_bad_buf_run_block_cipher(aes128, ktask);
    kryptos_bad_buf_run_block_cipher(aes192, ktask);
    kryptos_bad_buf_run_block_cipher(aes256, ktask);
    kryptos_bad_buf_run_block_cipher(serpent, ktask);
    kryptos_bad_buf_run_block_cipher(tea, ktask);
    kryptos_bad_buf_run_block_cipher(misty1, ktask);
    kryptos_bad_buf_run_block_cipher(mars128, ktask);
    kryptos_bad_buf_run_block_cipher(mars192, ktask);
    kryptos_bad_buf_run_block_cipher(mars256, ktask);
    kryptos_bad_buf_run_block_cipher(present80, ktask);
    kryptos_bad_buf_run_block_cipher(present128, ktask);
    kryptos_bad_buf_run_block_cipher(shacal1, ktask);
    kryptos_bad_buf_run_block_cipher(shacal2, ktask);
    kryptos_bad_buf_run_block_cipher(noekeon, ktask);
    kryptos_bad_buf_run_block_cipher(noekeon_d, ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(feal,
                                                       kryptos_feal_setup(ktask, "Boom!", 5, kKryptosECB, &feal_rounds),
                                                       kryptos_feal_setup(ktask, "Boom!", 5, kKryptosCBC, &feal_rounds),
                                                       kryptos_feal_setup(ktask, "Boom!", 5, kKryptosOFB, &feal_rounds),
                                                       kryptos_feal_setup(ktask, "Boom!", 5, kKryptosCTR, &feal_rounds),
                                                       ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(rc2,
                                                       kryptos_rc2_setup(ktask, "Boom!", 5, kKryptosECB, &rc2_t1),
                                                       kryptos_rc2_setup(ktask, "Boom!", 5, kKryptosCBC, &rc2_t1),
                                                       kryptos_rc2_setup(ktask, "Boom!", 5, kKryptosOFB, &rc2_t1),
                                                       kryptos_rc2_setup(ktask, "Boom!", 5, kKryptosCTR, &rc2_t1),
                                                       ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(saferk64,
                                                       kryptos_saferk64_setup(ktask, "Boom!", 5, kKryptosECB, &saferk64_n),
                                                       kryptos_saferk64_setup(ktask, "Boom!", 5, kKryptosCBC, &saferk64_n),
                                                       kryptos_saferk64_setup(ktask, "Boom!", 5, kKryptosOFB, &saferk64_n),
                                                       kryptos_saferk64_setup(ktask, "Boom!", 5, kKryptosCTR, &saferk64_n),
                                                       ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(triple_des,
                                                       kryptos_triple_des_setup(ktask, "Boom!", 5, kKryptosECB,
                                                                                tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size),
                                                       kryptos_triple_des_setup(ktask, "Boom!", 5, kKryptosCBC,
                                                                                tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size),
                                                       kryptos_triple_des_setup(ktask, "Boom!", 5, kKryptosOFB,
                                                                                tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size),
                                                       kryptos_triple_des_setup(ktask, "Boom!", 5, kKryptosCTR,
                                                                                tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size),
                                                       ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(triple_des_ede,
                                                       kryptos_triple_des_ede_setup(ktask, "Boom!", 5, kKryptosECB,
                                                                                    tdes_k2, &tdes_k2_size,
                                                                                    tdes_k3, &tdes_k3_size),
                                                       kryptos_triple_des_ede_setup(ktask, "Boom!", 5, kKryptosCBC,
                                                                                    tdes_k2, &tdes_k2_size,
                                                                                    tdes_k3, &tdes_k3_size),
                                                       kryptos_triple_des_ede_setup(ktask, "Boom!", 5, kKryptosOFB,
                                                                                    tdes_k2, &tdes_k2_size,
                                                                                    tdes_k3, &tdes_k3_size),
                                                       kryptos_triple_des_ede_setup(ktask, "Boom!", 5, kKryptosCTR,
                                                                                    tdes_k2, &tdes_k2_size,
                                                                                    tdes_k3, &tdes_k3_size), ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(xtea,
                                                       kryptos_xtea_setup(ktask, "Boom!!!!!!!!!!!!", 16, kKryptosECB,
                                                                          &xtea_rounds),
                                                       kryptos_xtea_setup(ktask, "Boom!!!!!!!!!!!!", 16, kKryptosCBC,
                                                                          &xtea_rounds),
                                                       kryptos_xtea_setup(ktask, "Boom!!!!!!!!!!!!", 16, kKryptosOFB,
                                                                          &xtea_rounds),
                                                       kryptos_xtea_setup(ktask, "Boom!!!!!!!!!!!!", 16, kKryptosCTR,
                                                                          &xtea_rounds), ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(rc5,
                                                       kryptos_rc5_setup(ktask, "Boom!", 5, kKryptosECB, &rc5_rounds),
                                                       kryptos_rc5_setup(ktask, "Boom!", 5, kKryptosCBC, &rc5_rounds),
                                                       kryptos_rc5_setup(ktask, "Boom!", 5, kKryptosOFB, &rc5_rounds),
                                                       kryptos_rc5_setup(ktask, "Boom!", 5, kKryptosCTR, &rc5_rounds), ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(rc6_128,
                                                       kryptos_rc6_128_setup(ktask, "Boom!", 5, kKryptosECB, &rc6_rounds),
                                                       kryptos_rc6_128_setup(ktask, "Boom!", 5, kKryptosCBC, &rc6_rounds),
                                                       kryptos_rc6_128_setup(ktask, "Boom!", 5, kKryptosOFB, &rc6_rounds),
                                                       kryptos_rc6_128_setup(ktask, "Boom!", 5, kKryptosCTR, &rc6_rounds),
                                                       ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(rc6_192,
                                                       kryptos_rc6_192_setup(ktask, "Boom!", 5, kKryptosECB, &rc6_rounds),
                                                       kryptos_rc6_192_setup(ktask, "Boom!", 5, kKryptosCBC, &rc6_rounds),
                                                       kryptos_rc6_192_setup(ktask, "Boom!", 5, kKryptosOFB, &rc6_rounds),
                                                       kryptos_rc6_192_setup(ktask, "Boom!", 5, kKryptosCTR, &rc6_rounds),
                                                       ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(rc6_256,
                                                       kryptos_rc6_256_setup(ktask, "Boom!", 5, kKryptosECB, &rc6_rounds),
                                                       kryptos_rc6_256_setup(ktask, "Boom!", 5, kKryptosCBC, &rc6_rounds),
                                                       kryptos_rc6_256_setup(ktask, "Boom!", 5, kKryptosOFB, &rc6_rounds),
                                                       kryptos_rc6_256_setup(ktask, "Boom!", 5, kKryptosCTR, &rc6_rounds),
                                                       ktask);
    kryptos_bad_buf_run_block_cipher_with_custom_setup(gost,
                                                       kryptos_gost_setup(ktask, "Boom!", 5, kKryptosECB,
                                                       gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8),
                                                       kryptos_gost_setup(ktask, "Boom!", 5, kKryptosCBC,
                                                       gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8),
                                                       kryptos_gost_setup(ktask, "Boom!", 5, kKryptosOFB,
                                                       gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8),
                                                       kryptos_gost_setup(ktask, "Boom!", 5, kKryptosCTR,
                                                       gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8),
                                                       ktask);

    kryptos_task_init_as_null(ktask);

    kryptos_rabbit_setup(ktask, "Boom!", 5, rabbit_iv);
    ktask->in = kryptos_get_random_block(1024);
    CUTE_ASSERT(ktask->in != NULL);
    ktask->in_size = 1024;
    kryptos_rabbit_cipher(&ktask);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    kryptos_seal_setup(ktask, "Boom!", 5, &seal_v, &seal_l, &seal_n);
    ktask->in = kryptos_get_random_block(1024);
    CUTE_ASSERT(ktask->in != NULL);
    ktask->in_size = 1024;
    kryptos_seal_cipher(&ktask);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);

    kryptos_arc4_setup(ktask, "Boom!", 5);
    ktask->in = kryptos_get_random_block(1024);
    CUTE_ASSERT(ktask->in != NULL);
    ktask->in_size = 1024;
    kryptos_arc4_cipher(&ktask);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_free(ktask, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);
CUTE_TEST_CASE_END
