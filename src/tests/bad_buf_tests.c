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

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)

CUTE_DECLARE_TEST_CASE(kryptos_des_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_idea_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_blowfish_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia128_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia192_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia256_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_cast5_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes128_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes192_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes256_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_serpent_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_tea_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_xtea_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_misty1_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars128_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars192_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars256_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_present80_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_present128_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_shacal1_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_shacal2_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_noekeon_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_noekeon_d_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_gost_ds_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_feal_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc2_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc5_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_128_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_192_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_256_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_saferk64_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_triple_des_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_triple_des_ede_bad_hmac_tests);
CUTE_DECLARE_TEST_CASE(kryptos_gost_bad_hmac_tests);

#endif

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

CUTE_TEST_CASE_SUITE(kryptos_bad_hmac_tests)
#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)

    CUTE_RUN_TEST(kryptos_des_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_idea_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_blowfish_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_camellia128_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_camellia192_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_camellia256_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_cast5_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_aes128_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_aes192_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_aes256_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_serpent_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_tea_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_misty1_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_mars128_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_mars192_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_mars256_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_present80_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_present128_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_shacal1_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_shacal2_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_noekeon_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_noekeon_d_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_gost_ds_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_feal_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_rc2_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_rc5_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_rc6_128_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_rc6_192_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_rc6_256_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_saferk64_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_triple_des_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_triple_des_ede_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_xtea_bad_hmac_tests);
    CUTE_RUN_TEST(kryptos_gost_bad_hmac_tests);

#else
# if !defined(KRYPTOS_NO_HMAC_TESTS)
    // TODO(Rafael): When there is no C99 support add a simple bare bone test with at least one block cipher and all
    //               available hash functions.
    printf("WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
# else
    printf("WARN: You have requested build this binary without the HMAC tests.\n");
# endif
#endif
CUTE_TEST_CASE_SUITE_END

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)

CUTE_TEST_CASE(kryptos_des_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(des, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(des, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(des, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(des, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(des, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(des, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(des, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(des, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_idea_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(idea, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(idea, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(idea, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(idea, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(idea, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(idea, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(idea, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(idea, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blowfish_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(blowfish, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(blowfish, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(blowfish, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(blowfish, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(blowfish, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(blowfish, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(blowfish, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(blowfish, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia128_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(camellia128, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia128, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(camellia128, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia128, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(camellia128, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia128, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(camellia128, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia128, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia192_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(camellia192, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia192, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(camellia192, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia192, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(camellia192, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia192, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(camellia192, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia192, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia256_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(camellia256, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(camellia256, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(camellia256, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(camellia256, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(camellia256, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(camellia256, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(camellia256, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(camellia256, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_cast5_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(cast5, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(cast5, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(cast5, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(cast5, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(cast5, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(cast5, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(cast5, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(cast5, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes128_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(aes128, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes128, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(aes128, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes128, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(aes128, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes128, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(aes128, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes128, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes192_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(aes192, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes192, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(aes192, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes192, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(aes192, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes192, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(aes192, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes192, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes256_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(aes256, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(aes256, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(aes256, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(aes256, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(aes256, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(aes256, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(aes256, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(aes256, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_serpent_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(serpent, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(serpent, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(serpent, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(serpent, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(serpent, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(serpent, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(serpent, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(serpent, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tea_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(tea, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(tea, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(tea, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(tea, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(tea, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(tea, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(tea, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(tea, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_misty1_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(misty1, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(misty1, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(misty1, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(misty1, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(misty1, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(misty1, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(misty1, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(misty1, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars128_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(mars128, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars128, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(mars128, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars128, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(mars128, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars128, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(mars128, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars128, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars192_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(mars192, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars192, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(mars192, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars192, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(mars192, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars192, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(mars192, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars192, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars256_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(mars256, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(mars256, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(mars256, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(mars256, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(mars256, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(mars256, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(mars256, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(mars256, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present80_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(present80, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present80, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(present80, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present80, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(present80, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present80, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(present80, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present80, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present128_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(present128, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(present128, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(present128, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(present128, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(present128, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(present128, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(present128, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(present128, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal1_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(shacal1, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal1, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(shacal1, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal1, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(shacal1, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal1, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(shacal1, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal1, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal2_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(shacal2, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(shacal2, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(shacal2, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(shacal2, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(shacal2, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(shacal2, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(shacal2, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(shacal2, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(noekeon, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(noekeon, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(noekeon, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(noekeon, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_d_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(noekeon_d, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(noekeon_d, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(noekeon_d, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(noekeon_d, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(noekeon_d, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(noekeon_d, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(noekeon_d, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(noekeon_d, whirlpool, ktask, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_ds_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;

    kryptos_bad_buf_run_hmac(gost_ds, sha1, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, sha256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, sha384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, sha512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, keccak224, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, keccak256, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, keccak384, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, keccak512, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, md4, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, md5, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, ripemd128, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, ripemd160, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, tiger, ktask, key, key_size, kKryptosECB);
    kryptos_bad_buf_run_hmac(gost_ds, whirlpool, ktask, key, key_size, kKryptosECB);

    kryptos_bad_buf_run_hmac(gost_ds, sha1, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, sha256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, sha384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, sha512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, keccak224, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, keccak256, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, keccak384, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, keccak512, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, md4, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, md5, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, ripemd128, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, ripemd160, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, tiger, ktask, key, key_size, kKryptosCBC);
    kryptos_bad_buf_run_hmac(gost_ds, whirlpool, ktask, key, key_size, kKryptosCBC);

    kryptos_bad_buf_run_hmac(gost_ds, sha1, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, sha256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, sha384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, sha512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, keccak224, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, keccak256, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, keccak384, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, keccak512, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, md4, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, md5, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, ripemd128, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, ripemd160, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, tiger, ktask, key, key_size, kKryptosOFB);
    kryptos_bad_buf_run_hmac(gost_ds, whirlpool, ktask, key, key_size, kKryptosOFB);

    kryptos_bad_buf_run_hmac(gost_ds, sha1, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, sha256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, sha384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, sha512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, sha3_512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, keccak224, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, keccak256, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, keccak384, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, keccak512, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, md4, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, md5, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, ripemd128, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, ripemd160, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, tiger, ktask, key, key_size, kKryptosCTR);
    kryptos_bad_buf_run_hmac(gost_ds, whirlpool, ktask, key, key_size, kKryptosCTR);


CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_feal_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
    int feal_rounds = 19;

    kryptos_bad_buf_run_hmac(feal, sha1, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha256, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha384, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha512, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_224, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_256, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_384, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_512, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak224, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak256, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak384, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak512, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, md4, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, md5, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, ripemd128, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, ripemd160, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, tiger, ktask, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, whirlpool, ktask, key, key_size, kKryptosECB, &feal_rounds);

    kryptos_bad_buf_run_hmac(feal, sha1, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha256, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha384, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha512, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_224, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_256, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_384, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_512, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak224, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak256, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak384, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak512, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, md4, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, md5, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, ripemd128, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, ripemd160, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, tiger, ktask, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, whirlpool, ktask, key, key_size, kKryptosCBC, &feal_rounds);

    kryptos_bad_buf_run_hmac(feal, sha1, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha256, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha384, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha512, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_224, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_256, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_384, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_512, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak224, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak256, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak384, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak512, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, md4, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, md5, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, ripemd128, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, ripemd160, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, tiger, ktask, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, whirlpool, ktask, key, key_size, kKryptosOFB, &feal_rounds);

    kryptos_bad_buf_run_hmac(feal, sha1, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha256, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha384, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha512, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_224, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_256, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_384, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, sha3_512, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak224, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak256, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak384, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, keccak512, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, md4, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, md5, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, ripemd128, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, ripemd160, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, tiger, ktask, key, key_size, kKryptosCTR, &feal_rounds);
    kryptos_bad_buf_run_hmac(feal, whirlpool, ktask, key, key_size, kKryptosCTR, &feal_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc2_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
    int rc2_t1 = 128;

    kryptos_bad_buf_run_hmac(rc2, sha1, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha256, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha384, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha512, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_224, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_256, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_384, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_512, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak224, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak256, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak384, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak512, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, md4, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, md5, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, ripemd128, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, ripemd160, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, tiger, ktask, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, whirlpool, ktask, key, key_size, kKryptosECB, &rc2_t1);

    kryptos_bad_buf_run_hmac(rc2, sha1, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha256, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha384, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha512, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_224, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_256, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_384, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_512, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak224, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak256, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak384, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak512, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, md4, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, md5, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, ripemd128, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, ripemd160, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, tiger, ktask, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, whirlpool, ktask, key, key_size, kKryptosCBC, &rc2_t1);

    kryptos_bad_buf_run_hmac(rc2, sha1, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha256, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha384, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha512, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_224, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_256, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_384, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_512, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak224, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak256, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak384, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak512, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, md4, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, md5, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, ripemd128, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, ripemd160, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, tiger, ktask, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, whirlpool, ktask, key, key_size, kKryptosOFB, &rc2_t1);

    kryptos_bad_buf_run_hmac(rc2, sha1, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha256, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha384, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha512, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_224, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_256, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_384, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, sha3_512, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak224, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak256, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak384, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, keccak512, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, md4, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, md5, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, ripemd128, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, ripemd160, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, tiger, ktask, key, key_size, kKryptosCTR, &rc2_t1);
    kryptos_bad_buf_run_hmac(rc2, whirlpool, ktask, key, key_size, kKryptosCTR, &rc2_t1);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc5_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
    int rc5_rounds = 48;

    kryptos_bad_buf_run_hmac(rc5, sha1, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha256, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha384, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha512, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_224, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_256, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_384, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_512, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak224, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak256, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak384, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak512, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, md4, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, md5, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, ripemd128, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, ripemd160, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, tiger, ktask, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, whirlpool, ktask, key, key_size, kKryptosECB, &rc5_rounds);

    kryptos_bad_buf_run_hmac(rc5, sha1, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha256, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha384, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha512, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_224, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_256, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_384, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_512, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak224, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak256, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak384, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak512, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, md4, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, md5, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, ripemd128, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, ripemd160, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, tiger, ktask, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, whirlpool, ktask, key, key_size, kKryptosCBC, &rc5_rounds);

    kryptos_bad_buf_run_hmac(rc5, sha1, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha256, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha384, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha512, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_224, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_256, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_384, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_512, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak224, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak256, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak384, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak512, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, md4, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, md5, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, ripemd128, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, ripemd160, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, tiger, ktask, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, whirlpool, ktask, key, key_size, kKryptosOFB, &rc5_rounds);

    kryptos_bad_buf_run_hmac(rc5, sha1, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha256, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha384, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha512, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_224, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_256, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_384, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, sha3_512, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak224, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak256, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak384, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, keccak512, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, md4, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, md5, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, ripemd128, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, ripemd160, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, tiger, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
    kryptos_bad_buf_run_hmac(rc5, whirlpool, ktask, key, key_size, kKryptosCTR, &rc5_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_128_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
    int rc6_rounds = 90;

    kryptos_bad_buf_run_hmac(rc6_128, sha1, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha256, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha384, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha512, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_224, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_256, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_384, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_512, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak224, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak256, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak384, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak512, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, md4, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, md5, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, ripemd128, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, ripemd160, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, tiger, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, whirlpool, ktask, key, key_size, kKryptosECB, &rc6_rounds);

    kryptos_bad_buf_run_hmac(rc6_128, sha1, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha256, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha384, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha512, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_224, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_256, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_384, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_512, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak224, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak256, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak384, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak512, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, md4, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, md5, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, ripemd128, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, ripemd160, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, tiger, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, whirlpool, ktask, key, key_size, kKryptosCBC, &rc6_rounds);

    kryptos_bad_buf_run_hmac(rc6_128, sha1, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha256, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha384, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha512, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_224, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_256, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_384, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_512, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak224, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak256, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak384, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak512, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, md4, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, md5, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, ripemd128, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, ripemd160, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, tiger, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, whirlpool, ktask, key, key_size, kKryptosOFB, &rc6_rounds);

    kryptos_bad_buf_run_hmac(rc6_128, sha1, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha256, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha384, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha512, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_224, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_256, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_384, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, sha3_512, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak224, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak256, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak384, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, keccak512, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, md4, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, md5, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, ripemd128, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, ripemd160, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, tiger, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_128, whirlpool, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_192_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
    int rc6_rounds = 90;

    kryptos_bad_buf_run_hmac(rc6_192, sha1, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha256, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha384, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha512, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_224, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_256, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_384, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_512, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak224, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak256, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak384, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak512, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, md4, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, md5, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, ripemd128, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, ripemd160, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, tiger, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, whirlpool, ktask, key, key_size, kKryptosECB, &rc6_rounds);

    kryptos_bad_buf_run_hmac(rc6_192, sha1, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha256, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha384, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha512, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_224, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_256, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_384, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_512, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak224, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak256, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak384, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak512, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, md4, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, md5, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, ripemd128, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, ripemd160, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, tiger, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, whirlpool, ktask, key, key_size, kKryptosCBC, &rc6_rounds);

    kryptos_bad_buf_run_hmac(rc6_192, sha1, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha256, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha384, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha512, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_224, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_256, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_384, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_512, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak224, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak256, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak384, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak512, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, md4, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, md5, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, ripemd128, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, ripemd160, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, tiger, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, whirlpool, ktask, key, key_size, kKryptosOFB, &rc6_rounds);

    kryptos_bad_buf_run_hmac(rc6_192, sha1, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha256, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha384, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha512, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_224, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_256, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_384, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, sha3_512, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak224, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak256, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak384, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, keccak512, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, md4, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, md5, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, ripemd128, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, ripemd160, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, tiger, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_192, whirlpool, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_256_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
    int rc6_rounds = 90;

    kryptos_bad_buf_run_hmac(rc6_256, sha1, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha256, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha384, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha512, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_224, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_256, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_384, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_512, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak224, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak256, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak384, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak512, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, md4, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, md5, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, ripemd128, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, ripemd160, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, tiger, ktask, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, whirlpool, ktask, key, key_size, kKryptosECB, &rc6_rounds);

    kryptos_bad_buf_run_hmac(rc6_256, sha1, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha256, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha384, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha512, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_224, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_256, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_384, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_512, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak224, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak256, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak384, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak512, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, md4, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, md5, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, ripemd128, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, ripemd160, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, tiger, ktask, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, whirlpool, ktask, key, key_size, kKryptosCBC, &rc6_rounds);

    kryptos_bad_buf_run_hmac(rc6_256, sha1, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha256, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha384, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha512, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_224, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_256, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_384, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_512, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak224, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak256, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak384, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak512, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, md4, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, md5, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, ripemd128, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, ripemd160, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, tiger, ktask, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, whirlpool, ktask, key, key_size, kKryptosOFB, &rc6_rounds);

    kryptos_bad_buf_run_hmac(rc6_256, sha1, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha256, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha384, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha512, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_224, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_256, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_384, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, sha3_512, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak224, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak256, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak384, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, keccak512, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, md4, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, md5, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, ripemd128, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, ripemd160, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, tiger, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
    kryptos_bad_buf_run_hmac(rc6_256, whirlpool, ktask, key, key_size, kKryptosCTR, &rc6_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_saferk64_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
    int saferk64_n = 6;

    kryptos_bad_buf_run_hmac(saferk64, sha1, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha256, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha384, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha512, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_224, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_256, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_384, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_512, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak224, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak256, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak384, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak512, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, md4, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, md5, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, ripemd128, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, ripemd160, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, tiger, ktask, key, key_size, kKryptosECB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, whirlpool, ktask, key, key_size, kKryptosECB, &saferk64_n);

    kryptos_bad_buf_run_hmac(saferk64, sha1, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha256, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha384, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha512, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_224, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_256, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_384, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_512, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak224, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak256, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak384, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak512, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, md4, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, md5, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, ripemd128, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, ripemd160, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, tiger, ktask, key, key_size, kKryptosCBC, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, whirlpool, ktask, key, key_size, kKryptosCBC, &saferk64_n);

    kryptos_bad_buf_run_hmac(saferk64, sha1, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha256, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha384, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha512, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_224, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_256, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_384, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_512, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak224, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak256, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak384, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak512, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, md4, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, md5, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, ripemd128, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, ripemd160, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, tiger, ktask, key, key_size, kKryptosOFB, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, whirlpool, ktask, key, key_size, kKryptosOFB, &saferk64_n);

    kryptos_bad_buf_run_hmac(saferk64, sha1, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha256, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha384, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha512, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_224, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_256, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_384, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, sha3_512, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak224, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak256, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak384, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, keccak512, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, md4, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, md5, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, ripemd128, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, ripemd160, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, tiger, ktask, key, key_size, kKryptosCTR, &saferk64_n);
    kryptos_bad_buf_run_hmac(saferk64, whirlpool, ktask, key, key_size, kKryptosCTR, &saferk64_n);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
    kryptos_u8_t *tdes_k2 = "abc", *tdes_k3 = "def";
    size_t tdes_k2_size = 3, tdes_k3_size = 3;

    kryptos_bad_buf_run_hmac(triple_des, sha1, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha256, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha384, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha512, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_224, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_256, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_384, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_512, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak224, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak256, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak384, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak512, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, md4, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, md5, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, ripemd128, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, ripemd160, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, tiger, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, whirlpool, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);

    kryptos_bad_buf_run_hmac(triple_des, sha1, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha256, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha384, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha512, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_224, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_256, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_384, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_512, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak224, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak256, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak384, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak512, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, md4, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, md5, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, ripemd128, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, ripemd160, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, tiger, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, whirlpool, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);

    kryptos_bad_buf_run_hmac(triple_des, sha1, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha256, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha384, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha512, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_224, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_256, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_384, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_512, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak224, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak256, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak384, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak512, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, md4, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, md5, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, ripemd128, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, ripemd160, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, tiger, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, whirlpool, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);

    kryptos_bad_buf_run_hmac(triple_des, sha1, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha256, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha384, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha512, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_224, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_256, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_384, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, sha3_512, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak224, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak256, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak384, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, keccak512, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, md4, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, md5, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, ripemd128, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, ripemd160, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, tiger, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des, whirlpool, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_ede_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
    kryptos_u8_t *tdes_k2 = "abc", *tdes_k3 = "def";
    size_t tdes_k2_size = 3, tdes_k3_size = 3;

    kryptos_bad_buf_run_hmac(triple_des_ede, sha1, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha256, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha384, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha512, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_224, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_256, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_384, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_512, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak224, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak256, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak384, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak512, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, md4, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, md5, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, ripemd128, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, ripemd160, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, tiger, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, whirlpool, ktask, key, key_size, kKryptosECB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);

    kryptos_bad_buf_run_hmac(triple_des_ede, sha1, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha256, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha384, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha512, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_224, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_256, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_384, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_512, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak224, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak256, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak384, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak512, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, md4, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, md5, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, ripemd128, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, ripemd160, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, tiger, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, whirlpool, ktask, key, key_size, kKryptosCBC,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);

    kryptos_bad_buf_run_hmac(triple_des_ede, sha1, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha256, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha384, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha512, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_224, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_256, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_384, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_512, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak224, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak256, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak384, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak512, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, md4, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, md5, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, ripemd128, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, ripemd160, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, tiger, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, whirlpool, ktask, key, key_size, kKryptosOFB,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);

    kryptos_bad_buf_run_hmac(triple_des_ede, sha1, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha256, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha384, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha512, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_224, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_256, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_384, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, sha3_512, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak224, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak256, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak384, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, keccak512, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, md4, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, md5, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, ripemd128, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, ripemd160, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, tiger, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
    kryptos_bad_buf_run_hmac(triple_des_ede, whirlpool, ktask, key, key_size, kKryptosCTR,
                             tdes_k2, &tdes_k2_size, tdes_k3, &tdes_k3_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_xtea_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
    int xtea_rounds = 72;

    kryptos_bad_buf_run_hmac(xtea, sha1, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha256, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha384, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha512, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_224, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_256, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_384, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_512, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak224, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak256, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak384, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak512, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, md4, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, md5, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, ripemd128, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, ripemd160, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, tiger, ktask, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, whirlpool, ktask, key, key_size, kKryptosECB, &xtea_rounds);

    kryptos_bad_buf_run_hmac(xtea, sha1, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha256, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha384, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha512, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_224, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_256, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_384, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_512, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak224, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak256, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak384, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak512, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, md4, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, md5, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, ripemd128, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, ripemd160, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, tiger, ktask, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, whirlpool, ktask, key, key_size, kKryptosCBC, &xtea_rounds);

    kryptos_bad_buf_run_hmac(xtea, sha1, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha256, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha384, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha512, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_224, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_256, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_384, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_512, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak224, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak256, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak384, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak512, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, md4, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, md5, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, ripemd128, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, ripemd160, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, tiger, ktask, key, key_size, kKryptosOFB, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, whirlpool, ktask, key, key_size, kKryptosOFB, &xtea_rounds);

    kryptos_bad_buf_run_hmac(xtea, sha1, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha256, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha384, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha512, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_224, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_256, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_384, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, sha3_512, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak224, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak256, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak384, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, keccak512, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, md4, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, md5, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, ripemd128, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, ripemd160, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, tiger, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
    kryptos_bad_buf_run_hmac(xtea, whirlpool, ktask, key, key_size, kKryptosCTR, &xtea_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_bad_hmac_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *key = "BoOmM!";
    size_t key_size = 6;
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

    kryptos_bad_buf_run_hmac(gost, sha1, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha256, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha384, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha512, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_224, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_256, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_384, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_512, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak224, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak256, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak384, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak512, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, md4, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, md5, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, ripemd128, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, ripemd160, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, tiger, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, whirlpool, ktask, key, key_size, kKryptosECB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);

    kryptos_bad_buf_run_hmac(gost, sha1, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha256, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha384, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha512, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_224, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_256, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_384, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_512, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak224, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak256, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak384, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak512, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, md4, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, md5, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, ripemd128, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, ripemd160, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, tiger, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, whirlpool, ktask, key, key_size, kKryptosCBC,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);

    kryptos_bad_buf_run_hmac(gost, sha1, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha256, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha384, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha512, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_224, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_256, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_384, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_512, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak224, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak256, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak384, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak512, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, md4, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, md5, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, ripemd128, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, ripemd160, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, tiger, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, whirlpool, ktask, key, key_size, kKryptosOFB,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);

    kryptos_bad_buf_run_hmac(gost, sha1, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha256, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha384, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha512, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_224, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_256, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_384, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, sha3_512, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak224, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak256, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak384, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, keccak512, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, md4, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, md5, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, ripemd128, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, ripemd160, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, tiger, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
    kryptos_bad_buf_run_hmac(gost, whirlpool, ktask, key, key_size, kKryptosCTR,
                             gost_s1, gost_s2, gost_s3, gost_s4, gost_s5, gost_s6, gost_s7, gost_s8);
CUTE_TEST_CASE_END

#endif
