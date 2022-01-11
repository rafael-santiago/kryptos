/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "poly1305_tests.h"
#include "test_vectors.h"
#include <kryptos.h>

#if defined(KRYPTOS_C99)
CUTE_DECLARE_TEST_CASE(kryptos_arc4_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_seal_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rabbit_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_salsa20_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_chacha20_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_des_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_idea_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_blowfish_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_feal_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc2_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc5_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_128_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_192_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_256_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia128_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia192_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia256_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_cast5_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_saferk64_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes128_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes192_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes256_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_serpent_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_triple_des_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_triple_des_ede_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_tea_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_xtea_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_misty1_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars128_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars192_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars256_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_present80_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_present128_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_shacal1_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_shacal2_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_noekeon_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_noekeon_d_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_gost_ds_poly1305_tests);
CUTE_DECLARE_TEST_CASE(kryptos_gost_poly1305_tests);
#endif // defined(KRYPTOS_C99)

CUTE_TEST_CASE_SUITE(kryptos_poly1305_tests)
#if defined(KRYPTOS_C99)
    CUTE_RUN_TEST(kryptos_arc4_poly1305_tests);
    CUTE_RUN_TEST(kryptos_seal_poly1305_tests);
    CUTE_RUN_TEST(kryptos_rabbit_poly1305_tests);
    CUTE_RUN_TEST(kryptos_salsa20_poly1305_tests);
    CUTE_RUN_TEST(kryptos_chacha20_poly1305_tests);
    CUTE_RUN_TEST(kryptos_des_poly1305_tests);
    CUTE_RUN_TEST(kryptos_idea_poly1305_tests);
    CUTE_RUN_TEST(kryptos_blowfish_poly1305_tests);
    CUTE_RUN_TEST(kryptos_feal_poly1305_tests);
    CUTE_RUN_TEST(kryptos_rc2_poly1305_tests);
    CUTE_RUN_TEST(kryptos_rc5_poly1305_tests);
    CUTE_RUN_TEST(kryptos_rc6_128_poly1305_tests);
    CUTE_RUN_TEST(kryptos_rc6_192_poly1305_tests);
    CUTE_RUN_TEST(kryptos_rc6_256_poly1305_tests);
    CUTE_RUN_TEST(kryptos_camellia128_poly1305_tests);
    CUTE_RUN_TEST(kryptos_camellia192_poly1305_tests);
    CUTE_RUN_TEST(kryptos_camellia256_poly1305_tests);
    CUTE_RUN_TEST(kryptos_cast5_poly1305_tests);
    CUTE_RUN_TEST(kryptos_saferk64_poly1305_tests);
    CUTE_RUN_TEST(kryptos_aes128_poly1305_tests);
    CUTE_RUN_TEST(kryptos_aes192_poly1305_tests);
    CUTE_RUN_TEST(kryptos_aes256_poly1305_tests);
    CUTE_RUN_TEST(kryptos_serpent_poly1305_tests);
    CUTE_RUN_TEST(kryptos_triple_des_poly1305_tests);
    CUTE_RUN_TEST(kryptos_triple_des_ede_poly1305_tests);
    CUTE_RUN_TEST(kryptos_tea_poly1305_tests);
    CUTE_RUN_TEST(kryptos_xtea_poly1305_tests);
    CUTE_RUN_TEST(kryptos_misty1_poly1305_tests);
    CUTE_RUN_TEST(kryptos_mars128_poly1305_tests);
    CUTE_RUN_TEST(kryptos_mars192_poly1305_tests);
    CUTE_RUN_TEST(kryptos_mars256_poly1305_tests);
    CUTE_RUN_TEST(kryptos_present80_poly1305_tests);
    CUTE_RUN_TEST(kryptos_present128_poly1305_tests);
    CUTE_RUN_TEST(kryptos_shacal1_poly1305_tests);
    CUTE_RUN_TEST(kryptos_shacal2_poly1305_tests);
    CUTE_RUN_TEST(kryptos_noekeon_poly1305_tests);
    CUTE_RUN_TEST(kryptos_noekeon_d_poly1305_tests);
    CUTE_RUN_TEST(kryptos_gost_ds_poly1305_tests);
    CUTE_RUN_TEST(kryptos_gost_poly1305_tests);
#else
    printf("WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
#endif // defined(KRYPTOS_C99)
CUTE_TEST_CASE_SUITE_END

CUTE_TEST_CASE(kryptos_poly1305_basic_tests)
    struct test_ctx {
        kryptos_u8_t *key;
        size_t key_size;
        kryptos_u8_t *msg;
        size_t msg_size;
        kryptos_u8_t *tag;
        size_t tag_size;
    } test_vector[] = {
        (kryptos_u8_t *)"\x85\xD6\xBE\x78\x57\x55\x6D\x33\x7F\x44\x52\xFE\x42\xD5\x06\xA8"
                        "\x01\x03\x80\x8A\xFB\x0D\xB2\xFD\x4A\xBF\xF6\xAF\x41\x49\xF5\x1B",
        32,
        (kryptos_u8_t *)"\x43\x72\x79\x70\x74\x6F\x67\x72\x61\x70\x68\x69\x63\x20\x46\x6F"
                        "\x72\x75\x6D\x20\x52\x65\x73\x65\x61\x72\x63\x68\x20\x47\x72\x6F"
                        "\x75\x70",
        34,
        (kryptos_u8_t *)"\xA8\x06\x1D\xC1\x30\x51\x36\xC6\xC2\x2B\x8B\xAF\x0C\x01\x27\xA9",
        16
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_task_ctx t, *ktask = &t;

    while (test != test_end) {
        kryptos_task_init_as_null(ktask);
        kryptos_task_set_encrypt_action(ktask);

        kryptos_poly1305(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosPOLY1305Error);
        CUTE_ASSERT(ktask->result_verbose != NULL);
        CUTE_ASSERT(strcmp(ktask->result_verbose, "No message to tag at output buffer.") == 0);

        ktask->out = (kryptos_u8_t *)kryptos_newseg(test->msg_size);
        CUTE_ASSERT(ktask->out != NULL);
        memcpy(ktask->out, test->msg, test->msg_size);
        ktask->out_size = test->msg_size;

        kryptos_poly1305(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosPOLY1305Error);
        CUTE_ASSERT(ktask->result_verbose != NULL);
        CUTE_ASSERT(strcmp(ktask->result_verbose, "No key to authenticate.") == 0);

        ktask->key = test->key;
        ktask->key_size = test->key_size;

        kryptos_poly1305(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosSuccess);

        CUTE_ASSERT(ktask->out_size == test->tag_size + test->msg_size);
        CUTE_ASSERT(ktask->out != NULL);
        CUTE_ASSERT(memcmp(ktask->out, test->tag, test->tag_size) == 0);

        kryptos_task_set_decrypt_action(ktask);

        ktask->in = NULL;
        ktask->in_size = 0;
        kryptos_poly1305(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosPOLY1305Error);
        CUTE_ASSERT(ktask->result_verbose != NULL);
        CUTE_ASSERT(strcmp(ktask->result_verbose, "No message to verify.") == 0);

        ktask->in = ktask->out;
        ktask->in_size = 16;
        kryptos_poly1305(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosPOLY1305Error);
        CUTE_ASSERT(ktask->result_verbose != NULL);
        CUTE_ASSERT(strcmp(ktask->result_verbose, "Message buffer seems to be incomplete.") == 0);

        ktask->in_size = ktask->out_size;
        ktask->out = NULL;
        ktask->out_size = 0;

        ktask->key = NULL;
        ktask->key_size = 0;
        kryptos_poly1305(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosPOLY1305Error);
        CUTE_ASSERT(ktask->result_verbose != NULL);
        CUTE_ASSERT(strcmp(ktask->result_verbose, "No key to authenticate.") == 0);
        ktask->key = test->key;
        ktask->key_size = test->key_size;

        kryptos_poly1305(&ktask);
        CUTE_ASSERT(ktask->result == kKryptosSuccess);

        CUTE_ASSERT(ktask->in_size == test->msg_size);
        CUTE_ASSERT(ktask->in != NULL);
        CUTE_ASSERT(memcmp(ktask->in, test->msg, ktask->in_size) == 0);

        kryptos_task_free(ktask, KRYPTOS_TASK_IN);

        test++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_arc4_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305Arc4Test";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, arc4, key, key_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_seal_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305SealTest";
    size_t key_size = strlen(key);
    size_t seal_n = 0, seal_l = 1024;
    kryptos_seal_version_t seal_version = kKryptosSEAL20;

    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, seal, key, key_size, &seal_version, &seal_l, &seal_n);

    seal_n = 0;
    seal_l = 2048;
    seal_version = kKryptosSEAL30;

    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, seal, key, key_size, &seal_version, &seal_l, &seal_n);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rabbit_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "QueHaVelho?!";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rabbit, key, key_size, NULL);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_salsa20_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305Salsa20Test.............";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, salsa20, key, key_size, NULL);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_chacha20_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305ChaCha20Test............";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, chacha20, key, key_size, NULL, NULL);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_des_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305DesTest";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, des, key, key_size, kKryptosECB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, des, key, key_size, kKryptosCBC);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, des, key, key_size, kKryptosOFB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, des, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_idea_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305IdeaTest";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, idea, key, key_size, kKryptosECB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, idea, key, key_size, kKryptosCBC);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, idea, key, key_size, kKryptosOFB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, idea, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blowfish_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305BlowfishTest";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, blowfish, key, key_size, kKryptosECB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, blowfish, key, key_size, kKryptosCBC);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, blowfish, key, key_size, kKryptosOFB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, blowfish, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_feal_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305FealTest";
    int feal_rounds = 16;
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, feal, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, feal, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, feal, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, feal, key, key_size, kKryptosCTR, &feal_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc2_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305RC2Test";
    size_t key_size = strlen(key);
    int rc2_t1 = 128;
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc2, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc2, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc2, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc2, key, key_size, kKryptosCTR, &rc2_t1);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc5_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305RC5Test";
    size_t key_size = strlen(key);
    int rc5_rounds = 32;
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc5, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc5, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc5, key, key_size, kKryptosOFB, &rc5_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc5, key, key_size, kKryptosCTR, &rc5_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_128_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305RC6Test";
    size_t key_size = strlen(key);
    int rc6_rounds = 40;
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_128, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_128, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_128, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_128, key, key_size, kKryptosCTR, &rc6_rounds);
    // INFO(Rafael): Overstated but possible so let's test.
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_128, key, key_size, kKryptosGCM, &rc6_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_192_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305RC6Test";
    size_t key_size = strlen(key);
    int rc6_rounds = 40;
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_192, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_192, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_192, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_192, key, key_size, kKryptosCTR, &rc6_rounds);
    // INFO(Rafael): Overstated but possible so let's test.
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_192, key, key_size, kKryptosGCM, &rc6_rounds);

CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_256_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305RC6Test";
    size_t key_size = strlen(key);
    int rc6_rounds = 40;
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_256, key, key_size, kKryptosOFB, &rc6_rounds);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_256, key, key_size, kKryptosCTR, &rc6_rounds);
    // INFO(Rafael): Overstated but possible so let's test.
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, rc6_256, key, key_size, kKryptosGCM, &rc6_rounds);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia128_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305CamelliaTest";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia128, key, key_size, kKryptosECB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia128, key, key_size, kKryptosCBC);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia128, key, key_size, kKryptosOFB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia128, key, key_size, kKryptosCTR);
    // INFO(Rafael): Overstated but possible so let's test.
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia128, key, key_size, kKryptosGCM);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia192_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305CamelliaTest";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia192, key, key_size, kKryptosECB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia192, key, key_size, kKryptosCBC);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia192, key, key_size, kKryptosOFB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia192, key, key_size, kKryptosCTR);
    // INFO(Rafael): Overstated but possible so let's test.
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia192, key, key_size, kKryptosGCM);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia256_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305CamelliaTest";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia256, key, key_size, kKryptosECB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia256, key, key_size, kKryptosCBC);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia256, key, key_size, kKryptosOFB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia256, key, key_size, kKryptosCTR);
    // INFO(Rafael): Overstated but possible so let's test.
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, camellia256, key, key_size, kKryptosGCM);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_cast5_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305Cast5Test";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, cast5, key, key_size, kKryptosECB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, cast5, key, key_size, kKryptosCBC);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, cast5, key, key_size, kKryptosOFB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, cast5, key, key_size, kKryptosCTR);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_saferk64_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305SaferK64Test";
    size_t key_size = strlen(key);
    int rounds_nr = 32;
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, saferk64, key, key_size, kKryptosECB, &rounds_nr);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, saferk64, key, key_size, kKryptosCBC, &rounds_nr);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, saferk64, key, key_size, kKryptosOFB, &rounds_nr);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, saferk64, key, key_size, kKryptosCTR, &rounds_nr);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes128_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305AESTest";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes128, key, key_size, kKryptosECB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes128, key, key_size, kKryptosCBC);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes128, key, key_size, kKryptosOFB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes128, key, key_size, kKryptosCTR);
    // INFO(Rafael): Overstated but possible so let's test.
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes128, key, key_size, kKryptosGCM);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes192_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305AESTest";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes192, key, key_size, kKryptosECB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes192, key, key_size, kKryptosCBC);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes192, key, key_size, kKryptosOFB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes192, key, key_size, kKryptosCTR);
    // INFO(Rafael): Overstated but possible so let's test.
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes192, key, key_size, kKryptosGCM);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes256_poly1305_tests)
    kryptos_task_ctx t;
    size_t tv, tv_nr, data_size;
    kryptos_u8_t *key = "Poly1305AESTest";
    size_t key_size = strlen(key);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes256, key, key_size, kKryptosECB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes256, key, key_size, kKryptosCBC);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes256, key, key_size, kKryptosOFB);
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes256, key, key_size, kKryptosCTR);
    // INFO(Rafael): Overstated but possible so let's test.
    kryptos_run_poly1305_tests(t, tv, tv_nr, data_size, aes256, key, key_size, kKryptosGCM);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_serpent_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_ede_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tea_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_xtea_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_misty1_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars128_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars192_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars256_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present80_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present128_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal1_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal2_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_d_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_ds_poly1305_tests)
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_poly1305_tests)
CUTE_TEST_CASE_END
