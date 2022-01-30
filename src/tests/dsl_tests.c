/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "dsl_tests.h"
#include <kryptos.h>
#include <string.h>

static kryptos_u8_t *dsl_tests_data = "IDIOT, n. A member of a large and powerful tribe whose influence in "
                            "human affairs has always been dominant and controlling. The Idiot's "
                            "activity is not confined to any special field of throught or action, but "
                            "'pervades and regulates the whole'. He has the last word in everything; his "
                            "decision is unappealable. He sets the fashions of opinion and taste, dictates "
                            "the limitations of speech and circumscribes conduct with a dead-line."; 
                            //... Everyone can point at least one.
static size_t dsl_tests_data_size = 432;

CUTE_DECLARE_TEST_CASE(kryptos_dsl_general_tests);

#if defined(KRYPTOS_C99)
CUTE_DECLARE_TEST_CASE(kryptos_arc4_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_seal_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rabbit_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_des_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_idea_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_blowfish_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_feal_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia_128_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia_192_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_camellia_256_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_cast5_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc2_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc5_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_128_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_192_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_rc6_256_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_saferk64_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes128_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes192_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_aes256_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_serpent_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_triple_des_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_triple_des_ede_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_tea_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_xtea_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_misty1_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars128_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars192_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_mars256_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_present80_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_present128_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_shacal1_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_shacal2_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_noekeon_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_noekeon_d_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_gost_ds_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_gost_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_salsa20_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_chacha20_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_twofish128_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_twofish192_dsl_tests);
CUTE_DECLARE_TEST_CASE(kryptos_twofish256_dsl_tests);
#endif

CUTE_TEST_CASE_SUITE(kryptos_dsl_tests)
    // WARN(Rafael): The correctness of each available cipher must not be tested here. It
    //               should be done within a dedicated test case. Here only the mechanics about
    //               using these ciphers indirectly is tested (when C99 support is present).
    //               For testing it is used only one fixed plaintext and short keys.
    CUTE_RUN_TEST(kryptos_dsl_general_tests);
#ifdef KRYPTOS_C99
    // INFO(Rafael): The cipher indirect calling tests. Let's test the variadic macro kryptos_run_cipher() variations.
    CUTE_RUN_TEST(kryptos_arc4_dsl_tests);
    CUTE_RUN_TEST(kryptos_seal_dsl_tests);
    CUTE_RUN_TEST(kryptos_rabbit_dsl_tests);
    CUTE_RUN_TEST(kryptos_salsa20_dsl_tests);
    CUTE_RUN_TEST(kryptos_chacha20_dsl_tests);
    CUTE_RUN_TEST(kryptos_des_dsl_tests);
    CUTE_RUN_TEST(kryptos_idea_dsl_tests);
    CUTE_RUN_TEST(kryptos_blowfish_dsl_tests);
    CUTE_RUN_TEST(kryptos_feal_dsl_tests);
    CUTE_RUN_TEST(kryptos_camellia_128_dsl_tests);
    CUTE_RUN_TEST(kryptos_camellia_192_dsl_tests);
    CUTE_RUN_TEST(kryptos_camellia_256_dsl_tests);
    CUTE_RUN_TEST(kryptos_cast5_dsl_tests);
    CUTE_RUN_TEST(kryptos_rc2_dsl_tests);
    CUTE_RUN_TEST(kryptos_rc5_dsl_tests);
    CUTE_RUN_TEST(kryptos_rc6_128_dsl_tests);
    CUTE_RUN_TEST(kryptos_rc6_192_dsl_tests);
    CUTE_RUN_TEST(kryptos_rc6_256_dsl_tests);
    CUTE_RUN_TEST(kryptos_saferk64_dsl_tests);
    CUTE_RUN_TEST(kryptos_aes128_dsl_tests);
    CUTE_RUN_TEST(kryptos_aes192_dsl_tests);
    CUTE_RUN_TEST(kryptos_aes256_dsl_tests);
    CUTE_RUN_TEST(kryptos_serpent_dsl_tests);
    CUTE_RUN_TEST(kryptos_triple_des_dsl_tests);
    CUTE_RUN_TEST(kryptos_triple_des_ede_dsl_tests);
    CUTE_RUN_TEST(kryptos_tea_dsl_tests);
    CUTE_RUN_TEST(kryptos_xtea_dsl_tests);
    CUTE_RUN_TEST(kryptos_misty1_dsl_tests);
    CUTE_RUN_TEST(kryptos_mars128_dsl_tests);
    CUTE_RUN_TEST(kryptos_mars192_dsl_tests);
    CUTE_RUN_TEST(kryptos_mars256_dsl_tests);
    CUTE_RUN_TEST(kryptos_present80_dsl_tests);
    CUTE_RUN_TEST(kryptos_present128_dsl_tests);
    CUTE_RUN_TEST(kryptos_shacal1_dsl_tests);
    CUTE_RUN_TEST(kryptos_shacal2_dsl_tests);
    CUTE_RUN_TEST(kryptos_noekeon_dsl_tests);
    CUTE_RUN_TEST(kryptos_noekeon_d_dsl_tests);
    CUTE_RUN_TEST(kryptos_gost_ds_dsl_tests);
    CUTE_RUN_TEST(kryptos_gost_dsl_tests);
    CUTE_RUN_TEST(kryptos_twofish128_dsl_tests);
    CUTE_RUN_TEST(kryptos_twofish192_dsl_tests);
    CUTE_RUN_TEST(kryptos_twofish256_dsl_tests);
#endif
CUTE_TEST_CASE_SUITE_END

CUTE_TEST_CASE(kryptos_dsl_general_tests)
    kryptos_task_ctx task;

    kryptos_task_set_ecb_mode(&task);
    CUTE_ASSERT(task.mode == kKryptosECB);

    kryptos_task_set_cbc_mode(&task);
    CUTE_ASSERT(task.mode == kKryptosCBC);

    kryptos_task_set_encrypt_action(&task);
    CUTE_ASSERT(task.action == kKryptosEncrypt);

    kryptos_task_set_decrypt_action(&task);
    CUTE_ASSERT(task.action == kKryptosDecrypt);

    task.result = kKryptosSuccess;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 1);

    task.result = kKryptosKeyError;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosProcessError;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosInvalidParams;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosInvalidCipher;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    task.result = kKryptosTaskResultNr;
    CUTE_ASSERT(kryptos_last_task_succeed(&task) == 0);

    kryptos_task_set_in(&task, dsl_tests_data, dsl_tests_data_size);
    CUTE_ASSERT(task.in == dsl_tests_data);
    CUTE_ASSERT(task.in_size == dsl_tests_data_size);

    kryptos_task_init_as_null(&task);

    task.in = NULL;
    task.in_size = 0;
    task.out = dsl_tests_data;
    task.out_size = dsl_tests_data_size;
    CUTE_ASSERT(kryptos_task_get_out(&task) == dsl_tests_data);
    CUTE_ASSERT(kryptos_task_get_out_size(&task) == dsl_tests_data_size);

    if (g_cute_leak_check == 1) {
        task.out = (kryptos_u8_t *) kryptos_newseg(0x10);
        task.out_size = 0x10;
        kryptos_task_free(&task, KRYPTOS_TASK_OUT);
        CUTE_ASSERT(task.out == NULL);
        CUTE_ASSERT(task.out_size == 0);

        task.in = (kryptos_u8_t *) kryptos_newseg(0x10);
        task.in_size = 0x10;
        task.out = (kryptos_u8_t *) kryptos_newseg(0x10);
        task.out_size = 0x10;
        kryptos_task_free(&task, KRYPTOS_TASK_OUT|KRYPTOS_TASK_IN);
        CUTE_ASSERT(task.in == NULL);
        CUTE_ASSERT(task.in_size == 0);
        CUTE_ASSERT(task.out == NULL);
        CUTE_ASSERT(task.out_size == 0);
        // WARN(Rafael): If the out block was not actually freed, the cutest leak check system will complain.
    } else {
        // WARN(Rafael): This is bad. Avoid it. If you have freed every single trinket that you alloc'd,
        //               you should have no fear. ;) The Leak System is your friend or supposed to be...
        printf("=== WARN: The leak check system is deactivated, due to it was not possible test the kryptos_task_free() macro."
               " It was SKIPPED.\n===\n");
    }
CUTE_TEST_CASE_END

#if defined(KRYPTOS_C99)
CUTE_TEST_CASE(kryptos_arc4_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_task_init_as_null(ktask);
    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_run_cipher(arc4, ktask, "arc4", 4);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    kryptos_task_set_in(ktask, kryptos_task_get_out(ktask), kryptos_task_get_out_size(ktask));
    kryptos_run_cipher(arc4, ktask, "arc4", 4);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_seal_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_seal_version_t seal_version;
    size_t seal_n, seal_l;

    kryptos_task_init_as_null(ktask);

    // SEAL 2.0
    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);

    seal_version = kKryptosSEAL20;
    seal_l = 1024;
    seal_n = 0;
    kryptos_run_cipher(seal, ktask, "seal", 4, &seal_version, &seal_l, &seal_n);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    kryptos_task_set_in(ktask, kryptos_task_get_out(ktask), kryptos_task_get_out_size(ktask));

    kryptos_run_cipher(seal, ktask, "seal", 4, &seal_version, &seal_l, &seal_n);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SEAL 3.0
    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);

    seal_version = kKryptosSEAL30;
    seal_l = 2048;
    seal_n = 0;
    kryptos_run_cipher(seal, ktask, "seal", 4, &seal_version, &seal_l, &seal_n);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    kryptos_task_set_in(ktask, kryptos_task_get_out(ktask), kryptos_task_get_out_size(ktask));

    kryptos_run_cipher(seal, ktask, "seal", 4, &seal_version, &seal_l, &seal_n);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rabbit_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    // RABBIT
    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);

    kryptos_run_cipher(rabbit, ktask, "rabbit", 6, NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    kryptos_task_set_in(ktask, kryptos_task_get_out(ktask), kryptos_task_get_out_size(ktask));

    kryptos_run_cipher(rabbit, ktask, "rabbit", 6, NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_salsa20_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    // SALSA20
    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);

    kryptos_run_cipher(salsa20, ktask, "salsa20\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00", 32, "salsa20\x00");
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    kryptos_task_set_in(ktask, kryptos_task_get_out(ktask), kryptos_task_get_out_size(ktask));

    kryptos_run_cipher(salsa20, ktask, "salsa20\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00", 32, "salsa20\x00");
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SALSA20
    // INFO(Rafael): Using random iv.
    kryptos_task_set_encrypt_action(ktask);
    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);

    kryptos_run_cipher(salsa20, ktask, "salsa20\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00", 32, NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    kryptos_task_set_decrypt_action(ktask);
    kryptos_task_set_in(ktask, kryptos_task_get_out(ktask), kryptos_task_get_out_size(ktask));

    kryptos_run_cipher(salsa20, ktask, "salsa20\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00", 32, NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_chacha20_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    // CHACHA20
    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);

    kryptos_run_cipher(chacha20, ktask, "chacha20\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00", 32, "chacha20\x00\x00\x00\x00", NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    kryptos_task_set_in(ktask, kryptos_task_get_out(ktask), kryptos_task_get_out_size(ktask));

    kryptos_run_cipher(chacha20, ktask, "chacha20\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00", 32, "chacha20\x00\x00\x00\x00", NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CHACHA20
    // INFO(Rafael): Using random iv.
    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);
    kryptos_run_cipher(chacha20, ktask, "chacha20\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00", 32, NULL, NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    kryptos_task_set_in(ktask, kryptos_task_get_out(ktask), kryptos_task_get_out_size(ktask));
    kryptos_task_set_decrypt_action(ktask);
    kryptos_run_cipher(chacha20, ktask, "chacha20\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00\x00\x00\x00\x00\x00\x00"
                                       "\x00\x00", 32, NULL, NULL);
    CUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(ktask->out != NULL);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_des_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // DES ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(des, ktask, "des", 3, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(des, ktask, "des", 3, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // DES CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(des, ktask, "des", 3, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(des, ktask, "des", 3, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // DES OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(des, ktask, "des", 3, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(des, ktask, "des", 3, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // DES CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(des, ktask, "des", 3, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(des, ktask, "des", 3, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // DES GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(des, ktask, "des", 3, kKryptosGCM);

    CUTE_ASSERT(ktask->result == kKryptosNoSupport);
    CUTE_ASSERT(ktask->out == NULL);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_idea_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // IDEA ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(idea, ktask, "idea", 4, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(idea, ktask, "idea", 4, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // IDEA CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(idea, ktask, "idea", 4, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(idea, ktask, "idea", 4, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // IDEA OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(idea, ktask, "idea", 4, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(idea, ktask, "idea", 4, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // IDEA CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(idea, ktask, "idea", 4, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(idea, ktask, "idea", 4, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // IDEA GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(idea, ktask, "idea", 4, kKryptosGCM);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_blowfish_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // BLOWFISH ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(blowfish, ktask, "blowfish", 8, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(blowfish, ktask, "blowfish", 8, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // BLOWFISH CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(blowfish, ktask, "blowfish", 8, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(blowfish, ktask, "blowfish", 8, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // BLOWFISH OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(blowfish, ktask, "blowfish", 8, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(blowfish, ktask, "blowfish", 8, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // BLOWFISH CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(blowfish, ktask, "blowfish", 8, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(blowfish, ktask, "blowfish", 8, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // BLOWFISH GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(blowfish, ktask, "blowfish", 8, kKryptosGCM);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_feal_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    int feal_rounds = 16;

    kryptos_task_init_as_null(ktask);

    // FEAL ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(feal, ktask, "feal", 4, kKryptosECB, &feal_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(feal, ktask, "feal", 4, kKryptosECB, &feal_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // FEAL CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(feal, ktask, "feal", 4, kKryptosCBC, &feal_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(feal, ktask, "feal", 4, kKryptosCBC, &feal_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // FEAL OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(feal, ktask, "feal", 4, kKryptosOFB, &feal_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(feal, ktask, "feal", 4, kKryptosOFB, &feal_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // FEAL CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(feal, ktask, "feal", 4, kKryptosCTR, &feal_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(feal, ktask, "feal", 4, kKryptosCTR, &feal_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // FEAL GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(feal, ktask, "feal", 4, kKryptosGCM, &feal_rounds);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia_128_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // CAMELLIA-128 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia128, ktask, "camellia", 8, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia128, ktask, "camellia", 8, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAMELLIA-128 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia128, ktask, "camellia", 8, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia128, ktask, "camellia", 8, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-128 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia128, ktask, "camellia", 8, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia128, ktask, "camellia", 8, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-128 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia128, ktask, "camellia", 8, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia128, ktask, "camellia", 8, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-128 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia128, ktask, "camellia", 8, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia128, ktask, "camellia", 8, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia_192_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // CAMELLIA-192 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia192, ktask, "camellia", 8, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia192, ktask, "camellia", 8, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAMELLIA-192 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia192, ktask, "camellia", 8, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia192, ktask, "camellia", 8, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-192 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia192, ktask, "camellia", 8, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia192, ktask, "camellia", 8, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-192 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia192, ktask, "camellia", 8, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia192, ktask, "camellia", 8, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-192 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia192, ktask, "camellia", 8, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia192, ktask, "camellia", 8, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_camellia_256_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // CAMELLIA-256 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia256, ktask, "camellia", 8, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia256, ktask, "camellia", 8, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAMELLIA-256 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia256, ktask, "camellia", 8, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia256, ktask, "camellia", 8, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-256 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia256, ktask, "camellia", 8, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia256, ktask, "camellia", 8, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-256 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia256, ktask, "camellia", 8, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia256, ktask, "camellia", 8, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAMELLIA-256 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(camellia256, ktask, "camellia", 8, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(camellia256, ktask, "camellia", 8, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_cast5_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // CAST5 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(cast5, ktask, "cast5", 5, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(cast5, ktask, "cast5", 5, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // CAST5 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(cast5, ktask, "cast5", 5, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(cast5, ktask, "cast5", 5, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAST5 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(cast5, ktask, "cast5", 5, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(cast5, ktask, "cast5", 5, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAST5 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(cast5, ktask, "cast5", 5, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(cast5, ktask, "cast5", 5, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // CAST5 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(cast5, ktask, "cast5", 5, kKryptosGCM);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);
    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc2_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    int rc2_t1 = 128;

    kryptos_task_init_as_null(ktask);

    // RC2 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc2, ktask, "rc2", 3, kKryptosECB, &rc2_t1);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc2, ktask, "rc2", 3, kKryptosECB, &rc2_t1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC2 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc2, ktask, "rc2", 3, kKryptosCBC, &rc2_t1);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc2, ktask, "rc2", 3, kKryptosCBC, &rc2_t1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC2 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc2, ktask, "rc2", 3, kKryptosOFB, &rc2_t1);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc2, ktask, "rc2", 3, kKryptosOFB, &rc2_t1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC2 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc2, ktask, "rc2", 3, kKryptosCTR, &rc2_t1);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc2, ktask, "rc2", 3, kKryptosCTR, &rc2_t1);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC2 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc2, ktask, "rc2", 3, kKryptosGCM, &rc2_t1);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc5_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    int rc5_rounds = 32;

    kryptos_task_init_as_null(ktask);

    // RC5 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc5, ktask, "rc5", 3, kKryptosECB, &rc5_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc5, ktask, "rc5", 3, kKryptosECB, &rc5_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC5 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc5, ktask, "rc5", 3, kKryptosCBC, &rc5_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc5, ktask, "rc5", 3, kKryptosCBC, &rc5_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC5 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc5, ktask, "rc5", 3, kKryptosOFB, &rc5_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc5, ktask, "rc5", 3, kKryptosOFB, &rc5_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC5 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc5, ktask, "rc5", 3, kKryptosCTR, &rc5_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc5, ktask, "rc5", 3, kKryptosCTR, &rc5_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC5 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc5, ktask, "rc5", 3, kKryptosGCM, &rc5_rounds);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_128_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    int rc6_rounds = 40;

    kryptos_task_init_as_null(ktask);

    // RC6-128 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_128, ktask, "rc6", 3, kKryptosECB, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_128, ktask, "rc6", 3, kKryptosECB, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC6-128 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_128, ktask, "rc6", 3, kKryptosCBC, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_128, ktask, "rc6", 3, kKryptosCBC, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-128 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_128, ktask, "rc6", 3, kKryptosOFB, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_128, ktask, "rc6", 3, kKryptosOFB, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-128 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_128, ktask, "rc6", 3, kKryptosCTR, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_128, ktask, "rc6", 3, kKryptosCTR, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-128 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_128, ktask, "rc6", 3, kKryptosGCM, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_128, ktask, "rc6", 3, kKryptosGCM, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_192_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    int rc6_rounds = 40;

    kryptos_task_init_as_null(ktask);

    // RC6-192 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_192, ktask, "rc6", 3, kKryptosECB, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_192, ktask, "rc6", 3, kKryptosECB, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC6-192 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_192, ktask, "rc6", 3, kKryptosCBC, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_192, ktask, "rc6", 3, kKryptosCBC, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-192 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_192, ktask, "rc6", 3, kKryptosOFB, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_192, ktask, "rc6", 3, kKryptosOFB, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-192 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_192, ktask, "rc6", 3, kKryptosCTR, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_192, ktask, "rc6", 3, kKryptosCTR, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-192 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_192, ktask, "rc6", 3, kKryptosGCM, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_192, ktask, "rc6", 3, kKryptosGCM, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_rc6_256_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    int rc6_rounds = 40;

    kryptos_task_init_as_null(ktask);

    // RC6-256 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_256, ktask, "rc6", 3, kKryptosECB, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_256, ktask, "rc6", 3, kKryptosECB, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // RC6-256 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_256, ktask, "rc6", 3, kKryptosCBC, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_256, ktask, "rc6", 3, kKryptosCBC, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-256 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_256, ktask, "rc6", 3, kKryptosOFB, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_256, ktask, "rc6", 3, kKryptosOFB, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-256 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_256, ktask, "rc6", 3, kKryptosCTR, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_256, ktask, "rc6", 3, kKryptosCTR, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // RC6-256 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(rc6_256, ktask, "rc6", 3, kKryptosGCM, &rc6_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(rc6_256, ktask, "rc6", 3, kKryptosGCM, &rc6_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_saferk64_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    int saferk64_rounds = 32;

    kryptos_task_init_as_null(ktask);

    // SAFER K-64 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(saferk64, ktask, "saferk64", 8, kKryptosECB, &saferk64_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(saferk64, ktask, "saferk64", 8, kKryptosECB, &saferk64_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SAFER K-64 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(saferk64, ktask, "saferk64", 8, kKryptosCBC, &saferk64_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(saferk64, ktask, "saferk64", 8, kKryptosCBC, &saferk64_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SAFER K-64 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(saferk64, ktask, "saferk64", 8, kKryptosOFB, &saferk64_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(saferk64, ktask, "saferk64", 8, kKryptosOFB, &saferk64_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SAFER K-64 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(saferk64, ktask, "saferk64", 8, kKryptosCTR, &saferk64_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(saferk64, ktask, "saferk64", 8, kKryptosCTR, &saferk64_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SAFER K-64 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(saferk64, ktask, "saferk64", 8, kKryptosGCM, &saferk64_rounds);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes128_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // AES-128 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes128, ktask, "aes128", 6, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes128, ktask, "aes128", 6, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // AES-128 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes128, ktask, "aes128", 6, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes128, ktask, "aes128", 6, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-128 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes128, ktask, "aes128", 6, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes128, ktask, "aes128", 6, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-128 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes128, ktask, "aes128", 6, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes128, ktask, "aes128", 6, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-128 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes128, ktask, "aes128", 6, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes128, ktask, "aes128", 6, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes192_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // AES-192 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes192, ktask, "aes192", 6, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes192, ktask, "aes192", 6, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // AES-192 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes192, ktask, "aes192", 6, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes192, ktask, "aes192", 6, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-192 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes192, ktask, "aes192", 6, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes192, ktask, "aes192", 6, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-192 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes192, ktask, "aes192", 6, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes192, ktask, "aes192", 6, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-192 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes192, ktask, "aes192", 6, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes192, ktask, "aes192", 6, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_aes256_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // AES-256 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, "aes256", 6, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, "aes256", 6, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // AES-256 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, "aes256", 6, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, "aes256", 6, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-256 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, "aes256", 6, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, "aes256", 6, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-256 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, "aes256", 6, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, "aes256", 6, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // AES-256 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, "aes256", 6, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(aes256, ktask, "aes256", 6, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_serpent_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // SERPENT ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(serpent, ktask, "serpent", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(serpent, ktask, "serpent", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SERPENT CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(serpent, ktask, "serpent", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(serpent, ktask, "serpent", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SERPENT OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(serpent, ktask, "serpent", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(serpent, ktask, "serpent", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SERPENT CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(serpent, ktask, "serpent", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(serpent, ktask, "serpent", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SERPENT GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(serpent, ktask, "serpent", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(serpent, ktask, "serpent", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;

    kryptos_task_init_as_null(ktask);

    // TRIPLE-DES ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    triple_des_key2 = "noel";
    triple_des_key2_size = 4;
    triple_des_key3 = "mitch";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des, ktask, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(triple_des, ktask, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TRIPLE-DES CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des, ktask, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(triple_des, ktask, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TRIPLE-DES OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des, ktask, "jimi", 4, kKryptosOFB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(triple_des, ktask, "jimi", 4, kKryptosOFB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TRIPLE-DES CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des, ktask, "jimi", 4, kKryptosCTR,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(triple_des, ktask, "jimi", 4, kKryptosCTR,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TRIPLE-DES GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des, ktask, "jimi", 4, kKryptosGCM,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_triple_des_ede_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;

    kryptos_task_init_as_null(ktask);

    // TRIPLE-DES EDE ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    triple_des_key2 = "noel";
    triple_des_key2_size = 4;
    triple_des_key3 = "mitch";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des_ede, ktask, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(triple_des_ede, ktask, "jimi", 4, kKryptosECB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TRIPLE-DES EDE CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des_ede, ktask, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(triple_des_ede, ktask, "jimi", 4, kKryptosCBC,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TRIPLE-DES EDE OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des_ede, ktask, "jimi", 4, kKryptosOFB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(triple_des_ede, ktask, "jimi", 4, kKryptosOFB,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TRIPLE-DES EDE CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des_ede, ktask, "jimi", 4, kKryptosCTR,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(triple_des_ede, ktask, "jimi", 4, kKryptosCTR,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TRIPLE-DES EDE GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    triple_des_key2 = "buddy";
    triple_des_key2_size = 5;
    triple_des_key3 = "billy";
    triple_des_key3_size = 5;
    kryptos_run_cipher(triple_des_ede, ktask, "jimi", 4, kKryptosGCM,
                       triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tea_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // TEA ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(tea, ktask, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(tea, ktask, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TEA CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(tea, ktask, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(tea, ktask, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TEA OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(tea, ktask, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(tea, ktask, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TEA CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(tea, ktask, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(tea, ktask, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TEA GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(tea, ktask, "tea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosGCM);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_xtea_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    int xtea_rounds = 48;

    kryptos_task_init_as_null(ktask);

    // XTEA ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(xtea, ktask, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosECB, &xtea_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(xtea, ktask, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosECB, &xtea_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // XTEA CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(xtea, ktask, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCBC, &xtea_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(xtea, ktask, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCBC, &xtea_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // XTEA OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(xtea, ktask, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosOFB, &xtea_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(xtea, ktask, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosOFB, &xtea_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // XTEA CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(xtea, ktask, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCTR, &xtea_rounds);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(xtea, ktask, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosCTR, &xtea_rounds);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // XTEA GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(xtea, ktask, "xtea\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16, kKryptosGCM, &xtea_rounds);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_misty1_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // MISTY1 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(misty1, ktask, "misty1", 6, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(misty1, ktask, "misty1", 6, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // MISTY1 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(misty1, ktask, "misty1", 6, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(misty1, ktask, "misty1", 6, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MISTY1 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(misty1, ktask, "misty1", 6, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(misty1, ktask, "misty1", 6, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MISTY1 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(misty1, ktask, "misty1", 6, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(misty1, ktask, "misty1", 6, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MISTY1 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(misty1, ktask, "misty1", 6, kKryptosGCM);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars128_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // MARS-128 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars128, ktask, "mars128", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars128, ktask, "mars128", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // MARS-128 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars128, ktask, "mars128", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars128, ktask, "mars128", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-128 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars128, ktask, "mars128", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars128, ktask, "mars128", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-128 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars128, ktask, "mars128", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars128, ktask, "mars128", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-128 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars128, ktask, "mars128", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars128, ktask, "mars128", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars192_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // MARS-192 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars192, ktask, "mars192", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars192, ktask, "mars192", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // MARS-192 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars192, ktask, "mars192", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars192, ktask, "mars192", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-192 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars192, ktask, "mars192", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars192, ktask, "mars192", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-192 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars192, ktask, "mars192", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars192, ktask, "mars192", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-192 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars192, ktask, "mars192", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars192, ktask, "mars192", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_mars256_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // MARS-256 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars256, ktask, "mars256", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars256, ktask, "mars256", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // MARS-256 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars256, ktask, "mars256", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars256, ktask, "mars256", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-256 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars256, ktask, "mars256", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars256, ktask, "mars256", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-256 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars256, ktask, "mars256", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars256, ktask, "mars256", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // MARS-256 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(mars256, ktask, "mars256", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(mars256, ktask, "mars256", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present80_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // PRESENT-80 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(present80, ktask, "present80", 9, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(present80, ktask, "present80", 9, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // PRESENT-80 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(present80, ktask, "present80", 9, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(present80, ktask, "present80", 9, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // PRESENT-80 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(present80, ktask, "present80", 9, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(present80, ktask, "present80", 9, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // PRESENT-80 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(present80, ktask, "present80", 9, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(present80, ktask, "present80", 9, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // PRESENT-80 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(present80, ktask, "present80", 9, kKryptosGCM);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_present128_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // PRESENT-128 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(present128, ktask, "present128", 10, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(present128, ktask, "present128", 10, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // PRESENT-128 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(present128, ktask, "present128", 10, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(present128, ktask, "present128", 10, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // PRESENT-128 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(present128, ktask, "present128", 10, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(present128, ktask, "present128", 10, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // PRESENT-128 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(present128, ktask, "present128", 10, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(present128, ktask, "present128", 10, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // PRESENT-128 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(present128, ktask, "present128", 10, kKryptosGCM);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal1_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // SHACAL-1 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(shacal1, ktask, "shacal1", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(shacal1, ktask, "shacal1", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SHACAL-1 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(shacal1, ktask, "shacal1", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(shacal1, ktask, "shacal1", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SHACAL-1 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(shacal1, ktask, "shacal1", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(shacal1, ktask, "shacal1", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SHACAL-1 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(shacal1, ktask, "shacal1", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(shacal1, ktask, "shacal1", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SHACAL-1 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(shacal1, ktask, "shacal1", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_shacal2_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // SHACAL-2 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(shacal2, ktask, "shacal2", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(shacal2, ktask, "shacal2", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // SHACAL-2 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(shacal2, ktask, "shacal2", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(shacal2, ktask, "shacal2", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SHACAL-2 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(shacal2, ktask, "shacal2", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(shacal2, ktask, "shacal2", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SHACAL-2 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(shacal2, ktask, "shacal2", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(shacal2, ktask, "shacal2", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // SHACAL-2 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(shacal2, ktask, "shacal2", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // NOEKEON ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(noekeon, ktask, "noekeon", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(noekeon, ktask, "noekeon", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // NOEKEON CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(noekeon, ktask, "noekeon", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(noekeon, ktask, "noekeon", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // NOEKEON OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(noekeon, ktask, "noekeon", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(noekeon, ktask, "noekeon", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // NOEKEON CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(noekeon, ktask, "noekeon", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(noekeon, ktask, "noekeon", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // NOEKEON GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(noekeon, ktask, "noekeon", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(noekeon, ktask, "noekeon", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_noekeon_d_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // NOEKEON DIRECT ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(noekeon_d, ktask, "noekeon_d", 9, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(noekeon_d, ktask, "noekeon_d", 9, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // NOEKEON DIRECT CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(noekeon_d, ktask, "noekeon_d", 9, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(noekeon_d, ktask, "noekeon_d", 9, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // NOEKEON DIRECT OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(noekeon_d, ktask, "noekeon_d", 9, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(noekeon_d, ktask, "noekeon_d", 9, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // NOEKEON DIRECT CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(noekeon_d, ktask, "noekeon_d", 9, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(noekeon_d, ktask, "noekeon_d", 9, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // NOEKEON DIRECT GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(noekeon_d, ktask, "noekeon_d", 9, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(noekeon_d, ktask, "noekeon_d", 9, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_ds_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // GOST-DS ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(gost_ds, ktask, "gost-ds", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(gost_ds, ktask, "gost-ds", 7, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // GOST-DS CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(gost_ds, ktask, "gost-ds", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(gost_ds, ktask, "gost-ds", 7, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // GOST-DS OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(gost_ds, ktask, "gost-ds", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(gost_ds, ktask, "gost-ds", 7, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // GOST-DS CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(gost_ds, ktask, "gost-ds", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(gost_ds, ktask, "gost-ds", 7, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // GOST-DS GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(gost_ds, ktask, "gost-ds", 7, kKryptosGCM);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gost_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t s1[16] = {
         4, 10,  9,  2, 13,  8,  0, 14,  6, 11,  1, 12,  7, 15,  5,  3
    };
    kryptos_u8_t s2[16] = {
        14, 11,  4, 12,  6, 13, 15, 10,  2,  3,  8,  1,  0,  7,  5,  9
    };
    kryptos_u8_t s3[16] = {
        5,  8,  1, 13, 10,  3,  4,  2, 14, 15, 12,  7,  6,  0,  9, 11
    };
    kryptos_u8_t s4[16] = {
        7, 13, 10,  1,  0,  8,  9, 15, 14,  4,  6, 12, 11,  2,  5,  3
    };
    kryptos_u8_t s5[16] = {
        6, 12,  7,  1,  5, 15, 13,  8,  4, 10,  9, 14,  0,  3, 11,  2
    };
    kryptos_u8_t s6[16] = {
        4, 11, 10,  0,  7,  2,  1, 13,  3,  6,  8,  5,  9, 12, 15, 14
    };
    kryptos_u8_t s7[16] = {
        13, 11,  4,  1,  3, 15,  5,  9,  0, 10, 14,  7,  6,  8,  2, 12
    };
    kryptos_u8_t s8[16] = {
         1, 15, 13,  0,  5,  7, 10,  4,  9,  2,  3, 14,  6, 11,  8, 12
    };

    kryptos_task_init_as_null(ktask);

    // GOST ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(gost, ktask, "gost", 4, kKryptosECB, s1, s2, s3, s4, s5, s6, s7, s8);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(gost, ktask, "gost", 4, kKryptosECB, s1, s2, s3, s4, s5, s6, s7, s8);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // GOST CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(gost, ktask, "gost", 4, kKryptosCBC, s1, s2, s3, s4, s5, s6, s7, s8);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(gost, ktask, "gost", 4, kKryptosCBC, s1, s2, s3, s4, s5, s6, s7, s8);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // GOST OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(gost, ktask, "gost", 4, kKryptosOFB, s1, s2, s3, s4, s5, s6, s7, s8);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(gost, ktask, "gost", 4, kKryptosOFB, s1, s2, s3, s4, s5, s6, s7, s8);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // GOST CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(gost, ktask, "gost", 4, kKryptosCTR, s1, s2, s3, s4, s5, s6, s7, s8);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(gost, ktask, "gost", 4, kKryptosCTR, s1, s2, s3, s4, s5, s6, s7, s8);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // GOST GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(gost, ktask, "gost", 4, kKryptosGCM, s1, s2, s3, s4, s5, s6, s7, s8);

    CUTE_ASSERT(ktask->out == NULL);
    CUTE_ASSERT(ktask->result == kKryptosNoSupport);

    kryptos_task_free(ktask, KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_twofish128_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // TWOFISH-128 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish128, ktask, "twofish128", 10, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish128, ktask, "twofish128", 10, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TWOFISH-128 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish128, ktask, "twofish128", 10, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish128, ktask, "twofish128", 10, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TWOFISH-128 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish128, ktask, "twofish128", 10, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish128, ktask, "twofish128", 10, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TWOFISH-128 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish128, ktask, "twofish128", 10, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish128, ktask, "twofish128", 10, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TWOFISH-128 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish128, ktask, "twofish128", 10, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish128, ktask, "twofish128", 10, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_twofish192_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // TWOFISH-192 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish192, ktask, "twofish192", 10, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish192, ktask, "twofish192", 10, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TWOFISH-192 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish192, ktask, "twofish192", 10, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish192, ktask, "twofish192", 10, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TWOFISH-192 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish192, ktask, "twofish192", 10, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish192, ktask, "twofish192", 10, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TWOFISH-192 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish192, ktask, "twofish192", 10, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish192, ktask, "twofish192", 10, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TWOFISH-192 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish192, ktask, "twofish192", 10, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish192, ktask, "twofish192", 10, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_twofish256_dsl_tests)
    kryptos_task_ctx t, *ktask = &t;

    kryptos_task_init_as_null(ktask);

    // TWOFISH-256 ECB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish256, ktask, "twofish256", 10, kKryptosECB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish256, ktask, "twofish256", 10, kKryptosECB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);

    // TWOFISH-256 CBC

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish256, ktask, "twofish256", 10, kKryptosCBC);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish256, ktask, "twofish256", 10, kKryptosCBC);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TWOFISH-256 OFB

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish256, ktask, "twofish256", 10, kKryptosOFB);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish256, ktask, "twofish256", 10, kKryptosOFB);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TWOFISH-256 CTR

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish256, ktask, "twofish256", 10, kKryptosCTR);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish256, ktask, "twofish256", 10, kKryptosCTR);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);

    // TWOFISH-256 GCM

    kryptos_task_set_in(ktask, dsl_tests_data, dsl_tests_data_size);
    kryptos_task_set_encrypt_action(ktask);

    kryptos_run_cipher(twofish256, ktask, "twofish256", 10, kKryptosGCM);

    CUTE_ASSERT(ktask->out != NULL);

    kryptos_task_set_in(ktask, ktask->out, ktask->out_size);
    kryptos_task_set_decrypt_action(ktask);

    kryptos_run_cipher(twofish256, ktask, "twofish256", 10, kKryptosGCM);

    CUTE_ASSERT(ktask->out_size == dsl_tests_data_size);
    CUTE_ASSERT(memcmp(ktask->out, dsl_tests_data, ktask->out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);
CUTE_TEST_CASE_END

#endif
