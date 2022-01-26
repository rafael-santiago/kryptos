/*
 *                                Copyright (C) 2022 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <siphash_tests.h>
#include <kryptos.h>

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_SIPHASH_TESTS)
# define kryptos_run_siphash_tests(t, plaintext, plaintext_size, cname, c, d, ...) {\
    /*INFO(Rafael): Normal flow, no authentication error.*/\
    kryptos_task_init_as_null(&t);\
    kryptos_task_set_in(&t, plaintext, plaintext_size);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_run_cipher_siphash(cname, c, d, &t, __VA_ARGS__);\
    KUTE_ASSERT(t.result == kKryptosSuccess);\
    KUTE_ASSERT(t.out != NULL);\
    KUTE_ASSERT(t.out_size > plaintext_size);\
    kryptos_task_set_in(&t, t.out, t.out_size);\
    t.out = NULL;\
    t.out_size = 0;\
    kryptos_task_set_decrypt_action(&t);\
    kryptos_run_cipher_siphash(cname, c, d, &t, __VA_ARGS__);\
    KUTE_ASSERT(t.result == kKryptosSuccess);\
    KUTE_ASSERT(t.out != NULL);\
    KUTE_ASSERT(t.out_size == plaintext_size);\
    KUTE_ASSERT(memcmp(t.out, plaintext, t.out_size) == 0);\
    if (strcmp(#cname, "salsa20") != 0 && strcmp(#cname, "chacha20") != 0) {\
        kryptos_task_free(&t, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    } else {\
        kryptos_task_free(&t, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    }\
    /*INFO(Rafael): Corrupted message flow.*/\
    kryptos_task_init_as_null(&t);\
    kryptos_task_set_in(&t, plaintext, plaintext_size);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_run_cipher_siphash(cname, c, d, &t, __VA_ARGS__);\
    KUTE_ASSERT(t.result == kKryptosSuccess);\
    KUTE_ASSERT(t.out != NULL);\
    KUTE_ASSERT(t.out_size > plaintext_size);\
    kryptos_task_set_in(&t, t.out, t.out_size);\
    t.out[t.out_size >> 1] += 1;\
    t.out = NULL;\
    t.out_size = 0;\
    kryptos_task_set_decrypt_action(&t);\
    kryptos_run_cipher_siphash(cname, c, d, &t, __VA_ARGS__);\
    KUTE_ASSERT(t.result == kKryptosSipHashError);\
    KUTE_ASSERT(strcmp(t.result_verbose, "Corrupted data.") == 0);\
    if (strcmp(#cname, "salsa20") != 0 && strcmp(#cname, "chacha20") != 0) {\
        kryptos_task_free(&t, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    } else {\
        kryptos_task_free(&t, KRYPTOS_TASK_IN);\
    }\
}

KUTE_DECLARE_TEST_CASE(kryptos_arc4_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_seal_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rabbit_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_salsa20_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_chacha20_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_des_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_idea_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_blowfish_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_feal_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rc2_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rc5_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rc6_128_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rc6_192_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rc6_256_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_camellia128_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_camellia192_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_camellia256_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_cast5_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_saferk64_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_aes128_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_aes192_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_aes256_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_serpent_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_triple_des_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_triple_des_ede_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_tea_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_xtea_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_misty1_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_mars128_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_mars192_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_mars256_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_present80_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_present128_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_shacal1_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_shacal2_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_noekeon_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_noekeon_d_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_gost_ds_siphash_tests);
KUTE_DECLARE_TEST_CASE(kryptos_gost_siphash_tests);
#endif // defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_SIPHASH_TESTS)

KUTE_TEST_CASE(kryptos_siphash_tests)
#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_SIPHASH_TESTS)
    KUTE_RUN_TEST(kryptos_arc4_siphash_tests);
    KUTE_RUN_TEST(kryptos_seal_siphash_tests);
    KUTE_RUN_TEST(kryptos_rabbit_siphash_tests);
    KUTE_RUN_TEST(kryptos_salsa20_siphash_tests);
    KUTE_RUN_TEST(kryptos_chacha20_siphash_tests);
    KUTE_RUN_TEST(kryptos_des_siphash_tests);
    KUTE_RUN_TEST(kryptos_idea_siphash_tests);
    KUTE_RUN_TEST(kryptos_blowfish_siphash_tests);
    KUTE_RUN_TEST(kryptos_feal_siphash_tests);
    KUTE_RUN_TEST(kryptos_rc2_siphash_tests);
    KUTE_RUN_TEST(kryptos_rc5_siphash_tests);
    KUTE_RUN_TEST(kryptos_rc6_128_siphash_tests);
    KUTE_RUN_TEST(kryptos_rc6_192_siphash_tests);
    KUTE_RUN_TEST(kryptos_rc6_256_siphash_tests);
    KUTE_RUN_TEST(kryptos_camellia128_siphash_tests);
    KUTE_RUN_TEST(kryptos_camellia192_siphash_tests);
    KUTE_RUN_TEST(kryptos_camellia256_siphash_tests);
    KUTE_RUN_TEST(kryptos_cast5_siphash_tests);
    KUTE_RUN_TEST(kryptos_saferk64_siphash_tests);
    KUTE_RUN_TEST(kryptos_aes128_siphash_tests);
    KUTE_RUN_TEST(kryptos_aes192_siphash_tests);
    KUTE_RUN_TEST(kryptos_aes256_siphash_tests);
    KUTE_RUN_TEST(kryptos_serpent_siphash_tests);
    KUTE_RUN_TEST(kryptos_triple_des_siphash_tests);
    KUTE_RUN_TEST(kryptos_triple_des_ede_siphash_tests);
    KUTE_RUN_TEST(kryptos_tea_siphash_tests);
    KUTE_RUN_TEST(kryptos_xtea_siphash_tests);
    KUTE_RUN_TEST(kryptos_misty1_siphash_tests);
    KUTE_RUN_TEST(kryptos_mars128_siphash_tests);
    KUTE_RUN_TEST(kryptos_mars192_siphash_tests);
    KUTE_RUN_TEST(kryptos_mars256_siphash_tests);
    KUTE_RUN_TEST(kryptos_present80_siphash_tests);
    KUTE_RUN_TEST(kryptos_present128_siphash_tests);
    KUTE_RUN_TEST(kryptos_shacal1_siphash_tests);
    KUTE_RUN_TEST(kryptos_shacal2_siphash_tests);
    KUTE_RUN_TEST(kryptos_noekeon_siphash_tests);
    KUTE_RUN_TEST(kryptos_noekeon_d_siphash_tests);
    KUTE_RUN_TEST(kryptos_gost_ds_siphash_tests);
    KUTE_RUN_TEST(kryptos_gost_siphash_tests);
#else
# if !defined(KRYPTOS_NO_SIPHASH_TESTS)
#  if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf("WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
#  elif defined(__linux__)
    printk(KERN_INFO "WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
#endif
# else
#  if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf("WARN: You have requested build this binary without the SipHash tests.\n");
#  elsif defined(__linux__)
    printk(KERN_INFO "WARN: You have requested build this binary without the SipHash tests.\n");
#  endif
# endif // !defined(KRYPTOS_NO_SIPHASH_TESTS)
#endif // defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_SIPHASH_TESTS)
KUTE_TEST_CASE_END

#if !defined(KRYPTOS_NO_SIPHASH_TESTS)

KUTE_TEST_CASE(kryptos_arc4_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashArc4Test";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, arc4, 2, 4, key, key_size);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_seal_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashArc4Test";
    size_t key_size = strlen((char *)key);
    size_t seal_n = 0, seal_l = 1024;
    kryptos_seal_version_t seal_version = kKryptosSEAL20;

    kryptos_run_siphash_tests(t, plaintext, plaintext_size, seal, 2, 4, key, key_size, &seal_version, &seal_l, &seal_n);

    seal_n = 0;
    seal_l = 2048;
    seal_version = kKryptosSEAL30;

    kryptos_run_siphash_tests(t, plaintext, plaintext_size, seal, 2, 4, key, key_size, &seal_version, &seal_l, &seal_n);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rabbit_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"'Run Awaaaaay!'";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rabbit, 2, 4, key, key_size, NULL);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_salsa20_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashSalsa20Test..............";
    size_t key_size = strlen((char *)key);
    kryptos_u8_t *nonce = (kryptos_u8_t *)"........"; // nonce again... old story, same story, lame story....
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, salsa20, 2, 4, key, key_size, NULL);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, salsa20, 2, 4, key, key_size, nonce);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_chacha20_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashChaCha20Test.............";
    size_t key_size = strlen((char *)key);
    kryptos_u8_t *nonce = (kryptos_u8_t *)"............";
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, chacha20, 2, 4, key, key_size, NULL, NULL);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, chacha20, 2, 4, key, key_size, nonce, NULL);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_des_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashDESTest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, des, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, des, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, des, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, des, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_idea_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashIDEATest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, idea, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, idea, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, idea, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, idea, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_blowfish_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashBlowfishTest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, blowfish, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, blowfish, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, blowfish, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, blowfish, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_feal_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashFEALTest";
    size_t key_size = strlen((char *)key);
    int feal_rounds = 16;
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, feal, 2, 4, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, feal, 2, 4, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, feal, 2, 4, key, key_size, kKryptosOFB, &feal_rounds);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, feal, 2, 4, key, key_size, kKryptosCTR, &feal_rounds);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc2_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashRC2Test";
    size_t key_size = strlen((char *)key);
    int rc2_t1 = 128;
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc2, 2, 4, key, key_size, kKryptosECB, &rc2_t1);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc2, 2, 4, key, key_size, kKryptosCBC, &rc2_t1);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc2, 2, 4, key, key_size, kKryptosOFB, &rc2_t1);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc2, 2, 4, key, key_size, kKryptosCTR, &rc2_t1);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc5_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashRC5Test";
    size_t key_size = strlen((char *)key);
    int rc5_rounds_nr = 32;
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc5, 2, 4, key, key_size, kKryptosECB, &rc5_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc5, 2, 4, key, key_size, kKryptosCBC, &rc5_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc5, 2, 4, key, key_size, kKryptosOFB, &rc5_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc5, 2, 4, key, key_size, kKryptosCTR, &rc5_rounds_nr);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc6_128_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashRC6Test";
    size_t key_size = strlen((char *)key);
    int rc6_rounds_nr = 40;
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_128, 2, 4, key, key_size, kKryptosECB, &rc6_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_128, 2, 4, key, key_size, kKryptosCBC, &rc6_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_128, 2, 4, key, key_size, kKryptosOFB, &rc6_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_128, 2, 4, key, key_size, kKryptosCTR, &rc6_rounds_nr);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_128, 2, 4, key, key_size, kKryptosGCM, &rc6_rounds_nr);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc6_192_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashRC6Test";
    size_t key_size = strlen((char *)key);
    int rc6_rounds_nr = 40;
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_192, 2, 4, key, key_size, kKryptosECB, &rc6_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_192, 2, 4, key, key_size, kKryptosCBC, &rc6_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_192, 2, 4, key, key_size, kKryptosOFB, &rc6_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_192, 2, 4, key, key_size, kKryptosCTR, &rc6_rounds_nr);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_192, 2, 4, key, key_size, kKryptosGCM, &rc6_rounds_nr);

KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc6_256_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashRC6Test";
    size_t key_size = strlen((char *)key);
    int rc6_rounds_nr = 40;
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_256, 2, 4, key, key_size, kKryptosECB, &rc6_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_256, 2, 4, key, key_size, kKryptosCBC, &rc6_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_256, 2, 4, key, key_size, kKryptosOFB, &rc6_rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_256, 2, 4, key, key_size, kKryptosCTR, &rc6_rounds_nr);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, rc6_256, 2, 4, key, key_size, kKryptosGCM, &rc6_rounds_nr);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_camellia128_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashCamelliaTest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia128, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia128, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia128, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia128, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia128, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_camellia192_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashCamelliaTest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia192, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia192, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia192, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia192, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia192, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_camellia256_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashCamelliaTest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia256, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia256, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia256, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia256, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, camellia256, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_cast5_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashCast5Test";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, cast5, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, cast5, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, cast5, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, cast5, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_saferk64_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashSaferK64Test";
    size_t key_size = strlen((char *)key);
    int rounds_nr = 32;
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, saferk64, 2, 4, key, key_size, kKryptosECB, &rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, saferk64, 2, 4, key, key_size, kKryptosCBC, &rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, saferk64, 2, 4, key, key_size, kKryptosOFB, &rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, saferk64, 2, 4, key, key_size, kKryptosCTR, &rounds_nr);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_aes128_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashAESTest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes128, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes128, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes128, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes128, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes128, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_aes192_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashAESTest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes192, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes192, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes192, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes192, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes192, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_aes256_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashAESTest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes256, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes256, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes256, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes256, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, aes256, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_serpent_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashSerpentTest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, serpent, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, serpent, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, serpent, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, serpent, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, serpent, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_triple_des_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key[3] =  {
        (kryptos_u8_t *)"SipHash3DESTest_0",
        (kryptos_u8_t *)"SipHash3DESTest_1",
        (kryptos_u8_t *)"SipHash3DESTest_2",
    };
    size_t key_size[3] = {
        strlen((char *)key[0]),
        strlen((char *)key[1]),
        strlen((char *)key[2])
    };
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, triple_des, 2, 4,
                              key[0], key_size[0], kKryptosECB, key[1], &key_size[1], key[2], &key_size[2]);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, triple_des, 2, 4,
                              key[0], key_size[0], kKryptosCBC, key[1], &key_size[1], key[2], &key_size[2]);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, triple_des, 2, 4,
                              key[0], key_size[0], kKryptosOFB, key[1], &key_size[1], key[2], &key_size[2]);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, triple_des, 2, 4,
                              key[0], key_size[0], kKryptosCTR, key[1], &key_size[1], key[2], &key_size[2]);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_triple_des_ede_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key[3] =  {
        (kryptos_u8_t *)"SipHash3DESTest_0",
        (kryptos_u8_t *)"SipHash3DESTest_1",
        (kryptos_u8_t *)"SipHash3DESTest_2",
    };
    size_t key_size[3] = {
        strlen((char *)key[0]),
        strlen((char *)key[1]),
        strlen((char *)key[2])
    };
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, triple_des_ede, 2, 4,
                              key[0], key_size[0], kKryptosECB, key[1], &key_size[1], key[2], &key_size[2]);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, triple_des_ede, 2, 4,
                              key[0], key_size[0], kKryptosCBC, key[1], &key_size[1], key[2], &key_size[2]);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, triple_des_ede, 2, 4,
                              key[0], key_size[0], kKryptosOFB, key[1], &key_size[1], key[2], &key_size[2]);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, triple_des_ede, 2, 4,
                              key[0], key_size[0], kKryptosCTR, key[1], &key_size[1], key[2], &key_size[2]);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_tea_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashTEATest..";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, tea, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, tea, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, tea, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, tea, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_xtea_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashXTEATest.";
    size_t key_size = strlen((char *)key);
    int rounds_nr = 48;
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, xtea, 2, 4, key, key_size, kKryptosECB, &rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, xtea, 2, 4, key, key_size, kKryptosCBC, &rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, xtea, 2, 4, key, key_size, kKryptosOFB, &rounds_nr);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, xtea, 2, 4, key, key_size, kKryptosCTR, &rounds_nr);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_misty1_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashMISTY1Test";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, misty1, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, misty1, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, misty1, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, misty1, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mars128_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashMARS128Test";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars128, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars128, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars128, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars128, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars128, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mars192_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashMARS192Test";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars192, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars192, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars192, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars192, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars192, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mars256_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashMARS256Test";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars256, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars256, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars256, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars256, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, mars256, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_present80_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashPRESENT80Test";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, present80, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, present80, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, present80, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, present80, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_present128_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashPRESENT128Test";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, present128, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, present128, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, present128, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, present128, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_shacal1_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashSHACAL-1Test";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, shacal1, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, shacal1, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, shacal1, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, shacal1, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_shacal2_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashSHACAL-2Test";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, shacal2, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, shacal2, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, shacal2, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, shacal2, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_noekeon_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashNoekeonTs";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, noekeon, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, noekeon, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, noekeon, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, noekeon, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, noekeon, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_noekeon_d_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashNoekeonDT";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, noekeon_d, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, noekeon_d, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, noekeon_d, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, noekeon_d, 2, 4, key, key_size, kKryptosCTR);
    // INFO(Rafael): An overkill but possible, let's test.
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, noekeon_d, 2, 4, key, key_size, kKryptosGCM);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_gost_ds_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashGost-DsTest";
    size_t key_size = strlen((char *)key);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, gost_ds, 2, 4, key, key_size, kKryptosECB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, gost_ds, 2, 4, key, key_size, kKryptosCBC);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, gost_ds, 2, 4, key, key_size, kKryptosOFB);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, gost_ds, 2, 4, key, key_size, kKryptosCTR);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_gost_siphash_tests)
    kryptos_u8_t *plaintext = (kryptos_u8_t *)"'The most important thing to do in your life "
                              "is not interfere with somebody else's life' "
                              "\n"
                              "'If you end up with a boring, miserable life "
                              "because you listened to your mom, your dad, "
                              "your teacher, your priest, or some guy on "
                              "television telling you how to do your shit, "
                              "then you deserve it.' (Frank Zappa)";
    size_t plaintext_size = strlen((char *)plaintext);
    kryptos_task_ctx t;
    kryptos_u8_t *key = (kryptos_u8_t *)"SipHashGostTest";
    size_t key_size = strlen((char *)key);
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
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, gost, 2, 4, key, key_size, kKryptosECB, s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, gost, 2, 4, key, key_size, kKryptosCBC, s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, gost, 2, 4, key, key_size, kKryptosOFB, s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_siphash_tests(t, plaintext, plaintext_size, gost, 2, 4, key, key_size, kKryptosCTR, s1, s2, s3, s4, s5, s6, s7, s8);
KUTE_TEST_CASE_END

#endif // !defined(KRYPTOS_NO_SIPHASH_TESTS)

KUTE_TEST_CASE(kryptos_siphash_basic_tests)
    struct test_ctx {
        const size_t c;
        const size_t d;
        const kryptos_u8_t *message;
        const size_t message_size;
        kryptos_u8_t *key;
        size_t key_size;
        const kryptos_u8_t *expected_sum;
        const size_t expected_sum_size;
    } test_vector[] = {
        {
            2,
            4,
            (kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E",
            15,
            (kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
            16,
            (kryptos_u8_t *)"\xA1\x29\xCA\x61\x49\xBE\x45\xE5",
            8
        }, // INFO(Rafael): Taken from the original paper 'SipHash: a fast short-input PRF' [Aumasson, Bernstein].
    }, *test = &test_vector[0], *test_end = test + sizeof(test_vector) / sizeof(test_vector[0]);
    kryptos_task_ctx t, *ktask = &t;

    while (test != test_end) {
        kryptos_task_init_as_null(ktask);

        // INFO(Rafael): Tagging.

        ktask->out = (kryptos_u8_t *)kryptos_newseg(test->message_size);
        KUTE_ASSERT(ktask->out != NULL);

        memcpy(ktask->out, test->message, test->message_size);
        ktask->out_size = test->message_size;

        ktask->key = test->key;
        ktask->key_size = test->key_size;

        kryptos_task_set_encrypt_action(ktask);

        kryptos_siphash(&ktask, test->c, test->d);
        KUTE_ASSERT(ktask->result == kKryptosSuccess);

        KUTE_ASSERT(ktask->out != NULL);
        KUTE_ASSERT(ktask->out_size == test->message_size + test->expected_sum_size);
        KUTE_ASSERT(memcmp(ktask->out, test->expected_sum, test->expected_sum_size) == 0);
        KUTE_ASSERT(memcmp(ktask->out + test->expected_sum_size, test->message, test->message_size) == 0);

        // INFO(Rafael): Verifying.

        ktask->in = ktask->out;
        ktask->in_size = ktask->out_size;
        ktask->out = NULL;
        ktask->out_size = 0;

        kryptos_task_set_decrypt_action(ktask);

        kryptos_siphash(&ktask, test->c, test->d);
        KUTE_ASSERT(ktask->result == kKryptosSuccess);

        kryptos_task_free(ktask, KRYPTOS_TASK_IN);

        kryptos_task_init_as_null(ktask);

        // INFO(Rafael): Bad message buffer.

        // INFO(Rafael): Tagging.

        ktask->out = (kryptos_u8_t *)kryptos_newseg(test->message_size);
        KUTE_ASSERT(ktask->out != NULL);

        memcpy(ktask->out, test->message, test->message_size);
        ktask->out_size = test->message_size;

        ktask->key = test->key;
        ktask->key_size = test->key_size;

        kryptos_task_set_encrypt_action(ktask);

        kryptos_siphash(&ktask, test->c, test->d);
        KUTE_ASSERT(ktask->result == kKryptosSuccess);

        KUTE_ASSERT(ktask->out != NULL);
        KUTE_ASSERT(ktask->out_size == test->message_size + test->expected_sum_size);
        KUTE_ASSERT(memcmp(ktask->out, test->expected_sum, test->expected_sum_size) == 0);
        KUTE_ASSERT(memcmp(ktask->out + test->expected_sum_size, test->message, test->message_size) == 0);

        // INFO(Rafael): Verifying (with message corruption).

        ktask->in = ktask->out;
        ktask->in_size = ktask->out_size;
        ktask->in[ktask->in_size >> 1] += 1;
        ktask->out = NULL;
        ktask->out_size = 0;

        kryptos_task_set_decrypt_action(ktask);

        kryptos_siphash(&ktask, test->c, test->d);
        KUTE_ASSERT(ktask->result == kKryptosSipHashError);
        KUTE_ASSERT(strcmp(ktask->result_verbose, "Corrupted data.") == 0);

        kryptos_task_free(ktask, KRYPTOS_TASK_IN);

        // INFO(Rafael): Bad key buffer.

        kryptos_task_init_as_null(ktask);

        // INFO(Rafael): Tagging.

        ktask->out = (kryptos_u8_t *)kryptos_newseg(test->message_size);
        KUTE_ASSERT(ktask->out != NULL);

        memcpy(ktask->out, test->message, test->message_size);
        ktask->out_size = test->message_size;

        ktask->key = test->key;
        ktask->key_size = test->key_size;

        kryptos_task_set_encrypt_action(ktask);

        kryptos_siphash(&ktask, test->c, test->d);
        KUTE_ASSERT(ktask->result == kKryptosSuccess);

        KUTE_ASSERT(ktask->out != NULL);
        KUTE_ASSERT(ktask->out_size == test->message_size + test->expected_sum_size);
        KUTE_ASSERT(memcmp(ktask->out + test->expected_sum_size, test->message, test->message_size) == 0);

        // INFO(Rafael): Verifying (with message corruption).

        ktask->in = ktask->out;
        ktask->in_size = ktask->out_size;
        ktask->out = NULL;
        ktask->out_size = 0;

        ktask->key = (kryptos_u8_t *)"'A good idea is an orphan without effective communication.'";
        ktask->key_size = strlen("'A good idea is an orphan without effective communication.'");

        kryptos_task_set_decrypt_action(ktask);

        kryptos_siphash(&ktask, test->c, test->d);
        KUTE_ASSERT(ktask->result == kKryptosSipHashError);
        KUTE_ASSERT(strcmp(ktask->result_verbose, "Corrupted data.") == 0);

        kryptos_task_free(ktask, KRYPTOS_TASK_IN);


        test++;
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_siphash_sum_tests)
    kryptos_u8_t *messages[] = {
        (kryptos_u8_t *)"Sob um governo que prende qualquer homem injustamente, "
                        "o unico lugar digno para um homem justo e tambem a prisao."
                        "Nas quais serao confinados e trancados longe do Estado, por um "
                        "ato do proprio Estado pois os que vao para a prisao ja antes "
                        "tinham se confinado nos seus principios.",
        (kryptos_u8_t *)"Se me dedico a outras metas e consideracoes, preciso ao menos "
                        "verificar se nao estou fazendo isso a custa de alguem em cujos ombros "
                        "esteja sentado. E preciso que eu saia de cima dele para que ele "
                        "tambem possa estar livre para fazer as suas consideracoes",
        (kryptos_u8_t *)"Toda a votacao e um tipo de jogo, tal como damas ou gamao, "
                        "com uma leve coloracao moral, onde se brinca com o certo e o errado "
                        "sobre questoes morais; e e claro que ha apostas nesse jogo. O carater "
                        "dos eleitores nao entra nas avaliacoes. Proclamo o meu voto - talvez - "
                        "de acordo com meu criterio moral; mas nao tenho um interesse vital "
                        "de que o certo saia vitorioso. Estou disposto a deixar essa decisao "
                        "para a maioria. O compromisso de votar, desta forma, nunca vai mais "
                        "longe do que as conveniencias. Nem mesmo o ato de votar pelo que e "
                        "certo implica fazer algo pelo certo. E apenas uma forma de expressar "
                        "publicamente o meu anemico desejo de que o certo venha a prevalecer. "
                        "Um homem sabio nao deixara o que e certo nas maos incertas do acaso "
                        "e nem esperara que a sua vitoria se de atraves da forca da maioria. "
                        "Ha escassa virtude nas acoes de massa dos homens.",
        (kryptos_u8_t *)"Se um homem e livre de pensamento, livre para fantasiar, livre de imaginacao, "
                        "de modo que aquilo que nunca e lhe parece ser na maior parte do tempo, governantes "
                        "ou reformadores insensatos nao sao capazes de lhe criar impedimentos fatais.",
    };
    size_t m, p;

    KUTE_ASSERT(kryptos_siphash_sum(NULL,
                                    15,
                                    (kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                                    16, 2, 4) == 0);

    KUTE_ASSERT(kryptos_siphash_sum((kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E",
                                    15,
                                    NULL,
                                    16, 2, 4) == 0);

    KUTE_ASSERT(kryptos_siphash_sum((kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E",
                                    15,
                                    (kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                                    0, 2, 4) == 0);

    KUTE_ASSERT(kryptos_siphash_sum((kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E",
                                    15,
                                    (kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                                    16, 0, 4) == 0);

    KUTE_ASSERT(kryptos_siphash_sum((kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E",
                                    15,
                                    (kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                                    16, 2, 0) == 0);

    KUTE_ASSERT(kryptos_siphash_sum((kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E",
                                    15,
                                    (kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                                    16, 2, 4) == 0xA129CA6149BE45E5);

    // INFO(Rafael): Hash "" would be uncommon but let's allow it. It seems cause no harm.

    KUTE_ASSERT(kryptos_siphash_sum(NULL,
                                    0,
                                    (kryptos_u8_t *)"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F",
                                    16, 2, 4) == 0x726FDB47DD0E0E31);

    // WARN(Rafael): MACs do not matter here, it only cannot explode, leak resources or cause undefined behaviors.
    for (p = 0; p < 10000; p++) {
        for (m = 0; m < sizeof(messages) / sizeof(messages[0]); m++) {
            kryptos_siphash_sum(messages[m], strlen((char *)messages[m]), (kryptos_u8_t *)"Thoreau", strlen("Thoreau"), 4, 8);
        }
    }
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_siphash_size_tests)
    KUTE_ASSERT(kryptos_siphash_size() == 8);
KUTE_TEST_CASE_END
