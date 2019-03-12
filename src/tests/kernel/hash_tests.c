/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include <hash_tests.h>
#include <kstring.h>
#include <kryptos.h>

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)

// INFO(Rafael): This is pretty crazy, because is uncommon execute this stuff in kernel mode, but if
//               the code is okay it should work.
//
//               But here we will use just one plaintext for each <hash;cipher> pair.
//

#define kryptos_run_hmac_tests(t, plaintext, plaintext_size, cname, hname, cipher_args...) {\
    kryptos_task_init_as_null(&t);\
    kryptos_task_set_in(&t, plaintext, plaintext_size);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_run_cipher_hmac(cname, hname, &t, cipher_args);\
    KUTE_ASSERT(t.in != NULL);\
    KUTE_ASSERT(t.out != NULL);\
    kryptos_task_set_in(&t, t.out, t.out_size);\
    kryptos_task_set_decrypt_action(&t);\
    kryptos_run_cipher_hmac(cname, hname, &t, cipher_args);\
    KUTE_ASSERT(t.in != NULL);\
    KUTE_ASSERT(t.out != NULL);\
    KUTE_ASSERT(t.out_size == plaintext_size);\
    KUTE_ASSERT(memcmp(t.out, plaintext, t.out_size) == 0);\
    if (t.mode == kKryptosECB) {\
        kryptos_task_free(&t, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN);\
    } else {\
        kryptos_task_free(&t, KRYPTOS_TASK_OUT | KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
    t.iv = NULL;\
    kryptos_task_set_in(&t, plaintext, plaintext_size);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_run_cipher_hmac(cname, hname, &t, cipher_args);\
    KUTE_ASSERT(t.in != NULL);\
    KUTE_ASSERT(t.out != NULL);\
    kryptos_task_set_in(&t, t.out, t.out_size);\
    t.in[t.in_size >> 1] = ~t.in[t.in_size >> 1];\
    kryptos_task_set_decrypt_action(&t);\
    kryptos_run_cipher_hmac(cname, hname, &t, cipher_args);\
    KUTE_ASSERT(kryptos_last_task_succeed(&t) == 0);\
    KUTE_ASSERT(t.result == kKryptosHMACError);\
    if (t.mode == kKryptosECB) {\
        kryptos_task_free(&t, KRYPTOS_TASK_IN);\
    } else {\
        kryptos_task_free(&t, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
    t.iv = NULL;\
    kryptos_task_set_in(&t, plaintext, plaintext_size);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_run_cipher_hmac(cname, hname, &t, cipher_args);\
    KUTE_ASSERT(t.in != NULL);\
    KUTE_ASSERT(t.out != NULL);\
    kryptos_task_set_in(&t, t.out, t.out_size);\
    t.in_size = kryptos_## hname ##_hash_size();\
    kryptos_task_set_decrypt_action(&t);\
    kryptos_run_cipher_hmac(cname, hname, &t, cipher_args);\
    KUTE_ASSERT(kryptos_last_task_succeed(&t) == 0);\
    KUTE_ASSERT(t.result == kKryptosHMACError);\
    if (t.mode == kKryptosECB) {\
        kryptos_task_free(&t, KRYPTOS_TASK_IN);\
    } else {\
        kryptos_task_free(&t, KRYPTOS_TASK_IN | KRYPTOS_TASK_IV);\
    }\
}

KUTE_DECLARE_TEST_CASE(kryptos_des_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_idea_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_blowfish_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_feal_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rc2_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rc5_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rc6_128_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rc6_192_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_rc6_256_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_camellia128_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_camellia192_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_camellia256_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_cast5_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_saferk64_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_aes128_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_aes192_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_aes256_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_serpent_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_triple_des_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_triple_des_ede_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_tea_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_xtea_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_misty1_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_mars128_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_mars192_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_mars256_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_present80_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_present128_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_shacal1_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_shacal2_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_noekeon_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_noekeon_d_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_gost_ds_hmac_tests);
KUTE_DECLARE_TEST_CASE(kryptos_gost_hmac_tests);

#endif

KUTE_TEST_CASE(kryptos_hmac_tests)
#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)
    KUTE_RUN_TEST(kryptos_des_hmac_tests);
    KUTE_RUN_TEST(kryptos_idea_hmac_tests);
    KUTE_RUN_TEST(kryptos_blowfish_hmac_tests);
    KUTE_RUN_TEST(kryptos_feal_hmac_tests);
    KUTE_RUN_TEST(kryptos_rc2_hmac_tests);
    KUTE_RUN_TEST(kryptos_rc5_hmac_tests);
    KUTE_RUN_TEST(kryptos_rc6_128_hmac_tests);
    KUTE_RUN_TEST(kryptos_rc6_192_hmac_tests);
    KUTE_RUN_TEST(kryptos_rc6_256_hmac_tests);
    KUTE_RUN_TEST(kryptos_camellia128_hmac_tests);
    KUTE_RUN_TEST(kryptos_camellia192_hmac_tests);
    KUTE_RUN_TEST(kryptos_camellia256_hmac_tests);
    KUTE_RUN_TEST(kryptos_cast5_hmac_tests);
    KUTE_RUN_TEST(kryptos_saferk64_hmac_tests);
    KUTE_RUN_TEST(kryptos_aes128_hmac_tests);
    KUTE_RUN_TEST(kryptos_aes192_hmac_tests);
    KUTE_RUN_TEST(kryptos_aes256_hmac_tests);
    KUTE_RUN_TEST(kryptos_serpent_hmac_tests);
    KUTE_RUN_TEST(kryptos_triple_des_hmac_tests);
    KUTE_RUN_TEST(kryptos_triple_des_ede_hmac_tests);
    KUTE_RUN_TEST(kryptos_tea_hmac_tests);
    KUTE_RUN_TEST(kryptos_xtea_hmac_tests);
    KUTE_RUN_TEST(kryptos_misty1_hmac_tests);
    KUTE_RUN_TEST(kryptos_mars128_hmac_tests);
    KUTE_RUN_TEST(kryptos_mars192_hmac_tests);
    KUTE_RUN_TEST(kryptos_mars256_hmac_tests);
    KUTE_RUN_TEST(kryptos_present80_hmac_tests);
    KUTE_RUN_TEST(kryptos_present128_hmac_tests);
    KUTE_RUN_TEST(kryptos_shacal1_hmac_tests);
    KUTE_RUN_TEST(kryptos_shacal2_hmac_tests);
    KUTE_RUN_TEST(kryptos_noekeon_hmac_tests);
    KUTE_RUN_TEST(kryptos_noekeon_d_hmac_tests);
    KUTE_RUN_TEST(kryptos_gost_ds_hmac_tests);
    KUTE_RUN_TEST(kryptos_gost_hmac_tests);
#else
# if !defined(KRYPTOS_NO_HMAC_TESTS)
    // TODO(Rafael): When there is no C99 support add a simple bare bone test with at least one block cipher and all
    //               available hash functions.
#  if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf("WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
#  elif defined(__linux__)
    printk(KERN_ERR "WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
#  endif
# else
#   if defined(__FreeBSD__) || defined(__NetBSD__)
    uprintf("WARN: You have requested build this binary without the HMAC tests.\n");
#   else
    printk(KERN_ERR "WARN: You have requested build this binary without the HMAC tests.\n");
#   endif
# endif // !defined(KRYPTOS_SKIP_HMAC_TESTS)
#endif // defined(KRYPTOS_C99) && !defined(KRYPTOS_SKIP_HMAC_TESTS)

KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_hash_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *message = "abc";
    size_t message_size = 3;
    kryptos_u8_t *raw_hash = NULL;

    kryptos_task_init_as_null(&t);

    t.in = message;
    t.in_size = message_size;

    // INFO(Rafael): SHA-1.

    KUTE_ASSERT(kryptos_sha1_hash_input_size() == 64);
    KUTE_ASSERT(kryptos_sha1_hash_size() == 20);
    kryptos_sha1_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_sha1_hash_size());
    raw_hash = "\xA9\x99\x3E\x36\x47\x06\x81\x6A\xBA\x3E\x25\x71\x78\x50\xC2\x6C\x9C\xD0\xD8\x9D";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(sha1, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): SHA-224.

    KUTE_ASSERT(kryptos_sha224_hash_input_size() == 64);
    KUTE_ASSERT(kryptos_sha224_hash_size() == 28);
    kryptos_sha224_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_sha224_hash_size());
    raw_hash = "\x23\x09\x7D\x22\x34\x05\xD8\x22\x86\x42\xA4\x77\xBD\xA2"
               "\x55\xB3\x2A\xAD\xBC\xE4\xBD\xA0\xB3\xF7\xE3\x6C\x9D\xA7";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(sha224, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): SHA-256.

    KUTE_ASSERT(kryptos_sha256_hash_input_size() == 64);
    KUTE_ASSERT(kryptos_sha256_hash_size() == 32);
    kryptos_sha256_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_sha256_hash_size());
    raw_hash = "\xBA\x78\x16\xBF\x8F\x01\xCF\xEA\x41\x41\x40\xDE\x5D\xAE\x22\x23"
               "\xB0\x03\x61\xA3\x96\x17\x7A\x9C\xB4\x10\xFF\x61\xF2\x00\x15\xAD";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(sha256, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): SHA-384.

    KUTE_ASSERT(kryptos_sha384_hash_input_size() == 128);
    KUTE_ASSERT(kryptos_sha384_hash_size() == 48);
    kryptos_sha384_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_sha384_hash_size());
    raw_hash = "\xCB\x00\x75\x3F\x45\xA3\x5E\x8B\xB5\xA0\x3D\x69\x9A\xC6\x50\x07"
               "\x27\x2C\x32\xAB\x0E\xDE\xD1\x63\x1A\x8B\x60\x5A\x43\xFF\x5B\xED"
               "\x80\x86\x07\x2B\xA1\xE7\xCC\x23\x58\xBA\xEC\xA1\x34\xC8\x25\xA7";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(sha384, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): SHA-512.

    KUTE_ASSERT(kryptos_sha512_hash_input_size() == 128);
    KUTE_ASSERT(kryptos_sha512_hash_size() == 64);
    kryptos_sha512_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_sha512_hash_size());
    raw_hash = "\xDD\xAF\x35\xA1\x93\x61\x7A\xBA\xCC\x41\x73\x49\xAE\x20\x41\x31"
               "\x12\xE6\xFA\x4E\x89\xA9\x7E\xA2\x0A\x9E\xEE\xE6\x4B\x55\xD3\x9A"
               "\x21\x92\x99\x2A\x27\x4F\xC1\xA8\x36\xBA\x3C\x23\xA3\xFE\xEB\xBD"
               "\x45\x4D\x44\x23\x64\x3C\xE8\x0E\x2A\x9A\xC9\x4F\xA5\x4C\xA4\x9F";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(sha512, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): SHA3-224.

    KUTE_ASSERT(kryptos_sha3_224_hash_input_size() == 144);
    KUTE_ASSERT(kryptos_sha3_224_hash_size() == 28);
    kryptos_sha3_224_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_sha3_224_hash_size());
    raw_hash = "\xE6\x42\x82\x4C\x3F\x8C\xF2\x4A\xD0\x92\x34\xEE\x7D\x3C"
               "\x76\x6F\xC9\xA3\xA5\x16\x8D\x0C\x94\xAD\x73\xB4\x6F\xDF";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(sha3_224, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): SHA3-256.

    KUTE_ASSERT(kryptos_sha3_256_hash_input_size() == 136);
    KUTE_ASSERT(kryptos_sha3_256_hash_size() == 32);
    kryptos_sha3_256_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_sha3_256_hash_size());
    raw_hash = "\x3A\x98\x5D\xA7\x4F\xE2\x25\xB2\x04\x5C\x17\x2D\x6B\xD3\x90\xBD"
               "\x85\x5F\x08\x6E\x3E\x9D\x52\x5B\x46\xBF\xE2\x45\x11\x43\x15\x32";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(sha3_256, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): SHA3-384.

    KUTE_ASSERT(kryptos_sha3_384_hash_input_size() == 104);
    KUTE_ASSERT(kryptos_sha3_384_hash_size() == 48);
    kryptos_sha3_384_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_sha3_384_hash_size());
    raw_hash = "\xEC\x01\x49\x82\x88\x51\x6F\xC9\x26\x45\x9F\x58\xE2\xC6\xAD\x8D"
               "\xF9\xB4\x73\xCB\x0F\xC0\x8C\x25\x96\xDA\x7C\xF0\xE4\x9B\xE4\xB2"
               "\x98\xD8\x8C\xEA\x92\x7A\xC7\xF5\x39\xF1\xED\xF2\x28\x37\x6D\x25";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(sha3_384, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): SHA3-512.

    KUTE_ASSERT(kryptos_sha3_512_hash_input_size() == 72);
    KUTE_ASSERT(kryptos_sha3_512_hash_size() == 64);
    kryptos_sha3_512_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_sha3_512_hash_size());
    raw_hash = "\xB7\x51\x85\x0B\x1A\x57\x16\x8A\x56\x93\xCD\x92\x4B\x6B\x09\x6E\x08"
               "\xF6\x21\x82\x74\x44\xF7\x0D\x88\x4F\x5D\x02\x40\xD2\x71\x2E\x10\xE1"
               "\x16\xE9\x19\x2A\xF3\xC9\x1A\x7E\xC5\x76\x47\xE3\x93\x40\x57\x34\x0B"
               "\x4C\xF4\x08\xD5\xA5\x65\x92\xF8\x27\x4E\xEC\x53\xF0";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): KECCAK-224.

    KUTE_ASSERT(kryptos_keccak224_hash_input_size() == 144);
    KUTE_ASSERT(kryptos_keccak224_hash_size() == 28);
    kryptos_keccak224_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_keccak224_hash_size());
    raw_hash = "\xC3\x04\x11\x76\x85\x06\xEB\xE1\xC2\x87\x1B\x1E\xE2\xE8"
               "\x7D\x38\xDF\x34\x23\x17\x30\x0A\x9B\x97\xA9\x5E\xC6\xA8";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(keccak224, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): KECCAK-256.

    KUTE_ASSERT(kryptos_keccak256_hash_input_size() == 136);
    KUTE_ASSERT(kryptos_keccak256_hash_size() == 32);
    kryptos_keccak256_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_keccak256_hash_size());
    raw_hash = "\x4E\x03\x65\x7A\xEA\x45\xA9\x4F\xC7\xD4\x7B\xA8\x26\xC8\xD6\x67"
               "\xC0\xD1\xE6\xE3\x3A\x64\xA0\x36\xEC\x44\xF5\x8F\xA1\x2D\x6C\x45";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(keccak256, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): KECCAK-384.

    KUTE_ASSERT(kryptos_keccak384_hash_input_size() == 104);
    KUTE_ASSERT(kryptos_keccak384_hash_size() == 48);
    kryptos_keccak384_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_keccak384_hash_size());
    raw_hash = "\xF7\xDF\x11\x65\xF0\x33\x33\x7B\xE0\x98\xE7\xD2\x88\xAD\x6A\x2F"
               "\x74\x40\x9D\x7A\x60\xB4\x9C\x36\x64\x22\x18\xDE\x16\x1B\x1F\x99"
               "\xF8\xC6\x81\xE4\xAF\xAF\x31\xA3\x4D\xB2\x9F\xB7\x63\xE3\xC2\x8E";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(keccak384, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): KECCAK-512.

    KUTE_ASSERT(kryptos_keccak512_hash_input_size() == 72);
    KUTE_ASSERT(kryptos_keccak512_hash_size() == 64);
    kryptos_keccak512_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_keccak512_hash_size());
    raw_hash = "\x18\x58\x7D\xC2\xEA\x10\x6B\x9A\x15\x63\xE3\x2B\x33\x12\x42\x1C\xA1"
               "\x64\xC7\xF1\xF0\x7B\xC9\x22\xA9\xC8\x3D\x77\xCE\xA3\xA1\xE5\xD0\xC6"
               "\x99\x10\x73\x90\x25\x37\x2D\xC1\x4A\xC9\x64\x26\x29\x37\x95\x40\xC1"
               "\x7E\x2A\x65\xB1\x9D\x77\xAA\x51\x1A\x9D\x00\xBB\x96";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(keccak512, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): MD4.

    KUTE_ASSERT(kryptos_md4_hash_input_size() == 64);
    KUTE_ASSERT(kryptos_md4_hash_size() == 16);
    kryptos_md4_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_md4_hash_size());
    raw_hash = "\xA4\x48\x01\x7A\xAF\x21\xD8\x52\x5F\xC1\x0A\xE8\x7A\xA6\x72\x9D";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(md4, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): MD5.

    KUTE_ASSERT(kryptos_md5_hash_input_size() == 64);
    KUTE_ASSERT(kryptos_md5_hash_size() == 16);
    kryptos_md5_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_md5_hash_size());
    raw_hash = "\x90\x01\x50\x98\x3C\xD2\x4F\xB0\xD6\x96\x3F\x7D\x28\xE1\x7F\x72";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(md5, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): RIPEMD-128.

    KUTE_ASSERT(kryptos_ripemd128_hash_input_size() == 64);
    KUTE_ASSERT(kryptos_ripemd128_hash_size() == 16);
    kryptos_ripemd128_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_ripemd128_hash_size());
    raw_hash = "\xC1\x4A\x12\x19\x9C\x66\xE4\xBA\x84\x63\x6B\x0F\x69\x14\x4C\x77";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(ripemd128, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): RIPEMD-160.

    KUTE_ASSERT(kryptos_ripemd160_hash_input_size() == 64);
    KUTE_ASSERT(kryptos_ripemd160_hash_size() == 20);
    kryptos_ripemd160_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_ripemd160_hash_size());
    raw_hash = "\x8E\xB2\x08\xF7\xE0\x5D\x98\x7A\x9B\x04\x4A\x8E\x98\xC6\xB0\x87\xF1\x5A\x0B\xFC";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(ripemd160, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    // INFO(Rafael): TIGER.

    KUTE_ASSERT(kryptos_tiger_hash_input_size() == 64);
    KUTE_ASSERT(kryptos_tiger_hash_size() == 24);
    kryptos_tiger_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_tiger_hash_size());
    raw_hash = "\x2A\xAB\x14\x84\xE8\xC1\x58\xF2\xBF\xB8\xC5\xFF\x41\xB5\x7A\x52\x51\x29\x13\x1C\x95\x7B\x5F\x93";
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

    kryptos_hash(tiger, ktask, message, message_size, 0);
    KUTE_ASSERT(memcmp(t.out, raw_hash, t.out_size) == 0);
    kryptos_task_free(ktask, KRYPTOS_TASK_OUT);

KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_hmac_basic_tests)
    struct test_step {
        kryptos_hash_func h;
        kryptos_hash_size_func h_input_size;
        kryptos_hash_size_func h_size;
        kryptos_u8_t *key;
        size_t key_size;
        kryptos_u8_t *data;
        size_t data_size;
        kryptos_u8_t *expected;
        size_t expected_size;
    };
#define add_hmac_test_step(h, k, ks, d, ds, e, es)\
 { kryptos_ ## h ## _hash, kryptos_ ## h ## _hash_input_size, kryptos_ ## h ## _hash_size, k, ks, d, ds, e, es }
    // INFO(Rafael): Test vector from RFC-4231.
    struct test_step test_vector[] = {
        // INFO(Rafael): Test case 1.
        add_hmac_test_step(sha224,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                           "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
                           "\x89\x6f\xb1\x12\x8a\xbb\xdf\x19\x68\x32\x10\x7c\xd4\x9d"
                           "\xf3\x3f\x47\xb4\xb1\x16\x99\x12\xba\x4f\x53\x68\x4b\x22", 28),
        add_hmac_test_step(sha256,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                           "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
                           "\xb0\x34\x4c\x61\xd8\xdb\x38\x53\x5c\xa8\xaf\xce\xaf\x0b\xf1\x2b"
                           "\x88\x1d\xc2\x00\xc9\x83\x3d\xa7\x26\xe9\x37\x6c\x2e\x32\xcf\xf7", 32),
        add_hmac_test_step(sha384,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                           "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
                           "\xaf\xd0\x39\x44\xd8\x48\x95\x62\x6b\x08\x25\xf4\xab\x46\x90\x7f"
                           "\x15\xf9\xda\xdb\xe4\x10\x1e\xc6\x82\xaa\x03\x4c\x7c\xeb\xc5\x9c"
                           "\xfa\xea\x9e\xa9\x07\x6e\xde\x7f\x4a\xf1\x52\xe8\xb2\xfa\x9c\xb6", 48),
        add_hmac_test_step(sha512,
                           "\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b", 20,
                           "\x48\x69\x20\x54\x68\x65\x72\x65", 8,
                           "\x87\xaa\x7c\xde\xa5\xef\x61\x9d\x4f\xf0\xb4\x24\x1a\x1d\x6c\xb0"
                           "\x23\x79\xf4\xe2\xce\x4e\xc2\x78\x7a\xd0\xb3\x05\x45\xe1\x7c\xde"
                           "\xda\xa8\x33\xb7\xd6\xb8\xa7\x02\x03\x8b\x27\x4e\xae\xa3\xf4\xe4"
                           "\xbe\x9d\x91\x4e\xeb\x61\xf1\x70\x2e\x69\x6c\x20\x3a\x12\x68\x54", 64),
        // INFO(Rafael): Test case 2.
        add_hmac_test_step(sha224,
                           "\x4a\x65\x66\x65", 4,
                           "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e"
                           "\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
                           "\xa3\x0e\x01\x09\x8b\xc6\xdb\xbf\x45\x69\x0f\x3a\x7e\x9e"
                           "\x6d\x0f\x8b\xbe\xa2\xa3\x9e\x61\x48\x00\x8f\xd0\x5e\x44", 28),
        add_hmac_test_step(sha256,
                           "\x4a\x65\x66\x65", 4,
                           "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e"
                           "\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
                           "\x5b\xdc\xc1\x46\xbf\x60\x75\x4e\x6a\x04\x24\x26\x08\x95\x75\xc7"
                           "\x5a\x00\x3f\x08\x9d\x27\x39\x83\x9d\xec\x58\xb9\x64\xec\x38\x43", 32),
        add_hmac_test_step(sha384,
                           "\x4a\x65\x66\x65", 4,
                           "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e"
                           "\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
                           "\xaf\x45\xd2\xe3\x76\x48\x40\x31\x61\x7f\x78\xd2\xb5\x8a\x6b\x1b"
                           "\x9c\x7e\xf4\x64\xf5\xa0\x1b\x47\xe4\x2e\xc3\x73\x63\x22\x44\x5e"
                           "\x8e\x22\x40\xca\x5e\x69\xe2\xc7\x8b\x32\x39\xec\xfa\xb2\x16\x49", 48),
        add_hmac_test_step(sha512,
                           "\x4a\x65\x66\x65", 4,
                           "\x77\x68\x61\x74\x20\x64\x6f\x20\x79\x61\x20\x77\x61\x6e"
                           "\x74\x20\x66\x6f\x72\x20\x6e\x6f\x74\x68\x69\x6e\x67\x3f", 28,
                           "\x16\x4b\x7a\x7b\xfc\xf8\x19\xe2\xe3\x95\xfb\xe7\x3b\x56\xe0\xa3"
                           "\x87\xbd\x64\x22\x2e\x83\x1f\xd6\x10\x27\x0c\xd7\xea\x25\x05\x54"
                           "\x97\x58\xbf\x75\xc0\x5a\x99\x4a\x6d\x03\x4f\x65\xf8\xf0\xe6\xfd"
                           "\xca\xea\xb1\xa3\x4d\x4a\x6b\x4b\x63\x6e\x07\x0a\x38\xbc\xe7\x37", 64),
        // INFO(Rafael): Test case 3.
        add_hmac_test_step(sha224,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd", 50,
                           "\x7f\xb3\xcb\x35\x88\xc6\xc1\xf6\xff\xa9\x69\x4d\x7d\x6a"
                           "\xd2\x64\x93\x65\xb0\xc1\xf6\x5d\x69\xd1\xec\x83\x33\xea", 28),
        add_hmac_test_step(sha256,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd", 50,
                           "\x77\x3e\xa9\x1e\x36\x80\x0e\x46\x85\x4d\xb8\xeb\xd0\x91\x81\xa7"
                           "\x29\x59\x09\x8b\x3e\xf8\xc1\x22\xd9\x63\x55\x14\xce\xd5\x65\xfe", 32),
        add_hmac_test_step(sha384,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd", 50,
                           "\x88\x06\x26\x08\xd3\xe6\xad\x8a\x0a\xa2\xac\xe0\x14\xc8\xa8\x6f"
                           "\x0a\xa6\x35\xd9\x47\xac\x9f\xeb\xe8\x3e\xf4\xe5\x59\x66\x14\x4b"
                           "\x2a\x5a\xb3\x9d\xc1\x38\x14\xb9\x4e\x3a\xb6\xe1\x01\xa3\x4f\x27", 48),
        add_hmac_test_step(sha512,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa", 20,
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd"
                           "\xdd\xdd", 50,
                           "\xfa\x73\xb0\x08\x9d\x56\xa2\x84\xef\xb0\xf0\x75\x6c\x89\x0b\xe9"
                           "\xb1\xb5\xdb\xdd\x8e\xe8\x1a\x36\x55\xf8\x3e\x33\xb2\x27\x9d\x39"
                           "\xbf\x3e\x84\x82\x79\xa7\x22\xc8\x06\xb4\x85\xa4\x7e\x67\xc8\x07"
                           "\xb9\x46\xa3\x37\xbe\xe8\x94\x26\x74\x27\x88\x59\xe1\x32\x92\xfb", 64),
        // INFO(Rafael): Test case 4.
        add_hmac_test_step(sha224,
                           "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                           "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd", 50,
                           "\x6c\x11\x50\x68\x74\x01\x3c\xac\x6a\x2a\xbc\x1b\xb3\x82"
                           "\x62\x7c\xec\x6a\x90\xd8\x6e\xfc\x01\x2d\xe7\xaf\xec\x5a", 28),
        add_hmac_test_step(sha256,
                           "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                           "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd", 50,
                           "\x82\x55\x8a\x38\x9a\x44\x3c\x0e\xa4\xcc\x81\x98\x99\xf2\x08\x3a"
                           "\x85\xf0\xfa\xa3\xe5\x78\xf8\x07\x7a\x2e\x3f\xf4\x67\x29\x66\x5b", 32),
        add_hmac_test_step(sha384,
                           "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                           "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd", 50,
                           "\x3e\x8a\x69\xb7\x78\x3c\x25\x85\x19\x33\xab\x62\x90\xaf\x6c\xa7"
                           "\x7a\x99\x81\x48\x08\x50\x00\x9c\xc5\x57\x7c\x6e\x1f\x57\x3b\x4e"
                           "\x68\x01\xdd\x23\xc4\xa7\xd6\x79\xcc\xf8\xa3\x86\xc6\x74\xcf\xfb", 48),
        add_hmac_test_step(sha512,
                           "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
                           "\x11\x12\x13\x14\x15\x16\x17\x18\x19", 25,
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd"
                           "\xcd\xcd", 50,
                           "\xb0\xba\x46\x56\x37\x45\x8c\x69\x90\xe5\xa8\xc5\xf6\x1d\x4a\xf7"
                           "\xe5\x76\xd9\x7f\xf9\x4b\x87\x2d\xe7\x6f\x80\x50\x36\x1e\xe3\xdb"
                           "\xa9\x1c\xa5\xc1\x1a\xa2\x5e\xb4\xd6\x79\x27\x5c\xc5\x78\x80\x63"
                           "\xa5\xf1\x97\x41\x12\x0c\x4f\x2d\xe2\xad\xeb\xeb\x10\xa2\x98\xdd", 64),
        // INFO(Rafael): Test case 6.
        add_hmac_test_step(sha224,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa", 131,
                           "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65"
                           "\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a"
                           "\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79"
                           "\x20\x46\x69\x72\x73\x74", 54,
                           "\x95\xe9\xa0\xdb\x96\x20\x95\xad\xae\xbe\x9b\x2d\x6f\x0d"
                           "\xbc\xe2\xd4\x99\xf1\x12\xf2\xd2\xb7\x27\x3f\xa6\x87\x0e", 28),
        add_hmac_test_step(sha256,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa", 131,
                           "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65"
                           "\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a"
                           "\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79"
                           "\x20\x46\x69\x72\x73\x74", 54,
                           "\x60\xe4\x31\x59\x1e\xe0\xb6\x7f\x0d\x8a\x26\xaa\xcb\xf5\xb7\x7f"
                           "\x8e\x0b\xc6\x21\x37\x28\xc5\x14\x05\x46\x04\x0f\x0e\xe3\x7f\x54", 32),
        add_hmac_test_step(sha384,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa", 131,
                           "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65"
                           "\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a"
                           "\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79"
                           "\x20\x46\x69\x72\x73\x74", 54,
                           "\x4e\xce\x08\x44\x85\x81\x3e\x90\x88\xd2\xc6\x3a\x04\x1b\xc5\xb4"
                           "\x4f\x9e\xf1\x01\x2a\x2b\x58\x8f\x3c\xd1\x1f\x05\x03\x3a\xc4\xc6"
                           "\x0c\x2e\xf6\xab\x40\x30\xfe\x82\x96\x24\x8d\xf1\x63\xf4\x49\x52", 48),
        add_hmac_test_step(sha512,
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
                           "\xaa\xaa\xaa", 131,
                           "\x54\x65\x73\x74\x20\x55\x73\x69\x6e\x67\x20\x4c\x61\x72\x67\x65"
                           "\x72\x20\x54\x68\x61\x6e\x20\x42\x6c\x6f\x63\x6b\x2d\x53\x69\x7a"
                           "\x65\x20\x4b\x65\x79\x20\x2d\x20\x48\x61\x73\x68\x20\x4b\x65\x79"
                           "\x20\x46\x69\x72\x73\x74", 54,
                           "\x80\xb2\x42\x63\xc7\xc1\xa3\xeb\xb7\x14\x93\xc1\xdd\x7b\xe8\xb4"
                           "\x9b\x46\xd1\xf4\x1b\x4a\xee\xc1\x12\x1b\x01\x37\x83\xf8\xf3\x52"
                           "\x6b\x56\xd0\x37\xe0\x5f\x25\x98\xbd\x0f\xd2\x21\x5d\x6a\x1e\x52"
                           "\x95\xe6\x4f\x73\xf6\x3f\x0a\xec\x8b\x91\x5a\x98\x5d\x78\x65\x98", 64)
    };
    size_t test_vector_nr = sizeof(test_vector) / sizeof(test_vector[0]), t;
    kryptos_task_ctx task, *ktask = &task;

    for (t = 0; t < test_vector_nr; t++) {
        kryptos_task_init_as_null(ktask);
        ktask->action = kKryptosEncrypt;
        ktask->key = test_vector[t].key;
        ktask->key_size = test_vector[t].key_size;
        ktask->out_size = test_vector[t].data_size;
        ktask->out = (kryptos_u8_t *) kryptos_newseg(ktask->out_size);
        KUTE_ASSERT(ktask->out != NULL);
        memcpy(ktask->out, test_vector[t].data, ktask->out_size);
        kryptos_hmac(&ktask, test_vector[t].h, test_vector[t].h_input_size, test_vector[t].h_size);
        KUTE_ASSERT(kryptos_last_task_succeed(ktask) == 1);
        KUTE_ASSERT(ktask->out_size == test_vector[t].expected_size + test_vector[t].data_size);
        // INFO(Rafael): The implementation of HMAC in kryptos during its evaluation phase concats the hash out with the data.
        KUTE_ASSERT(memcmp(ktask->out, test_vector[t].expected, test_vector[t].expected_size) == 0);
        KUTE_ASSERT(memcmp(ktask->out + test_vector[t].expected_size, test_vector[t].data, test_vector[t].data_size) == 0);
        kryptos_task_free(ktask, KRYPTOS_TASK_OUT);
    }

#undef add_hmac_test_step
KUTE_TEST_CASE_END

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)

KUTE_TEST_CASE(kryptos_des_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                          "Friends and colleagues come to me,\n"
                          "Speaking words of wisdom:\n"
                          "Write in C.\n\n"
                          " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): DES/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): DES/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_idea_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): IDEA/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): IDEA/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, idea, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_blowfish_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): BLOWFISH/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): BLOWFISH/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, blowfish, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_feal_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    int feal_rounds = 8;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): FEAL/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha1, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha3_224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha3_256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha3_384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha3_512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, keccak224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, keccak256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, keccak384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, keccak512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, md4, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, md5, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, ripemd128, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, ripemd160, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, tiger, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, whirlpool, key, key_size, kKryptosECB, &feal_rounds);

    // INFO(Rafael): FEAL/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha1, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha3_224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha3_256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha3_384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, sha3_512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, keccak224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, keccak256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, keccak384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, keccak512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, md4, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, md5, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, ripemd128, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, ripemd160, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, tiger, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, feal, whirlpool, key, key_size, kKryptosCBC, &feal_rounds);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc2_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    int rc2_T1 = 64;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): RC2/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha1, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha3_224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha3_256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha3_384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha3_512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, keccak224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, keccak256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, keccak384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, keccak512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, md4, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, md5, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, ripemd128, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, ripemd160, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, tiger, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, whirlpool, key, key_size, kKryptosECB, &rc2_T1);

    // INFO(Rafael): RC2/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha1, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha3_224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha3_256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha3_384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, sha3_512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, keccak224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, keccak256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, keccak384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, keccak512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, md4, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, md5, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, ripemd128, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, ripemd160, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, tiger, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc2, whirlpool, key, key_size, kKryptosCBC, &rc2_T1);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc5_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    int rc5_rounds = 20;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): RC5/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha1, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha224, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha256, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha384, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha512, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha3_224, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha3_256, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha3_384, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha3_512, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, keccak224, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, keccak256, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, keccak384, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, keccak512, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, md4, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, md5, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, ripemd128, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, ripemd160, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, tiger, key, key_size, kKryptosECB, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, whirlpool, key, key_size, kKryptosECB, &rc5_rounds);

    // INFO(Rafael): RC5/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha1, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha224, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha256, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha384, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha512, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha3_224, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha3_256, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha3_384, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, sha3_512, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, keccak224, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, keccak256, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, keccak384, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, keccak512, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, md4, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, md5, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, ripemd128, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, ripemd160, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, tiger, key, key_size, kKryptosCBC, &rc5_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc5, whirlpool, key, key_size, kKryptosCBC, &rc5_rounds);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc6_128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    int rc6_rounds = 40;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): RC6-128/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha1, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha3_224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha3_256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha3_384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha3_512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, keccak224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, keccak256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, keccak384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, keccak512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, md4, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, md5, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, ripemd128, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, ripemd160, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, tiger, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, whirlpool, key, key_size, kKryptosECB, &rc6_rounds);

    // INFO(Rafael): RC6-128/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha1, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha3_224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha3_256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha3_384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, sha3_512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, keccak224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, keccak256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, keccak384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, keccak512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, md4, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, md5, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, ripemd128, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, ripemd160, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, tiger, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_128, whirlpool, key, key_size, kKryptosCBC, &rc6_rounds);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc6_192_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    int rc6_rounds = 40;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): RC6-192/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha1, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha3_224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha3_256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha3_384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha3_512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, keccak224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, keccak256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, keccak384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, keccak512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, md4, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, md5, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, ripemd128, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, ripemd160, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, tiger, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, whirlpool, key, key_size, kKryptosECB, &rc6_rounds);

    // INFO(Rafael): RC6-192/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha1, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha3_224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha3_256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha3_384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, sha3_512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, keccak224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, keccak256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, keccak384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, keccak512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, md4, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, md5, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, ripemd128, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, ripemd160, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, tiger, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_192, whirlpool, key, key_size, kKryptosCBC, &rc6_rounds);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_rc6_256_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    int rc6_rounds = 40;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): RC6-256/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha1, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha3_224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha3_256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha3_384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha3_512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, keccak224, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, keccak256, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, keccak384, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, keccak512, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, md4, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, md5, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, ripemd128, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, ripemd160, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, tiger, key, key_size, kKryptosECB, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, whirlpool, key, key_size, kKryptosECB, &rc6_rounds);

    // INFO(Rafael): RC6-256/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha1, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha3_224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha3_256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha3_384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, sha3_512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, keccak224, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, keccak256, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, keccak384, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, keccak512, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, md4, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, md5, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, ripemd128, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, ripemd160, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, tiger, key, key_size, kKryptosCBC, &rc6_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, rc6_256, whirlpool, key, key_size, kKryptosCBC, &rc6_rounds);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_camellia128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): CAMELLIA-128/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): CAMELLIA-128/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia128, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_camellia192_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): CAMELLIA-192/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): CAMELLIA-192/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia192, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_camellia256_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): CAMELLIA-256/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): CAMELLIA-256/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, camellia256, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_cast5_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): CAST5/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): CAST5/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, cast5, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_saferk64_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    int saferk64_rounds = 6;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): SAFER-K64/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha1, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha3_224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha3_256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha3_384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha3_512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, keccak224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, keccak256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, keccak384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, keccak512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, md4, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, md5, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, ripemd128, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, ripemd160, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, tiger, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, whirlpool, key, key_size, kKryptosECB, &saferk64_rounds);

    // INFO(Rafael): SAFER-K64/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha1, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha3_224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha3_256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha3_384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, sha3_512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, keccak224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, keccak256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, keccak384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, keccak512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, md4, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, md5, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, ripemd128, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, ripemd160, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, tiger, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, saferk64, whirlpool, key, key_size, kKryptosCBC, &saferk64_rounds);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_aes128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): AES-128/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): AES-128/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes128, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_aes192_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): AES-192/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): AES-192/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes192, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_aes256_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): AES-256/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): AES-256/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, aes256, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_serpent_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): SERPENT/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): SERPENT/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, serpent, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_triple_des_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): TRIPLE-DES/ECB.

    triple_des_key2 = "riverintheroad";
    triple_des_key2_size = 14;
    triple_des_key3 = "thewayyouusedtodo";
    triple_des_key3_size = 17;

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha1, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha3_224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha3_256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha3_384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha3_512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, keccak224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, keccak256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, keccak384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, keccak512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, md4, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, md5, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, ripemd128, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, ripemd160, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, tiger, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, whirlpool, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    // INFO(Rafael): TRIPLE-DES/CBC.

    triple_des_key2 = "riverintheroad";
    triple_des_key2_size = 14;
    triple_des_key3 = "thewayyouusedtodo";
    triple_des_key3_size = 17;

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha1, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha3_224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha3_256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha3_384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, sha3_512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, keccak224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, keccak256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, keccak384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, keccak512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, md4, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, md5, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, ripemd128, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, ripemd160, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, tiger, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des, whirlpool, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_triple_des_ede_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): TRIPLE-DES-EDE/ECB.

    triple_des_key2 = "riverintheroad";
    triple_des_key2_size = 14;
    triple_des_key3 = "thewayyouusedtodo";
    triple_des_key3_size = 17;

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha1, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha3_224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha3_256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha3_384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha3_512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, keccak224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, keccak256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, keccak384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, keccak512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, md4, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, md5, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, ripemd128, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, ripemd160, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, tiger, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, whirlpool, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    // INFO(Rafael): TRIPLE-DES-EDE/CBC.

    triple_des_key2 = "riverintheroad";
    triple_des_key2_size = 14;
    triple_des_key3 = "thewayyouusedtodo";
    triple_des_key3_size = 17;

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha1, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha3_224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha3_256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha3_384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, sha3_512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, keccak224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, keccak256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, keccak384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, keccak512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, md4, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, md5, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, ripemd128, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, ripemd160, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, tiger, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, triple_des_ede, whirlpool, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_tea_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): TEA/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): TEA/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, tea, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_xtea_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    int xtea_rounds = 64;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): XTEA/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha1, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha224, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha256, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha384, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha512, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha3_224, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha3_256, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha3_384, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha3_512, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, keccak224, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, keccak256, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, keccak384, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, keccak512, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, md4, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, md5, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, ripemd128, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, ripemd160, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, tiger, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, whirlpool, key, key_size, kKryptosECB, &xtea_rounds);

    // INFO(Rafael): XTEA/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha1, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha224, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha256, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha384, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha512, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha3_224, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha3_256, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha3_384, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, sha3_512, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, keccak224, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, keccak256, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, keccak384, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, keccak512, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, md4, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, md5, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, ripemd128, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, ripemd160, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, tiger, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, xtea, whirlpool, key, key_size, kKryptosCBC, &xtea_rounds);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_misty1_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): MISTY1/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): MISTY1/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, misty1, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mars128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): MARS-128/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): MARS-128/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars128, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mars192_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): MARS-192/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): MARS-192/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars192, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_mars256_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): MARS-256/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): MARS-256/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, mars256, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_present80_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): PRESENT-80/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): PRESENT-80/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present80, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_present128_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): PRESENT-128/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): PRESENT-128/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, present128, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_shacal1_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): SHACAL-1/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): SHACAL-1/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal1, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_shacal2_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): SHACAL-2/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): SHACAL-2/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, shacal2, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_noekeon_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): NOEKEON/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): NOEKEON/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_noekeon_d_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): NOEKEON/DIRECT/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): NOEKEON/DIRECT/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, noekeon_d, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_gost_ds_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): GOST-DS/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, tiger, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, whirlpool, key, key_size, kKryptosECB);

    // INFO(Rafael): GOST-DS/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, tiger, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost_ds, whirlpool, key, key_size, kKryptosCBC);
KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_gost_hmac_tests)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_task_ctx t;
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
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);

    // INFO(Rafael): GOST/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha1, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha224, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha256, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha384, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha512, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha3_224, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha3_256, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha3_384, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha3_512, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, keccak224, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, keccak256, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, keccak384, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, keccak512, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, md4, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, md5, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, ripemd128, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, ripemd160, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, tiger, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, whirlpool, key, key_size, kKryptosECB,
                           s1, s2, s3, s4, s5, s6, s7, s8);

    // INFO(Rafael): GOST/CBC.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha1, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha224, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha256, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha384, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha512, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha3_224, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha3_256, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha3_384, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, sha3_512, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, keccak224, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, keccak256, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, keccak384, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, keccak512, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, md4, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, md5, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, ripemd128, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, ripemd160, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, tiger, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
    kryptos_run_hmac_tests(t, plaintext, plaintext_size, gost, whirlpool, key, key_size, kKryptosCBC,
                           s1, s2, s3, s4, s5, s6, s7, s8);
KUTE_TEST_CASE_END

#undef kryptos_run_hmac_tests

#endif
