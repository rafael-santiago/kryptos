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

    // INFO(Rafael): MD4.

    KUTE_ASSERT(kryptos_md4_hash_input_size() == 64);
    KUTE_ASSERT(kryptos_md4_hash_size() == 16);
    kryptos_md4_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_md4_hash_size());
    raw_hash = "\xA4\x48\x01\x7A\xAF\x21\xD8\x52\x5F\xC1\x0A\xE8\x7A\xA6\x72\x9D";
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

    // INFO(Rafael): RIPEMD-128.

    KUTE_ASSERT(kryptos_ripemd128_hash_input_size() == 64);
    KUTE_ASSERT(kryptos_ripemd128_hash_size() == 16);
    kryptos_ripemd128_hash(&ktask, 0);
    KUTE_ASSERT(t.out != NULL);
    KUTE_ASSERT(t.out_size == kryptos_ripemd128_hash_size());
    raw_hash = "\xC1\x4A\x12\x19\x9C\x66\xE4\xBA\x84\x63\x6B\x0F\x69\x14\x4C\x77";
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

KUTE_TEST_CASE_END

KUTE_TEST_CASE(kryptos_hmac_tests)
    // INFO(Rafael): This is pretty crazy, because is uncommon execute this kind of work in kernel mode, but if
    //               the code is okay it should work.
    //
    //               But here we will use just one plaintext for each <hash;cipher> pair.
    //


#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)

#define kryptos_run_hmac_tests(t, plaintext, plaintext_size, cname, hname, cipher_args...) {\
    kryptos_task_set_in(&t, plaintext, plaintext_size);\
    kryptos_task_init_as_null(&t);\
    kryptos_task_set_encrypt_action(&t);\
    kryptos_run_cipher_hmac(cname, hname, &t, cipher_args);\
    KUTE_ASSERT(t.in != NULL);\
    KUTE_ASSERT(t.out != NULL);\
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
        kryptos_task_free(&t, KRYPTOS_TASK_IN | KRYPTOS_TASK_OUT);\
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
    kryptos_u8_t *key = "nooneknows";
    size_t key_size = 10;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);
    __unused int feal_rounds = 8, rc2_T1 = 64, saferk64_rounds = 6;
    __unused kryptos_camellia_keysize_t camellia_size;
    __unused size_t tv, tv_nr, data_size;
    __unused kryptos_task_ctx t;
    __unused kryptos_u8_t *triple_des_key2, *triple_des_key3;
    __unused size_t triple_des_key2_size, triple_des_key3_size;

    // INFO(Rafael): DES/ECB.

    kryptos_run_hmac_tests(t, plaintext, plaintext_size, des, sha1, key, key_size, kKryptosECB);


#undef kryptos_run_hmac_tests

#else
# if !defined(KRYPTOS_NO_HMAC_TESTS)
    // TODO(Rafael): When there is no C99 support add a simple bare bone test with at least one block cipher and all
    //               available hash functions.
#  if defined(__FreeBSD__)
    uprintf("WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
#  elif defined(__linux__)
    printk(KERNEL_INFO "WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
#  endif
# else
#   if defined(__FreeBSD__)
    uprintf("WARN: You have requested build this binary without the HMAC tests.\n");
#   else
    printk(KERNEL_INFO "WARN: You have requested build this binary without the HMAC tests.\n");
#   endif
# endif // !defined(KRYPTOS_SKIP_HMAC_TESTS)
#endif // defined(KRYPTOS_C99) && !defined(KRYPTOS_SKIP_HMAC_TESTS)

KUTE_TEST_CASE_END
