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

KUTE_TEST_CASE(kryptos_hmac_tests)
    // INFO(Rafael): This is pretty crazy, because is uncommon execute this stuff in kernel mode, but if
    //               the code is okay it should work.
    //
    //               But here we will use just one plaintext for each <hash;cipher> pair.
    //


#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)

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
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    kryptos_u8_t *plaintext = "When I find my code in tons of trouble,\n"
                              "Friends and colleagues come to me,\n"
                              "Speaking words of wisdom:\n"
                              "Write in C.\n\n"
                              " -- Write in C(\"Let it Be\")\n";
    size_t plaintext_size = kstrlen(plaintext);
    int feal_rounds = 8, rc2_T1 = 64, saferk64_rounds = 6;
    kryptos_task_ctx t;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;
    int xtea_rounds = 64;
    int rc5_rounds = 20;
    int rc6_rounds = 40;

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

#undef kryptos_run_hmac_tests

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
