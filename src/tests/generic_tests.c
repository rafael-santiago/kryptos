/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "generic_tests.h"
#include <kryptos_padding.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#include <kryptos_fortuna.h>
#include <kryptos_task_check.h>
#include <kryptos_block_parser.h>
#include <kryptos_endianness_utils.h>
#include <kryptos_iv_utils.h>
#include <kryptos_hex.h>
#include <kryptos_hash_common.h>
#include <kryptos_sha1.h>
#include <kryptos_userland_funcs.h>
#include <kryptos_gcm_utils.h>
#include <string.h>
#if !defined(_WIN32)
# include <dlfcn.h>
# if !defined(RTLD_NEXT)
#  define RTLD_NEXT -1
# endif
# else
# include <windows.h>
#endif

static kryptos_task_result_t E_stub(kryptos_u8_t **h, size_t *h_size, kryptos_u8_t *key, size_t key_size, void *arg);

static kryptos_task_result_t E_bad_stub(kryptos_u8_t **h, size_t *h_size, kryptos_u8_t *key, size_t key_size, void *arg);

CUTE_TEST_CASE(kryptos_padding_tests)
    struct padding_tests_ctx {
        const kryptos_u8_t *buffer;
        size_t buffer_size;
        const size_t block_size;
        size_t expected_buffer_size;
        const kryptos_u8_t *pad;
    };
    struct padding_tests_ctx tests[] = {
        { "XXXXXXXXXXXXXXXXXXXXXXXXXXXX", 28, 8, 32, "XXXXXXXXXXXXXXXXXXXXXXXXXXXX\x0\x0\x0\x4" },
        { "ABC",                           3, 4,  4, "ABC\x1"                                   },
        { "ABCD",                          4, 4,  8, "ABCD\x0\x0\x0\x4"                         },
        { "A",                             1, 8,  8, "A\x0\x0\x0\x0\x0\x0\x7"                   }
    };
    size_t tests_nr = sizeof(tests) / sizeof(tests[0]), t = 0;
    kryptos_u8_t *pad = NULL;
    size_t buffer_size;
//    size_t old_size;

    while (t < tests_nr) {
        buffer_size = tests[t].buffer_size;
        pad = kryptos_ansi_x923_padding(tests[t].buffer,
                                        &buffer_size,
                                        tests[t].block_size, 0);
        CUTE_ASSERT(pad != NULL);
        CUTE_ASSERT(buffer_size == tests[t].expected_buffer_size);

//        for (old_size = 0; old_size < buffer_size; old_size++) {
//            printf(" %.2x ", pad[old_size]);
//        }
//        printf("\n");

        CUTE_ASSERT(memcmp(pad, tests[t].pad, buffer_size) == 0);

        kryptos_freeseg(pad, buffer_size);
        pad = NULL;

        buffer_size = tests[t].buffer_size;
        pad = kryptos_ansi_x923_padding(tests[t].buffer,
                                        &buffer_size,
                                        tests[t].block_size, 1);

        CUTE_ASSERT(pad != NULL);

        CUTE_ASSERT(buffer_size == tests[t].expected_buffer_size);

        CUTE_ASSERT(pad[buffer_size - 1] == tests[t].pad[tests[t].expected_buffer_size - 1]);

        kryptos_freeseg(pad, buffer_size);

        t++;
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sys_get_random_block_tests)
    void *block = NULL;
    size_t b = 0;

    CUTE_ASSERT(kryptos_sys_get_random_block(0) == NULL);

    for (b = 1; b < 101; b++) {
        block = kryptos_sys_get_random_block(b);
        CUTE_ASSERT(block != NULL);
        kryptos_freeseg(block, b);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_get_random_block_tests)
    void *block = NULL;
    size_t b = 0;

    CUTE_ASSERT(kryptos_get_random_block(0) == NULL);

    for (b = 1; b < 101; b++) {
        block = kryptos_get_random_block(b);
        CUTE_ASSERT(block != NULL);
        kryptos_freeseg(block, b);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_unbiased_rand_mod_u8_tests)
    kryptos_unbiased_rand_mod_u8(0xAB);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_unbiased_rand_mod_u16_tests)
    kryptos_unbiased_rand_mod_u16(0xABCD);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_unbiased_rand_mod_u32_tests)
    kryptos_unbiased_rand_mod_u32(0xABCDEF00);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_unbiased_rand_mod_u64_tests)
    kryptos_unbiased_rand_mod_u64(17237128);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_block_parser_tests)
    kryptos_u8_t *in = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", *in_p;
    kryptos_u8_t *in_end = NULL;
    kryptos_u8_t *out = NULL;

    in_p = in;
    in_end = in_p + 16;

    out = (kryptos_u8_t *) kryptos_newseg(16);
    CUTE_ASSERT(out != NULL);
    memset(out, 0, 16);

    // INFO(Rafael): 16-bit block parsing.

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x00\x01", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x02\x03", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x04\x05", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x06\x07", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x08\x09", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x0a\x0b", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x0c\x0d", 2) == 0);

    out = kryptos_block_parser(out, 2, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x0e\x0f", 2) == 0);

    CUTE_ASSERT(kryptos_block_parser(out, 2, in_p, in_end, &in_p) == NULL);

    in_p = in;
    in_end = in_p + 16;

    // INFO(Rafael): 32-bit block parsing.

    out = kryptos_block_parser(out, 4, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x00\x01\x02\x03", 4) == 0);

    out = kryptos_block_parser(out, 4, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x04\x05\x06\x07", 4) == 0);

    out = kryptos_block_parser(out, 4, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x08\x09\x0a\x0b", 4) == 0);

    out = kryptos_block_parser(out, 4, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x0c\x0d\x0e\x0f", 4) == 0);

    CUTE_ASSERT(kryptos_block_parser(out, 4, in_p, in_end, &in_p) == NULL);

    in_p = in;
    in_end = in_p + 16;

    // INFO(Rafael): 64-bit block parsing.

    out = kryptos_block_parser(out, 8, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x00\x01\x02\x03\x04\x05\x06\x07", 8) == 0);

    out = kryptos_block_parser(out, 8, in_p, in_end, &in_p);
    CUTE_ASSERT(out != NULL);
    CUTE_ASSERT(memcmp(out, "\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f", 8) == 0);

    CUTE_ASSERT(kryptos_block_parser(out, 8, in_p, in_end, &in_p) == NULL);

    kryptos_freeseg(out, 8);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_endianness_utils_tests)
    kryptos_u8_t *data = NULL;
    kryptos_u32_t deadbeef = 0;
    kryptos_u16_t beef = 0;
    kryptos_u64_t deadbeefdeadbeef = 0;

    data = (kryptos_u8_t *)kryptos_newseg(2);
    CUTE_ASSERT(data != NULL);
    memcpy(data, "\xbe\xef", 2);
    memcpy(&beef, data, 2);
    beef = kryptos_get_u16_as_big_endian(data, 2);
    CUTE_ASSERT(beef == 0xbeef);
    memset(data, 0, 2);
    data = kryptos_cpy_u16_as_big_endian(data, 2, beef);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(*data == 0xbe && *(data + 1) == 0xef);
    kryptos_freeseg(data, sizeof(kryptos_u16_t));

    data = (kryptos_u8_t *)kryptos_newseg(4);
    CUTE_ASSERT(data != NULL);
    memcpy(data, "\xde\xad\xbe\xef", 4);
    memcpy(&deadbeef, data, 4);
    deadbeef = kryptos_get_u32_as_big_endian(data, 4);
    CUTE_ASSERT(deadbeef == 0xdeadbeef);
    memset(data, 0, 4);
    data = kryptos_cpy_u32_as_big_endian(data, 4, deadbeef);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(*data == 0xde && *(data + 1) == 0xad && *(data + 2) == 0xbe && *(data + 3) == 0xef);
    kryptos_freeseg(data, sizeof(kryptos_u32_t));

    data = (kryptos_u8_t *)kryptos_newseg(8);
    CUTE_ASSERT(data != NULL);
    memcpy(data, "\xde\xad\xbe\xef\xde\xad\xbe\xef", 8);
    memcpy(&deadbeefdeadbeef, data, 8);
    deadbeefdeadbeef = kryptos_get_u64_as_big_endian(data, 8);
    CUTE_ASSERT(deadbeefdeadbeef == 0xdeadbeefdeadbeef);
    memset(data, 0, 8);
    data = kryptos_cpy_u64_as_big_endian(data, 8, deadbeefdeadbeef);
    CUTE_ASSERT(data != NULL);
    CUTE_ASSERT(      *data == 0xde && *(data + 1) == 0xad && *(data + 2) == 0xbe && *(data + 3) == 0xef &&
                *(data + 4) == 0xde && *(data + 5) == 0xad && *(data + 6) == 0xbe && *(data + 7) == 0xef);
    kryptos_freeseg(data, sizeof(kryptos_u64_t));
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_apply_iv_tests)
    kryptos_u8_t *iv = NULL;
    kryptos_u8_t *block = NULL;
    size_t s = 27;
    iv = (kryptos_u8_t *) kryptos_newseg(s + 1);
    CUTE_ASSERT(iv != NULL);
    strncpy(iv, "rofginkoolerautahtsdiordeht", s);
    block = (kryptos_u8_t *) kryptos_newseg(s);
    CUTE_ASSERT(block != NULL);
    strncpy(block, "thedroidsthatuarelookingfor", s);
    CUTE_ASSERT(kryptos_apply_iv(block, iv, s) == block);
    CUTE_ASSERT(kryptos_apply_iv(block, iv, s) == block);
    CUTE_ASSERT(memcmp(block, "thedroidsthatuarelookingfor", 27) == 0);
    kryptos_freeseg(iv, s + 1);
    kryptos_freeseg(block, s);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_iv_data_flush_tests)
    kryptos_u8_t *y = "hellyeah!";
    kryptos_u8_t *iv = kryptos_newseg(9);
    size_t s = 9;
    CUTE_ASSERT(iv != NULL);
    kryptos_iv_data_flush(iv, y, s);
    CUTE_ASSERT(memcmp(iv, "hellyeah!", s) == 0);
    kryptos_freeseg(iv, s);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_task_check_tests)
    kryptos_u8_t *key = "blah";
    kryptos_u8_t *in = "bleh";
    kryptos_u8_t *iv = "bluh";
    kryptos_task_ctx t;
    kryptos_task_ctx *ktask = &t;
    kryptos_u8_t *rsa_k_pub = "-----BEGIN RSA PARAM N-----\n"
                              "q/agiHElaTH+B056kexqvlrlHcbr4c8lF2lvFdH6VnrdyZCRYxYVJS1wixnxrUeMpJ7l2g+hEHYlgRxM3xrGaA==\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "Q9mxxs0+nosV5jzwUs1UmYEhXLrYAszE9q0S3hljhpXD9ANvkzCUC5nM8FZ3+44V1IrPhIYZYDwfSrGlhwG4Aw==\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *rsa_k_priv = "-----BEGIN RSA PARAM N-----\n"
                               "q/agiHElaTH+B056kexqvlrlHcbr4c8lF2lvFdH6VnrdyZCRYxYVJS1wixnxrUeMpJ7l2g+hEHYlgRxM3xrGaA==\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "K04+KEU3GyG2ABjJu+sTqV5yH8mgO8aIPdygWvBq9GzJfTmLt18cck2pc7y6lmYLsl+NxgFo7KTliwXAjU3eGg==\n"
                               "-----END RSA PARAM D-----\n";
    kryptos_u8_t *label = "L";
    size_t label_size = 1;
    kryptos_u8_t *elgamal_k_pub = "-----BEGIN ELGAMAL PARAM P-----\n"
                                  "LWy0fB4Y6Bc=\n"
                                  "-----END ELGAMAL PARAM P-----\n"
                                  "-----BEGIN ELGAMAL PARAM Q-----\n"
                                  "DYBegQ==\n"
                                  "-----END ELGAMAL PARAM Q-----\n"
                                  "-----BEGIN ELGAMAL PARAM G-----\n"
                                  "7LbbqIYLtgg=\n"
                                  "-----END ELGAMAL PARAM G-----\n"
                                  "-----BEGIN ELGAMAL PARAM B-----\n"
                                  "zVTveNNhyhc=\n"
                                  "-----END ELGAMAL PARAM B-----\n";

    kryptos_u8_t *elgamal_k_priv = "-----BEGIN ELGAMAL PARAM P-----\n"
                                   "LWy0fB4Y6Bc=\n"
                                   "-----END ELGAMAL PARAM P-----\n"
                                   "-----BEGIN ELGAMAL PARAM D-----\n"
                                   "Wnb/HA==\n"
                                   "-----END ELGAMAL PARAM D-----\n";

    t.cipher = -1;
    t.mode = kKryptosECB;
    t.key = key;
    t.key_size = 4;
    t.iv = in;
    t.iv_size = 4;
    t.in = in;
    t.out = NULL;
    t.out_size = 0;

    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidCipher);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid cipher.") == 0);

    t.cipher = kKryptosCipherARC4;
    t.key = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid key data.") == 0);

    t.key = key;
    t.key_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid key data.") == 0);

    t.cipher = kKryptosCipherAES128;
    t.action = kKryptosEncrypt;
    t.key_size = 4;
    t.mode = kKryptosCBC;
    t.iv = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid iv data.") == 0);

    t.iv = iv;
    t.iv_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid iv data.") == 0);

    t.mode = kKryptosECB;
    t.iv_size = 4;
    t.in = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "No input.") == 0);

    t.in = in;
    t.in_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "No input.") == 0);

    t.in_size = 4;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);

    t.mode = kKryptosCipherModeNr;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid operation mode.") == 0);

    t.mode = kKryptosECB;
    t.action = kKryptosActionNr;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid task action.") == 0);

    t.cipher = kKryptosCipherARC4;
    t.iv = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);

    t.cipher = kKryptosCipherSEAL;
    t.iv = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);

    t.cipher = kKryptosCipherARC4;
    t.iv_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);

    t.cipher = kKryptosCipherSEAL;
    t.iv_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);

    t.cipher = kKryptosCipherRABBIT;
    t.iv = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
    CUTE_ASSERT(t.result_verbose == NULL);

    t.cipher = kKryptosCipherRABBIT;
    t.iv = "\x00\x00\x00\x00\x00\x00\x00\x00";
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(t.result_verbose != NULL);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid iv data.") == 0);

    t.cipher = kKryptosCipherRABBIT;
    t.iv_size = 8;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result_verbose == NULL);
    CUTE_ASSERT(t.result == kKryptosSuccess);

    t.key = key;
    t.key_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);
    CUTE_ASSERT(strcmp(t.result_verbose, "Invalid key data.") == 0);

    t.cipher = kKryptosCipherRSA;
    t.key = NULL;
    t.key_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.action = kKryptosEncrypt;
    t.key = rsa_k_priv;
    t.key_size = strlen(rsa_k_priv);
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosKeyError);

    t.key = rsa_k_pub;
    t.key_size = strlen(rsa_k_pub);
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);

    t.action = kKryptosDecrypt;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosKeyError);

    t.key = rsa_k_priv;
    t.key_size = strlen(rsa_k_priv);
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);

    t.cipher = kKryptosCipherRSAOAEP;
    t.arg[0] = t.arg[1] = t.arg[2] = t.arg[3] = NULL;
    t.key = NULL;
    t.key_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.action = kKryptosEncrypt;
    t.key = rsa_k_priv;
    t.key_size = strlen(rsa_k_priv);
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosKeyError);

    t.key = rsa_k_pub;
    t.key_size = strlen(rsa_k_pub);
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);

    t.action = kKryptosDecrypt;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosKeyError);

    t.key = rsa_k_priv;
    t.key_size = strlen(rsa_k_priv);
    t.arg[0] = label;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.arg[0] = NULL;
    t.arg[1] = &label_size;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.arg[1] = NULL;
    t.arg[2] = (kryptos_hash_func) label;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.arg[2] = NULL;
    t.arg[3] = (kryptos_hash_size_func) label;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.arg[3] = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);

    t.arg[0] = label;
    t.arg[1] = &label_size;
    t.arg[2] = (kryptos_hash_func) label;
    t.arg[3] = (kryptos_hash_size_func) label;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);

    t.cipher = kKryptosCipherELGAMAL;
    t.key = NULL;
    t.key_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.action = kKryptosEncrypt;
    t.key = elgamal_k_priv;
    t.key_size = strlen(elgamal_k_priv);
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosKeyError);

    t.key = elgamal_k_pub;
    t.key_size = strlen(elgamal_k_pub);
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);

    t.action = kKryptosDecrypt;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosKeyError);

    t.key = elgamal_k_priv;
    t.key_size = strlen(elgamal_k_priv);
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);

    t.cipher = kKryptosCipherELGAMALOAEP;
    t.arg[0] = t.arg[1] = t.arg[2] = t.arg[3] = NULL;
    t.key = NULL;
    t.key_size = 0;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.action = kKryptosEncrypt;
    t.key = elgamal_k_priv;
    t.key_size = strlen(elgamal_k_priv);
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosKeyError);

    t.key = elgamal_k_pub;
    t.key_size = strlen(elgamal_k_pub);
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);

    t.action = kKryptosDecrypt;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosKeyError);

    t.key = elgamal_k_priv;
    t.key_size = strlen(elgamal_k_priv);
    t.arg[0] = label;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.arg[0] = NULL;
    t.arg[1] = &label_size;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.arg[1] = NULL;
    t.arg[2] = (kryptos_hash_func) label;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.arg[2] = NULL;
    t.arg[3] = (kryptos_hash_size_func) label;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 0);
    CUTE_ASSERT(t.result == kKryptosInvalidParams);

    t.arg[3] = NULL;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);

    t.arg[0] = label;
    t.arg[1] = &label_size;
    t.arg[2] = (kryptos_hash_func) label;
    t.arg[3] = (kryptos_hash_size_func) label;
    CUTE_ASSERT(kryptos_task_check(&ktask) == 1);
    CUTE_ASSERT(t.result == kKryptosSuccess);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_task_check_sign_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *rsa_k_pub = "-----BEGIN RSA PARAM N-----\n"
                              "q/agiHElaTH+B056kexqvlrlHcbr4c8lF2lvFdH6VnrdyZCRYxYVJS1wixnxrUeMpJ7l2g+hEHYlgRxM3xrGaA==\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "Q9mxxs0+nosV5jzwUs1UmYEhXLrYAszE9q0S3hljhpXD9ANvkzCUC5nM8FZ3+44V1IrPhIYZYDwfSrGlhwG4Aw==\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *rsa_k_priv = "-----BEGIN RSA PARAM N-----\n"
                               "q/agiHElaTH+B056kexqvlrlHcbr4c8lF2lvFdH6VnrdyZCRYxYVJS1wixnxrUeMpJ7l2g+hEHYlgRxM3xrGaA==\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "K04+KEU3GyG2ABjJu+sTqV5yH8mgO8aIPdygWvBq9GzJfTmLt18cck2pc7y6lmYLsl+NxgFo7KTliwXAjU3eGg==\n"
                               "-----END RSA PARAM D-----\n";
    size_t k;

    kryptos_u8_t *dsa_k_pub = "-----BEGIN DSA P-----\n"
                              "12Ga65Y5bQ4=\n"
                              "-----END DSA P-----\n"
                              "-----BEGIN DSA Q-----\n"
                              "P1wB2Q==\n"
                              "-----END DSA Q-----\n"
                              "-----BEGIN DSA G-----\n"
                              "gp2RBbxgtAQ=\n"
                              "-----END DSA G-----\n"
                              "-----BEGIN DSA E-----\n"
                              "bfVPLj3soAc=\n"
                              "-----END DSA E-----\n";

    kryptos_u8_t *dsa_k_priv = "-----BEGIN DSA P-----\n"
                               "12Ga65Y5bQ4=\n"
                               "-----END DSA P-----\n"
                               "-----BEGIN DSA Q-----\n"
                               "P1wB2Q==\n"
                               "-----END DSA Q-----\n"
                               "-----BEGIN DSA G-----\n"
                               "gp2RBbxgtAQ=\n"
                               "-----END DSA G-----\n"
                               "-----BEGIN DSA D-----\n"
                               "XiL6Hg==\n"
                               "-----END DSA D-----\n";

    CUTE_ASSERT(kryptos_task_check_sign(NULL) == 0);

    // INFO(Rafael): Sign using RSA.

    ktask->cipher = kKryptosCipherAES128;
    ktask->in = NULL;
    ktask->in_size = 0;
    ktask->key = NULL;
    ktask->key_size = 0;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->cipher = kKryptosCipherRSA;
    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in = "rsa";

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in_size = 3;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = rsa_k_pub;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = rsa_k_priv;
    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);

    // INFO(Rafael): Sign using RSA-EMSA-PSS.

    ktask->arg[0] = ktask->arg[1] = ktask->arg[2] = NULL;

    ktask->cipher = kKryptosCipherAES128;
    ktask->in = NULL;
    ktask->in_size = 0;
    ktask->key = NULL;
    ktask->key_size = 0;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->cipher = kKryptosCipherRSAEMSAPSS;
    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in = "rsa";

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in_size = 3;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = rsa_k_pub;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = rsa_k_priv;
    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->arg[0] = &k;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);

    ktask->arg[2] = kryptos_sha1_hash_size;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->arg[1] = kryptos_sha1_hash;
    ktask->arg[2] = NULL;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->arg[1] = kryptos_sha1_hash;
    ktask->arg[2] = kryptos_sha1_hash_size;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);

    // INFO(Rafael): Sign using DSA.

    ktask->cipher = kKryptosCipherDSA;
    ktask->in = NULL;
    ktask->in_size = 0;
    ktask->key = NULL;
    ktask->key_size = 0;
    ktask->arg[0] = ktask->arg[1] = NULL;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in = "dsa";

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in_size = 3;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = dsa_k_pub;

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = dsa_k_priv;
    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_sign(&ktask) == 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_task_check_verify_tests)
    kryptos_task_ctx t, *ktask = &t;
    kryptos_u8_t *rsa_k_pub = "-----BEGIN RSA PARAM N-----\n"
                              "q/agiHElaTH+B056kexqvlrlHcbr4c8lF2lvFdH6VnrdyZCRYxYVJS1wixnxrUeMpJ7l2g+hEHYlgRxM3xrGaA==\n"
                              "-----END RSA PARAM N-----\n"
                              "-----BEGIN RSA PARAM E-----\n"
                              "Q9mxxs0+nosV5jzwUs1UmYEhXLrYAszE9q0S3hljhpXD9ANvkzCUC5nM8FZ3+44V1IrPhIYZYDwfSrGlhwG4Aw==\n"
                              "-----END RSA PARAM E-----\n";

    kryptos_u8_t *rsa_k_priv = "-----BEGIN RSA PARAM N-----\n"
                               "q/agiHElaTH+B056kexqvlrlHcbr4c8lF2lvFdH6VnrdyZCRYxYVJS1wixnxrUeMpJ7l2g+hEHYlgRxM3xrGaA==\n"
                               "-----END RSA PARAM N-----\n"
                               "-----BEGIN RSA PARAM D-----\n"
                               "K04+KEU3GyG2ABjJu+sTqV5yH8mgO8aIPdygWvBq9GzJfTmLt18cck2pc7y6lmYLsl+NxgFo7KTliwXAjU3eGg==\n"
                               "-----END RSA PARAM D-----\n";
    size_t k;

    kryptos_u8_t *dsa_k_pub = "-----BEGIN DSA P-----\n"
                              "12Ga65Y5bQ4=\n"
                              "-----END DSA P-----\n"
                              "-----BEGIN DSA Q-----\n"
                              "P1wB2Q==\n"
                              "-----END DSA Q-----\n"
                              "-----BEGIN DSA G-----\n"
                              "gp2RBbxgtAQ=\n"
                              "-----END DSA G-----\n"
                              "-----BEGIN DSA E-----\n"
                              "bfVPLj3soAc=\n"
                              "-----END DSA E-----\n";

    kryptos_u8_t *dsa_k_priv = "-----BEGIN DSA P-----\n"
                               "12Ga65Y5bQ4=\n"
                               "-----END DSA P-----\n"
                               "-----BEGIN DSA Q-----\n"
                               "P1wB2Q==\n"
                               "-----END DSA Q-----\n"
                               "-----BEGIN DSA G-----\n"
                               "gp2RBbxgtAQ=\n"
                               "-----END DSA G-----\n"
                               "-----BEGIN DSA D-----\n"
                               "XiL6Hg==\n"
                               "-----END DSA D-----\n";

    CUTE_ASSERT(kryptos_task_check_sign(NULL) == 0);

    // INFO(Rafael): Verify using RSA.

    ktask->cipher = kKryptosCipherAES128;
    ktask->in = NULL;
    ktask->in_size = 0;
    ktask->key = NULL;
    ktask->key_size = 0;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->cipher = kKryptosCipherRSA;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in = "rsa";

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in_size = 3;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = rsa_k_priv;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = rsa_k_pub;
    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);

    // INFO(Rafael): Verify using RSA-EMSA-PSS.

    ktask->arg[0] = ktask->arg[1] = ktask->arg[2] = NULL;

    ktask->cipher = kKryptosCipherAES128;
    ktask->in = NULL;
    ktask->in_size = 0;
    ktask->key = NULL;
    ktask->key_size = 0;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->cipher = kKryptosCipherRSAEMSAPSS;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in = "rsa";

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in_size = 3;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = rsa_k_priv;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = rsa_k_pub;
    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->arg[0] = &k;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);

    ktask->arg[1] = kryptos_sha1_hash;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->arg[1] = NULL;
    ktask->arg[2] = kryptos_sha1_hash_size;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->arg[1] = kryptos_sha1_hash;
    ktask->arg[2] = kryptos_sha1_hash_size;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);

    // INFO(Rafael): Verify using DSA.

    ktask->cipher = kKryptosCipherDSA;
    ktask->in = NULL;
    ktask->in_size = 0;
    ktask->key = NULL;
    ktask->key_size = 0;
    ktask->arg[0] = ktask->arg[1] = NULL;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in = "dsa";

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosInvalidParams);

    ktask->in_size = 3;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = dsa_k_priv;

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 0);
    CUTE_ASSERT(ktask->result == kKryptosKeyError);

    ktask->key = dsa_k_pub;
    ktask->key_size = strlen(ktask->key);

    CUTE_ASSERT(kryptos_task_check_verify(&ktask) == 1);
    CUTE_ASSERT(ktask->result == kKryptosSuccess);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hex_tests)
    struct test_ctx {
        kryptos_u32_t u32;
        kryptos_u8_t *u32_expected;
        kryptos_u64_t u64;
        kryptos_u8_t *u64_expected;
    };
    struct test_ctx tv[] = {
        { 0x00000000, "00000000", 0x0000000000000000, "0000000000000000" },
        { 0x11000000, "11000000", 0x1100000000000000, "1100000000000000" },
        { 0x22000000, "22000000", 0x2200000000000000, "2200000000000000" },
        { 0x33000000, "33000000", 0x3300000000000000, "3300000000000000" },
        { 0x44000000, "44000000", 0x4400000000000000, "4400000000000000" },
        { 0x55000000, "55000000", 0x5500000000000000, "5500000000000000" },
        { 0x66000000, "66000000", 0x6600000000000000, "6600000000000000" },
        { 0x77000000, "77000000", 0x7700000000000000, "7700000000000000" },
        { 0x88000000, "88000000", 0x8800000000000000, "8800000000000000" },
        { 0x99000000, "99000000", 0x9900000000000000, "9900000000000000" },
        { 0xAA000000, "AA000000", 0xAA00000000000000, "AA00000000000000" },
        { 0xBB000000, "BB000000", 0xBB00000000000000, "BB00000000000000" },
        { 0xCC000000, "CC000000", 0xCC00000000000000, "CC00000000000000" },
        { 0xDD000000, "DD000000", 0xDD00000000000000, "DD00000000000000" },
        { 0xEE000000, "EE000000", 0xEE00000000000000, "EE00000000000000" },
        { 0xFF000000, "FF000000", 0xFF00000000000000, "FF00000000000000" },
        { 0x00110000, "00110000", 0x0011000000000000, "0011000000000000" },
        { 0x00220000, "00220000", 0x0022000000000000, "0022000000000000" },
        { 0x00330000, "00330000", 0x0033000000000000, "0033000000000000" },
        { 0x00440000, "00440000", 0x0044000000000000, "0044000000000000" },
        { 0x00550000, "00550000", 0x0055000000000000, "0055000000000000" },
        { 0x00660000, "00660000", 0x0066000000000000, "0066000000000000" },
        { 0x00770000, "00770000", 0x0077000000000000, "0077000000000000" },
        { 0x00880000, "00880000", 0x0088000000000000, "0088000000000000" },
        { 0x00990000, "00990000", 0x0099000000000000, "0099000000000000" },
        { 0x00AA0000, "00AA0000", 0x00AA000000000000, "00AA000000000000" },
        { 0x00BB0000, "00BB0000", 0x00BB000000000000, "00BB000000000000" },
        { 0x00CC0000, "00CC0000", 0x00CC000000000000, "00CC000000000000" },
        { 0x00DD0000, "00DD0000", 0x00DD000000000000, "00DD000000000000" },
        { 0x00EE0000, "00EE0000", 0x00EE000000000000, "00EE000000000000" },
        { 0x00FF0000, "00FF0000", 0x00FF000000000000, "00FF000000000000" },
        { 0x00001100, "00001100", 0x0000110000000000, "0000110000000000" },
        { 0x00002200, "00002200", 0x0000220000000000, "0000220000000000" },
        { 0x00003300, "00003300", 0x0000330000000000, "0000330000000000" },
        { 0x00004400, "00004400", 0x0000440000000000, "0000440000000000" },
        { 0x00005500, "00005500", 0x0000550000000000, "0000550000000000" },
        { 0x00006600, "00006600", 0x0000660000000000, "0000660000000000" },
        { 0x00007700, "00007700", 0x0000770000000000, "0000770000000000" },
        { 0x00008800, "00008800", 0x0000880000000000, "0000880000000000" },
        { 0x00009900, "00009900", 0x0000990000000000, "0000990000000000" },
        { 0x0000AA00, "0000AA00", 0x0000AA0000000000, "0000AA0000000000" },
        { 0x0000BB00, "0000BB00", 0x0000BB0000000000, "0000BB0000000000" },
        { 0x0000CC00, "0000CC00", 0x0000CC0000000000, "0000CC0000000000" },
        { 0x0000DD00, "0000DD00", 0x0000DD0000000000, "0000DD0000000000" },
        { 0x0000EE00, "0000EE00", 0x0000EE0000000000, "0000EE0000000000" },
        { 0x0000FF00, "0000FF00", 0x0000FF0000000000, "0000FF0000000000" },
        { 0x00000011, "00000011", 0x0000001100000000, "0000001100000000" },
        { 0x00000022, "00000022", 0x0000002200000000, "0000002200000000" },
        { 0x00000033, "00000033", 0x0000003300000000, "0000003300000000" },
        { 0x00000044, "00000044", 0x0000004400000000, "0000004400000000" },
        { 0x00000055, "00000055", 0x0000005500000000, "0000005500000000" },
        { 0x00000066, "00000066", 0x0000006600000000, "0000006600000000" },
        { 0x00000077, "00000077", 0x0000007700000000, "0000007700000000" },
        { 0x00000088, "00000088", 0x0000008800000000, "0000008800000000" },
        { 0x00000099, "00000099", 0x0000009900000000, "0000009900000000" },
        { 0x000000AA, "000000AA", 0x000000AA00000000, "000000AA00000000" },
        { 0x000000BB, "000000BB", 0x000000BB00000000, "000000BB00000000" },
        { 0x000000CC, "000000CC", 0x000000CC00000000, "000000CC00000000" },
        { 0x000000DD, "000000DD", 0x000000DD00000000, "000000DD00000000" },
        { 0x000000EE, "000000EE", 0x000000EE00000000, "000000EE00000000" },
        { 0x000000FF, "000000FF", 0x000000FF00000000, "000000FF00000000" },
        { 0x00000000, "00000000", 0x0000000011000000, "0000000011000000" },
        { 0x00000000, "00000000", 0x0000000022000000, "0000000022000000" },
        { 0x00000000, "00000000", 0x0000000033000000, "0000000033000000" },
        { 0x00000000, "00000000", 0x0000000044000000, "0000000044000000" },
        { 0x00000000, "00000000", 0x0000000055000000, "0000000055000000" },
        { 0x00000000, "00000000", 0x0000000066000000, "0000000066000000" },
        { 0x00000000, "00000000", 0x0000000077000000, "0000000077000000" },
        { 0x00000000, "00000000", 0x0000000088000000, "0000000088000000" },
        { 0x00000000, "00000000", 0x0000000099000000, "0000000099000000" },
        { 0x00000000, "00000000", 0x00000000AA000000, "00000000AA000000" },
        { 0x00000000, "00000000", 0x00000000BB000000, "00000000BB000000" },
        { 0x00000000, "00000000", 0x00000000CC000000, "00000000CC000000" },
        { 0x00000000, "00000000", 0x00000000DD000000, "00000000DD000000" },
        { 0x00000000, "00000000", 0x00000000EE000000, "00000000EE000000" },
        { 0x00000000, "00000000", 0x00000000FF000000, "00000000FF000000" },
        { 0x00000000, "00000000", 0x0000000000110000, "0000000000110000" },
        { 0x00000000, "00000000", 0x0000000000220000, "0000000000220000" },
        { 0x00000000, "00000000", 0x0000000000330000, "0000000000330000" },
        { 0x00000000, "00000000", 0x0000000000440000, "0000000000440000" },
        { 0x00000000, "00000000", 0x0000000000550000, "0000000000550000" },
        { 0x00000000, "00000000", 0x0000000000660000, "0000000000660000" },
        { 0x00000000, "00000000", 0x0000000000770000, "0000000000770000" },
        { 0x00000000, "00000000", 0x0000000000880000, "0000000000880000" },
        { 0x00000000, "00000000", 0x0000000000990000, "0000000000990000" },
        { 0x00000000, "00000000", 0x0000000000AA0000, "0000000000AA0000" },
        { 0x00000000, "00000000", 0x0000000000BB0000, "0000000000BB0000" },
        { 0x00000000, "00000000", 0x0000000000CC0000, "0000000000CC0000" },
        { 0x00000000, "00000000", 0x0000000000DD0000, "0000000000DD0000" },
        { 0x00000000, "00000000", 0x0000000000EE0000, "0000000000EE0000" },
        { 0x00000000, "00000000", 0x0000000000FF0000, "0000000000FF0000" },
        { 0x00000000, "00000000", 0x0000000000001100, "0000000000001100" },
        { 0x00000000, "00000000", 0x0000000000002200, "0000000000002200" },
        { 0x00000000, "00000000", 0x0000000000003300, "0000000000003300" },
        { 0x00000000, "00000000", 0x0000000000004400, "0000000000004400" },
        { 0x00000000, "00000000", 0x0000000000005500, "0000000000005500" },
        { 0x00000000, "00000000", 0x0000000000006600, "0000000000006600" },
        { 0x00000000, "00000000", 0x0000000000007700, "0000000000007700" },
        { 0x00000000, "00000000", 0x0000000000008800, "0000000000008800" },
        { 0x00000000, "00000000", 0x0000000000009900, "0000000000009900" },
        { 0x00000000, "00000000", 0x000000000000AA00, "000000000000AA00" },
        { 0x00000000, "00000000", 0x000000000000BB00, "000000000000BB00" },
        { 0x00000000, "00000000", 0x000000000000CC00, "000000000000CC00" },
        { 0x00000000, "00000000", 0x000000000000DD00, "000000000000DD00" },
        { 0x00000000, "00000000", 0x000000000000EE00, "000000000000EE00" },
        { 0x00000000, "00000000", 0x000000000000FF00, "000000000000FF00" },
        { 0x00000000, "00000000", 0x0000000000000011, "0000000000000011" },
        { 0x00000000, "00000000", 0x0000000000000022, "0000000000000022" },
        { 0x00000000, "00000000", 0x0000000000000033, "0000000000000033" },
        { 0x00000000, "00000000", 0x0000000000000044, "0000000000000044" },
        { 0x00000000, "00000000", 0x0000000000000055, "0000000000000055" },
        { 0x00000000, "00000000", 0x0000000000000066, "0000000000000066" },
        { 0x00000000, "00000000", 0x0000000000000077, "0000000000000077" },
        { 0x00000000, "00000000", 0x0000000000000088, "0000000000000088" },
        { 0x00000000, "00000000", 0x0000000000000099, "0000000000000099" },
        { 0x00000000, "00000000", 0x00000000000000AA, "00000000000000AA" },
        { 0x00000000, "00000000", 0x00000000000000BB, "00000000000000BB" },
        { 0x00000000, "00000000", 0x00000000000000CC, "00000000000000CC" },
        { 0x00000000, "00000000", 0x00000000000000DD, "00000000000000DD" },
        { 0x00000000, "00000000", 0x00000000000000EE, "00000000000000EE" },
        { 0x00000000, "00000000", 0x00000000000000FF, "00000000000000FF" },
    };
    size_t tv_nr = sizeof(tv) / sizeof(tv[0]), t;
    kryptos_u8_t buf[20];
    for (t = 0; t < tv_nr; t++) {
        kryptos_u32_to_hex(buf, sizeof(buf), tv[t].u32);
        CUTE_ASSERT(strcmp(buf, tv[t].u32_expected) == 0);
        kryptos_u64_to_hex(buf, sizeof(buf), tv[t].u64);
        CUTE_ASSERT(strcmp(buf, tv[t].u64_expected) == 0);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hash_common_tests)
    size_t index_decision_table32[] = {
         0,  0,  0,  0,
         1,  1,  1,  1,
         2,  2,  2,  2,
         3,  3,  3,  3,
         4,  4,  4,  4,
         5,  5,  5,  5,
         6,  6,  6,  6,
         7,  7,  7,  7,
         8,  8,  8,  8,
         9,  9,  9,  9,
        10, 10, 10, 10,
        11, 11, 11, 11,
        12, 12, 12, 12,
        13, 13, 13, 13,
        14, 14, 14, 14,
        15, 15, 15, 15
    };
    kryptos_u32_t u32_input[16];
    size_t index_decision_table64[] = {
         0,  0,  0,  0,  0,  0,  0,  0,
         1,  1,  1,  1,  1,  1,  1,  1,
         2,  2,  2,  2,  2,  2,  2,  2,
         3,  3,  3,  3,  3,  3,  3,  3,
         4,  4,  4,  4,  4,  4,  4,  4,
         5,  5,  5,  5,  5,  5,  5,  5,
         6,  6,  6,  6,  6,  6,  6,  6,
         7,  7,  7,  7,  7,  7,  7,  7,
         8,  8,  8,  8,  8,  8,  8,  8,
         9,  9,  9,  9,  9,  9,  9,  9,
        10, 10, 10, 10, 10, 10, 10, 10,
        11, 11, 11, 11, 11, 11, 11, 11,
        12, 12, 12, 12, 12, 12, 12, 12,
        13, 13, 13, 13, 13, 13, 13, 13,
        14, 14, 14, 14, 14, 14, 14, 14,
        15, 15, 15, 15, 15, 15, 15, 15
    };
    kryptos_u64_t u64_input[16];
    kryptos_u64_t curr_len, total_len;
    int paddin2times = 0;

    kryptos_hash_ld_u8buf_as_u32_blocks("abc", 3,
                                        u32_input, 16,
                                        index_decision_table32);

    CUTE_ASSERT(u32_input[ 0] == 0x616263);
    CUTE_ASSERT(u32_input[ 1] == 0x0);
    CUTE_ASSERT(u32_input[ 2] == 0x0);
    CUTE_ASSERT(u32_input[ 3] == 0x0);
    CUTE_ASSERT(u32_input[ 4] == 0x0);
    CUTE_ASSERT(u32_input[ 5] == 0x0);
    CUTE_ASSERT(u32_input[ 6] == 0x0);
    CUTE_ASSERT(u32_input[ 7] == 0x0);
    CUTE_ASSERT(u32_input[ 8] == 0x0);
    CUTE_ASSERT(u32_input[ 9] == 0x0);
    CUTE_ASSERT(u32_input[10] == 0x0);
    CUTE_ASSERT(u32_input[11] == 0x0);
    CUTE_ASSERT(u32_input[12] == 0x0);
    CUTE_ASSERT(u32_input[13] == 0x0);
    CUTE_ASSERT(u32_input[14] == 0x0);
    CUTE_ASSERT(u32_input[15] == 0x0);

    curr_len = 3;
    total_len = 24;

    kryptos_hash_apply_pad_on_u32_block(u32_input, 16,
                                        index_decision_table32,
                                        curr_len, total_len,
                                        &paddin2times, 0x80, 56);

    CUTE_ASSERT(u32_input[ 0] == 0x61626380);
    CUTE_ASSERT(u32_input[ 1] == 0x0);
    CUTE_ASSERT(u32_input[ 2] == 0x0);
    CUTE_ASSERT(u32_input[ 3] == 0x0);
    CUTE_ASSERT(u32_input[ 4] == 0x0);
    CUTE_ASSERT(u32_input[ 5] == 0x0);
    CUTE_ASSERT(u32_input[ 6] == 0x0);
    CUTE_ASSERT(u32_input[ 7] == 0x0);
    CUTE_ASSERT(u32_input[ 8] == 0x0);
    CUTE_ASSERT(u32_input[ 9] == 0x0);
    CUTE_ASSERT(u32_input[10] == 0x0);
    CUTE_ASSERT(u32_input[11] == 0x0);
    CUTE_ASSERT(u32_input[12] == 0x0);
    CUTE_ASSERT(u32_input[13] == 0x0);
    CUTE_ASSERT(u32_input[14] == 0x0);
    CUTE_ASSERT(u32_input[15] == 0x18);


    curr_len = 56;
    total_len = 24;
    paddin2times = 0;

    kryptos_hash_apply_pad_on_u32_block(u32_input, 16,
                                        index_decision_table32,
                                        curr_len, total_len,
                                        &paddin2times, 0x80, 56);
    CUTE_ASSERT(paddin2times == 1);

    paddin2times = 0;

    kryptos_hash_ld_u8buf_as_u64_blocks("abc", 3,
                                        u64_input, 16,
                                        index_decision_table64);

    CUTE_ASSERT(u64_input[ 0] == 0x616263);
    CUTE_ASSERT(u64_input[ 1] == 0x0);
    CUTE_ASSERT(u64_input[ 2] == 0x0);
    CUTE_ASSERT(u64_input[ 3] == 0x0);
    CUTE_ASSERT(u64_input[ 4] == 0x0);
    CUTE_ASSERT(u64_input[ 5] == 0x0);
    CUTE_ASSERT(u64_input[ 6] == 0x0);
    CUTE_ASSERT(u64_input[ 7] == 0x0);
    CUTE_ASSERT(u64_input[ 8] == 0x0);
    CUTE_ASSERT(u64_input[ 9] == 0x0);
    CUTE_ASSERT(u64_input[10] == 0x0);
    CUTE_ASSERT(u64_input[11] == 0x0);
    CUTE_ASSERT(u64_input[12] == 0x0);
    CUTE_ASSERT(u64_input[13] == 0x0);
    CUTE_ASSERT(u64_input[14] == 0x0);
    CUTE_ASSERT(u64_input[15] == 0x0);

    curr_len = 3;
    total_len = 24;

    kryptos_hash_apply_pad_on_u64_block(u64_input, 16,
                                        index_decision_table64,
                                        curr_len, total_len,
                                        &paddin2times, 0x80, 120);

    CUTE_ASSERT(u64_input[ 0] == 0x6162638000000000);
    CUTE_ASSERT(u64_input[ 1] == 0x0);
    CUTE_ASSERT(u64_input[ 2] == 0x0);
    CUTE_ASSERT(u64_input[ 3] == 0x0);
    CUTE_ASSERT(u64_input[ 4] == 0x0);
    CUTE_ASSERT(u64_input[ 5] == 0x0);
    CUTE_ASSERT(u64_input[ 6] == 0x0);
    CUTE_ASSERT(u64_input[ 7] == 0x0);
    CUTE_ASSERT(u64_input[ 8] == 0x0);
    CUTE_ASSERT(u64_input[ 9] == 0x0);
    CUTE_ASSERT(u64_input[10] == 0x0);
    CUTE_ASSERT(u64_input[11] == 0x0);
    CUTE_ASSERT(u64_input[12] == 0x0);
    CUTE_ASSERT(u64_input[13] == 0x0);
    CUTE_ASSERT(u64_input[14] == 0x0);
    CUTE_ASSERT(u64_input[15] == 0x18);


    curr_len = 120;
    total_len = 24;
    paddin2times = 0;

    kryptos_hash_apply_pad_on_u64_block(u64_input, 16,
                                        index_decision_table64,
                                        curr_len, total_len,
                                        &paddin2times, 0x80, 120);
    CUTE_ASSERT(paddin2times == 1);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_iv_inc_u32_tests)
    kryptos_u8_t iv[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00 };
    kryptos_u8_t expected_iv[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00 };
    kryptos_u32_t r;

    r = 0;

    while (r < 0xFFFF) {
        kryptos_iv_inc_u32(iv, 8);

        r += 1;

        expected_iv[4] = r >> 24;
        expected_iv[5] = (r & 0xFF0000) >> 16;
        expected_iv[6] = (r & 0xFF00) >> 8;
        expected_iv[7] = r & 0xFF;

        CUTE_ASSERT(memcmp(iv, expected_iv, 8) == 0);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_fortuna_general_tests)
    struct kryptos_fortuna_ctx *fortuna;
    kryptos_u8_t *block;
    int t, i;

    for (i = 0; i < 2; i++) {
        fortuna = kryptos_fortuna_init(i);
        CUTE_ASSERT(fortuna != NULL);

        for (t = 0; t < 10; t++) {
            block = kryptos_fortuna_get_random_block(fortuna, t + 1);
            CUTE_ASSERT(block != NULL);
            memset(block, 0, t + 1); // INFO(Rafael): If it did not allocate the right size, SIGSEGV and/or undefined behavior
                                     //               (hopefully) may occur...
            kryptos_freeseg(block, t + 1);
        }

        if (i) {
            kryptos_fortuna_fini(fortuna);
        }

        fortuna = kryptos_fortuna_init(i);
        CUTE_ASSERT(fortuna != NULL);

        CUTE_ASSERT(kryptos_fortuna_reseed(fortuna, "fortes fortuna adiuvat", 22) == 1);

        for (t = 0; t < 10; t++) {
            block = kryptos_fortuna_get_random_block(fortuna, t + 1);
            CUTE_ASSERT(block != NULL);
            memset(block, 0, t + 1); // INFO(Rafael): If it did not allocate the right size, SIGSEGV and/or undefined behavior
                                     //               (hopefully) may occur...
            kryptos_freeseg(block, t + 1);
        }

        for (t = 0; t < 10; t++) {
            kryptos_fortuna_get_random_byte(fortuna);
        }

        CUTE_ASSERT(fortuna->seed_size == 32);
        CUTE_ASSERT(memcmp(fortuna->seed, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                                          "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 32) != 0);

        kryptos_fortuna_fini(fortuna);
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_csprng_context_change_tests)
    kryptos_u8_t *block;
    size_t c, b;

    for (c = 0; c < 3; c++) {
        // INFO(Rafael): Fortuna stuff.
        CUTE_ASSERT(kryptos_set_csprng(kKryptosCSPRNGFortuna) == 1);

        block = kryptos_get_random_block(101);
        CUTE_ASSERT(block != NULL);
        kryptos_freeseg(block, 101);

        for (b = 0; b < 101; b++) {
            kryptos_get_random_byte();
        }

        // INFO(Rafael): Native system csprng stuff.
        CUTE_ASSERT(kryptos_set_csprng(kKryptosCSPRNGSystem) == 1);

        block = kryptos_get_random_block(101);
        CUTE_ASSERT(block != NULL);
        kryptos_freeseg(block, 101);

        for (b = 0; b < 101; b++) {
            kryptos_get_random_byte();
        }
    }
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_memset_tests)
    char buf[10];
    void *(*curr_libmemset)(void *, int, size_t) = memset;
    CUTE_ASSERT(curr_libmemset == kryptos_memset);
    CUTE_ASSERT(kryptos_memset(buf, '.', sizeof(buf)) == &buf[0]);
    CUTE_ASSERT(memcmp(buf, "..........", sizeof(buf)) == 0);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_memcmp_tests)
    // INFO(Rafael): If this test has passed the memcmp will be tested in the test case 'kryptos_memset_tests'.
# if !defined(_WIN32)
    void *libc_so = (void *)RTLD_NEXT;
    int (*libc_memcmp)(const void *, const void *, size_t);
    CUTE_ASSERT((libc_memcmp = (void *)dlsym(libc_so, "memcmp")) !=  NULL);
    CUTE_ASSERT(libc_memcmp != memcmp);
# else
    HMODULE libc_handle = NULL;
    char *libc_dll[] = {
        "MSVCRT.dll",
        "MSVCR70.dll",
        "MSVCR70d.dll",
        "MSVCR71.dll",
        "MSVCR71d.dll",
        "MSVCR80.dll",
        "MSCVR80d.dll",
        "MSVCR90.dll",
        "MSVCR90d.dll",
        "MSVCR100.dll",
        "MSVCR100d.dll",
        "MSVCR110.dll",
        "MSVCR110d.dll",
        "MSVCR120.dll",
        "MSCVR120d.dll"
    };
    size_t libc_dll_nr = sizeof(libc_dll) / sizeof(libc_dll[0]), l;
    int (*libc_memcmp)(const void *, const void *, size_t);

    for (l = 0; libc_handle == NULL && l < libc_dll_nr; l++) {
        libc_handle = GetModuleHandle(libc_dll[l]);
    }

    CUTE_ASSERT(libc_handle != NULL);

    CUTE_ASSERT((libc_memcmp = (void *)GetProcAddress(libc_handle, "memcmp")) != NULL);
    CUTE_ASSERT(libc_memcmp != memcmp);
#endif
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_memory_tests)
    char *data = NULL;

    data = kryptos_newseg(102);

    CUTE_ASSERT(data != NULL);

    CUTE_ASSERT(memset(data, 0, 102) == data);

    data = kryptos_realloc(data, 819);

    CUTE_ASSERT(data != NULL);

    CUTE_ASSERT(memset(data, 0, 819) == data);

    kryptos_freeseg(data, 819);

    kryptos_avoid_ram_swap();

    data = kryptos_newseg(102);

    CUTE_ASSERT(data != NULL);

    CUTE_ASSERT(memset(data, 0, 102) == data);

    data = kryptos_realloc(data, 819);

    CUTE_ASSERT(data != NULL);

    CUTE_ASSERT(memset(data, 0, 819) == data);

    kryptos_freeseg(data, 819);

    kryptos_allow_ram_swap();
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_gcm_gf_mul_tests)
    kryptos_u32_t  x[4] = { 0x66E94BD4, 0xEF8A2C3B, 0x884CFA59, 0xCA342B2E };
    kryptos_u32_t  y[4] = { 0x0388DACE, 0x60B6A392, 0xF328C2B9, 0x71B2FE78 };
    kryptos_u32_t ez[4] = { 0x5E2EC746, 0x91706288, 0x2C85B068, 0x5353DEB7 };

    // INFO(Rafael): It is important to use x or y as the destination variable,
    //               the internals of GCM implementation takes advantage of this convenience.

    kryptos_gcm_gf_mul(x, y, x);

    CUTE_ASSERT(memcmp(x, ez, sizeof(x)) == 0);
CUTE_TEST_CASE_END

static kryptos_task_result_t E_stub(kryptos_u8_t **h, size_t *h_size, kryptos_u8_t *key, size_t key_size, void *arg) {
    kryptos_u8_t *hp;
    hp = (kryptos_u8_t *)kryptos_newseg(16);
    if (*h == NULL) {
        hp[ 0] = 0x66;
        hp[ 1] = 0xE9;
        hp[ 2] = 0x4B;
        hp[ 3] = 0xD4;
        hp[ 4] = 0xEF;
        hp[ 5] = 0x8A;
        hp[ 6] = 0x2C;
        hp[ 7] = 0x3B;
        hp[ 8] = 0x88;
        hp[ 9] = 0x4C;
        hp[10] = 0xFA;
        hp[11] = 0x59;
        hp[12] = 0xCA;
        hp[13] = 0x34;
        hp[14] = 0x2B;
        hp[15] = 0x2E;
    } else if (*h != NULL) {
        kryptos_freeseg(*h, 0);
        hp[ 0] = 0x58;
        hp[ 1] = 0xE2;
        hp[ 2] = 0xFC;
        hp[ 3] = 0xCE;
        hp[ 4] = 0xFA;
        hp[ 5] = 0x7E;
        hp[ 6] = 0x30;
        hp[ 7] = 0x61;
        hp[ 8] = 0x36;
        hp[ 9] = 0x7F;
        hp[10] = 0x1D;
        hp[11] = 0x57;
        hp[12] = 0xA4;
        hp[13] = 0xE7;
        hp[14] = 0x45;
        hp[15] = 0x5A;
    }
    *h = hp;
    *h_size = 16;
    return kKryptosSuccess;
}

static kryptos_task_result_t E_bad_stub(kryptos_u8_t **h, size_t *h_size, kryptos_u8_t *key, size_t key_size, void *arg) {
    kryptos_u8_t *hp;
    hp = (kryptos_u8_t *)kryptos_newseg(16);
    if (*h == NULL) {
        hp[ 0] = 0x66;
        hp[ 1] = 0xE9;
        hp[ 2] = 0x4B;
        hp[ 3] = 0xD4;
        hp[ 4] = 0xEF;
        hp[ 5] = 0x8A;
        hp[ 6] = 0x2C;
        hp[ 7] = 0x3B;
        hp[ 8] = 0x88;
        hp[ 9] = 0x4C;
        hp[10] = 0xFA;
        hp[11] = 0x59;
        hp[12] = 0xCA;
        hp[13] = 0x34;
        hp[14] = 0x2B;
        hp[15] = 0x2E;
    } else if (*h != NULL) {
        kryptos_freeseg(*h, 0);
        hp[ 0] = 0x58;
        hp[ 1] = 0xE2;
        hp[ 2] = 0xFC;
        hp[ 3] = 0xCE;
        hp[ 4] = 0xFA;
        hp[ 5] = 0x7E;
        hp[ 6] = 0x31; // INFO(Rafael): Flipping one bit. It is equivalent of flipping one bit in the cryptogram (user data).
        hp[ 7] = 0x61;
        hp[ 8] = 0x36;
        hp[ 9] = 0x7F;
        hp[10] = 0x1D;
        hp[11] = 0x57;
        hp[12] = 0xA4;
        hp[13] = 0xE7;
        hp[14] = 0x45;
        hp[15] = 0x5A;
    }
    *h = hp;
    *h_size = 16;
    return kKryptosSuccess;
}

CUTE_TEST_CASE(kryptos_gcm_tests)
    // INFO(Rafael): This test data was picked from Nist spec 'The Galois/Counter Mode of Operation' (revised) [Test case 2].
    kryptos_u8_t *c;
    size_t c_size;
    kryptos_u8_t *key = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    kryptos_u8_t *etag = "\xAB\x6E\x47\xD4\x2C\xEC\x13\xBD\xF5\x3A\x67\xB2\x12\x57\xBD\xDF";
    kryptos_u8_t *ec = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"                  // INFO(Rafael): IV.
                       "\x03\x88\xDA\xCE\x60\xB6\xA3\x92\xF3\x28\xC2\xB9\x71\xB2\xFE\x78"; // INFO(Rafael): Cryptogram.
    size_t ec_size = 28;

    //INFO (Rafael): ----- No corrupted data case -----

    c = (kryptos_u8_t *)kryptos_newseg(28);
    CUTE_ASSERT(c != NULL);
    memcpy(c, ec, ec_size);
    c_size = ec_size;

    // INFO(Rafael): GMAC generation test.

    CUTE_ASSERT(kryptos_gcm_auth(&c, &c_size, 12, key, 16, NULL, 0, E_stub, NULL) == kKryptosSuccess);

    // INFO(Rafael): After a well-succeeded generation the tag is appended to the cryptogram (the first 16-bytes).

    CUTE_ASSERT(memcmp(c, etag, 16) == 0);

    // INFO(Rafael): GMAC verification test.

    CUTE_ASSERT(kryptos_gcm_verify(&c, &c_size, 12, key, 16, NULL, 0, E_stub, NULL) == kKryptosSuccess);

    // INFO(Rafael): After a well-succeeded verification the tag is removed from the cryptogram.

    CUTE_ASSERT(c_size == ec_size);
    CUTE_ASSERT(memcmp(c, ec, c_size) == 0);

    kryptos_freeseg(c, c_size);

    //INFO (Rafael): ----- Corrupted data case -----

    c = (kryptos_u8_t *)kryptos_newseg(28);
    CUTE_ASSERT(c != NULL);
    memcpy(c, ec, ec_size);
    c_size = ec_size;

    // INFO(Rafael): GMAC generation test.

    CUTE_ASSERT(kryptos_gcm_auth(&c, &c_size, 12, key, 16, NULL, 0, E_stub, NULL) == kKryptosSuccess);

    // INFO(Rafael): After a well-succeeded generation the tag is appended to the cryptogram (the first 16-bytes).

    CUTE_ASSERT(memcmp(c, etag, 16) == 0);

    // INFO(Rafael): GMAC verification test. Let's flip just one bit by passing the "bad" encryption stub.

    CUTE_ASSERT(kryptos_gcm_verify(&c, &c_size, 12, key, 16, NULL, 0, E_bad_stub, NULL) == kKryptosGMACError);

    // INFO(Rafael): After a non well-succeeded verification the tag is not removed from the cryptogram.

    CUTE_ASSERT(c_size != ec_size);
    CUTE_ASSERT(memcmp(c, ec, ec_size) != 0);

    kryptos_freeseg(c, c_size);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_u32_rev_tests)
    kryptos_u32_t value = 0xEFBEADDE;
    CUTE_ASSERT(kryptos_u32_rev(value) == 0xDEADBEEF);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_u64_rev_tests)
    kryptos_u64_t value = 0x00CABABA5EDAF000;
    CUTE_ASSERT(kryptos_u64_rev(value) == 0x00F0DA5EBABACA00);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_u8_ptr_to_hex_tests)
    kryptos_u8_t *result;
    size_t result_size;
    kryptos_u8_t *u8 = "\xDE\xAD\xBe\xeF\xba\xBA\xCA\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0b\x0C\x0D\x0E\x0F";
    size_t u8_size = 23;

    CUTE_ASSERT(kryptos_u8_ptr_to_hex(NULL, u8_size, &result_size) == NULL);
    CUTE_ASSERT(kryptos_u8_ptr_to_hex(u8, 0, &result_size) == NULL);
    CUTE_ASSERT(kryptos_u8_ptr_to_hex(u8, u8_size, NULL) == NULL);

    CUTE_ASSERT((result = kryptos_u8_ptr_to_hex(u8, u8_size, &result_size)) != NULL);

    CUTE_ASSERT(result_size == (u8_size << 1));

    CUTE_ASSERT(memcmp(result, "DEADBEEFBABACA000102030405060708090A0B0C0D0E0F", result_size) == 0);

    kryptos_freeseg(result, result_size);
CUTE_TEST_CASE_END
