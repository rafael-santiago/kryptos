/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */
#include "hash_tests.h"
#include "test_vectors.h"
#include <kryptos.h>

CUTE_TEST_CASE(kryptos_sha1_tests)
    kryptos_run_hash_tests(sha1, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha224_tests)
    kryptos_run_hash_tests(sha224, 64, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha256_tests)
    kryptos_run_hash_tests(sha256, 64, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha384_tests)
    kryptos_run_hash_tests(sha384, 128, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha512_tests)
    kryptos_run_hash_tests(sha512, 128, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md4_tests)
    kryptos_run_hash_tests(md4, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md5_tests)
    kryptos_run_hash_tests(md5, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd128_tests)
    kryptos_run_hash_tests(ripemd128, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd160_tests)
    kryptos_run_hash_tests(ripemd160, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hmac_tests)

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)
    kryptos_u8_t *key = "nooneknows";
    size_t key_size = 10;
    int feal_rounds = 8, rc2_T1 = 64, saferk64_rounds = 6;
    kryptos_camellia_keysize_t camellia_size;
    size_t tv, tv_nr, data_size;
    kryptos_task_ctx t;
    kryptos_u8_t *triple_des_key2, *triple_des_key3;
    size_t triple_des_key2_size, triple_des_key3_size;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd160, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd160, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd160, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha1, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md4, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md5, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd128, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd160, key, key_size, kKryptosECB, &feal_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha1, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md4, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md5, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd128, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd160, key, key_size, kKryptosCBC, &feal_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha1, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md4, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md5, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd128, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd160, key, key_size, kKryptosECB, &rc2_T1);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha1, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md4, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md5, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd128, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd160, key, key_size, kKryptosCBC, &rc2_T1);

    camellia_size = kKryptosCAMELLIA128;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosECB, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosCBC, &camellia_size);

    camellia_size = kKryptosCAMELLIA192;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosECB, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosCBC, &camellia_size);

    camellia_size = kKryptosCAMELLIA256;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosECB, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosCBC, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd160, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha1, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md4, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md5, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd128, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd160, key, key_size, kKryptosECB, &saferk64_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha1, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md4, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md5, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd128, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd160, key, key_size, kKryptosCBC, &saferk64_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes, ripemd160, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd160, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd160, key, key_size, kKryptosCBC);

    triple_des_key2 = "gowithflow";
    triple_des_key2_size = 10;
    triple_des_key3 = "hangintree";
    triple_des_key3_size = 10;
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha1, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md4, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md5, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd128, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd160, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha1, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md4, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md5, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd128, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd160, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    triple_des_key2 = "gowithflow";
    triple_des_key2_size = 10;
    triple_des_key3 = "hangintree";
    triple_des_key3_size = 10;
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha1, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md4, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md5, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd128, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd160, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha1, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md4, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md5, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd128, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd160, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
#else
# if !defined(KRYPTOS_NO_HMAC_TESTS)
    // TODO(Rafael): When there is no C99 support add a simple bare bone test with at least one block cipher and all
    //               available hash functions.
    printf("WARN: This test runs only when libkryptos is compiled with C99 support. It will be skipped.\n");
# else
    printf("WARN: You have requested build this binary without the HMAC tests.\n");
# endif // !defined(KRYPTOS_SKIP_HMAC_TESTS)
#endif // defined(KRYPTOS_C99) && !defined(KRYPTOS_SKIP_HMAC_TESTS)

CUTE_TEST_CASE_END