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

CUTE_TEST_CASE(kryptos_sha1_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha1, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha224_tests)
    kryptos_run_hash_tests(sha224, 64, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha224_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha224, 64, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha256_tests)
    kryptos_run_hash_tests(sha256, 64, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha256_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha256, 64, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha384_tests)
    kryptos_run_hash_tests(sha384, 128, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha384_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha384, 128, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha512_tests)
    kryptos_run_hash_tests(sha512, 128, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha512_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha512, 128, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md4_tests)
    kryptos_run_hash_tests(md4, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md4_hash_macro_tests)
    kryptos_run_hash_macro_tests(md4, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md5_tests)
    kryptos_run_hash_tests(md5, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_md5_hash_macro_tests)
    kryptos_run_hash_macro_tests(md5, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd128_tests)
    kryptos_run_hash_tests(ripemd128, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd128_hash_macro_tests)
    kryptos_run_hash_macro_tests(ripemd128, 64, 16);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd160_tests)
    kryptos_run_hash_tests(ripemd160, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_ripemd160_hash_macro_tests)
    kryptos_run_hash_macro_tests(ripemd160, 64, 20);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_224_tests)
    kryptos_run_hash_tests(sha3_224, 144, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_224_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha3_224, 144, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_256_tests)
    kryptos_run_hash_tests(sha3_256, 136, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_256_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha3_256, 136, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_384_tests)
    kryptos_run_hash_tests(sha3_384, 104, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_384_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha3_384, 104, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_512_tests)
    kryptos_run_hash_tests(sha3_512, 72, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_sha3_512_hash_macro_tests)
    kryptos_run_hash_macro_tests(sha3_512, 72, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak224_tests)
    kryptos_run_hash_tests(keccak224, 144, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak224_hash_macro_tests)
    kryptos_run_hash_macro_tests(keccak224, 144, 28);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak256_tests)
    kryptos_run_hash_tests(keccak256, 136, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak256_hash_macro_tests)
    kryptos_run_hash_macro_tests(keccak256, 136, 32);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak384_tests)
    kryptos_run_hash_tests(keccak384, 104, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak384_hash_macro_tests)
    kryptos_run_hash_macro_tests(keccak384, 104, 48);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak512_tests)
    kryptos_run_hash_tests(keccak512, 72, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_keccak512_hash_macro_tests)
    kryptos_run_hash_macro_tests(keccak512, 72, 64);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tiger_tests)
    kryptos_run_hash_tests(tiger, 64, 24);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_tiger_hash_macro_tests)
    kryptos_run_hash_macro_tests(tiger, 64, 24);
CUTE_TEST_CASE_END

CUTE_TEST_CASE(kryptos_hmac_tests)

#if defined(KRYPTOS_C99) && !defined(KRYPTOS_NO_HMAC_TESTS)
    kryptos_u8_t *key = "nooneknows\x00\x00\x00\x00\x00\x00";
    size_t key_size = 16;
    int feal_rounds = 8, rc2_T1 = 64, saferk64_rounds = 6, xtea_rounds = 64;
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
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, tiger, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, des, tiger, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, tiger, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, idea, tiger, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, tiger, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, blowfish, tiger, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha1, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak224, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak256, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak384, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak512, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md4, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md5, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd128, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd160, key, key_size, kKryptosECB, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, tiger, key, key_size, kKryptosECB, &feal_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha1, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, sha3_512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak224, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak256, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak384, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, keccak512, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md4, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, md5, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd128, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, ripemd160, key, key_size, kKryptosCBC, &feal_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, feal, tiger, key, key_size, kKryptosCBC, &feal_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha1, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak224, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak256, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak384, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak512, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md4, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md5, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd128, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd160, key, key_size, kKryptosECB, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, tiger, key, key_size, kKryptosECB, &rc2_T1);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha1, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, sha3_512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak224, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak256, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak384, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, keccak512, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md4, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, md5, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd128, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, ripemd160, key, key_size, kKryptosCBC, &rc2_T1);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, rc2, tiger, key, key_size, kKryptosCBC, &rc2_T1);

    camellia_size = kKryptosCAMELLIA128;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, tiger, key, key_size, kKryptosECB, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, tiger, key, key_size, kKryptosCBC, &camellia_size);

    camellia_size = kKryptosCAMELLIA192;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, tiger, key, key_size, kKryptosECB, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, tiger, key, key_size, kKryptosCBC, &camellia_size);

    camellia_size = kKryptosCAMELLIA256;

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak224, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak256, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak384, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak512, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosECB, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, tiger, key, key_size, kKryptosECB, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha1, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, sha3_384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak224, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak256, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak384, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, keccak512, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md4, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, md5, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd128, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, ripemd160, key, key_size, kKryptosCBC, &camellia_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, camellia, tiger, key, key_size, kKryptosCBC, &camellia_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, tiger, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, cast5, tiger, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha1, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak224, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak256, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak384, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak512, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md4, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md5, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd128, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd160, key, key_size, kKryptosECB, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, tiger, key, key_size, kKryptosECB, &saferk64_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha1, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, sha3_512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak224, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak256, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak384, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, keccak512, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md4, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, md5, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd128, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, ripemd160, key, key_size, kKryptosCBC, &saferk64_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, saferk64, tiger, key, key_size, kKryptosCBC, &saferk64_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, tiger, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes128, tiger, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, tiger, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes192, tiger, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, tiger, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, aes256, tiger, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, tiger, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, serpent, tiger, key, key_size, kKryptosCBC);

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
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md4, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md5, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd128, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd160, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, tiger, key, key_size, kKryptosECB,
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
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md4, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, md5, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd128, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, ripemd160, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, tiger, key, key_size, kKryptosCBC,
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
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak224, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak256, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak384, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak512, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md4, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md5, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd128, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd160, key, key_size, kKryptosECB,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, tiger, key, key_size, kKryptosECB,
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
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, sha3_384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, sha3_512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des, keccak224, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak256, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak384, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, keccak512, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md4, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, md5, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd128, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, ripemd160, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, triple_des_ede, tiger, key, key_size, kKryptosCBC,
                           triple_des_key2, &triple_des_key2_size, triple_des_key3, &triple_des_key3_size);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, tiger, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, tea, tiger, key, key_size, kKryptosCBC);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha1, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha224, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha256, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha384, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha512, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_224, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_256, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_384, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_512, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak224, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak256, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak384, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak512, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, md4, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, md5, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, ripemd128, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, ripemd160, key, key_size, kKryptosECB, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, tiger, key, key_size, kKryptosECB, &xtea_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha1, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha224, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha256, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha384, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha512, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_224, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_256, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_384, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, sha3_512, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak224, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak256, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak384, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, keccak512, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, md4, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, md5, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, ripemd128, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, ripemd160, key, key_size, kKryptosCBC, &xtea_rounds);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, xtea, tiger, key, key_size, kKryptosCBC, &xtea_rounds);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha1, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak224, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak256, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak384, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak512, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, md4, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, md5, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, ripemd128, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, ripemd160, key, key_size, kKryptosECB);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, tiger, key, key_size, kKryptosECB);

    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha1, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, sha3_512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak224, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak256, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak384, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, keccak512, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, md4, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, md5, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, ripemd128, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, ripemd160, key, key_size, kKryptosCBC);
    kryptos_run_hmac_tests(t, tv, tv_nr, data_size, misty1, tiger, key, key_size, kKryptosCBC);
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
